using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Logging.Models;

namespace BaseScanner.Analyzers.Logging;

/// <summary>
/// Analyzes log level appropriateness.
/// Detects issues like errors logged as Info, exceptions logged as Debug, etc.
/// </summary>
public class LogLevelAnalyzer : ILoggingDetector
{
    public string Category => "LogLevel";

    // Log levels ordered by severity (higher = more severe)
    private static readonly Dictionary<string, int> LogLevelSeverity = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Trace"] = 0,
        ["Verbose"] = 0,
        ["Debug"] = 1,
        ["Information"] = 2,
        ["Info"] = 2,
        ["Warning"] = 3,
        ["Warn"] = 3,
        ["Error"] = 4,
        ["Critical"] = 5,
        ["Fatal"] = 5
    };

    // Keywords that suggest error-level logging is appropriate
    private static readonly HashSet<string> ErrorKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "error", "failed", "failure", "exception", "crash", "critical",
        "fatal", "corrupt", "invalid", "unauthorized", "forbidden",
        "timeout", "unavailable", "refused", "rejected", "denied"
    };

    // Keywords that suggest warning-level logging is appropriate
    private static readonly HashSet<string> WarningKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "warning", "warn", "deprecated", "obsolete", "retry", "fallback",
        "slow", "degraded", "partial", "incomplete", "missing", "unexpected"
    };

    // Keywords that suggest debug/trace logging is appropriate
    private static readonly HashSet<string> DebugKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "entering", "exiting", "starting", "completing", "processing",
        "received", "sending", "request", "response", "value", "result"
    };

    public Task<List<LoggingIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root)
    {
        var issues = new List<LoggingIssue>();
        var filePath = document.FilePath ?? "";

        // Find all log invocations
        var logInvocations = FindLogInvocations(root, semanticModel);

        foreach (var logStatement in logInvocations)
        {
            // Check for exception logged at inappropriate level
            CheckExceptionLogLevel(logStatement, filePath, issues);

            // Check for message content vs log level mismatch
            CheckMessageLevelMismatch(logStatement, filePath, issues);

            // Check for verbose logging in production code paths
            CheckVerboseInProduction(logStatement, root, filePath, issues);
        }

        return Task.FromResult(issues);
    }

    private List<LogStatement> FindLogInvocations(SyntaxNode root, SemanticModel semanticModel)
    {
        var statements = new List<LogStatement>();

        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var logStatement = TryParseLogStatement(invocation, semanticModel);
            if (logStatement != null)
            {
                statements.Add(logStatement);
            }
        }

        return statements;
    }

    private LogStatement? TryParseLogStatement(InvocationExpressionSyntax invocation, SemanticModel semanticModel)
    {
        string? methodName = null;
        string? framework = null;
        string? level = null;

        if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            methodName = memberAccess.Name.Identifier.Text;

            // Try to determine the framework from the receiver type
            var receiverType = semanticModel.GetTypeInfo(memberAccess.Expression).Type;
            if (receiverType != null)
            {
                var typeName = receiverType.ToDisplayString();
                framework = DetermineFramework(typeName);
            }

            // Parse the log level from the method name
            level = ParseLogLevel(methodName);
        }
        else if (invocation.Expression is IdentifierNameSyntax identifier)
        {
            methodName = identifier.Identifier.Text;
            level = ParseLogLevel(methodName);
        }

        if (level == null || framework == null)
            return null;

        var lineSpan = invocation.GetLocation().GetLineSpan();
        var messageTemplate = ExtractMessageTemplate(invocation);
        var hasException = HasExceptionArgument(invocation, semanticModel);
        var isStructured = IsStructuredLogging(messageTemplate);

        return new LogStatement
        {
            Node = invocation,
            Level = level,
            Framework = framework,
            MessageTemplate = messageTemplate,
            Arguments = invocation.ArgumentList.Arguments.Select(a => (SyntaxNode)a).ToList(),
            HasExceptionArgument = hasException,
            IsStructured = isStructured,
            Line = lineSpan.StartLinePosition.Line + 1,
            FilePath = invocation.SyntaxTree.FilePath
        };
    }

    private string? DetermineFramework(string typeName)
    {
        if (typeName.Contains("Microsoft.Extensions.Logging") || typeName.Contains("ILogger"))
            return "ILogger";
        if (typeName.Contains("Serilog"))
            return "Serilog";
        if (typeName.Contains("NLog"))
            return "NLog";
        if (typeName.Contains("log4net"))
            return "log4net";
        if (typeName.Contains("Logger") || typeName.Contains("Log"))
            return "Unknown";

        return null;
    }

    private string? ParseLogLevel(string methodName)
    {
        // ILogger methods
        if (methodName.StartsWith("Log"))
        {
            var level = methodName.Substring(3);
            if (LogLevelSeverity.ContainsKey(level))
                return level;
            if (methodName == "Log")
                return "Dynamic"; // LogLevel is passed as parameter
        }

        // Serilog/NLog/log4net methods
        if (LogLevelSeverity.ContainsKey(methodName))
            return methodName;

        // Common variations
        return methodName.ToLowerInvariant() switch
        {
            "logtrace" or "trace" => "Trace",
            "logdebug" or "debug" => "Debug",
            "loginfo" or "info" or "loginformation" or "information" => "Information",
            "logwarn" or "warn" or "logwarning" or "warning" => "Warning",
            "logerror" or "error" => "Error",
            "logcritical" or "critical" or "logfatal" or "fatal" => "Critical",
            _ => null
        };
    }

    private string? ExtractMessageTemplate(InvocationExpressionSyntax invocation)
    {
        foreach (var arg in invocation.ArgumentList.Arguments)
        {
            if (arg.Expression is LiteralExpressionSyntax literal &&
                literal.IsKind(SyntaxKind.StringLiteralExpression))
            {
                return literal.Token.ValueText;
            }
            if (arg.Expression is InterpolatedStringExpressionSyntax interpolated)
            {
                return interpolated.ToString();
            }
        }
        return null;
    }

    private bool HasExceptionArgument(InvocationExpressionSyntax invocation, SemanticModel semanticModel)
    {
        foreach (var arg in invocation.ArgumentList.Arguments)
        {
            var typeInfo = semanticModel.GetTypeInfo(arg.Expression);
            if (typeInfo.Type != null)
            {
                var typeName = typeInfo.Type.ToDisplayString();
                if (typeName.Contains("Exception") || typeName == "System.Exception")
                    return true;
            }
        }
        return false;
    }

    private bool IsStructuredLogging(string? messageTemplate)
    {
        if (string.IsNullOrEmpty(messageTemplate))
            return false;

        // Structured logging uses {PropertyName} placeholders
        return messageTemplate.Contains("{") && messageTemplate.Contains("}") &&
               !messageTemplate.Contains("$\""); // Not interpolated string
    }

    private void CheckExceptionLogLevel(LogStatement logStatement, string filePath, List<LoggingIssue> issues)
    {
        if (!logStatement.HasExceptionArgument)
            return;

        var level = logStatement.Level;
        var severity = LogLevelSeverity.GetValueOrDefault(level, 2);

        // Exception logged at Debug or Trace level
        if (severity <= 1)
        {
            var lineSpan = logStatement.Node.GetLocation().GetLineSpan();
            issues.Add(new LoggingIssue
            {
                IssueType = LoggingIssueType.InconsistentLevel,
                Severity = LoggingSeverity.High,
                Description = $"Exception logged at {level} level - exceptions typically warrant Warning or higher",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                ProblematicCode = logStatement.Node.ToString(),
                Suggestion = "Log exceptions at Warning, Error, or Critical level",
                RecommendedCode = logStatement.Node.ToString().Replace($".{level}(", ".Error("),
                LoggingFramework = logStatement.Framework,
                Confidence = "High"
            });
        }

        // Exception logged at Info level
        if (severity == 2)
        {
            var lineSpan = logStatement.Node.GetLocation().GetLineSpan();
            issues.Add(new LoggingIssue
            {
                IssueType = LoggingIssueType.InconsistentLevel,
                Severity = LoggingSeverity.Medium,
                Description = $"Exception logged at Information level - consider using Warning or Error",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                ProblematicCode = logStatement.Node.ToString(),
                Suggestion = "Use Warning or Error level for exceptions",
                LoggingFramework = logStatement.Framework,
                Confidence = "Medium"
            });
        }
    }

    private void CheckMessageLevelMismatch(LogStatement logStatement, string filePath, List<LoggingIssue> issues)
    {
        var message = logStatement.MessageTemplate?.ToLowerInvariant() ?? "";
        var level = logStatement.Level;
        var currentSeverity = LogLevelSeverity.GetValueOrDefault(level, 2);

        // Check if error keywords are used with low-severity log level
        if (ErrorKeywords.Any(k => message.Contains(k)) && currentSeverity < 4)
        {
            var lineSpan = logStatement.Node.GetLocation().GetLineSpan();
            issues.Add(new LoggingIssue
            {
                IssueType = LoggingIssueType.InconsistentLevel,
                Severity = LoggingSeverity.Medium,
                Description = $"Message contains error-related keywords but logged at {level} level",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                ProblematicCode = logStatement.Node.ToString(),
                Suggestion = "Consider using Error or Critical level for error conditions",
                LoggingFramework = logStatement.Framework,
                Confidence = "Medium"
            });
        }

        // Check if warning keywords are used with Info or lower
        if (WarningKeywords.Any(k => message.Contains(k)) && currentSeverity < 3)
        {
            var lineSpan = logStatement.Node.GetLocation().GetLineSpan();
            issues.Add(new LoggingIssue
            {
                IssueType = LoggingIssueType.InconsistentLevel,
                Severity = LoggingSeverity.Low,
                Description = $"Message contains warning-related keywords but logged at {level} level",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                ProblematicCode = logStatement.Node.ToString(),
                Suggestion = "Consider using Warning level",
                LoggingFramework = logStatement.Framework,
                Confidence = "Low"
            });
        }

        // Check if debug-like content is logged at Error level
        if (DebugKeywords.Any(k => message.Contains(k)) && currentSeverity >= 4 &&
            !ErrorKeywords.Any(k => message.Contains(k)))
        {
            var lineSpan = logStatement.Node.GetLocation().GetLineSpan();
            issues.Add(new LoggingIssue
            {
                IssueType = LoggingIssueType.InconsistentLevel,
                Severity = LoggingSeverity.Low,
                Description = $"Routine operation logged at {level} level - may cause log noise",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                ProblematicCode = logStatement.Node.ToString(),
                Suggestion = "Consider using Debug or Information level for routine operations",
                LoggingFramework = logStatement.Framework,
                Confidence = "Low"
            });
        }
    }

    private void CheckVerboseInProduction(
        LogStatement logStatement,
        SyntaxNode root,
        string filePath,
        List<LoggingIssue> issues)
    {
        var level = logStatement.Level;
        if (level != "Debug" && level != "Trace" && level != "Verbose")
            return;

        // Check if this is in a production code path (controller, service, etc.)
        var containingClass = logStatement.Node.Ancestors()
            .OfType<ClassDeclarationSyntax>()
            .FirstOrDefault();

        if (containingClass == null)
            return;

        var className = containingClass.Identifier.Text;
        var isProductionPath = className.EndsWith("Controller") ||
                               className.EndsWith("Service") ||
                               className.EndsWith("Handler") ||
                               className.EndsWith("Middleware") ||
                               className.EndsWith("Repository");

        // Check if in a hot path (loop, frequently called method)
        var isInLoop = logStatement.Node.Ancestors()
            .Any(n => n is ForStatementSyntax or
                      ForEachStatementSyntax or
                      WhileStatementSyntax or
                      DoStatementSyntax);

        if (isProductionPath || isInLoop)
        {
            var context = isInLoop ? "inside a loop" : "in production code";
            var lineSpan = logStatement.Node.GetLocation().GetLineSpan();

            issues.Add(new LoggingIssue
            {
                IssueType = LoggingIssueType.VerboseInProduction,
                Severity = isInLoop ? LoggingSeverity.High : LoggingSeverity.Medium,
                Description = $"{level} logging {context} may impact performance",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                ProblematicCode = logStatement.Node.ToString(),
                Suggestion = isInLoop
                    ? "Remove or guard with IsEnabled check, or move outside loop"
                    : "Consider guarding with IsEnabled check or reducing verbosity",
                RecommendedCode = $"if (_logger.IsEnabled(LogLevel.{level})) {{ {logStatement.Node} }}",
                LoggingFramework = logStatement.Framework,
                Confidence = isInLoop ? "High" : "Medium",
                Metadata = new Dictionary<string, string>
                {
                    ["Context"] = context,
                    ["ContainingClass"] = className
                }
            });
        }
    }
}
