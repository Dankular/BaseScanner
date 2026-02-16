using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Logging.Models;

namespace BaseScanner.Analyzers.Logging;

/// <summary>
/// Analyzes structured logging patterns.
/// Detects issues like string concatenation/interpolation instead of structured logging templates.
/// </summary>
public class StructuredLoggingAnalyzer : ILoggingDetector
{
    public string Category => "StructuredLogging";

    // Frameworks that support structured logging
    private static readonly HashSet<string> StructuredLoggingFrameworks = new(StringComparer.OrdinalIgnoreCase)
    {
        "ILogger", "Microsoft.Extensions.Logging.ILogger",
        "Serilog", "Serilog.ILogger", "Serilog.Log",
        "NLog", "NLog.ILogger", "NLog.Logger"
    };

    public Task<List<LoggingIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root)
    {
        var issues = new List<LoggingIssue>();
        var filePath = document.FilePath ?? "";

        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var framework = GetLoggingFramework(invocation, semanticModel);
            if (framework == null)
                continue;

            // Check for string interpolation in log messages
            CheckStringInterpolation(invocation, framework, filePath, issues);

            // Check for string concatenation in log messages
            CheckStringConcatenation(invocation, framework, filePath, issues);

            // Check for string.Format usage
            CheckStringFormat(invocation, framework, filePath, issues);

            // Check for missing structured properties
            CheckMissingStructuredProperties(invocation, semanticModel, framework, filePath, issues);

            // Check for exception message instead of exception object
            CheckExceptionMessageLogging(invocation, semanticModel, framework, filePath, issues);
        }

        return Task.FromResult(issues);
    }

    private string? GetLoggingFramework(InvocationExpressionSyntax invocation, SemanticModel semanticModel)
    {
        if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            var methodName = memberAccess.Name.Identifier.Text;
            if (!IsLoggingMethodName(methodName))
                return null;

            var receiverType = semanticModel.GetTypeInfo(memberAccess.Expression).Type;
            if (receiverType != null)
            {
                var typeName = receiverType.ToDisplayString();

                if (typeName.Contains("ILogger") || typeName.Contains("Microsoft.Extensions.Logging"))
                    return "ILogger";
                if (typeName.Contains("Serilog"))
                    return "Serilog";
                if (typeName.Contains("NLog"))
                    return "NLog";
                if (typeName.Contains("log4net"))
                    return "log4net";
            }
        }

        return null;
    }

    private bool IsLoggingMethodName(string methodName)
    {
        var loggingMethods = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Log", "LogTrace", "LogDebug", "LogInformation", "LogWarning", "LogError", "LogCritical",
            "Trace", "Debug", "Information", "Info", "Warning", "Warn", "Error", "Fatal", "Critical",
            "Write", "Verbose"
        };

        return loggingMethods.Contains(methodName);
    }

    private void CheckStringInterpolation(
        InvocationExpressionSyntax invocation,
        string framework,
        string filePath,
        List<LoggingIssue> issues)
    {
        foreach (var argument in invocation.ArgumentList.Arguments)
        {
            if (argument.Expression is InterpolatedStringExpressionSyntax interpolated)
            {
                // Skip if no actual interpolations (just a string)
                if (!interpolated.Contents.OfType<InterpolationSyntax>().Any())
                    continue;

                var lineSpan = invocation.GetLocation().GetLineSpan();
                var structuredTemplate = ConvertToStructuredTemplate(interpolated);

                issues.Add(new LoggingIssue
                {
                    IssueType = LoggingIssueType.StringConcatInLog,
                    Severity = LoggingSeverity.Medium,
                    Description = "String interpolation in log message prevents structured logging benefits",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    ProblematicCode = invocation.ToString(),
                    Suggestion = "Use message template with named placeholders for structured logging",
                    RecommendedCode = structuredTemplate,
                    LoggingFramework = framework,
                    Confidence = "High",
                    Metadata = new Dictionary<string, string>
                    {
                        ["InterpolationCount"] = interpolated.Contents.OfType<InterpolationSyntax>().Count().ToString()
                    }
                });

                return; // Report once per invocation
            }
        }
    }

    private void CheckStringConcatenation(
        InvocationExpressionSyntax invocation,
        string framework,
        string filePath,
        List<LoggingIssue> issues)
    {
        foreach (var argument in invocation.ArgumentList.Arguments)
        {
            if (argument.Expression is BinaryExpressionSyntax binary &&
                binary.IsKind(SyntaxKind.AddExpression))
            {
                // Check if this is string concatenation
                if (ContainsStringLiteral(binary))
                {
                    var lineSpan = invocation.GetLocation().GetLineSpan();

                    issues.Add(new LoggingIssue
                    {
                        IssueType = LoggingIssueType.StringConcatInLog,
                        Severity = LoggingSeverity.Medium,
                        Description = "String concatenation in log message - use structured logging template",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        ProblematicCode = invocation.ToString(),
                        Suggestion = "Replace string concatenation with message template placeholders",
                        RecommendedCode = "// Example: _logger.LogInformation(\"Processing {ItemName} with ID {ItemId}\", name, id);",
                        LoggingFramework = framework,
                        Confidence = "High"
                    });

                    return;
                }
            }
        }
    }

    private void CheckStringFormat(
        InvocationExpressionSyntax invocation,
        string framework,
        string filePath,
        List<LoggingIssue> issues)
    {
        foreach (var argument in invocation.ArgumentList.Arguments)
        {
            if (argument.Expression is InvocationExpressionSyntax innerInvocation)
            {
                var methodName = GetMethodName(innerInvocation);
                if (methodName == "Format" || methodName == "string.Format")
                {
                    var lineSpan = invocation.GetLocation().GetLineSpan();

                    issues.Add(new LoggingIssue
                    {
                        IssueType = LoggingIssueType.StringConcatInLog,
                        Severity = LoggingSeverity.Medium,
                        Description = "string.Format() in log message - use structured logging template instead",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        ProblematicCode = invocation.ToString(),
                        Suggestion = "Replace string.Format with message template placeholders",
                        RecommendedCode = ConvertStringFormatToTemplate(innerInvocation),
                        LoggingFramework = framework,
                        Confidence = "High"
                    });

                    return;
                }
            }
        }
    }

    private void CheckMissingStructuredProperties(
        InvocationExpressionSyntax invocation,
        SemanticModel semanticModel,
        string framework,
        string filePath,
        List<LoggingIssue> issues)
    {
        var arguments = invocation.ArgumentList.Arguments;
        if (arguments.Count == 0)
            return;

        // Get the message template
        var firstArg = arguments[0];
        string? template = null;

        if (firstArg.Expression is LiteralExpressionSyntax literal &&
            literal.IsKind(SyntaxKind.StringLiteralExpression))
        {
            template = literal.Token.ValueText;
        }

        if (string.IsNullOrEmpty(template))
            return;

        // Count placeholders in template
        var placeholderCount = CountPlaceholders(template);

        // Count non-message arguments (excluding exception which is often first or last)
        var valueArgCount = 0;
        for (int i = 1; i < arguments.Count; i++)
        {
            var argType = semanticModel.GetTypeInfo(arguments[i].Expression).Type;
            if (argType != null && !argType.ToDisplayString().Contains("Exception"))
            {
                valueArgCount++;
            }
        }

        // Mismatch between placeholders and arguments
        if (placeholderCount > 0 && placeholderCount != valueArgCount)
        {
            var lineSpan = invocation.GetLocation().GetLineSpan();

            issues.Add(new LoggingIssue
            {
                IssueType = LoggingIssueType.StringConcatInLog,
                Severity = LoggingSeverity.Low,
                Description = $"Placeholder count ({placeholderCount}) doesn't match argument count ({valueArgCount})",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                ProblematicCode = invocation.ToString(),
                Suggestion = "Ensure message template placeholders match the provided arguments",
                LoggingFramework = framework,
                Confidence = "Medium",
                Metadata = new Dictionary<string, string>
                {
                    ["PlaceholderCount"] = placeholderCount.ToString(),
                    ["ArgumentCount"] = valueArgCount.ToString()
                }
            });
        }

        // Check for positional placeholders ({0}, {1}) instead of named ones
        if (ContainsPositionalPlaceholders(template))
        {
            var lineSpan = invocation.GetLocation().GetLineSpan();

            issues.Add(new LoggingIssue
            {
                IssueType = LoggingIssueType.StringConcatInLog,
                Severity = LoggingSeverity.Low,
                Description = "Using positional placeholders ({0}, {1}) instead of named placeholders",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                ProblematicCode = invocation.ToString(),
                Suggestion = "Use named placeholders like {UserId}, {OrderId} for better log searching and readability",
                LoggingFramework = framework,
                Confidence = "High"
            });
        }
    }

    private void CheckExceptionMessageLogging(
        InvocationExpressionSyntax invocation,
        SemanticModel semanticModel,
        string framework,
        string filePath,
        List<LoggingIssue> issues)
    {
        // Check if we're in a catch block
        var catchClause = invocation.Ancestors().OfType<CatchClauseSyntax>().FirstOrDefault();
        if (catchClause == null)
            return;

        var exceptionVarName = catchClause.Declaration?.Identifier.Text;
        if (string.IsNullOrEmpty(exceptionVarName))
            return;

        // Look for .Message property access without passing the exception object
        bool logsExceptionMessage = false;
        bool logsExceptionObject = false;

        foreach (var argument in invocation.ArgumentList.Arguments)
        {
            var argText = argument.Expression.ToString();

            // Check if logging ex.Message or ex.ToString()
            if (argText.Contains($"{exceptionVarName}.Message") ||
                argText.Contains($"{exceptionVarName}.ToString()"))
            {
                logsExceptionMessage = true;
            }

            // Check if the exception object itself is passed
            if (argument.Expression is IdentifierNameSyntax id &&
                id.Identifier.Text == exceptionVarName)
            {
                logsExceptionObject = true;
            }

            // Check type of argument
            var typeInfo = semanticModel.GetTypeInfo(argument.Expression);
            if (typeInfo.Type?.ToDisplayString().Contains("Exception") == true &&
                !argText.Contains(".Message"))
            {
                logsExceptionObject = true;
            }
        }

        // Also check template for exception placeholder
        var templateArg = invocation.ArgumentList.Arguments.FirstOrDefault();
        if (templateArg?.Expression is LiteralExpressionSyntax literal)
        {
            var template = literal.Token.ValueText;
            if (template.Contains($"{{{exceptionVarName}}}") ||
                template.Contains("{Exception}") ||
                template.Contains("{ex}"))
            {
                logsExceptionObject = true;
            }
        }

        if (logsExceptionMessage && !logsExceptionObject)
        {
            var lineSpan = invocation.GetLocation().GetLineSpan();

            issues.Add(new LoggingIssue
            {
                IssueType = LoggingIssueType.LoggingException,
                Severity = LoggingSeverity.High,
                Description = "Logging exception message but not the exception object - stack trace will be lost",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                ProblematicCode = invocation.ToString(),
                Suggestion = "Pass the exception object as a parameter to preserve stack trace",
                RecommendedCode = framework == "ILogger"
                    ? $"_logger.LogError({exceptionVarName}, \"Error message here\");"
                    : $"_logger.Error({exceptionVarName}, \"Error message here\");",
                LoggingFramework = framework,
                Confidence = "High",
                Metadata = new Dictionary<string, string>
                {
                    ["ExceptionVariable"] = exceptionVarName
                }
            });
        }
    }

    private bool ContainsStringLiteral(BinaryExpressionSyntax binary)
    {
        return binary.Left is LiteralExpressionSyntax left && left.IsKind(SyntaxKind.StringLiteralExpression) ||
               binary.Right is LiteralExpressionSyntax right && right.IsKind(SyntaxKind.StringLiteralExpression) ||
               (binary.Left is BinaryExpressionSyntax leftBinary && ContainsStringLiteral(leftBinary)) ||
               (binary.Right is BinaryExpressionSyntax rightBinary && ContainsStringLiteral(rightBinary));
    }

    private string? GetMethodName(InvocationExpressionSyntax invocation)
    {
        if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            var expr = memberAccess.Expression.ToString();
            var method = memberAccess.Name.Identifier.Text;
            return expr == "string" ? $"string.{method}" : method;
        }
        if (invocation.Expression is IdentifierNameSyntax identifier)
        {
            return identifier.Identifier.Text;
        }
        return null;
    }

    private string ConvertToStructuredTemplate(InterpolatedStringExpressionSyntax interpolated)
    {
        var template = new System.Text.StringBuilder("\"");
        var args = new List<string>();
        var argIndex = 0;

        foreach (var content in interpolated.Contents)
        {
            if (content is InterpolatedStringTextSyntax text)
            {
                template.Append(text.TextToken.ValueText);
            }
            else if (content is InterpolationSyntax interpolation)
            {
                var argName = GetArgumentName(interpolation.Expression, argIndex++);
                template.Append($"{{{argName}}}");
                args.Add(interpolation.Expression.ToString());
            }
        }

        template.Append("\"");

        if (args.Count > 0)
        {
            template.Append(", ");
            template.Append(string.Join(", ", args));
        }

        return $"// Use: _logger.LogInformation({template});";
    }

    private string GetArgumentName(ExpressionSyntax expression, int index)
    {
        if (expression is IdentifierNameSyntax identifier)
        {
            return ToPascalCase(identifier.Identifier.Text);
        }
        if (expression is MemberAccessExpressionSyntax memberAccess)
        {
            return ToPascalCase(memberAccess.Name.Identifier.Text);
        }
        return $"Arg{index}";
    }

    private string ToPascalCase(string name)
    {
        if (string.IsNullOrEmpty(name))
            return name;

        // Remove leading underscore if present
        if (name.StartsWith("_"))
            name = name.Substring(1);

        // Capitalize first letter
        return char.ToUpperInvariant(name[0]) + name.Substring(1);
    }

    private string ConvertStringFormatToTemplate(InvocationExpressionSyntax formatInvocation)
    {
        var args = formatInvocation.ArgumentList.Arguments;
        if (args.Count == 0)
            return "// No format string found";

        var formatArg = args[0];
        if (formatArg.Expression is not LiteralExpressionSyntax literal)
            return "// Dynamic format string - manual conversion needed";

        var formatString = literal.Token.ValueText;
        var convertedTemplate = ConvertFormatStringToTemplate(formatString, args.Skip(1).ToList());

        return $"// Use: _logger.LogInformation({convertedTemplate});";
    }

    private string ConvertFormatStringToTemplate(string formatString, List<ArgumentSyntax> args)
    {
        var result = formatString;

        for (int i = 0; i < args.Count; i++)
        {
            var argName = GetArgumentName(args[i].Expression, i);
            result = result.Replace($"{{{i}}}", $"{{{argName}}}");
            result = result.Replace($"{{{i}:", $"{{{argName}:"); // Preserve format specifiers
        }

        return $"\"{result}\", {string.Join(", ", args.Select(a => a.Expression.ToString()))}";
    }

    private int CountPlaceholders(string template)
    {
        var count = 0;
        var inPlaceholder = false;

        foreach (var c in template)
        {
            if (c == '{')
            {
                inPlaceholder = true;
            }
            else if (c == '}' && inPlaceholder)
            {
                count++;
                inPlaceholder = false;
            }
        }

        return count;
    }

    private bool ContainsPositionalPlaceholders(string template)
    {
        // Check for {0}, {1}, etc.
        for (int i = 0; i < 20; i++)
        {
            if (template.Contains($"{{{i}}}") || template.Contains($"{{{i}:"))
                return true;
        }
        return false;
    }
}
