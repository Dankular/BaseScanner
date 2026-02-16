using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Logging.Models;
using System.Text.RegularExpressions;

namespace BaseScanner.Analyzers.Logging;

/// <summary>
/// Detects sensitive data (PII, passwords, tokens, secrets) in log statements.
/// Helps prevent accidental exposure of confidential information.
/// </summary>
public class SensitiveDataDetector : ILoggingDetector
{
    public string Category => "SensitiveData";

    // Patterns for sensitive data in log messages and arguments
    private static readonly List<SensitiveDataPattern> SensitivePatterns = new()
    {
        // Credentials
        new("Password", @"\b(password|passwd|pwd)\b", LoggingSeverity.Critical,
            "Passwords should never be logged. Use [REDACTED] or exclude entirely."),
        new("Secret", @"\b(secret|secretkey|secret[_-]?key)\b", LoggingSeverity.Critical,
            "Secrets should never be logged. Store securely and reference by ID."),
        new("Token", @"\b(token|access[_-]?token|refresh[_-]?token|bearer[_-]?token|auth[_-]?token)\b", LoggingSeverity.Critical,
            "Tokens should not be logged. Log token type or last 4 characters only."),
        new("API Key", @"\b(api[_-]?key|apikey)\b", LoggingSeverity.Critical,
            "API keys should not be logged. Reference by name or ID only."),
        new("Credential", @"\b(credential|credentials|creds)\b", LoggingSeverity.Critical,
            "Credentials should not be logged."),

        // PII - Identity
        new("SSN", @"\b(ssn|social[_-]?security|social[_-]?security[_-]?number)\b", LoggingSeverity.Critical,
            "SSN is highly sensitive PII - never log."),
        new("Social Security", @"\bsocial\s*security\b", LoggingSeverity.Critical,
            "Social Security numbers are highly sensitive - never log."),

        // PII - Financial
        new("Credit Card", @"\b(credit[_-]?card|card[_-]?number|ccn|cc[_-]?num)\b", LoggingSeverity.Critical,
            "Credit card numbers should never be logged. Log last 4 digits only if needed."),
        new("CVV", @"\b(cvv|cvc|cvv2|cvc2|security[_-]?code)\b", LoggingSeverity.Critical,
            "CVV codes should never be logged or stored."),
        new("Bank Account", @"\b(bank[_-]?account|account[_-]?number|routing[_-]?number)\b", LoggingSeverity.High,
            "Bank account details should not be logged."),

        // PII - Contact
        new("Email", @"\b(email|e[_-]?mail|email[_-]?address)\b", LoggingSeverity.Medium,
            "Consider masking email addresses in logs (e.g., j***@example.com)."),
        new("Phone", @"\b(phone|phone[_-]?number|mobile|cell|telephone)\b", LoggingSeverity.Medium,
            "Consider masking phone numbers in logs."),
        new("Address", @"\b(address|street[_-]?address|mailing[_-]?address|home[_-]?address)\b", LoggingSeverity.Medium,
            "Physical addresses are PII - consider masking or excluding."),

        // PII - Personal
        new("DOB", @"\b(dob|date[_-]?of[_-]?birth|birth[_-]?date|birthday)\b", LoggingSeverity.Medium,
            "Date of birth is PII - avoid logging."),
        new("Birth Date", @"\bbirth\s*date\b", LoggingSeverity.Medium,
            "Birth date is PII - avoid logging."),

        // Cryptographic
        new("Private Key", @"\b(private[_-]?key|priv[_-]?key)\b", LoggingSeverity.Critical,
            "Private keys should never be logged."),
        new("Encryption Key", @"\b(encryption[_-]?key|aes[_-]?key|symmetric[_-]?key)\b", LoggingSeverity.Critical,
            "Encryption keys should never be logged."),
        new("Certificate", @"\b(certificate|cert|x509)\b", LoggingSeverity.High,
            "Be careful logging certificate details - avoid private key content."),

        // Session/Auth
        new("Session", @"\b(session[_-]?id|sessionid|session[_-]?token)\b", LoggingSeverity.High,
            "Session IDs can enable session hijacking - log carefully."),
        new("Cookie", @"\b(cookie|auth[_-]?cookie)\b", LoggingSeverity.High,
            "Cookie values should not be logged."),
        new("JWT", @"\b(jwt|json[_-]?web[_-]?token)\b", LoggingSeverity.High,
            "JWT tokens contain sensitive claims - avoid logging full token."),

        // Connection Strings
        new("Connection String", @"\b(connection[_-]?string|connstring|conn[_-]?str)\b", LoggingSeverity.High,
            "Connection strings may contain credentials - redact passwords.")
    };

    // Regex patterns for detecting actual sensitive values (not just variable names)
    private static readonly List<(string Name, Regex Pattern, LoggingSeverity Severity)> ValuePatterns = new()
    {
        ("Credit Card Number", new Regex(@"\b(?:\d{4}[- ]?){3}\d{4}\b", RegexOptions.Compiled), LoggingSeverity.Critical),
        ("SSN Format", new Regex(@"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b", RegexOptions.Compiled), LoggingSeverity.Critical),
        ("Email Address", new Regex(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", RegexOptions.Compiled), LoggingSeverity.Medium),
        ("Phone Number", new Regex(@"\b(?:\+?1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b", RegexOptions.Compiled), LoggingSeverity.Medium),
        ("AWS Key", new Regex(@"AKIA[0-9A-Z]{16}", RegexOptions.Compiled), LoggingSeverity.Critical),
        ("JWT Token", new Regex(@"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", RegexOptions.Compiled), LoggingSeverity.Critical),
        ("Bearer Token", new Regex(@"Bearer\s+[A-Za-z0-9\-_.~+/]+=*", RegexOptions.Compiled | RegexOptions.IgnoreCase), LoggingSeverity.Critical)
    };

    public Task<List<LoggingIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root)
    {
        var issues = new List<LoggingIssue>();
        var filePath = document.FilePath ?? "";

        // Find all log invocations
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (!IsLoggingInvocation(invocation, semanticModel))
                continue;

            // Check arguments for sensitive data
            CheckArgumentsForSensitiveData(invocation, semanticModel, filePath, issues);

            // Check message template for sensitive data patterns
            CheckMessageTemplateForSensitiveData(invocation, filePath, issues);
        }

        return Task.FromResult(issues);
    }

    private bool IsLoggingInvocation(InvocationExpressionSyntax invocation, SemanticModel semanticModel)
    {
        if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            var methodName = memberAccess.Name.Identifier.Text;

            // Check for common logging method names
            if (IsLoggingMethodName(methodName))
            {
                var receiverType = semanticModel.GetTypeInfo(memberAccess.Expression).Type;
                if (receiverType != null)
                {
                    var typeName = receiverType.ToDisplayString();
                    return IsLoggingType(typeName);
                }
            }
        }

        return false;
    }

    private bool IsLoggingMethodName(string methodName)
    {
        var loggingMethods = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Log", "LogTrace", "LogDebug", "LogInformation", "LogWarning", "LogError", "LogCritical",
            "Trace", "Debug", "Information", "Info", "Warning", "Warn", "Error", "Fatal", "Critical",
            "Write", "ForContext", "Verbose"
        };

        return loggingMethods.Contains(methodName);
    }

    private bool IsLoggingType(string typeName)
    {
        return typeName.Contains("ILogger") ||
               typeName.Contains("Logger") ||
               typeName.Contains("Serilog") ||
               typeName.Contains("NLog") ||
               typeName.Contains("log4net") ||
               typeName.Contains("ILog");
    }

    private void CheckArgumentsForSensitiveData(
        InvocationExpressionSyntax invocation,
        SemanticModel semanticModel,
        string filePath,
        List<LoggingIssue> issues)
    {
        foreach (var argument in invocation.ArgumentList.Arguments)
        {
            // Check variable names being logged
            CheckExpressionForSensitiveNames(argument.Expression, semanticModel, invocation, filePath, issues);

            // Check string literal values
            if (argument.Expression is LiteralExpressionSyntax literal &&
                literal.IsKind(SyntaxKind.StringLiteralExpression))
            {
                CheckStringForSensitiveValues(literal.Token.ValueText, invocation, filePath, issues);
            }

            // Check interpolated strings
            if (argument.Expression is InterpolatedStringExpressionSyntax interpolated)
            {
                foreach (var content in interpolated.Contents)
                {
                    if (content is InterpolationSyntax interpolation)
                    {
                        CheckExpressionForSensitiveNames(interpolation.Expression, semanticModel, invocation, filePath, issues);
                    }
                    else if (content is InterpolatedStringTextSyntax text)
                    {
                        CheckStringForSensitiveValues(text.TextToken.ValueText, invocation, filePath, issues);
                    }
                }
            }

            // Check anonymous types with sensitive property names
            if (argument.Expression is AnonymousObjectCreationExpressionSyntax anonymousObject)
            {
                foreach (var init in anonymousObject.Initializers)
                {
                    var propName = init.NameEquals?.Name.Identifier.Text ?? "";
                    CheckNameForSensitivePatterns(propName, invocation, filePath, issues, "property");
                }
            }
        }
    }

    private void CheckExpressionForSensitiveNames(
        ExpressionSyntax expression,
        SemanticModel semanticModel,
        InvocationExpressionSyntax logInvocation,
        string filePath,
        List<LoggingIssue> issues)
    {
        string? name = null;

        if (expression is IdentifierNameSyntax identifier)
        {
            name = identifier.Identifier.Text;
        }
        else if (expression is MemberAccessExpressionSyntax memberAccess)
        {
            name = memberAccess.Name.Identifier.Text;
        }

        if (!string.IsNullOrEmpty(name))
        {
            CheckNameForSensitivePatterns(name, logInvocation, filePath, issues, "variable");
        }

        // Recursively check nested expressions
        foreach (var child in expression.DescendantNodes().OfType<IdentifierNameSyntax>())
        {
            CheckNameForSensitivePatterns(child.Identifier.Text, logInvocation, filePath, issues, "variable");
        }
    }

    private void CheckNameForSensitivePatterns(
        string name,
        InvocationExpressionSyntax logInvocation,
        string filePath,
        List<LoggingIssue> issues,
        string context)
    {
        foreach (var pattern in SensitivePatterns)
        {
            if (Regex.IsMatch(name, pattern.Pattern, RegexOptions.IgnoreCase))
            {
                var lineSpan = logInvocation.GetLocation().GetLineSpan();
                issues.Add(new LoggingIssue
                {
                    IssueType = LoggingIssueType.SensitiveDataLogged,
                    Severity = pattern.Severity,
                    Description = $"{pattern.Category} ({context} '{name}') may be logged",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    ProblematicCode = logInvocation.ToString(),
                    Suggestion = pattern.Recommendation,
                    RecommendedCode = GenerateRedactedCode(logInvocation.ToString(), name),
                    Confidence = "High",
                    Metadata = new Dictionary<string, string>
                    {
                        ["SensitiveDataCategory"] = pattern.Category,
                        ["MatchedPattern"] = pattern.Pattern
                    }
                });
                return; // One issue per invocation per name
            }
        }
    }

    private void CheckMessageTemplateForSensitiveData(
        InvocationExpressionSyntax invocation,
        string filePath,
        List<LoggingIssue> issues)
    {
        var messageArg = invocation.ArgumentList.Arguments.FirstOrDefault();
        if (messageArg == null) return;

        string? messageText = null;

        if (messageArg.Expression is LiteralExpressionSyntax literal &&
            literal.IsKind(SyntaxKind.StringLiteralExpression))
        {
            messageText = literal.Token.ValueText;
        }
        else if (messageArg.Expression is InterpolatedStringExpressionSyntax interpolated)
        {
            messageText = interpolated.ToString();
        }

        if (string.IsNullOrEmpty(messageText))
            return;

        // Check for placeholder names that suggest sensitive data
        var placeholderRegex = new Regex(@"\{([^}:]+)(?::[^}]*)?\}");
        foreach (Match match in placeholderRegex.Matches(messageText))
        {
            var placeholderName = match.Groups[1].Value;
            foreach (var pattern in SensitivePatterns)
            {
                if (Regex.IsMatch(placeholderName, pattern.Pattern, RegexOptions.IgnoreCase))
                {
                    var lineSpan = invocation.GetLocation().GetLineSpan();
                    issues.Add(new LoggingIssue
                    {
                        IssueType = LoggingIssueType.SensitiveDataLogged,
                        Severity = pattern.Severity,
                        Description = $"Log template contains sensitive placeholder '{{{placeholderName}}}'",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        ProblematicCode = invocation.ToString(),
                        Suggestion = pattern.Recommendation,
                        Confidence = "High",
                        Metadata = new Dictionary<string, string>
                        {
                            ["SensitiveDataCategory"] = pattern.Category,
                            ["PlaceholderName"] = placeholderName
                        }
                    });
                    break;
                }
            }
        }
    }

    private void CheckStringForSensitiveValues(
        string value,
        InvocationExpressionSyntax logInvocation,
        string filePath,
        List<LoggingIssue> issues)
    {
        foreach (var (name, pattern, severity) in ValuePatterns)
        {
            if (pattern.IsMatch(value))
            {
                var lineSpan = logInvocation.GetLocation().GetLineSpan();
                var maskedValue = MaskValue(pattern.Match(value).Value);

                issues.Add(new LoggingIssue
                {
                    IssueType = LoggingIssueType.SensitiveDataLogged,
                    Severity = severity,
                    Description = $"Potential {name} detected in log message",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    ProblematicCode = logInvocation.ToString(),
                    Suggestion = $"Remove or mask the {name.ToLowerInvariant()}",
                    Confidence = "Medium",
                    Metadata = new Dictionary<string, string>
                    {
                        ["DetectedPattern"] = name,
                        ["MaskedValue"] = maskedValue
                    }
                });
                return; // One issue per value pattern
            }
        }
    }

    private string MaskValue(string value)
    {
        if (value.Length <= 8)
            return "****";

        return value.Substring(0, 4) + "****" + value.Substring(value.Length - 4);
    }

    private string GenerateRedactedCode(string code, string sensitiveName)
    {
        // Suggest replacing sensitive data with [REDACTED] or masking function
        return $"// Consider: _logger.LogInformation(\"... {{MaskedData}}\", MaskSensitiveData({sensitiveName}));";
    }

    private record SensitiveDataPattern(
        string Category,
        string Pattern,
        LoggingSeverity Severity,
        string Recommendation);
}
