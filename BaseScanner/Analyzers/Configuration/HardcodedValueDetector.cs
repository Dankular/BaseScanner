using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Configuration.Models;
using System.Text.RegularExpressions;

namespace BaseScanner.Analyzers.Configuration;

/// <summary>
/// Detects hardcoded configuration values in source code including:
/// - Connection strings
/// - URLs and endpoints
/// - File paths (Windows and Unix)
/// - Credentials and secrets
/// - IP addresses and port numbers
/// </summary>
public class HardcodedValueDetector
{
    // Regex patterns for detection
    private static readonly Regex UrlPattern = new(
        @"^(https?|ftp)://",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ConnectionStringPattern = new(
        @"Server\s*=|Data Source\s*=|Initial Catalog\s*=|Database\s*=|Integrated Security\s*=|User Id\s*=|Password\s*=",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex WindowsPathPattern = new(
        @"[A-Za-z]:\\",
        RegexOptions.Compiled);

    private static readonly Regex UnixPathPattern = new(
        @"^/[a-z]+/",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex IpAddressPattern = new(
        @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        RegexOptions.Compiled);

    private static readonly Regex PortNumberPattern = new(
        @":\d{4,5}\b",
        RegexOptions.Compiled);

    private static readonly Regex CredentialPattern = new(
        @"(password|pwd|passwd|secret|apikey|api_key|token|auth|credential)\s*(=|:)\s*[""'][^""']+[""']",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex UsernamePattern = new(
        @"(username|user|userid|user_id|login)\s*(=|:)\s*[""'][^""']+[""']",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Known safe patterns to exclude
    private static readonly HashSet<string> SafeUrls = new(StringComparer.OrdinalIgnoreCase)
    {
        "http://localhost",
        "https://localhost",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "http://example.com",
        "https://example.com",
        "http://www.example.com",
        "https://www.example.com",
        "http://schemas.xmlsoap.org",
        "http://www.w3.org",
        "https://www.w3.org"
    };

    private static readonly HashSet<string> SafePaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/api/",
        "/v1/",
        "/v2/",
        "/swagger/",
        "/health",
        "/ping"
    };

    /// <summary>
    /// Detect hardcoded values in the given syntax tree.
    /// </summary>
    public Task<List<ConfigurationIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root)
    {
        var issues = new List<ConfigurationIssue>();
        var filePath = document.FilePath ?? "";

        // Find all string literals
        var stringLiterals = root.DescendantNodes()
            .OfType<LiteralExpressionSyntax>()
            .Where(l => l.IsKind(SyntaxKind.StringLiteralExpression));

        foreach (var literal in stringLiterals)
        {
            var value = literal.Token.ValueText;
            if (string.IsNullOrWhiteSpace(value) || value.Length < 3)
                continue;

            // Skip if inside XML documentation
            if (IsInXmlDocumentation(literal))
                continue;

            // Check for various hardcoded patterns
            CheckConnectionString(literal, value, filePath, issues);
            CheckUrl(literal, value, filePath, issues);
            CheckFilePath(literal, value, filePath, issues);
            CheckCredentials(literal, value, filePath, issues);
            CheckIpAddress(literal, value, filePath, issues);
        }

        // Check interpolated strings
        var interpolatedStrings = root.DescendantNodes()
            .OfType<InterpolatedStringExpressionSyntax>();

        foreach (var interpolated in interpolatedStrings)
        {
            var fullText = interpolated.ToString();
            CheckConnectionString(interpolated, fullText, filePath, issues);
            CheckUrl(interpolated, fullText, filePath, issues);
            CheckFilePath(interpolated, fullText, filePath, issues);
        }

        return Task.FromResult(issues);
    }

    private void CheckConnectionString(SyntaxNode node, string value, string filePath, List<ConfigurationIssue> issues)
    {
        if (!ConnectionStringPattern.IsMatch(value))
            return;

        // Additional check for common connection string components
        var isConnectionString = value.Contains("Server", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("Data Source", StringComparison.OrdinalIgnoreCase) ||
                                 value.Contains("Initial Catalog", StringComparison.OrdinalIgnoreCase);

        if (!isConnectionString)
            return;

        var lineSpan = node.GetLocation().GetLineSpan();
        var maskedValue = MaskSensitiveValue(value);

        issues.Add(new ConfigurationIssue
        {
            IssueType = ConfigurationIssueType.HardcodedConnection,
            Severity = ConfigurationSeverity.Critical,
            FilePath = filePath,
            StartLine = lineSpan.StartLinePosition.Line + 1,
            EndLine = lineSpan.EndLinePosition.Line + 1,
            CodeSnippet = node.Parent?.ToString().Trim() ?? node.ToString().Trim(),
            Description = "Hardcoded connection string detected in source code. Connection strings should be stored in configuration files or environment variables.",
            Recommendation = "Move connection string to appsettings.json or use environment variables. Access via IConfiguration.GetConnectionString().",
            DetectedValue = maskedValue,
            SuggestedFix = "var connectionString = _configuration.GetConnectionString(\"DefaultConnection\");",
            Confidence = "High"
        });
    }

    private void CheckUrl(SyntaxNode node, string value, string filePath, List<ConfigurationIssue> issues)
    {
        if (!UrlPattern.IsMatch(value))
            return;

        // Skip safe/example URLs
        if (SafeUrls.Any(safe => value.StartsWith(safe, StringComparison.OrdinalIgnoreCase)))
            return;

        // Skip relative API paths
        if (SafePaths.Any(safe => value.Contains(safe, StringComparison.OrdinalIgnoreCase) && !value.Contains("://", StringComparison.Ordinal)))
            return;

        // Skip if it's just a schema URL
        if (value.Contains("schemas.") || value.Contains("www.w3.org") || value.Contains("xmlns"))
            return;

        var lineSpan = node.GetLocation().GetLineSpan();

        issues.Add(new ConfigurationIssue
        {
            IssueType = ConfigurationIssueType.HardcodedUrl,
            Severity = ConfigurationSeverity.High,
            FilePath = filePath,
            StartLine = lineSpan.StartLinePosition.Line + 1,
            EndLine = lineSpan.EndLinePosition.Line + 1,
            CodeSnippet = node.Parent?.ToString().Trim() ?? node.ToString().Trim(),
            Description = "Hardcoded URL/endpoint detected. URLs should be configurable to support different environments.",
            Recommendation = "Move URL to configuration and access via IConfiguration. Consider using named HttpClient with base address configuration.",
            DetectedValue = value,
            SuggestedFix = "var apiUrl = _configuration[\"ApiSettings:BaseUrl\"];",
            Confidence = "High"
        });
    }

    private void CheckFilePath(SyntaxNode node, string value, string filePath, List<ConfigurationIssue> issues)
    {
        var isWindowsPath = WindowsPathPattern.IsMatch(value);
        var isUnixPath = UnixPathPattern.IsMatch(value);

        if (!isWindowsPath && !isUnixPath)
            return;

        // Skip if it looks like a relative path pattern
        if (value.StartsWith("/api/") || value.StartsWith("/v"))
            return;

        var severity = ConfigurationSeverity.Medium;
        var description = "Hardcoded file path detected.";

        // Higher severity for system paths
        if (value.Contains("Program Files", StringComparison.OrdinalIgnoreCase) ||
            value.Contains("/etc/", StringComparison.Ordinal) ||
            value.Contains("/usr/", StringComparison.Ordinal) ||
            value.Contains("/var/", StringComparison.Ordinal) ||
            value.Contains("System32", StringComparison.OrdinalIgnoreCase))
        {
            severity = ConfigurationSeverity.High;
            description = "Hardcoded system path detected. This may cause issues across different environments or operating systems.";
        }

        var lineSpan = node.GetLocation().GetLineSpan();

        issues.Add(new ConfigurationIssue
        {
            IssueType = ConfigurationIssueType.HardcodedPath,
            Severity = severity,
            FilePath = filePath,
            StartLine = lineSpan.StartLinePosition.Line + 1,
            EndLine = lineSpan.EndLinePosition.Line + 1,
            CodeSnippet = node.Parent?.ToString().Trim() ?? node.ToString().Trim(),
            Description = description + " Hardcoded paths reduce portability and complicate deployment.",
            Recommendation = "Use Path.Combine with configurable base paths. Store paths in configuration or use well-known folder APIs (Environment.SpecialFolder).",
            DetectedValue = value,
            SuggestedFix = "var basePath = _configuration[\"AppSettings:DataPath\"];\nvar fullPath = Path.Combine(basePath, fileName);",
            Confidence = "High"
        });
    }

    private void CheckCredentials(SyntaxNode node, string value, string filePath, List<ConfigurationIssue> issues)
    {
        var fullContext = node.Parent?.ToString() ?? node.ToString();

        var hasPassword = CredentialPattern.IsMatch(fullContext);
        var hasUsername = UsernamePattern.IsMatch(fullContext);

        if (!hasPassword && !hasUsername)
            return;

        var lineSpan = node.GetLocation().GetLineSpan();
        var severity = hasPassword ? ConfigurationSeverity.Critical : ConfigurationSeverity.High;
        var maskedValue = hasPassword ? "[REDACTED]" : MaskSensitiveValue(value);

        issues.Add(new ConfigurationIssue
        {
            IssueType = ConfigurationIssueType.HardcodedCredential,
            Severity = severity,
            FilePath = filePath,
            StartLine = lineSpan.StartLinePosition.Line + 1,
            EndLine = lineSpan.EndLinePosition.Line + 1,
            CodeSnippet = MaskCredentialsInCode(node.Parent?.ToString().Trim() ?? node.ToString().Trim()),
            Description = hasPassword
                ? "Hardcoded password/secret detected in source code. This is a critical security vulnerability."
                : "Hardcoded username/credential detected in source code.",
            Recommendation = hasPassword
                ? "Remove credentials from source code immediately. Use Azure Key Vault, AWS Secrets Manager, or environment variables for secrets."
                : "Consider moving credentials to secure configuration. Use managed identities where possible.",
            DetectedValue = maskedValue,
            SuggestedFix = "var secret = _configuration[\"Secrets:ApiKey\"];\n// Or use: Environment.GetEnvironmentVariable(\"API_KEY\")",
            Confidence = "High"
        });
    }

    private void CheckIpAddress(SyntaxNode node, string value, string filePath, List<ConfigurationIssue> issues)
    {
        if (!IpAddressPattern.IsMatch(value))
            return;

        // Skip localhost
        if (value.Contains("127.0.0.1") || value.Contains("0.0.0.0"))
            return;

        // Skip if it looks like a version number (1.0.0.0)
        if (Regex.IsMatch(value, @"^\d+\.\d+\.\d+\.\d+$") && !value.StartsWith("10.") && !value.StartsWith("192.168.") && !value.StartsWith("172."))
        {
            // Could be version, check context
            var context = node.Parent?.ToString() ?? "";
            if (context.Contains("Version", StringComparison.OrdinalIgnoreCase) ||
                context.Contains("Assembly", StringComparison.OrdinalIgnoreCase))
                return;
        }

        var hasPort = PortNumberPattern.IsMatch(value);
        var lineSpan = node.GetLocation().GetLineSpan();

        issues.Add(new ConfigurationIssue
        {
            IssueType = ConfigurationIssueType.HardcodedUrl,
            Severity = ConfigurationSeverity.Medium,
            FilePath = filePath,
            StartLine = lineSpan.StartLinePosition.Line + 1,
            EndLine = lineSpan.EndLinePosition.Line + 1,
            CodeSnippet = node.Parent?.ToString().Trim() ?? node.ToString().Trim(),
            Description = hasPort
                ? "Hardcoded IP address with port detected. Network configuration should be environment-specific."
                : "Hardcoded IP address detected. IP addresses may change between environments.",
            Recommendation = "Move network configuration to appsettings.json. Use DNS names when possible for better maintainability.",
            DetectedValue = value,
            SuggestedFix = "var serverAddress = _configuration[\"Network:ServerAddress\"];",
            Confidence = "Medium"
        });
    }

    private static bool IsInXmlDocumentation(SyntaxNode node)
    {
        var parent = node.Parent;
        while (parent != null)
        {
            if (parent is DocumentationCommentTriviaSyntax)
                return true;
            parent = parent.Parent;
        }
        return false;
    }

    private static string MaskSensitiveValue(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= 8)
            return "****";

        return value[..4] + new string('*', Math.Min(value.Length - 4, 20));
    }

    private static string MaskCredentialsInCode(string code)
    {
        // Mask password values in code snippets
        var result = Regex.Replace(code,
            @"(password|pwd|passwd|secret|apikey|api_key|token)\s*(=|:)\s*[""']([^""']+)[""']",
            "$1$2\"[REDACTED]\"",
            RegexOptions.IgnoreCase);

        return result;
    }
}
