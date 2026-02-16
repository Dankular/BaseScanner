using Microsoft.CodeAnalysis;

namespace BaseScanner.Analyzers.Logging.Models;

/// <summary>
/// Types of logging issues that can be detected.
/// </summary>
public enum LoggingIssueType
{
    /// <summary>Error logged at Info level, exception logged as Debug, etc.</summary>
    InconsistentLevel,

    /// <summary>PII, passwords, tokens, or other sensitive data in logs.</summary>
    SensitiveDataLogged,

    /// <summary>Catch block without any logging.</summary>
    ExceptionNotLogged,

    /// <summary>Using string interpolation instead of structured logging.</summary>
    StringConcatInLog,

    /// <summary>No correlation ID in request handling code.</summary>
    MissingCorrelation,

    /// <summary>Debug or Trace logging in production code paths.</summary>
    VerboseInProduction,

    /// <summary>Logging exception message but not the exception object.</summary>
    LoggingException
}

/// <summary>
/// Severity levels for logging issues.
/// </summary>
public enum LoggingSeverity
{
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Represents a detected logging quality issue.
/// </summary>
public record LoggingIssue
{
    /// <summary>Type of the logging issue.</summary>
    public required LoggingIssueType IssueType { get; init; }

    /// <summary>Severity of the issue.</summary>
    public required LoggingSeverity Severity { get; init; }

    /// <summary>Human-readable description of the issue.</summary>
    public required string Description { get; init; }

    /// <summary>Path to the file containing the issue.</summary>
    public required string FilePath { get; init; }

    /// <summary>Starting line number (1-based).</summary>
    public required int StartLine { get; init; }

    /// <summary>Ending line number (1-based).</summary>
    public required int EndLine { get; init; }

    /// <summary>The problematic code snippet.</summary>
    public required string ProblematicCode { get; init; }

    /// <summary>Suggested fix or improvement.</summary>
    public required string Suggestion { get; init; }

    /// <summary>Recommended fixed code.</summary>
    public string? RecommendedCode { get; init; }

    /// <summary>Logging framework detected (ILogger, Serilog, NLog, log4net).</summary>
    public string? LoggingFramework { get; init; }

    /// <summary>Confidence level of the detection.</summary>
    public string Confidence { get; init; } = "Medium";

    /// <summary>Additional context or details.</summary>
    public Dictionary<string, string> Metadata { get; init; } = [];
}

/// <summary>
/// Represents sensitive data detected in a log statement.
/// </summary>
public record SensitiveDataMatch
{
    /// <summary>The category of sensitive data (e.g., "Password", "PII", "Token").</summary>
    public required string Category { get; init; }

    /// <summary>The specific pattern that matched.</summary>
    public required string Pattern { get; init; }

    /// <summary>The matched content (masked for security).</summary>
    public required string MaskedMatch { get; init; }

    /// <summary>Severity of exposing this data type.</summary>
    public required LoggingSeverity Severity { get; init; }

    /// <summary>Recommendation for handling this data type.</summary>
    public required string Recommendation { get; init; }
}

/// <summary>
/// Summary of logging analysis results.
/// </summary>
public record LoggingAnalysisSummary
{
    /// <summary>Total number of logging issues found.</summary>
    public int TotalIssues { get; init; }

    /// <summary>Count of Critical severity issues.</summary>
    public int CriticalCount { get; init; }

    /// <summary>Count of High severity issues.</summary>
    public int HighCount { get; init; }

    /// <summary>Count of Medium severity issues.</summary>
    public int MediumCount { get; init; }

    /// <summary>Count of Low severity issues.</summary>
    public int LowCount { get; init; }

    /// <summary>Issues grouped by type.</summary>
    public Dictionary<LoggingIssueType, int> IssuesByType { get; init; } = [];

    /// <summary>Issues grouped by file.</summary>
    public Dictionary<string, int> IssuesByFile { get; init; } = [];

    /// <summary>Logging frameworks detected in the codebase.</summary>
    public HashSet<string> DetectedFrameworks { get; init; } = [];

    /// <summary>Overall logging quality score (0-100).</summary>
    public double QualityScore { get; init; }

    /// <summary>Key recommendations for improving logging quality.</summary>
    public List<string> Recommendations { get; init; } = [];
}

/// <summary>
/// Complete result of logging quality analysis.
/// </summary>
public record LoggingAnalysisResult
{
    /// <summary>All detected logging issues.</summary>
    public List<LoggingIssue> Issues { get; init; } = [];

    /// <summary>Summary of the analysis.</summary>
    public LoggingAnalysisSummary Summary { get; init; } = new();

    /// <summary>Timestamp of when analysis was performed.</summary>
    public DateTime AnalyzedAt { get; init; } = DateTime.UtcNow;

    /// <summary>Project that was analyzed.</summary>
    public string? ProjectPath { get; init; }
}

/// <summary>
/// Interface for individual logging issue detectors.
/// </summary>
public interface ILoggingDetector
{
    /// <summary>The category of logging issues this detector finds.</summary>
    string Category { get; }

    /// <summary>Detect logging issues in the given document.</summary>
    Task<List<LoggingIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root);
}

/// <summary>
/// Represents information about a log statement.
/// </summary>
public record LogStatement
{
    /// <summary>The syntax node of the log invocation.</summary>
    public required SyntaxNode Node { get; init; }

    /// <summary>The log level (Debug, Info, Warning, Error, etc.).</summary>
    public required string Level { get; init; }

    /// <summary>The logging framework being used.</summary>
    public required string Framework { get; init; }

    /// <summary>The message template or format string.</summary>
    public string? MessageTemplate { get; init; }

    /// <summary>Arguments passed to the log method.</summary>
    public List<SyntaxNode> Arguments { get; init; } = [];

    /// <summary>Whether an exception is being logged.</summary>
    public bool HasExceptionArgument { get; init; }

    /// <summary>Whether structured logging is being used.</summary>
    public bool IsStructured { get; init; }

    /// <summary>Line number in the source file.</summary>
    public int Line { get; init; }

    /// <summary>The file path.</summary>
    public string? FilePath { get; init; }
}

/// <summary>
/// Context information about where logging occurs.
/// </summary>
public record LoggingContext
{
    /// <summary>Whether this is inside a catch block.</summary>
    public bool InCatchBlock { get; init; }

    /// <summary>Whether this is in a request handler (controller, API endpoint).</summary>
    public bool InRequestHandler { get; init; }

    /// <summary>Whether this appears to be production code (not test).</summary>
    public bool IsProductionCode { get; init; }

    /// <summary>The containing method name.</summary>
    public string? ContainingMethod { get; init; }

    /// <summary>The containing class name.</summary>
    public string? ContainingClass { get; init; }

    /// <summary>Exception variable name if in catch block.</summary>
    public string? ExceptionVariableName { get; init; }
}
