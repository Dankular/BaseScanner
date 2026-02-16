using System.Collections.Immutable;

namespace BaseScanner.Reporting.Models;

/// <summary>
/// Base interface for all reporter implementations.
/// </summary>
public interface IReporter
{
    /// <summary>
    /// Generate a report from the given analysis result.
    /// </summary>
    Task<string> GenerateAsync(ReportData data, ReportOptions options);

    /// <summary>
    /// Write the report to the specified output path.
    /// </summary>
    Task WriteAsync(ReportData data, ReportOptions options, string outputPath);
}

/// <summary>
/// Unified report data structure containing all analysis results.
/// </summary>
public record ReportData
{
    /// <summary>
    /// Project information.
    /// </summary>
    public required ProjectInfo Project { get; init; }

    /// <summary>
    /// Timestamp when the analysis was performed.
    /// </summary>
    public DateTime AnalysisTimestamp { get; init; } = DateTime.UtcNow;

    /// <summary>
    /// All issues found during analysis.
    /// </summary>
    public ImmutableList<ReportIssue> Issues { get; init; } = [];

    /// <summary>
    /// Rules that were used during analysis.
    /// </summary>
    public ImmutableList<ReportRule> Rules { get; init; } = [];

    /// <summary>
    /// Summary metrics for the report.
    /// </summary>
    public ReportSummary Summary { get; init; } = new();

    /// <summary>
    /// Historical data for trend analysis (if available).
    /// </summary>
    public ImmutableList<HistoricalSnapshot> History { get; init; } = [];
}

/// <summary>
/// Project information for the report.
/// </summary>
public record ProjectInfo
{
    /// <summary>
    /// Project name.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Full path to the project file.
    /// </summary>
    public required string Path { get; init; }

    /// <summary>
    /// Version from project file or git tag.
    /// </summary>
    public string Version { get; init; } = "";

    /// <summary>
    /// Git commit hash if available.
    /// </summary>
    public string CommitHash { get; init; } = "";

    /// <summary>
    /// Git branch name if available.
    /// </summary>
    public string Branch { get; init; } = "";

    /// <summary>
    /// Total number of files analyzed.
    /// </summary>
    public int FileCount { get; init; }

    /// <summary>
    /// Total lines of code analyzed.
    /// </summary>
    public int TotalLinesOfCode { get; init; }
}

/// <summary>
/// A single issue/finding from the analysis.
/// </summary>
public record ReportIssue
{
    /// <summary>
    /// Unique identifier for this issue instance.
    /// </summary>
    public string Id { get; init; } = Guid.NewGuid().ToString("N")[..8];

    /// <summary>
    /// Rule ID that detected this issue.
    /// </summary>
    public required string RuleId { get; init; }

    /// <summary>
    /// Severity level.
    /// </summary>
    public required IssueSeverity Severity { get; init; }

    /// <summary>
    /// Category of the issue.
    /// </summary>
    public required string Category { get; init; }

    /// <summary>
    /// Human-readable message describing the issue.
    /// </summary>
    public required string Message { get; init; }

    /// <summary>
    /// Detailed description of the issue.
    /// </summary>
    public string Description { get; init; } = "";

    /// <summary>
    /// Location of the issue.
    /// </summary>
    public required IssueLocation Location { get; init; }

    /// <summary>
    /// Data flow path for taint-style issues.
    /// </summary>
    public ImmutableList<CodeFlowLocation> CodeFlow { get; init; } = [];

    /// <summary>
    /// Suggested fix if available.
    /// </summary>
    public IssueFix? Fix { get; init; }

    /// <summary>
    /// Additional properties for the issue.
    /// </summary>
    public ImmutableDictionary<string, string> Properties { get; init; } = ImmutableDictionary<string, string>.Empty;

    /// <summary>
    /// Tags for filtering/grouping.
    /// </summary>
    public ImmutableList<string> Tags { get; init; } = [];

    /// <summary>
    /// Fingerprint for deduplication across runs.
    /// </summary>
    public string Fingerprint { get; init; } = "";

    /// <summary>
    /// CWE ID for security issues.
    /// </summary>
    public string? CweId { get; init; }

    /// <summary>
    /// Confidence level of the detection.
    /// </summary>
    public ConfidenceLevel Confidence { get; init; } = ConfidenceLevel.Medium;
}

/// <summary>
/// Location of an issue in source code.
/// </summary>
public record IssueLocation
{
    /// <summary>
    /// Absolute path to the file.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Relative path from project root.
    /// </summary>
    public string RelativePath { get; init; } = "";

    /// <summary>
    /// Starting line number (1-based).
    /// </summary>
    public required int StartLine { get; init; }

    /// <summary>
    /// Ending line number (1-based).
    /// </summary>
    public int EndLine { get; init; }

    /// <summary>
    /// Starting column (1-based).
    /// </summary>
    public int StartColumn { get; init; } = 1;

    /// <summary>
    /// Ending column (1-based).
    /// </summary>
    public int EndColumn { get; init; }

    /// <summary>
    /// The source code snippet.
    /// </summary>
    public string Snippet { get; init; } = "";

    /// <summary>
    /// Logical location (e.g., "MyClass.MyMethod").
    /// </summary>
    public string LogicalLocation { get; init; } = "";
}

/// <summary>
/// A location in a code flow (for data flow analysis).
/// </summary>
public record CodeFlowLocation
{
    /// <summary>
    /// Step number in the flow.
    /// </summary>
    public int Step { get; init; }

    /// <summary>
    /// Location of this step.
    /// </summary>
    public required IssueLocation Location { get; init; }

    /// <summary>
    /// Description of what happens at this step.
    /// </summary>
    public string Message { get; init; } = "";

    /// <summary>
    /// Kind of step (source, propagation, sink).
    /// </summary>
    public CodeFlowKind Kind { get; init; } = CodeFlowKind.Propagation;
}

/// <summary>
/// Kind of code flow step.
/// </summary>
public enum CodeFlowKind
{
    Source,
    Propagation,
    Sink
}

/// <summary>
/// A suggested fix for an issue.
/// </summary>
public record IssueFix
{
    /// <summary>
    /// Description of the fix.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Code replacements to apply.
    /// </summary>
    public ImmutableList<CodeReplacement> Replacements { get; init; } = [];
}

/// <summary>
/// A code replacement as part of a fix.
/// </summary>
public record CodeReplacement
{
    /// <summary>
    /// Location to replace.
    /// </summary>
    public required IssueLocation Location { get; init; }

    /// <summary>
    /// New text to insert.
    /// </summary>
    public required string NewText { get; init; }
}

/// <summary>
/// A rule/analyzer definition.
/// </summary>
public record ReportRule
{
    /// <summary>
    /// Unique rule identifier.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// Short name of the rule.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Full description of the rule.
    /// </summary>
    public string Description { get; init; } = "";

    /// <summary>
    /// Help text or remediation guidance.
    /// </summary>
    public string HelpText { get; init; } = "";

    /// <summary>
    /// URL for more information.
    /// </summary>
    public string HelpUri { get; init; } = "";

    /// <summary>
    /// Default severity level.
    /// </summary>
    public IssueSeverity DefaultSeverity { get; init; } = IssueSeverity.Warning;

    /// <summary>
    /// Category of the rule.
    /// </summary>
    public string Category { get; init; } = "";

    /// <summary>
    /// Tags for the rule.
    /// </summary>
    public ImmutableList<string> Tags { get; init; } = [];

    /// <summary>
    /// CWE IDs if this is a security rule.
    /// </summary>
    public ImmutableList<string> CweIds { get; init; } = [];
}

/// <summary>
/// Summary of report metrics.
/// </summary>
public record ReportSummary
{
    /// <summary>
    /// Total number of issues found.
    /// </summary>
    public int TotalIssues { get; init; }

    /// <summary>
    /// Count of error-level issues.
    /// </summary>
    public int ErrorCount { get; init; }

    /// <summary>
    /// Count of warning-level issues.
    /// </summary>
    public int WarningCount { get; init; }

    /// <summary>
    /// Count of info-level issues.
    /// </summary>
    public int InfoCount { get; init; }

    /// <summary>
    /// Issues grouped by category.
    /// </summary>
    public ImmutableDictionary<string, int> IssuesByCategory { get; init; } = ImmutableDictionary<string, int>.Empty;

    /// <summary>
    /// Issues grouped by rule.
    /// </summary>
    public ImmutableDictionary<string, int> IssuesByRule { get; init; } = ImmutableDictionary<string, int>.Empty;

    /// <summary>
    /// Issues grouped by file.
    /// </summary>
    public ImmutableDictionary<string, int> IssuesByFile { get; init; } = ImmutableDictionary<string, int>.Empty;

    /// <summary>
    /// Number of files with issues.
    /// </summary>
    public int FilesWithIssues { get; init; }

    /// <summary>
    /// Total files analyzed.
    /// </summary>
    public int FilesAnalyzed { get; init; }

    /// <summary>
    /// Analysis duration in milliseconds.
    /// </summary>
    public long AnalysisDurationMs { get; init; }

    /// <summary>
    /// Quality score (0-100).
    /// </summary>
    public double QualityScore { get; init; }

    /// <summary>
    /// Security score (0-100).
    /// </summary>
    public double SecurityScore { get; init; }
}

/// <summary>
/// Historical snapshot for trend analysis.
/// </summary>
public record HistoricalSnapshot
{
    /// <summary>
    /// Timestamp of the snapshot.
    /// </summary>
    public DateTime Timestamp { get; init; }

    /// <summary>
    /// Git commit hash.
    /// </summary>
    public string CommitHash { get; init; } = "";

    /// <summary>
    /// Summary at this point in time.
    /// </summary>
    public ReportSummary Summary { get; init; } = new();
}

/// <summary>
/// Severity levels for issues.
/// </summary>
public enum IssueSeverity
{
    /// <summary>
    /// Informational only.
    /// </summary>
    Note = 0,

    /// <summary>
    /// Warning-level issue.
    /// </summary>
    Warning = 1,

    /// <summary>
    /// Error-level issue.
    /// </summary>
    Error = 2,

    /// <summary>
    /// Critical/security issue.
    /// </summary>
    Critical = 3
}

/// <summary>
/// Confidence level of detection.
/// </summary>
public enum ConfidenceLevel
{
    Low,
    Medium,
    High
}

/// <summary>
/// Options for report generation.
/// </summary>
public record ReportOptions
{
    /// <summary>
    /// Include source code snippets.
    /// </summary>
    public bool IncludeSnippets { get; init; } = true;

    /// <summary>
    /// Include suggested fixes.
    /// </summary>
    public bool IncludeFixes { get; init; } = true;

    /// <summary>
    /// Include code flow for data flow issues.
    /// </summary>
    public bool IncludeCodeFlows { get; init; } = true;

    /// <summary>
    /// Minimum severity to include.
    /// </summary>
    public IssueSeverity MinSeverity { get; init; } = IssueSeverity.Note;

    /// <summary>
    /// Maximum number of issues to include.
    /// </summary>
    public int MaxIssues { get; init; } = 1000;

    /// <summary>
    /// Include historical trend data.
    /// </summary>
    public bool IncludeHistory { get; init; } = false;

    /// <summary>
    /// Format-specific options.
    /// </summary>
    public ImmutableDictionary<string, string> FormatOptions { get; init; } = ImmutableDictionary<string, string>.Empty;

    /// <summary>
    /// Title for the report.
    /// </summary>
    public string Title { get; init; } = "Code Analysis Report";

    /// <summary>
    /// Base URL for file links (for HTML reports).
    /// </summary>
    public string BaseUrl { get; init; } = "";
}

/// <summary>
/// Output format for reports.
/// </summary>
public enum ReportFormat
{
    Sarif,
    JUnit,
    Html,
    GitHubAnnotations,
    AzureDevOps,
    Json,
    Markdown
}

/// <summary>
/// Factory for creating reporters.
/// </summary>
public static class ReporterFactory
{
    /// <summary>
    /// Create a reporter for the specified format.
    /// </summary>
    public static IReporter Create(ReportFormat format)
    {
        return format switch
        {
            ReportFormat.Sarif => new SarifReporter(),
            ReportFormat.JUnit => new JUnitReporter(),
            ReportFormat.Html => new HtmlReporter(),
            ReportFormat.GitHubAnnotations => new GithubAnnotationReporter(),
            ReportFormat.AzureDevOps => new AzureDevOpsReporter(),
            _ => throw new ArgumentException($"Unsupported format: {format}", nameof(format))
        };
    }
}

/// <summary>
/// Extension methods for building report data.
/// </summary>
public static class ReportDataExtensions
{
    /// <summary>
    /// Calculate the summary from issues.
    /// </summary>
    public static ReportSummary CalculateSummary(this IEnumerable<ReportIssue> issues, int filesAnalyzed, long durationMs)
    {
        var issueList = issues.ToList();

        var byCategory = issueList
            .GroupBy(i => i.Category)
            .ToImmutableDictionary(g => g.Key, g => g.Count());

        var byRule = issueList
            .GroupBy(i => i.RuleId)
            .ToImmutableDictionary(g => g.Key, g => g.Count());

        var byFile = issueList
            .GroupBy(i => i.Location.RelativePath)
            .ToImmutableDictionary(g => g.Key, g => g.Count());

        var errorCount = issueList.Count(i => i.Severity >= IssueSeverity.Error);
        var warningCount = issueList.Count(i => i.Severity == IssueSeverity.Warning);
        var infoCount = issueList.Count(i => i.Severity == IssueSeverity.Note);

        // Calculate quality score (100 - penalty for issues)
        var penalty = errorCount * 5 + warningCount * 2 + infoCount * 0.5;
        var qualityScore = Math.Max(0, Math.Min(100, 100 - penalty));

        // Security score based on security-category issues
        var securityIssues = issueList.Count(i =>
            i.Category.Contains("Security", StringComparison.OrdinalIgnoreCase) ||
            i.CweId != null);
        var securityScore = securityIssues == 0 ? 100 : Math.Max(0, 100 - securityIssues * 10);

        return new ReportSummary
        {
            TotalIssues = issueList.Count,
            ErrorCount = errorCount,
            WarningCount = warningCount,
            InfoCount = infoCount,
            IssuesByCategory = byCategory,
            IssuesByRule = byRule,
            IssuesByFile = byFile,
            FilesWithIssues = byFile.Count,
            FilesAnalyzed = filesAnalyzed,
            AnalysisDurationMs = durationMs,
            QualityScore = qualityScore,
            SecurityScore = securityScore
        };
    }

    /// <summary>
    /// Generate a fingerprint for deduplication.
    /// </summary>
    public static string GenerateFingerprint(this ReportIssue issue)
    {
        var data = $"{issue.RuleId}:{issue.Location.RelativePath}:{issue.Location.LogicalLocation}:{issue.Message}";
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(data));
        return Convert.ToHexString(hash)[..16];
    }
}
