using Microsoft.CodeAnalysis;

namespace BaseScanner.Analyzers.Documentation.Models;

/// <summary>
/// Types of documentation issues that can be detected.
/// </summary>
public enum DocumentationIssueType
{
    // Missing documentation
    MissingPublicDoc,
    MissingParamDoc,
    MissingReturnDoc,
    MissingExceptionDoc,
    MissingTypeParamDoc,

    // Stale/incorrect documentation
    StaleComment,
    MismatchedParamDoc,
    ObsoleteReference,

    // Naming issues
    MisleadingName,
    AbbreviationOveruse,
    InconsistentNaming,
    VerbNounMismatch,

    // Other issues
    TodoComment,
    FixmeComment,
    HackComment,
    EmptyDocumentation,
    GenericDocumentation
}

/// <summary>
/// Severity of documentation issues.
/// </summary>
public enum DocIssueSeverity
{
    Info = 0,
    Warning = 25,
    Minor = 50,
    Major = 75,
    Critical = 100
}

/// <summary>
/// Category of documentation issues.
/// </summary>
public enum DocIssueCategory
{
    MissingDocumentation,
    StaleDocumentation,
    NamingQuality,
    Completeness,
    ActionItem
}

/// <summary>
/// Represents a detected documentation issue.
/// </summary>
public record DocumentationIssue
{
    /// <summary>
    /// Type of the documentation issue.
    /// </summary>
    public required DocumentationIssueType IssueType { get; init; }

    /// <summary>
    /// Category this issue falls under.
    /// </summary>
    public required DocIssueCategory Category { get; init; }

    /// <summary>
    /// Severity of the issue.
    /// </summary>
    public required DocIssueSeverity Severity { get; init; }

    /// <summary>
    /// Path to the file containing the issue.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Starting line number (1-based).
    /// </summary>
    public required int StartLine { get; init; }

    /// <summary>
    /// Ending line number (1-based).
    /// </summary>
    public required int EndLine { get; init; }

    /// <summary>
    /// Name of the symbol with the issue.
    /// </summary>
    public required string SymbolName { get; init; }

    /// <summary>
    /// Kind of the symbol (class, method, property, etc.).
    /// </summary>
    public required string SymbolKind { get; init; }

    /// <summary>
    /// Human-readable description of the issue.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Suggested fix or improvement.
    /// </summary>
    public string Suggestion { get; init; } = "";

    /// <summary>
    /// The problematic code or documentation snippet.
    /// </summary>
    public string CurrentCode { get; init; } = "";

    /// <summary>
    /// Suggested replacement code or documentation.
    /// </summary>
    public string SuggestedCode { get; init; } = "";

    /// <summary>
    /// Confidence level of the detection (0-100).
    /// </summary>
    public int Confidence { get; init; } = 100;

    /// <summary>
    /// Additional context or metadata.
    /// </summary>
    public Dictionary<string, object> Metadata { get; init; } = [];
}

/// <summary>
/// Represents a suggestion for improving a name.
/// </summary>
public record NameSuggestion
{
    /// <summary>
    /// The original name.
    /// </summary>
    public required string OriginalName { get; init; }

    /// <summary>
    /// Suggested improved name.
    /// </summary>
    public required string SuggestedName { get; init; }

    /// <summary>
    /// Reason for the suggestion.
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>
    /// Confidence in the suggestion (0-100).
    /// </summary>
    public int Confidence { get; init; } = 50;
}

/// <summary>
/// Documentation coverage metrics for a symbol.
/// </summary>
public record DocumentationCoverage
{
    /// <summary>
    /// Name of the symbol.
    /// </summary>
    public required string SymbolName { get; init; }

    /// <summary>
    /// Kind of symbol (class, method, etc.).
    /// </summary>
    public required string SymbolKind { get; init; }

    /// <summary>
    /// File path containing the symbol.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Whether the symbol has a summary.
    /// </summary>
    public bool HasSummary { get; init; }

    /// <summary>
    /// Whether the symbol has remarks.
    /// </summary>
    public bool HasRemarks { get; init; }

    /// <summary>
    /// Whether the symbol has example documentation.
    /// </summary>
    public bool HasExample { get; init; }

    /// <summary>
    /// Number of parameters.
    /// </summary>
    public int ParameterCount { get; init; }

    /// <summary>
    /// Number of documented parameters.
    /// </summary>
    public int DocumentedParameterCount { get; init; }

    /// <summary>
    /// Number of type parameters.
    /// </summary>
    public int TypeParameterCount { get; init; }

    /// <summary>
    /// Number of documented type parameters.
    /// </summary>
    public int DocumentedTypeParameterCount { get; init; }

    /// <summary>
    /// Whether the return value is documented (if applicable).
    /// </summary>
    public bool? HasReturnDoc { get; init; }

    /// <summary>
    /// Number of exceptions that could be thrown.
    /// </summary>
    public int ExceptionCount { get; init; }

    /// <summary>
    /// Number of documented exceptions.
    /// </summary>
    public int DocumentedExceptionCount { get; init; }

    /// <summary>
    /// Overall coverage score (0-100).
    /// </summary>
    public double CoverageScore { get; init; }
}

/// <summary>
/// Summary of documentation analysis for a file.
/// </summary>
public record FileDocumentationSummary
{
    /// <summary>
    /// Path to the file.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Total number of public symbols.
    /// </summary>
    public int TotalPublicSymbols { get; init; }

    /// <summary>
    /// Number of documented public symbols.
    /// </summary>
    public int DocumentedPublicSymbols { get; init; }

    /// <summary>
    /// Overall documentation coverage percentage.
    /// </summary>
    public double CoveragePercentage { get; init; }

    /// <summary>
    /// Issues found in this file.
    /// </summary>
    public List<DocumentationIssue> Issues { get; init; } = [];

    /// <summary>
    /// Coverage details per symbol.
    /// </summary>
    public List<DocumentationCoverage> SymbolCoverage { get; init; } = [];
}

/// <summary>
/// Summary of documentation analysis for a project.
/// </summary>
public record DocumentationSummary
{
    /// <summary>
    /// Total number of issues found.
    /// </summary>
    public int TotalIssues { get; init; }

    /// <summary>
    /// Issues by severity.
    /// </summary>
    public Dictionary<DocIssueSeverity, int> IssuesBySeverity { get; init; } = [];

    /// <summary>
    /// Issues by category.
    /// </summary>
    public Dictionary<DocIssueCategory, int> IssuesByCategory { get; init; } = [];

    /// <summary>
    /// Issues by type.
    /// </summary>
    public Dictionary<DocumentationIssueType, int> IssuesByType { get; init; } = [];

    /// <summary>
    /// Total public symbols analyzed.
    /// </summary>
    public int TotalPublicSymbols { get; init; }

    /// <summary>
    /// Total documented public symbols.
    /// </summary>
    public int DocumentedPublicSymbols { get; init; }

    /// <summary>
    /// Overall documentation coverage percentage.
    /// </summary>
    public double OverallCoveragePercentage { get; init; }

    /// <summary>
    /// Count of TODO comments.
    /// </summary>
    public int TodoCount { get; init; }

    /// <summary>
    /// Count of FIXME comments.
    /// </summary>
    public int FixmeCount { get; init; }

    /// <summary>
    /// Count of HACK comments.
    /// </summary>
    public int HackCount { get; init; }

    /// <summary>
    /// Documentation quality score (0-100).
    /// </summary>
    public double QualityScore { get; init; }

    /// <summary>
    /// Naming quality score (0-100).
    /// </summary>
    public double NamingQualityScore { get; init; }
}

/// <summary>
/// Complete result of documentation analysis.
/// </summary>
public record DocumentationResult
{
    /// <summary>
    /// All documentation issues found.
    /// </summary>
    public List<DocumentationIssue> Issues { get; init; } = [];

    /// <summary>
    /// File-by-file documentation summary.
    /// </summary>
    public List<FileDocumentationSummary> FileSummaries { get; init; } = [];

    /// <summary>
    /// Overall documentation summary.
    /// </summary>
    public DocumentationSummary Summary { get; init; } = new();

    /// <summary>
    /// Name suggestions for improving naming quality.
    /// </summary>
    public List<NameSuggestion> NameSuggestions { get; init; } = [];

    /// <summary>
    /// Timestamp of analysis.
    /// </summary>
    public DateTime AnalyzedAt { get; init; } = DateTime.UtcNow;
}
