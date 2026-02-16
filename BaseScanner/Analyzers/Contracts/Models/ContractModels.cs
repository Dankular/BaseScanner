namespace BaseScanner.Analyzers.Contracts.Models;

/// <summary>
/// Types of contract violations that can be detected.
/// </summary>
public enum ContractType
{
    /// <summary>
    /// Parameter used without null check.
    /// </summary>
    NullPrecondition,

    /// <summary>
    /// Index used without bounds check.
    /// </summary>
    RangePrecondition,

    /// <summary>
    /// Method requires object in specific state.
    /// </summary>
    StatePrecondition,

    /// <summary>
    /// Return value guarantees (never null, etc.).
    /// </summary>
    Postcondition,

    /// <summary>
    /// Class state consistency rules.
    /// </summary>
    Invariant,

    /// <summary>
    /// "Get" method that modifies state.
    /// </summary>
    SideEffect
}

/// <summary>
/// Severity levels for contract issues.
/// </summary>
public enum ContractSeverity
{
    Info,
    Warning,
    Error,
    Critical
}

/// <summary>
/// Method purity classification.
/// </summary>
public enum MethodPurity
{
    /// <summary>
    /// Method has no side effects and doesn't read external state.
    /// </summary>
    Pure,

    /// <summary>
    /// Method reads external state but doesn't modify it.
    /// </summary>
    ReadsState,

    /// <summary>
    /// Method modifies state (fields, properties, or parameters).
    /// </summary>
    ModifiesState,

    /// <summary>
    /// Method performs I/O operations.
    /// </summary>
    HasIO
}

/// <summary>
/// Base record for all contract issues.
/// </summary>
public record ContractIssue
{
    /// <summary>
    /// The type of contract issue.
    /// </summary>
    public required ContractType Type { get; init; }

    /// <summary>
    /// Severity of the issue.
    /// </summary>
    public required ContractSeverity Severity { get; init; }

    /// <summary>
    /// File path where the issue was found.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Line number (1-based).
    /// </summary>
    public required int Line { get; init; }

    /// <summary>
    /// Column number (1-based).
    /// </summary>
    public required int Column { get; init; }

    /// <summary>
    /// Name of the class containing the issue.
    /// </summary>
    public required string ClassName { get; init; }

    /// <summary>
    /// Name of the method containing the issue.
    /// </summary>
    public required string MethodName { get; init; }

    /// <summary>
    /// Human-readable description.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Recommended fix or guard clause.
    /// </summary>
    public required string Suggestion { get; init; }

    /// <summary>
    /// The code snippet with the issue.
    /// </summary>
    public required string CodeSnippet { get; init; }

    /// <summary>
    /// Suggested code fix.
    /// </summary>
    public string SuggestedFix { get; init; } = "";

    /// <summary>
    /// Confidence level of the detection (0.0 to 1.0).
    /// </summary>
    public double Confidence { get; init; } = 0.8;
}

/// <summary>
/// Precondition that should be checked at method entry.
/// </summary>
public record PreconditionIssue : ContractIssue
{
    /// <summary>
    /// The parameter or expression that should be validated.
    /// </summary>
    public required string TargetExpression { get; init; }

    /// <summary>
    /// Expected condition that should be true.
    /// </summary>
    public required string ExpectedCondition { get; init; }

    /// <summary>
    /// Type of exception to throw if condition is not met.
    /// </summary>
    public required string ExceptionType { get; init; }
}

/// <summary>
/// Postcondition that should be guaranteed on method exit.
/// </summary>
public record PostconditionIssue : ContractIssue
{
    /// <summary>
    /// The return value or state that has a guarantee.
    /// </summary>
    public required string TargetExpression { get; init; }

    /// <summary>
    /// The guarantee (e.g., "never null", "always positive").
    /// </summary>
    public required string Guarantee { get; init; }

    /// <summary>
    /// Whether this is a documented guarantee or inferred.
    /// </summary>
    public bool IsInferred { get; init; } = true;
}

/// <summary>
/// Class invariant that should always be true.
/// </summary>
public record InvariantIssue : ContractIssue
{
    /// <summary>
    /// The fields or state involved in the invariant.
    /// </summary>
    public required List<string> InvolvedMembers { get; init; }

    /// <summary>
    /// The invariant condition.
    /// </summary>
    public required string InvariantCondition { get; init; }

    /// <summary>
    /// Methods that might violate this invariant.
    /// </summary>
    public List<string> PotentiallyViolatingMethods { get; init; } = [];
}

/// <summary>
/// Side effect detected in a method.
/// </summary>
public record SideEffectIssue : ContractIssue
{
    /// <summary>
    /// The purity level of the method.
    /// </summary>
    public required MethodPurity Purity { get; init; }

    /// <summary>
    /// Expected purity based on naming conventions.
    /// </summary>
    public required MethodPurity ExpectedPurity { get; init; }

    /// <summary>
    /// Fields that are modified.
    /// </summary>
    public List<string> ModifiedFields { get; init; } = [];

    /// <summary>
    /// Properties that are modified.
    /// </summary>
    public List<string> ModifiedProperties { get; init; } = [];

    /// <summary>
    /// External calls that cause side effects.
    /// </summary>
    public List<string> SideEffectCalls { get; init; } = [];
}

/// <summary>
/// Purity analysis result for a method.
/// </summary>
public record MethodPurityInfo
{
    /// <summary>
    /// Fully qualified method name.
    /// </summary>
    public required string MethodName { get; init; }

    /// <summary>
    /// Class containing the method.
    /// </summary>
    public required string ClassName { get; init; }

    /// <summary>
    /// File path.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Line number.
    /// </summary>
    public required int Line { get; init; }

    /// <summary>
    /// The detected purity level.
    /// </summary>
    public required MethodPurity Purity { get; init; }

    /// <summary>
    /// Fields that are read.
    /// </summary>
    public List<string> ReadsFields { get; init; } = [];

    /// <summary>
    /// Fields that are written.
    /// </summary>
    public List<string> WritesFields { get; init; } = [];

    /// <summary>
    /// Properties that are read.
    /// </summary>
    public List<string> ReadsProperties { get; init; } = [];

    /// <summary>
    /// Properties that are written.
    /// </summary>
    public List<string> WritesProperties { get; init; } = [];

    /// <summary>
    /// I/O operations performed.
    /// </summary>
    public List<string> IOOperations { get; init; } = [];

    /// <summary>
    /// Whether the method name suggests it should be pure.
    /// </summary>
    public bool NameSuggestsPurity { get; init; }
}

/// <summary>
/// Summary of contract analysis results.
/// </summary>
public record ContractSummary
{
    public int TotalIssues { get; init; }
    public int NullPreconditions { get; init; }
    public int RangePreconditions { get; init; }
    public int StatePreconditions { get; init; }
    public int Postconditions { get; init; }
    public int Invariants { get; init; }
    public int SideEffects { get; init; }

    public int CriticalCount { get; init; }
    public int ErrorCount { get; init; }
    public int WarningCount { get; init; }
    public int InfoCount { get; init; }

    public Dictionary<string, int> IssuesByFile { get; init; } = [];
    public Dictionary<string, int> IssuesByClass { get; init; } = [];
}

/// <summary>
/// Complete result of contract analysis.
/// </summary>
public record ContractAnalysisResult
{
    public List<PreconditionIssue> Preconditions { get; init; } = [];
    public List<PostconditionIssue> Postconditions { get; init; } = [];
    public List<InvariantIssue> Invariants { get; init; } = [];
    public List<SideEffectIssue> SideEffects { get; init; } = [];
    public List<MethodPurityInfo> PurityAnalysis { get; init; } = [];
    public ContractSummary Summary { get; init; } = new();
}
