using System.Collections.Immutable;

namespace BaseScanner.Analyzers.Naming.Models;

/// <summary>
/// Types of symbol naming conventions.
/// </summary>
public enum NamingConvention
{
    PascalCase,         // MyClass, MyMethod
    CamelCase,          // myVariable, parameter
    UpperSnakeCase,     // MY_CONSTANT
    LowerSnakeCase,     // my_variable
    HungarianNotation,  // strName, intCount
    IPrefixed,          // IMyInterface
    UnderscorePrefixed, // _privateField
    Unknown
}

/// <summary>
/// Categories of named symbols.
/// </summary>
public enum SymbolCategory
{
    Class,
    Interface,
    Struct,
    Record,
    Enum,
    EnumMember,
    Delegate,
    Method,
    Property,
    Event,
    PrivateField,
    PublicField,
    ProtectedField,
    InternalField,
    Constant,
    Parameter,
    LocalVariable,
    TypeParameter,
    Namespace,
    Unknown
}

/// <summary>
/// Semantic purpose inferred from naming patterns.
/// </summary>
public enum SemanticPurpose
{
    BooleanPredicate,       // IsX, HasX, CanX, ShouldX
    Getter,                 // GetX
    Setter,                 // SetX
    Creator,                // CreateX, BuildX, MakeX, NewX
    AsyncOperation,         // XAsync
    EventHandler,           // OnEventName, HandleEventName
    Validator,              // ValidateX, CheckX
    Parser,                 // ParseX, TryParseX
    Converter,              // ToX, ConvertToX, AsX
    Finder,                 // FindX, SearchX, LookupX
    Factory,                // CreateX, BuildX (returning new instances)
    Comparer,               // CompareX, EqualsX
    Aggregator,             // SumX, CountX, AverageX
    Disposer,               // Dispose, Close, Cleanup
    Initializer,            // Initialize, Init, Setup
    Unknown
}

/// <summary>
/// Severity of naming violations.
/// </summary>
public enum NamingViolationSeverity
{
    Error = 100,        // Critical violations (e.g., public field without proper casing)
    Warning = 75,       // Important violations (e.g., method should be PascalCase)
    Suggestion = 50,    // Minor violations (e.g., abbreviation usage)
    Info = 25           // Informational (e.g., potential improvements)
}

/// <summary>
/// A single naming convention violation.
/// </summary>
public record NamingViolation
{
    public required string SymbolName { get; init; }
    public required SymbolCategory SymbolCategory { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required int Column { get; init; }
    public required string RuleId { get; init; }
    public required string RuleName { get; init; }
    public required string Message { get; init; }
    public required NamingViolationSeverity Severity { get; init; }
    public required NamingConvention ExpectedConvention { get; init; }
    public required NamingConvention ActualConvention { get; init; }
    public string? SuggestedName { get; init; }
    public string? ContainingTypeName { get; init; }
    public string? Explanation { get; init; }
}

/// <summary>
/// Result of semantic name analysis for a single symbol.
/// </summary>
public record SemanticNameAnalysis
{
    public required string SymbolName { get; init; }
    public required SymbolCategory SymbolCategory { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required SemanticPurpose InferredPurpose { get; init; }
    public required string ReturnType { get; init; }
    public required bool IsAsync { get; init; }
    public required bool HasPotentialSideEffects { get; init; }
    public List<SemanticIssue> Issues { get; init; } = [];
}

/// <summary>
/// A semantic issue with a method or property name.
/// </summary>
public record SemanticIssue
{
    public required string IssueType { get; init; }
    public required string Message { get; init; }
    public required NamingViolationSeverity Severity { get; init; }
    public string? Suggestion { get; init; }
    public string? Explanation { get; init; }
}

/// <summary>
/// Term usage tracking for consistency analysis.
/// </summary>
public record TermUsage
{
    public required string Term { get; init; }
    public required string NormalizedTerm { get; init; }
    public required string Context { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string SymbolName { get; init; }
    public required SymbolCategory SymbolCategory { get; init; }
}

/// <summary>
/// A group of inconsistent terms that likely refer to the same concept.
/// </summary>
public record TermInconsistency
{
    public required string Concept { get; init; }
    public required List<string> VariantTerms { get; init; }
    public required List<TermUsage> Usages { get; init; }
    public required int TotalOccurrences { get; init; }
    public string? RecommendedTerm { get; init; }
    public string? Explanation { get; init; }
}

/// <summary>
/// Abbreviation usage tracking.
/// </summary>
public record AbbreviationUsage
{
    public required string Abbreviation { get; init; }
    public required string? ExpandedForm { get; init; }
    public required List<TermUsage> Usages { get; init; }
    public required bool IsConsistentlyUsed { get; init; }
    public List<string> InconsistentForms { get; init; } = [];
}

/// <summary>
/// Complete result of naming convention analysis.
/// </summary>
public record NamingAnalysisResult
{
    public required string ProjectPath { get; init; }
    public required DateTime AnalyzedAt { get; init; }
    public required int TotalSymbolsAnalyzed { get; init; }
    public required List<NamingViolation> Violations { get; init; }
    public required List<SemanticNameAnalysis> SemanticIssues { get; init; }
    public required List<TermInconsistency> TermInconsistencies { get; init; }
    public required List<AbbreviationUsage> AbbreviationIssues { get; init; }
    public required NamingAnalysisSummary Summary { get; init; }
}

/// <summary>
/// Summary statistics for naming analysis.
/// </summary>
public record NamingAnalysisSummary
{
    public int TotalViolations { get; init; }
    public int ErrorCount { get; init; }
    public int WarningCount { get; init; }
    public int SuggestionCount { get; init; }
    public int InfoCount { get; init; }
    public Dictionary<SymbolCategory, int> ViolationsByCategory { get; init; } = [];
    public Dictionary<string, int> ViolationsByRule { get; init; } = [];
    public int SemanticIssueCount { get; init; }
    public int TermInconsistencyCount { get; init; }
    public int AbbreviationIssueCount { get; init; }
    public double NamingQualityScore { get; init; } // 0-100 score
    public List<string> TopIssues { get; init; } = [];
}

/// <summary>
/// Configuration for naming convention rules.
/// </summary>
public record NamingConfiguration
{
    public Dictionary<SymbolCategory, NamingRule> Rules { get; init; } = [];
    public List<string> AllowedAbbreviations { get; init; } = [];
    public List<string> AllowedPrefixes { get; init; } = [];
    public List<string> AllowedSuffixes { get; init; } = [];
    public List<TermEquivalence> TermEquivalences { get; init; } = [];
    public bool EnforceSemanticNaming { get; init; } = true;
    public bool CheckTerminologyConsistency { get; init; } = true;
    public int MinNameLength { get; init; } = 2;
    public int MaxNameLength { get; init; } = 50;
}

/// <summary>
/// A single naming rule definition.
/// </summary>
public record NamingRule
{
    public required string RuleId { get; init; }
    public required string RuleName { get; init; }
    public required SymbolCategory AppliesTo { get; init; }
    public required NamingConvention Convention { get; init; }
    public string? RequiredPrefix { get; init; }
    public string? RequiredSuffix { get; init; }
    public string? ForbiddenPrefix { get; init; }
    public NamingViolationSeverity Severity { get; init; } = NamingViolationSeverity.Warning;
    public string Description { get; init; } = "";
    public bool IsEnabled { get; init; } = true;
}

/// <summary>
/// Defines equivalent terms that should be used consistently.
/// </summary>
public record TermEquivalence
{
    public required string PreferredTerm { get; init; }
    public required List<string> AlternativeTerms { get; init; }
    public string? Domain { get; init; } // e.g., "User management", "Data access"
}

/// <summary>
/// Quality analysis for a single name.
/// </summary>
public record NameQualityAnalysis
{
    public required string Name { get; init; }
    public required SymbolCategory Category { get; init; }
    public required bool IsValid { get; init; }
    public required double QualityScore { get; init; } // 0-100
    public List<string> Issues { get; init; } = [];
    public List<string> Strengths { get; init; } = [];
    public string? SuggestedImprovement { get; init; }

    // Name components
    public List<string> Words { get; init; } = [];
    public bool ContainsAbbreviation { get; init; }
    public bool ContainsNumber { get; init; }
    public int Length { get; init; }
    public NamingConvention DetectedConvention { get; init; }
}

/// <summary>
/// Patterns detected in naming across the codebase.
/// </summary>
public record NamingPattern
{
    public required string Pattern { get; init; }
    public required string Description { get; init; }
    public required int OccurrenceCount { get; init; }
    public required List<string> Examples { get; init; }
    public bool IsRecommended { get; init; }
    public string? Alternative { get; init; }
}
