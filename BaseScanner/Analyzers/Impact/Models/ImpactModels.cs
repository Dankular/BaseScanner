using System.Collections.Immutable;

namespace BaseScanner.Analyzers.Impact.Models;

/// <summary>
/// Types of dependencies between code elements.
/// </summary>
public enum DependencyType
{
    /// <summary>Method A directly calls Method B.</summary>
    DirectCall,

    /// <summary>Class A uses Type B (field, parameter, return type, local variable).</summary>
    TypeUsage,

    /// <summary>Class A extends or implements B.</summary>
    Inheritance,

    /// <summary>Method A accesses a field in Type B.</summary>
    FieldAccess,

    /// <summary>Class A subscribes to an event defined in Class B.</summary>
    EventSubscription,

    /// <summary>Method A accesses a property in Type B.</summary>
    PropertyAccess,

    /// <summary>Type A implements interface B.</summary>
    InterfaceImplementation,

    /// <summary>Method overrides a base class method.</summary>
    Override,

    /// <summary>Generic type constraint dependency.</summary>
    GenericConstraint
}

/// <summary>
/// Represents a single dependency edge in the graph.
/// </summary>
public record DependencyEdge
{
    /// <summary>Fully qualified name of the source symbol.</summary>
    public required string Source { get; init; }

    /// <summary>Fully qualified name of the target symbol.</summary>
    public required string Target { get; init; }

    /// <summary>Type of dependency.</summary>
    public required DependencyType Type { get; init; }

    /// <summary>File path where this dependency is declared.</summary>
    public required string FilePath { get; init; }

    /// <summary>Line number of the dependency.</summary>
    public required int Line { get; init; }

    /// <summary>Additional metadata about the dependency.</summary>
    public Dictionary<string, string> Metadata { get; init; } = [];
}

/// <summary>
/// Represents a node in the dependency graph.
/// </summary>
public record DependencyNode
{
    /// <summary>Fully qualified name of the symbol.</summary>
    public required string FullyQualifiedName { get; init; }

    /// <summary>Simple name of the symbol.</summary>
    public required string Name { get; init; }

    /// <summary>Type of symbol (Type, Method, Property, Field, Event).</summary>
    public required SymbolKind Kind { get; init; }

    /// <summary>Containing type for members.</summary>
    public string? ContainingType { get; init; }

    /// <summary>File path where this symbol is defined.</summary>
    public required string FilePath { get; init; }

    /// <summary>Line number of the symbol definition.</summary>
    public required int Line { get; init; }

    /// <summary>Accessibility modifier.</summary>
    public required AccessibilityLevel Accessibility { get; init; }

    /// <summary>Whether this symbol is part of the public API.</summary>
    public bool IsPublicApi { get; init; }

    /// <summary>Test coverage percentage (0-100), -1 if unknown.</summary>
    public double TestCoverage { get; init; } = -1;

    /// <summary>Whether this is a critical path symbol.</summary>
    public bool IsCritical { get; init; }

    /// <summary>Custom criticality weight (1-10).</summary>
    public int CriticalityWeight { get; init; } = 1;
}

/// <summary>
/// Kinds of symbols that can be tracked.
/// </summary>
public enum SymbolKind
{
    Type,
    Method,
    Property,
    Field,
    Event,
    Constructor,
    Indexer,
    Operator
}

/// <summary>
/// Accessibility levels.
/// </summary>
public enum AccessibilityLevel
{
    Public,
    Internal,
    Protected,
    ProtectedInternal,
    Private,
    PrivateProtected
}

/// <summary>
/// Complete dependency graph for a codebase.
/// </summary>
public record DependencyGraph
{
    /// <summary>All nodes in the graph.</summary>
    public ImmutableDictionary<string, DependencyNode> Nodes { get; init; } =
        ImmutableDictionary<string, DependencyNode>.Empty;

    /// <summary>Outgoing edges (source -> targets).</summary>
    public ImmutableDictionary<string, ImmutableList<DependencyEdge>> OutgoingEdges { get; init; } =
        ImmutableDictionary<string, ImmutableList<DependencyEdge>>.Empty;

    /// <summary>Incoming edges (target -> sources).</summary>
    public ImmutableDictionary<string, ImmutableList<DependencyEdge>> IncomingEdges { get; init; } =
        ImmutableDictionary<string, ImmutableList<DependencyEdge>>.Empty;

    /// <summary>When this graph was built.</summary>
    public DateTime BuiltAt { get; init; } = DateTime.UtcNow;

    /// <summary>Project path this graph was built from.</summary>
    public required string ProjectPath { get; init; }

    /// <summary>Total number of nodes.</summary>
    public int NodeCount => Nodes.Count;

    /// <summary>Total number of edges.</summary>
    public int EdgeCount => OutgoingEdges.Values.Sum(e => e.Count);
}

/// <summary>
/// Result of impact analysis for a changed symbol.
/// </summary>
public record ImpactAnalysisResult
{
    /// <summary>The symbol that was analyzed.</summary>
    public required string ChangedSymbol { get; init; }

    /// <summary>Type of change that was analyzed.</summary>
    public required ChangeType ChangeType { get; init; }

    /// <summary>Direct dependents (immediate impact).</summary>
    public required ImpactSet DirectImpact { get; init; }

    /// <summary>Transitive dependents (full downstream impact).</summary>
    public required ImpactSet TransitiveImpact { get; init; }

    /// <summary>Risk assessment for this change.</summary>
    public required RiskAssessment Risk { get; init; }

    /// <summary>Suggested actions to mitigate risk.</summary>
    public List<MitigationAction> Mitigations { get; init; } = [];

    /// <summary>When this analysis was performed.</summary>
    public DateTime AnalyzedAt { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Types of changes that can be analyzed.
/// </summary>
public enum ChangeType
{
    SignatureChange,
    Deletion,
    Rename,
    TypeChange,
    AccessibilityChange,
    BehaviorChange,
    Addition
}

/// <summary>
/// A set of impacted symbols with categorization.
/// </summary>
public record ImpactSet
{
    /// <summary>All impacted symbols.</summary>
    public ImmutableHashSet<string> Symbols { get; init; } = ImmutableHashSet<string>.Empty;

    /// <summary>Impacted symbols by type.</summary>
    public ImmutableDictionary<DependencyType, ImmutableHashSet<string>> ByDependencyType { get; init; } =
        ImmutableDictionary<DependencyType, ImmutableHashSet<string>>.Empty;

    /// <summary>Impacted symbols by file.</summary>
    public ImmutableDictionary<string, ImmutableHashSet<string>> ByFile { get; init; } =
        ImmutableDictionary<string, ImmutableHashSet<string>>.Empty;

    /// <summary>Number of unique files affected.</summary>
    public int AffectedFileCount => ByFile.Count;

    /// <summary>Total number of impacted symbols.</summary>
    public int Count => Symbols.Count;
}

/// <summary>
/// Risk assessment for a change.
/// </summary>
public record RiskAssessment
{
    /// <summary>Overall risk score (0-100).</summary>
    public required double Score { get; init; }

    /// <summary>Risk level classification.</summary>
    public required RiskLevel Level { get; init; }

    /// <summary>Breakdown of risk factors.</summary>
    public required RiskFactors Factors { get; init; }

    /// <summary>Explanation of the risk assessment.</summary>
    public required string Explanation { get; init; }

    /// <summary>Confidence level of this assessment (0-100).</summary>
    public double Confidence { get; init; } = 100;
}

/// <summary>
/// Risk level classifications.
/// </summary>
public enum RiskLevel
{
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Individual risk factors that contribute to the overall score.
/// </summary>
public record RiskFactors
{
    /// <summary>Risk from number of dependents (0-25).</summary>
    public double DependentCountRisk { get; init; }

    /// <summary>Risk from breaking public API (0-25).</summary>
    public double PublicApiRisk { get; init; }

    /// <summary>Risk from affecting critical paths (0-25).</summary>
    public double CriticalPathRisk { get; init; }

    /// <summary>Risk from low test coverage (0-25).</summary>
    public double TestCoverageRisk { get; init; }

    /// <summary>Additional risk factors.</summary>
    public Dictionary<string, double> Additional { get; init; } = [];
}

/// <summary>
/// Suggested action to mitigate risk.
/// </summary>
public record MitigationAction
{
    /// <summary>Type of mitigation.</summary>
    public required MitigationType Type { get; init; }

    /// <summary>Description of the action.</summary>
    public required string Description { get; init; }

    /// <summary>Priority of this action (1 = highest).</summary>
    public required int Priority { get; init; }

    /// <summary>Estimated effort (Low, Medium, High).</summary>
    public required string Effort { get; init; }

    /// <summary>Specific symbols this action applies to.</summary>
    public List<string> TargetSymbols { get; init; } = [];
}

/// <summary>
/// Types of mitigation actions.
/// </summary>
public enum MitigationType
{
    AddTests,
    UpdateDocumentation,
    NotifyTeam,
    IncrementalRollout,
    CreateDeprecationPlan,
    AddCompatibilityShim,
    ReviewBeforeCommit
}

/// <summary>
/// Result of a what-if analysis.
/// </summary>
public record WhatIfResult
{
    /// <summary>The hypothetical change that was analyzed.</summary>
    public required WhatIfScenario Scenario { get; init; }

    /// <summary>Impact analysis result.</summary>
    public required ImpactAnalysisResult Impact { get; init; }

    /// <summary>Whether the change would break compilation.</summary>
    public bool WouldBreakCompilation { get; init; }

    /// <summary>Compilation errors that would occur.</summary>
    public List<PredictedError> PredictedErrors { get; init; } = [];

    /// <summary>Required code changes to fix breaks.</summary>
    public List<RequiredChange> RequiredChanges { get; init; } = [];

    /// <summary>Recommendations for proceeding with this change.</summary>
    public List<string> Recommendations { get; init; } = [];
}

/// <summary>
/// A hypothetical change scenario.
/// </summary>
public record WhatIfScenario
{
    /// <summary>The symbol being changed.</summary>
    public required string TargetSymbol { get; init; }

    /// <summary>Type of change.</summary>
    public required ChangeType ChangeType { get; init; }

    /// <summary>Description of the change.</summary>
    public required string Description { get; init; }

    /// <summary>For signature changes, the new signature.</summary>
    public string? NewSignature { get; init; }

    /// <summary>For renames, the new name.</summary>
    public string? NewName { get; init; }
}

/// <summary>
/// A predicted compilation error.
/// </summary>
public record PredictedError
{
    /// <summary>Error code (e.g., CS0103).</summary>
    public required string ErrorCode { get; init; }

    /// <summary>Error message.</summary>
    public required string Message { get; init; }

    /// <summary>File where the error would occur.</summary>
    public required string FilePath { get; init; }

    /// <summary>Line number.</summary>
    public required int Line { get; init; }

    /// <summary>The symbol that would cause this error.</summary>
    public required string AffectedSymbol { get; init; }
}

/// <summary>
/// A required code change to fix a break.
/// </summary>
public record RequiredChange
{
    /// <summary>File to change.</summary>
    public required string FilePath { get; init; }

    /// <summary>Line number to change.</summary>
    public required int Line { get; init; }

    /// <summary>Description of what needs to change.</summary>
    public required string Description { get; init; }

    /// <summary>The symbol that needs updating.</summary>
    public required string SymbolToUpdate { get; init; }

    /// <summary>Suggested fix, if available.</summary>
    public string? SuggestedFix { get; init; }

    /// <summary>Whether this is an automatic fix.</summary>
    public bool CanAutoFix { get; init; }
}

/// <summary>
/// Summary of change impact analysis.
/// </summary>
public record ImpactSummary
{
    /// <summary>Number of directly impacted symbols.</summary>
    public required int DirectImpactCount { get; init; }

    /// <summary>Number of transitively impacted symbols.</summary>
    public required int TransitiveImpactCount { get; init; }

    /// <summary>Number of files affected.</summary>
    public required int AffectedFileCount { get; init; }

    /// <summary>Whether public API is affected.</summary>
    public required bool AffectsPublicApi { get; init; }

    /// <summary>Whether critical paths are affected.</summary>
    public required bool AffectsCriticalPaths { get; init; }

    /// <summary>Risk level.</summary>
    public required RiskLevel RiskLevel { get; init; }

    /// <summary>Breakdown by dependency type.</summary>
    public Dictionary<DependencyType, int> ByDependencyType { get; init; } = [];
}

/// <summary>
/// Options for impact analysis.
/// </summary>
public record ImpactAnalysisOptions
{
    /// <summary>Maximum depth for transitive analysis.</summary>
    public int MaxTransitiveDepth { get; init; } = 10;

    /// <summary>Include test projects in analysis.</summary>
    public bool IncludeTestProjects { get; init; } = true;

    /// <summary>Types of dependencies to track.</summary>
    public ImmutableHashSet<DependencyType> DependencyTypes { get; init; } =
        ImmutableHashSet.Create(
            DependencyType.DirectCall,
            DependencyType.TypeUsage,
            DependencyType.Inheritance,
            DependencyType.FieldAccess,
            DependencyType.EventSubscription);

    /// <summary>Symbols to treat as critical (fully qualified names).</summary>
    public ImmutableHashSet<string> CriticalSymbols { get; init; } = ImmutableHashSet<string>.Empty;

    /// <summary>File patterns to exclude.</summary>
    public ImmutableList<string> ExcludePatterns { get; init; } = [".Designer.cs", ".g.cs", ".generated.cs"];

    /// <summary>Whether to calculate test coverage risk.</summary>
    public bool CalculateTestCoverageRisk { get; init; } = false;
}

/// <summary>
/// Statistics about the dependency graph.
/// </summary>
public record DependencyGraphStats
{
    /// <summary>Total number of types.</summary>
    public int TypeCount { get; init; }

    /// <summary>Total number of methods.</summary>
    public int MethodCount { get; init; }

    /// <summary>Total number of properties.</summary>
    public int PropertyCount { get; init; }

    /// <summary>Total number of fields.</summary>
    public int FieldCount { get; init; }

    /// <summary>Total number of events.</summary>
    public int EventCount { get; init; }

    /// <summary>Total number of dependency edges.</summary>
    public int EdgeCount { get; init; }

    /// <summary>Breakdown of edges by type.</summary>
    public Dictionary<DependencyType, int> EdgesByType { get; init; } = [];

    /// <summary>Average dependencies per symbol.</summary>
    public double AverageDependencies { get; init; }

    /// <summary>Maximum incoming dependencies for a single symbol.</summary>
    public int MaxIncomingDependencies { get; init; }

    /// <summary>Symbol with most incoming dependencies.</summary>
    public string? MostDependedUponSymbol { get; init; }

    /// <summary>Maximum outgoing dependencies for a single symbol.</summary>
    public int MaxOutgoingDependencies { get; init; }

    /// <summary>Symbol with most outgoing dependencies.</summary>
    public string? MostDependentSymbol { get; init; }
}

/// <summary>
/// Result of batch impact analysis.
/// </summary>
public record BatchImpactResult
{
    /// <summary>Individual results for each changed symbol.</summary>
    public required List<ImpactAnalysisResult> Results { get; init; }

    /// <summary>Combined impact across all changes.</summary>
    public required ImpactSet CombinedImpact { get; init; }

    /// <summary>Overall risk assessment.</summary>
    public required RiskAssessment OverallRisk { get; init; }

    /// <summary>Symbols that appear in multiple impact sets.</summary>
    public ImmutableHashSet<string> OverlappingSymbols { get; init; } = ImmutableHashSet<string>.Empty;

    /// <summary>When this analysis was performed.</summary>
    public DateTime AnalyzedAt { get; init; } = DateTime.UtcNow;
}
