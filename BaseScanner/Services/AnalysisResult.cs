using System.Text.Json.Serialization;

namespace BaseScanner.Services;

/// <summary>
/// Complete analysis result containing all analyzer outputs.
/// Designed for JSON serialization to MCP clients.
/// </summary>
public record AnalysisResult
{
    public required string ProjectPath { get; init; }
    public required AnalysisSummary Summary { get; init; }
    public List<string> UnusedFiles { get; init; } = [];
    public List<string> MissingFiles { get; init; } = [];

    // Deep analysis
    public List<DeprecatedCodeItem>? DeprecatedCode { get; init; }
    public List<UsageItem>? DeadCode { get; init; }
    public List<UsageItem>? LowUsageCode { get; init; }

    // Sentiment analysis
    public SentimentResult? Sentiment { get; init; }

    // Performance analysis
    public List<IssueItem>? PerformanceIssues { get; init; }

    // Exception handling
    public List<IssueItem>? ExceptionHandlingIssues { get; init; }

    // Resource leaks
    public List<IssueItem>? ResourceLeakIssues { get; init; }

    // Dependencies
    public DependencyResult? Dependencies { get; init; }

    // Magic values
    public List<MagicValueItem>? MagicValues { get; init; }

    // Git churn
    public GitChurnResult? GitChurn { get; init; }

    // Refactoring
    public RefactoringResult? Refactoring { get; init; }

    // Architecture
    public ArchitectureResult? Architecture { get; init; }

    // Safety
    public SafetyResult? Safety { get; init; }

    // Optimizations
    public OptimizationResult? Optimizations { get; init; }

    // Security Analysis
    public SecurityAnalysisResult? Security { get; init; }

    // Metrics Dashboard
    public MetricsDashboardResult? Metrics { get; init; }

    // New Analyzers (Phase 1-4)

    /// <summary>Test coverage analysis with test smell detection</summary>
    public TestCoverageResultDto? TestCoverage { get; init; }

    /// <summary>Documentation quality and completeness</summary>
    public DocumentationResultDto? Documentation { get; init; }

    /// <summary>Dependency vulnerability scanning</summary>
    public VulnerabilityResultDto? Vulnerabilities { get; init; }

    /// <summary>Semantic code clone detection</summary>
    public CloneAnalysisResultDto? Clones { get; init; }

    /// <summary>Change impact analysis</summary>
    public ImpactAnalysisResultDto? Impact { get; init; }

    /// <summary>Technical debt scoring and prioritization</summary>
    public TechnicalDebtResultDto? TechnicalDebt { get; init; }

    /// <summary>Thread safety and race condition detection</summary>
    public ThreadSafetyResultDto? ThreadSafety { get; init; }

    /// <summary>Memory leak detection</summary>
    public MemoryLeakResultDto? MemoryLeaks { get; init; }

    /// <summary>.NET migration assistance</summary>
    public MigrationResultDto? Migration { get; init; }

    /// <summary>Naming convention analysis</summary>
    public NamingResultDto? Naming { get; init; }

    /// <summary>Contract and invariant analysis</summary>
    public ContractAnalysisResultDto? Contracts { get; init; }

    /// <summary>Configuration analysis</summary>
    public ConfigurationResultDto? Configuration { get; init; }

    /// <summary>Logging quality analysis</summary>
    public LoggingQualityResultDto? LoggingQuality { get; init; }

    /// <summary>API design analysis</summary>
    public ApiDesignResultDto? ApiDesign { get; init; }
}

// Security result types

public record SecurityAnalysisResult
{
    public int TotalVulnerabilities { get; init; }
    public int CriticalCount { get; init; }
    public int HighCount { get; init; }
    public int MediumCount { get; init; }
    public int LowCount { get; init; }
    public List<SecurityIssueItem> Vulnerabilities { get; init; } = [];
    public Dictionary<string, int> VulnerabilitiesByType { get; init; } = [];
    public Dictionary<string, int> VulnerabilitiesByCwe { get; init; } = [];
}

public record SecurityIssueItem
{
    public required string VulnerabilityType { get; init; }
    public required string Severity { get; init; }
    public required string CweId { get; init; }
    public required string FilePath { get; init; }
    public required int StartLine { get; init; }
    public required int EndLine { get; init; }
    public required string Description { get; init; }
    public required string Recommendation { get; init; }
    public required string VulnerableCode { get; init; }
    public required string SecureCode { get; init; }
    public required string Confidence { get; init; }
    public string CweLink => $"https://cwe.mitre.org/data/definitions/{CweId.Replace("CWE-", "")}.html";
}

// Metrics dashboard result types

public record MetricsDashboardResult
{
    public required int HealthScore { get; init; }
    public required int TotalFiles { get; init; }
    public required int TotalLines { get; init; }
    public required int TotalMethods { get; init; }
    public required int TotalClasses { get; init; }
    public required double AverageCyclomaticComplexity { get; init; }
    public required int MaxCyclomaticComplexity { get; init; }
    public required int MethodsAboveComplexityThreshold { get; init; }
    public required double MaintainabilityIndex { get; init; }
    public required int TechnicalDebtMinutes { get; init; }
    public List<HotspotFileItem> Hotspots { get; init; } = [];
    public Dictionary<string, int> IssuesByCategory { get; init; } = [];
    public Dictionary<string, int> IssuesBySeverity { get; init; } = [];
}

public record HotspotFileItem
{
    public required string FilePath { get; init; }
    public required int IssueCount { get; init; }
    public required int CriticalOrHighCount { get; init; }
    public required int Lines { get; init; }
    public required int Methods { get; init; }
}

public record AnalysisSummary
{
    public int TotalFilesOnDisk { get; init; }
    public int FilesInCompilation { get; init; }
    public int UnusedFiles { get; init; }
    public int MissingFiles { get; init; }
    public int PerformanceIssues { get; init; }
    public int ExceptionIssues { get; init; }
    public int ResourceIssues { get; init; }
    public int MagicValues { get; init; }
    public int LongMethods { get; init; }
    public int GodClasses { get; init; }
    public int NullSafetyIssues { get; init; }
    public int ImmutabilityOpportunities { get; init; }
    public int LoggingGaps { get; init; }
    public int OptimizationOpportunities { get; init; }
    public int TotalIssues { get; init; }
}

public record IssueItem
{
    public required string Type { get; init; }
    public required string Severity { get; init; }
    public required string Message { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public string? CodeSnippet { get; init; }
}

public record DeprecatedCodeItem
{
    public required string SymbolKind { get; init; }
    public required string SymbolName { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string Message { get; init; }
    public required bool IsError { get; init; }
    public string? Replacement { get; init; }
}

public record UsageItem
{
    public required string SymbolKind { get; init; }
    public required string SymbolName { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required int ReferenceCount { get; init; }
}

public record SentimentResult
{
    public required int TotalBlocks { get; init; }
    public required double AverageQualityScore { get; init; }
    public required double AverageComplexity { get; init; }
    public required int HighComplexityCount { get; init; }
    public required int ProblematicCount { get; init; }
    public required int DuplicateGroups { get; init; }
    public required int SimilarGroups { get; init; }
    public required Dictionary<string, int> QualityDistribution { get; init; }
    public required Dictionary<string, int> MarkerCounts { get; init; }
    public List<CodeBlockItem>? ProblematicBlocks { get; init; }
    public List<CodeBlockItem>? HighComplexityBlocks { get; init; }
}

public record CodeBlockItem
{
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string BlockType { get; init; }
    public required string ContainingType { get; init; }
    public required string Name { get; init; }
    public required int QualityScore { get; init; }
    public required string QualityRating { get; init; }
    public required int CyclomaticComplexity { get; init; }
    public required int NestingDepth { get; init; }
    public required int LineCount { get; init; }
    public List<string> SentimentMarkers { get; init; } = [];
}

public record DependencyResult
{
    public List<CircularDependencyItem> CircularDependencies { get; init; } = [];
    public List<CouplingItem> HighCouplingTypes { get; init; } = [];
}

public record CircularDependencyItem
{
    public required string Type { get; init; }
    public required List<string> Cycle { get; init; }
}

public record CouplingItem
{
    public required string TypeName { get; init; }
    public required string FilePath { get; init; }
    public required int EfferentCoupling { get; init; }
    public required int AfferentCoupling { get; init; }
    public required double Instability { get; init; }
}

public record MagicValueItem
{
    public required string Type { get; init; }
    public required string Value { get; init; }
    public required int Occurrences { get; init; }
    public List<LocationItem> Locations { get; init; } = [];
}

public record LocationItem
{
    public required string FilePath { get; init; }
    public required int Line { get; init; }
}

public record GitChurnResult
{
    public required bool GitAvailable { get; init; }
    public List<FileChurnItem> TopChurnedFiles { get; init; } = [];
    public List<HotspotItem> Hotspots { get; init; } = [];
    public List<FileChurnItem> StaleFiles { get; init; } = [];
}

public record FileChurnItem
{
    public required string FilePath { get; init; }
    public required int CommitCount { get; init; }
    public required int TotalChurn { get; init; }
    public required int DaysSinceLastChange { get; init; }
}

public record HotspotItem
{
    public required string FilePath { get; init; }
    public required double Score { get; init; }
    public required int ChurnCount { get; init; }
    public required string Reason { get; init; }
}

public record RefactoringResult
{
    public List<LongMethodItem> LongMethods { get; init; } = [];
    public List<GodClassItem> GodClasses { get; init; } = [];
    public List<FeatureEnvyItem> FeatureEnvy { get; init; } = [];
    public List<ParameterSmellItem> ParameterSmells { get; init; } = [];
    public List<DataClumpItem> DataClumps { get; init; } = [];
}

public record LongMethodItem
{
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string ClassName { get; init; }
    public required string MethodName { get; init; }
    public required int LineCount { get; init; }
    public required int Complexity { get; init; }
    public List<ExtractCandidateItem> ExtractCandidates { get; init; } = [];
}

public record ExtractCandidateItem
{
    public required int StartLine { get; init; }
    public required int EndLine { get; init; }
    public required string SuggestedName { get; init; }
    public required string Reason { get; init; }
}

public record GodClassItem
{
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string ClassName { get; init; }
    public required int MethodCount { get; init; }
    public required int FieldCount { get; init; }
    public required double LCOM { get; init; }
    public List<string> Responsibilities { get; init; } = [];
}

public record FeatureEnvyItem
{
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string ClassName { get; init; }
    public required string MethodName { get; init; }
    public required string EnviedClass { get; init; }
    public required int EnviedMemberAccess { get; init; }
    public required double EnvyRatio { get; init; }
}

public record ParameterSmellItem
{
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string ClassName { get; init; }
    public required string MethodName { get; init; }
    public required int ParameterCount { get; init; }
    public required string SmellType { get; init; }
    public required string Suggestion { get; init; }
}

public record DataClumpItem
{
    public required List<string> Parameters { get; init; }
    public required int Occurrences { get; init; }
    public required string SuggestedClassName { get; init; }
    public List<string> Locations { get; init; } = [];
}

public record ArchitectureResult
{
    public List<PublicApiItem> PublicApi { get; init; } = [];
    public List<EntryPointItem> EntryPoints { get; init; } = [];
    public List<DeadEndItem> DeadEnds { get; init; } = [];
    public List<InheritanceItem> DeepInheritance { get; init; } = [];
    public List<CompositionCandidateItem> CompositionCandidates { get; init; } = [];
    public List<InterfaceIssueItem> InterfaceIssues { get; init; } = [];
}

public record PublicApiItem
{
    public required string TypeName { get; init; }
    public required string MemberName { get; init; }
    public required string MemberType { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string BreakingChangeRisk { get; init; }
}

public record EntryPointItem
{
    public required string TypeName { get; init; }
    public required string MethodName { get; init; }
    public required int OutgoingCalls { get; init; }
}

public record DeadEndItem
{
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string TypeName { get; init; }
    public required string MethodName { get; init; }
    public required int IncomingCalls { get; init; }
}

public record InheritanceItem
{
    public required string TypeName { get; init; }
    public required int Depth { get; init; }
    public required List<string> Chain { get; init; }
}

public record CompositionCandidateItem
{
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string TypeName { get; init; }
    public required string Suggestion { get; init; }
}

public record InterfaceIssueItem
{
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string InterfaceName { get; init; }
    public required int MemberCount { get; init; }
    public List<string> SuggestedSplits { get; init; } = [];
}

public record SafetyResult
{
    public List<NullSafetyItem> NullIssues { get; init; } = [];
    public List<ImmutabilityItem> ImmutabilityIssues { get; init; } = [];
    public List<LoggingGapItem> LoggingGaps { get; init; } = [];
    public double AverageLoggingCoverage { get; init; }
    public int ClassesWithLowCoverage { get; init; }
}

public record NullSafetyItem
{
    public required string Type { get; init; }
    public required string Severity { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string Description { get; init; }
}

public record ImmutabilityItem
{
    public required string Type { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string MemberName { get; init; }
    public required string Suggestion { get; init; }
}

public record LoggingGapItem
{
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string ClassName { get; init; }
    public required string MethodName { get; init; }
    public required string GapType { get; init; }
    public required string Description { get; init; }
}

// Optimization result types

public record OptimizationResult
{
    public List<OptimizationItem> Opportunities { get; init; } = [];
    public OptimizationSummary Summary { get; init; } = new();
}

public record OptimizationSummary
{
    public int TotalOpportunities { get; init; }
    public int HighConfidenceCount { get; init; }
    public int PerformanceOptimizations { get; init; }
    public int ReadabilityImprovements { get; init; }
    public int ModernizationOpportunities { get; init; }
    public double EstimatedImpactScore { get; init; }
}

public record OptimizationItem
{
    /// <summary>
    /// Category: Performance, Readability, Modernization
    /// </summary>
    public required string Category { get; init; }

    /// <summary>
    /// Specific optimization type (e.g., LinqAny, AsyncVoid, ListToHashSet)
    /// </summary>
    public required string Type { get; init; }

    public required string FilePath { get; init; }
    public required int StartLine { get; init; }
    public required int EndLine { get; init; }

    /// <summary>
    /// Human-readable description of the optimization opportunity.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// The current code that can be optimized.
    /// </summary>
    public required string CurrentCode { get; init; }

    /// <summary>
    /// The suggested optimized code.
    /// </summary>
    public required string SuggestedCode { get; init; }

    /// <summary>
    /// Confidence level: High, Medium, Low
    /// </summary>
    public required string Confidence { get; init; }

    /// <summary>
    /// Impact level: Critical, High, Medium, Low
    /// </summary>
    public required string Impact { get; init; }

    /// <summary>
    /// Whether the transformation is semantically safe.
    /// </summary>
    public required bool IsSemanticallySafe { get; init; }

    /// <summary>
    /// Assumptions required for the transformation to be safe.
    /// </summary>
    public List<string> Assumptions { get; init; } = [];

    /// <summary>
    /// Potential risks of applying this optimization.
    /// </summary>
    public List<string> Risks { get; init; } = [];
}

// Concurrency analysis result types

public record ConcurrencyAnalysisResultDto
{
    public int TotalIssues { get; init; }
    public int CriticalCount { get; init; }
    public int HighCount { get; init; }
    public int MediumCount { get; init; }
    public List<ConcurrencyIssueDto> Issues { get; init; } = [];
    public Dictionary<string, int> IssuesByType { get; init; } = [];
}

public record ConcurrencyIssueDto
{
    public required string IssueType { get; init; }
    public required string Severity { get; init; }
    public required string Message { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required int EndLine { get; init; }
    public string? CodeSnippet { get; init; }
    public string? SuggestedFix { get; init; }
    public string? CweId { get; init; }
}

// Framework analysis result types

public record FrameworkAnalysisResultDto
{
    public required string Framework { get; init; }
    public int TotalIssues { get; init; }
    public int CriticalCount { get; init; }
    public int HighCount { get; init; }
    public int MediumCount { get; init; }
    public List<FrameworkIssueDto> Issues { get; init; } = [];
    public Dictionary<string, int> IssuesByType { get; init; } = [];
}

public record FrameworkIssueDto
{
    public required string IssueType { get; init; }
    public required string Severity { get; init; }
    public required string Message { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public string? CweId { get; init; }
    public string? SuggestedFix { get; init; }
    public string? CodeSnippet { get; init; }
}

// Code quality result types

public record CodeQualityResultDto
{
    public int TotalIssues { get; init; }
    public List<CodeQualityIssueDto> Issues { get; init; } = [];
    public List<MethodMetricsDto> MethodMetrics { get; init; } = [];
    public Dictionary<string, int> IssuesByCategory { get; init; } = [];
    public double AverageCognitiveComplexity { get; init; }
    public int MethodsAboveThreshold { get; init; }
}

public record CodeQualityIssueDto
{
    public required string Category { get; init; }
    public required string IssueType { get; init; }
    public required string Severity { get; init; }
    public required string Message { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public string? Suggestion { get; init; }
    public string? CweId { get; init; }
}

public record MethodMetricsDto
{
    public required string MethodName { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public int LineCount { get; init; }
    public int ParameterCount { get; init; }
    public int NestingDepth { get; init; }
    public int CognitiveComplexity { get; init; }
    public int CyclomaticComplexity { get; init; }
    public int LocalVariableCount { get; init; }
}

// Virtual workspace comparison result

public record TransformationComparisonResultDto
{
    public required string OriginalFilePath { get; init; }
    public List<TransformationBranchResultDto> Results { get; init; } = [];
    public TransformationBranchResultDto? BestResult { get; init; }
    public int TotalStrategiesApplied { get; init; }
    public int FailedStrategies { get; init; }
}

public record TransformationBranchResultDto
{
    public required string StrategyName { get; init; }
    public required string Category { get; init; }
    public required string Description { get; init; }
    public required double OverallScore { get; init; }
    public double ComplexityDelta { get; init; }
    public double CognitiveComplexityDelta { get; init; }
    public int LocDelta { get; init; }
    public double MaintainabilityDelta { get; init; }
    public bool CompilationValid { get; init; }
    public bool SemanticsPreserved { get; init; }
    public string? UnifiedDiff { get; init; }
    public int AddedLines { get; init; }
    public int RemovedLines { get; init; }
    public string? Error { get; init; }
}

// ============================================================================
// NEW ANALYZER RESULT TYPES (Phase 1-4)
// ============================================================================

// Test Coverage Analysis
public record TestCoverageResultDto
{
    public double OverallCoverage { get; init; }
    public int TotalMethods { get; init; }
    public int CoveredMethods { get; init; }
    public int UncoveredMethods { get; init; }
    public List<UncoveredMethodDto> UncoveredMethodsList { get; init; } = [];
    public List<TestSmellDto> TestSmells { get; init; } = [];
    public List<CriticalGapDto> CriticalGaps { get; init; } = [];
    public Dictionary<string, double> CoverageByNamespace { get; init; } = [];
}

public record UncoveredMethodDto
{
    public required string MethodName { get; init; }
    public required string ClassName { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string Reason { get; init; }
}

public record TestSmellDto
{
    public required string SmellType { get; init; }
    public required string TestName { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string Description { get; init; }
    public required string Recommendation { get; init; }
}

public record CriticalGapDto
{
    public required string GapType { get; init; }
    public required string MethodName { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string Severity { get; init; }
    public required string Description { get; init; }
}

// Documentation Quality Analysis
public record DocumentationResultDto
{
    public double DocumentationCoverage { get; init; }
    public int TotalPublicMembers { get; init; }
    public int DocumentedMembers { get; init; }
    public List<MissingDocDto> MissingDocs { get; init; } = [];
    public List<StaleDocDto> StaleDocs { get; init; } = [];
    public List<NamingIssueDto> NamingIssues { get; init; } = [];
    public List<TodoCommentDto> UnresolvedTodos { get; init; } = [];
    public Dictionary<string, double> CoverageByNamespace { get; init; } = [];
}

public record MissingDocDto
{
    public required string MemberType { get; init; }
    public required string MemberName { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string Severity { get; init; }
}

public record StaleDocDto
{
    public required string IssueType { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string Description { get; init; }
    public required string Suggestion { get; init; }
}

public record NamingIssueDto
{
    public required string IssueType { get; init; }
    public required string CurrentName { get; init; }
    public required string SuggestedName { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string Reason { get; init; }
}

public record TodoCommentDto
{
    public required string CommentType { get; init; }
    public required string Text { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
}

// Vulnerability Scanning
public record VulnerabilityResultDto
{
    public int TotalPackages { get; init; }
    public int VulnerablePackages { get; init; }
    public int OutdatedPackages { get; init; }
    public int DeprecatedPackages { get; init; }
    public List<PackageVulnerabilityDto> Vulnerabilities { get; init; } = [];
    public List<OutdatedPackageDto> Outdated { get; init; } = [];
    public List<UpgradeRecommendationDto> Recommendations { get; init; } = [];
    public VulnerabilitySummaryDto Summary { get; init; } = new();
}

public record VulnerabilitySummaryDto
{
    public int Critical { get; init; }
    public int High { get; init; }
    public int Medium { get; init; }
    public int Low { get; init; }
    public double RiskScore { get; init; }
    public string RiskLevel { get; init; } = "Unknown";
}

public record PackageVulnerabilityDto
{
    public required string PackageId { get; init; }
    public required string InstalledVersion { get; init; }
    public string? CveId { get; init; }
    public string? GhsaId { get; init; }
    public required string Severity { get; init; }
    public double CvssScore { get; init; }
    public required string Description { get; init; }
    public string? FixedInVersion { get; init; }
    public bool IsTransitive { get; init; }
    public string? AdvisoryUrl { get; init; }
}

public record OutdatedPackageDto
{
    public required string PackageId { get; init; }
    public required string InstalledVersion { get; init; }
    public required string LatestVersion { get; init; }
    public int MajorVersionsBehind { get; init; }
    public required string UpdateUrgency { get; init; }
}

public record UpgradeRecommendationDto
{
    public required string PackageId { get; init; }
    public required string CurrentVersion { get; init; }
    public required string RecommendedVersion { get; init; }
    public required string Reason { get; init; }
    public int Priority { get; init; }
}

// Clone Detection
public record CloneAnalysisResultDto
{
    public double CloneCoverage { get; init; }
    public int TotalCloneClasses { get; init; }
    public int TotalClonedLines { get; init; }
    public List<CloneClassDto> CloneClasses { get; init; } = [];
    public List<ExtractionOpportunityDto> ExtractionOpportunities { get; init; } = [];
}

public record CloneClassDto
{
    public required string CloneId { get; init; }
    public required string CloneType { get; init; }
    public int InstanceCount { get; init; }
    public int LinesPerInstance { get; init; }
    public double Similarity { get; init; }
    public List<CloneInstanceDto> Instances { get; init; } = [];
    public string? SuggestedMethodName { get; init; }
}

public record CloneInstanceDto
{
    public required string FilePath { get; init; }
    public int StartLine { get; init; }
    public int EndLine { get; init; }
    public string? CodeSnippet { get; init; }
}

public record ExtractionOpportunityDto
{
    public required string CloneId { get; init; }
    public required string SuggestedRefactoring { get; init; }
    public int EstimatedLinesReduced { get; init; }
    public string? ProposedCode { get; init; }
}

// Impact Analysis
public record ImpactAnalysisResultDto
{
    public required string TargetSymbol { get; init; }
    public int DirectDependents { get; init; }
    public int TransitiveDependents { get; init; }
    public required string RiskLevel { get; init; }
    public List<ImpactedFileDto> ImpactedFiles { get; init; } = [];
    public List<ImpactChainDto> ImpactChains { get; init; } = [];
    public List<string> TestsToRun { get; init; } = [];
    public Dictionary<string, int> ImpactByNamespace { get; init; } = [];
}

public record ImpactedFileDto
{
    public required string FilePath { get; init; }
    public int ImpactedSymbols { get; init; }
    public required string ImpactType { get; init; }
}

public record ImpactChainDto
{
    public required string Source { get; init; }
    public required string Destination { get; init; }
    public List<string> Path { get; init; } = [];
    public required string DependencyType { get; init; }
}

// Technical Debt
public record TechnicalDebtResultDto
{
    public double TotalDebtMinutes { get; init; }
    public double TotalDebtDays { get; init; }
    public double DebtRatio { get; init; }
    public required string DebtRating { get; init; }
    public List<DebtItemDto> AllDebt { get; init; } = [];
    public List<DebtItemDto> QuickWins { get; init; } = [];
    public List<DebtItemDto> MajorProjects { get; init; } = [];
    public DebtTrendDto? Trend { get; init; }
    public Dictionary<string, double> DebtByCategory { get; init; } = [];
    public Dictionary<string, double> DebtByFile { get; init; } = [];
}

public record DebtItemDto
{
    public required string Category { get; init; }
    public required string IssueType { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string Description { get; init; }
    public double EstimatedMinutes { get; init; }
    public double Interest { get; init; }
    public int Priority { get; init; }
}

public record DebtTrendDto
{
    public double WeeklyChange { get; init; }
    public double MonthlyChange { get; init; }
    public required string TrendDirection { get; init; }
}

// Thread Safety
public record ThreadSafetyResultDto
{
    public int TotalIssues { get; init; }
    public List<ThreadSafetyIssueDto> Issues { get; init; } = [];
    public List<SharedStateDto> SharedState { get; init; } = [];
    public List<string> ThreadSafeClasses { get; init; } = [];
    public List<string> ThreadUnsafeClasses { get; init; } = [];
}

public record ThreadSafetyIssueDto
{
    public required string IssueType { get; init; }
    public required string Severity { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string Description { get; init; }
    public string? SharedResource { get; init; }
    public List<string> AccessingMethods { get; init; } = [];
    public required string Recommendation { get; init; }
    public string? FixCode { get; init; }
}

public record SharedStateDto
{
    public required string FieldName { get; init; }
    public required string DeclaringType { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public bool IsStatic { get; init; }
    public List<string> AccessingMethods { get; init; } = [];
}

// Memory Leaks
public record MemoryLeakResultDto
{
    public int TotalLeaks { get; init; }
    public List<MemoryLeakDto> Leaks { get; init; } = [];
    public List<EventSubscriptionDto> UnbalancedSubscriptions { get; init; } = [];
    public List<StaticCollectionDto> GrowingCollections { get; init; } = [];
    public List<ClosureCaptureDto> ProblematicClosures { get; init; } = [];
}

public record MemoryLeakDto
{
    public required string LeakType { get; init; }
    public required string Severity { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string Description { get; init; }
    public required string LeakedResource { get; init; }
    public required string Recommendation { get; init; }
    public string? FixCode { get; init; }
}

public record EventSubscriptionDto
{
    public required string EventName { get; init; }
    public required string SubscriberType { get; init; }
    public required string FilePath { get; init; }
    public int SubscribeLine { get; init; }
    public int? UnsubscribeLine { get; init; }
    public bool IsBalanced { get; init; }
}

public record StaticCollectionDto
{
    public required string FieldName { get; init; }
    public required string CollectionType { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public bool HasRemoveOperations { get; init; }
    public bool HasSizeLimit { get; init; }
}

public record ClosureCaptureDto
{
    public required string LambdaLocation { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public List<string> CapturedVariables { get; init; } = [];
    public required string Risk { get; init; }
}

// Migration
public record MigrationResultDto
{
    public required string CurrentFramework { get; init; }
    public required string RecommendedFramework { get; init; }
    public int TotalMigrationItems { get; init; }
    public required string Complexity { get; init; }
    public List<DeprecatedApiDto> DeprecatedApis { get; init; } = [];
    public List<ApiMigrationDto> ApiMigrations { get; init; } = [];
    public List<PlatformIssueDto> PlatformIssues { get; init; } = [];
}

public record DeprecatedApiDto
{
    public required string ApiName { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string Reason { get; init; }
    public string? Replacement { get; init; }
}

public record ApiMigrationDto
{
    public required string OldApi { get; init; }
    public required string NewApi { get; init; }
    public int OccurrenceCount { get; init; }
    public required string MigrationGuide { get; init; }
    public required string Difficulty { get; init; }
}

public record PlatformIssueDto
{
    public required string IssueType { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string Description { get; init; }
    public required string Platform { get; init; }
}

// Naming Conventions
public record NamingResultDto
{
    public int TotalViolations { get; init; }
    public List<NamingViolationDto> Violations { get; init; } = [];
    public List<MisleadingNameDto> MisleadingNames { get; init; } = [];
    public List<InconsistentTermDto> InconsistentTerms { get; init; } = [];
    public Dictionary<string, int> ViolationsByRule { get; init; } = [];
}

public record NamingViolationDto
{
    public required string Rule { get; init; }
    public required string ElementType { get; init; }
    public required string CurrentName { get; init; }
    public required string SuggestedName { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
}

public record MisleadingNameDto
{
    public required string MemberName { get; init; }
    public required string MemberType { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string Issue { get; init; }
    public required string Suggestion { get; init; }
}

public record InconsistentTermDto
{
    public required string Term { get; init; }
    public List<string> Variations { get; init; } = [];
    public int OccurrenceCount { get; init; }
    public required string Recommendation { get; init; }
}

// Contracts
public record ContractAnalysisResultDto
{
    public List<PreconditionDto> Preconditions { get; init; } = [];
    public List<PostconditionDto> Postconditions { get; init; } = [];
    public List<InvariantDto> Invariants { get; init; } = [];
    public List<SideEffectDto> SideEffects { get; init; } = [];
    public List<GuardSuggestionDto> SuggestedGuards { get; init; } = [];
}

public record PreconditionDto
{
    public required string MethodName { get; init; }
    public required string Parameter { get; init; }
    public required string PreconditionType { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string Suggestion { get; init; }
    public string? GeneratedGuardCode { get; init; }
}

public record PostconditionDto
{
    public required string MethodName { get; init; }
    public required string Condition { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
}

public record InvariantDto
{
    public required string ClassName { get; init; }
    public required string InvariantDescription { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
}

public record SideEffectDto
{
    public required string MethodName { get; init; }
    public required string MethodType { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string Effect { get; init; }
    public required string Severity { get; init; }
}

public record GuardSuggestionDto
{
    public required string MethodName { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string GuardCode { get; init; }
    public required string Reason { get; init; }
}

// Configuration
public record ConfigurationResultDto
{
    public List<HardcodedConfigDto> HardcodedValues { get; init; } = [];
    public List<EnvironmentCodeDto> EnvironmentCode { get; init; } = [];
    public List<ConfigKeyDto> UsedConfigKeys { get; init; } = [];
    public List<ConfigKeyDto> MissingConfigKeys { get; init; } = [];
    public List<ConfigKeyDto> UnusedConfigKeys { get; init; } = [];
}

public record HardcodedConfigDto
{
    public required string ValueType { get; init; }
    public required string Value { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string SuggestedConfigKey { get; init; }
    public required string Recommendation { get; init; }
}

public record EnvironmentCodeDto
{
    public required string IssueType { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string Environment { get; init; }
    public required string Description { get; init; }
}

public record ConfigKeyDto
{
    public required string Key { get; init; }
    public required string Source { get; init; }
    public string? FilePath { get; init; }
    public int? Line { get; init; }
}

// Logging Quality
public record LoggingQualityResultDto
{
    public int TotalLogStatements { get; init; }
    public List<LoggingIssueDto> Issues { get; init; } = [];
    public List<SensitiveLogDto> SensitiveDataLogs { get; init; } = [];
    public List<MissingLogDto> MissingLogs { get; init; } = [];
    public Dictionary<string, int> LogsByLevel { get; init; } = [];
    public double StructuredLoggingPercentage { get; init; }
}

public record LoggingIssueDto
{
    public required string IssueType { get; init; }
    public required string Severity { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string CurrentCode { get; init; }
    public required string Recommendation { get; init; }
    public string? SuggestedCode { get; init; }
}

public record SensitiveLogDto
{
    public required string SensitiveType { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string VariableName { get; init; }
    public required string Recommendation { get; init; }
}

public record MissingLogDto
{
    public required string Context { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string Reason { get; init; }
    public required string SuggestedLevel { get; init; }
}

// API Design
public record ApiDesignResultDto
{
    public List<ConsistencyIssueDto> ConsistencyIssues { get; init; } = [];
    public List<BreakingChangeDto> PotentialBreakingChanges { get; init; } = [];
    public List<RestViolationDto> RestViolations { get; init; } = [];
    public ApiMetricsDto Metrics { get; init; } = new();
    public List<ApiImprovementDto> Suggestions { get; init; } = [];
}

public record ConsistencyIssueDto
{
    public required string IssueType { get; init; }
    public required string Description { get; init; }
    public List<string> AffectedMembers { get; init; } = [];
    public required string Recommendation { get; init; }
}

public record BreakingChangeDto
{
    public required string ChangeType { get; init; }
    public required string MemberName { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string Description { get; init; }
    public required string Impact { get; init; }
}

public record RestViolationDto
{
    public required string ViolationType { get; init; }
    public required string ControllerName { get; init; }
    public required string ActionName { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string Description { get; init; }
    public required string Recommendation { get; init; }
}

public record ApiMetricsDto
{
    public int TotalEndpoints { get; init; }
    public int PublicMembers { get; init; }
    public int BreakingChangesRisk { get; init; }
    public double ConsistencyScore { get; init; }
}

public record ApiImprovementDto
{
    public required string Category { get; init; }
    public required string MemberName { get; init; }
    public required string FilePath { get; init; }
    public int Line { get; init; }
    public required string Suggestion { get; init; }
    public required string Priority { get; init; }
}
