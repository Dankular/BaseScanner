namespace BaseScanner.Analyzers.Migration.Models;

/// <summary>
/// Represents a mapping from an old/deprecated API to a new/recommended API.
/// </summary>
public record ApiMapping
{
    /// <summary>
    /// The old/deprecated API pattern (e.g., "System.Net.WebRequest")
    /// </summary>
    public required string OldApi { get; init; }

    /// <summary>
    /// The new/recommended API (e.g., "System.Net.Http.HttpClient")
    /// </summary>
    public required string NewApi { get; init; }

    /// <summary>
    /// Category of the API (e.g., "Networking", "Collections", "Serialization")
    /// </summary>
    public required string Category { get; init; }

    /// <summary>
    /// Complexity of migrating from old to new API: Low, Medium, High, VeryHigh
    /// </summary>
    public required MigrationComplexity Complexity { get; init; }

    /// <summary>
    /// Why the old API is deprecated or should be replaced
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>
    /// Detailed migration guidance
    /// </summary>
    public required string MigrationGuide { get; init; }

    /// <summary>
    /// Whether this is a security risk (e.g., BinaryFormatter)
    /// </summary>
    public bool IsSecurityRisk { get; init; }

    /// <summary>
    /// Whether this blocks .NET Core/5+ migration
    /// </summary>
    public bool IsBlockingIssue { get; init; }

    /// <summary>
    /// Required NuGet packages for the new API
    /// </summary>
    public List<string> RequiredPackages { get; init; } = [];

    /// <summary>
    /// Example code showing old usage
    /// </summary>
    public string? OldCodeExample { get; init; }

    /// <summary>
    /// Example code showing new usage
    /// </summary>
    public string? NewCodeExample { get; init; }
}

/// <summary>
/// Migration complexity levels.
/// </summary>
public enum MigrationComplexity
{
    /// <summary>Simple drop-in replacement</summary>
    Low,
    /// <summary>Requires some code changes</summary>
    Medium,
    /// <summary>Requires significant refactoring</summary>
    High,
    /// <summary>Requires architectural changes</summary>
    VeryHigh
}

/// <summary>
/// Represents a detected deprecated API usage.
/// </summary>
public record DeprecatedApiUsage
{
    /// <summary>
    /// The API being used (e.g., "System.Net.WebRequest")
    /// </summary>
    public required string Api { get; init; }

    /// <summary>
    /// The mapping to the new API, if available
    /// </summary>
    public ApiMapping? Mapping { get; init; }

    /// <summary>
    /// Path to the file containing the usage
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Line number (1-based)
    /// </summary>
    public required int Line { get; init; }

    /// <summary>
    /// Column number (1-based)
    /// </summary>
    public required int Column { get; init; }

    /// <summary>
    /// The code snippet containing the usage
    /// </summary>
    public required string CodeSnippet { get; init; }

    /// <summary>
    /// Type of usage: TypeReference, MethodCall, PropertyAccess, Inheritance
    /// </summary>
    public required string UsageType { get; init; }

    /// <summary>
    /// The containing type name
    /// </summary>
    public string? ContainingType { get; init; }

    /// <summary>
    /// The containing method name
    /// </summary>
    public string? ContainingMethod { get; init; }
}

/// <summary>
/// Represents platform-specific code that may not be portable.
/// </summary>
public record PlatformSpecificCode
{
    /// <summary>
    /// Type of platform-specific code: Registry, PInvoke, COM, WinForms, WPF, etc.
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// Specific API or pattern detected
    /// </summary>
    public required string Api { get; init; }

    /// <summary>
    /// Platform this code is specific to: Windows, Linux, macOS
    /// </summary>
    public required string Platform { get; init; }

    /// <summary>
    /// Path to the file
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Line number (1-based)
    /// </summary>
    public required int Line { get; init; }

    /// <summary>
    /// Column number (1-based)
    /// </summary>
    public required int Column { get; init; }

    /// <summary>
    /// The code snippet
    /// </summary>
    public required string CodeSnippet { get; init; }

    /// <summary>
    /// Impact level: Blocking, High, Medium, Low
    /// </summary>
    public required string Impact { get; init; }

    /// <summary>
    /// Description of the issue
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Suggested cross-platform alternative, if any
    /// </summary>
    public string? Alternative { get; init; }

    /// <summary>
    /// Whether this can be conditionally compiled
    /// </summary>
    public bool CanBeConditional { get; init; }
}

/// <summary>
/// Framework compatibility check result.
/// </summary>
public record CompatibilityResult
{
    /// <summary>
    /// Target framework being checked against (e.g., "net8.0", "net9.0")
    /// </summary>
    public required string TargetFramework { get; init; }

    /// <summary>
    /// Overall compatibility: Compatible, PartiallyCompatible, NotCompatible
    /// </summary>
    public required CompatibilityLevel Level { get; init; }

    /// <summary>
    /// APIs that are not available in the target framework
    /// </summary>
    public List<UnavailableApi> UnavailableApis { get; init; } = [];

    /// <summary>
    /// Packages that need to be updated or replaced
    /// </summary>
    public List<PackageCompatibility> PackageIssues { get; init; } = [];

    /// <summary>
    /// Project file changes needed
    /// </summary>
    public List<ProjectChange> RequiredChanges { get; init; } = [];

    /// <summary>
    /// Summary statistics
    /// </summary>
    public CompatibilitySummary Summary { get; init; } = new();
}

/// <summary>
/// Compatibility level.
/// </summary>
public enum CompatibilityLevel
{
    /// <summary>Fully compatible, no changes needed</summary>
    Compatible,
    /// <summary>Mostly compatible, minor changes needed</summary>
    PartiallyCompatible,
    /// <summary>Not compatible, significant changes needed</summary>
    NotCompatible,
    /// <summary>Compatibility cannot be determined</summary>
    Unknown
}

/// <summary>
/// An API that is not available in the target framework.
/// </summary>
public record UnavailableApi
{
    /// <summary>
    /// The unavailable API
    /// </summary>
    public required string Api { get; init; }

    /// <summary>
    /// Reason it's unavailable
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>
    /// Alternative API, if any
    /// </summary>
    public string? Alternative { get; init; }

    /// <summary>
    /// Number of usages in the codebase
    /// </summary>
    public int UsageCount { get; init; }

    /// <summary>
    /// Files containing usages
    /// </summary>
    public List<string> Files { get; init; } = [];
}

/// <summary>
/// Package compatibility information.
/// </summary>
public record PackageCompatibility
{
    /// <summary>
    /// Package name
    /// </summary>
    public required string PackageName { get; init; }

    /// <summary>
    /// Current version
    /// </summary>
    public required string CurrentVersion { get; init; }

    /// <summary>
    /// Whether the package is compatible
    /// </summary>
    public required bool IsCompatible { get; init; }

    /// <summary>
    /// Minimum compatible version, if any
    /// </summary>
    public string? MinimumCompatibleVersion { get; init; }

    /// <summary>
    /// Replacement package, if different
    /// </summary>
    public string? ReplacementPackage { get; init; }

    /// <summary>
    /// Notes about the package migration
    /// </summary>
    public string? Notes { get; init; }
}

/// <summary>
/// A required project file change.
/// </summary>
public record ProjectChange
{
    /// <summary>
    /// Type of change: AddProperty, RemoveProperty, UpdateProperty, AddPackage, RemovePackage, UpdatePackage
    /// </summary>
    public required string ChangeType { get; init; }

    /// <summary>
    /// The element or package being changed
    /// </summary>
    public required string Target { get; init; }

    /// <summary>
    /// Current value, if applicable
    /// </summary>
    public string? CurrentValue { get; init; }

    /// <summary>
    /// New value, if applicable
    /// </summary>
    public string? NewValue { get; init; }

    /// <summary>
    /// Reason for the change
    /// </summary>
    public required string Reason { get; init; }

    /// <summary>
    /// Whether this change is required or optional
    /// </summary>
    public bool IsRequired { get; init; } = true;
}

/// <summary>
/// Compatibility summary statistics.
/// </summary>
public record CompatibilitySummary
{
    public int TotalIssues { get; init; }
    public int BlockingIssues { get; init; }
    public int UnavailableApiCount { get; init; }
    public int PackageIssueCount { get; init; }
    public int ProjectChangeCount { get; init; }
    public double CompatibilityScore { get; init; } // 0.0 to 1.0
}

/// <summary>
/// A migration step in the plan.
/// </summary>
public record MigrationStep
{
    /// <summary>
    /// Order of execution (1-based)
    /// </summary>
    public required int Order { get; init; }

    /// <summary>
    /// Phase: Preparation, CoreMigration, ApiUpdates, Testing, Cleanup
    /// </summary>
    public required MigrationPhase Phase { get; init; }

    /// <summary>
    /// Title of the step
    /// </summary>
    public required string Title { get; init; }

    /// <summary>
    /// Detailed description
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Estimated effort in hours
    /// </summary>
    public required double EstimatedHours { get; init; }

    /// <summary>
    /// Risk level: Low, Medium, High
    /// </summary>
    public required string RiskLevel { get; init; }

    /// <summary>
    /// Whether this step can be automated
    /// </summary>
    public bool CanBeAutomated { get; init; }

    /// <summary>
    /// Dependencies on other steps (by order number)
    /// </summary>
    public List<int> Dependencies { get; init; } = [];

    /// <summary>
    /// Files affected by this step
    /// </summary>
    public List<string> AffectedFiles { get; init; } = [];

    /// <summary>
    /// Specific actions to take
    /// </summary>
    public List<string> Actions { get; init; } = [];

    /// <summary>
    /// Verification steps
    /// </summary>
    public List<string> VerificationSteps { get; init; } = [];
}

/// <summary>
/// Migration phases.
/// </summary>
public enum MigrationPhase
{
    /// <summary>Preparation and planning</summary>
    Preparation,
    /// <summary>Core framework migration</summary>
    CoreMigration,
    /// <summary>API updates and replacements</summary>
    ApiUpdates,
    /// <summary>Platform-specific code handling</summary>
    PlatformHandling,
    /// <summary>Testing and validation</summary>
    Testing,
    /// <summary>Cleanup and optimization</summary>
    Cleanup
}

/// <summary>
/// Complete migration plan.
/// </summary>
public record MigrationPlan
{
    /// <summary>
    /// Source framework
    /// </summary>
    public required string SourceFramework { get; init; }

    /// <summary>
    /// Target framework
    /// </summary>
    public required string TargetFramework { get; init; }

    /// <summary>
    /// Project being migrated
    /// </summary>
    public required string ProjectName { get; init; }

    /// <summary>
    /// Overall complexity: Low, Medium, High, VeryHigh
    /// </summary>
    public required MigrationComplexity OverallComplexity { get; init; }

    /// <summary>
    /// Total estimated effort in hours
    /// </summary>
    public required double TotalEstimatedHours { get; init; }

    /// <summary>
    /// Confidence level in the estimate: Low, Medium, High
    /// </summary>
    public required string EstimateConfidence { get; init; }

    /// <summary>
    /// Blocking issues that must be resolved before migration
    /// </summary>
    public List<BlockingIssue> BlockingIssues { get; init; } = [];

    /// <summary>
    /// Ordered list of migration steps
    /// </summary>
    public List<MigrationStep> Steps { get; init; } = [];

    /// <summary>
    /// Package migrations needed
    /// </summary>
    public List<PackageMigration> PackageMigrations { get; init; } = [];

    /// <summary>
    /// Risk assessment
    /// </summary>
    public RiskAssessment Risks { get; init; } = new();

    /// <summary>
    /// Summary statistics
    /// </summary>
    public MigrationSummary Summary { get; init; } = new();

    /// <summary>
    /// When the plan was generated
    /// </summary>
    public DateTime GeneratedAt { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// A blocking issue that prevents migration.
/// </summary>
public record BlockingIssue
{
    /// <summary>
    /// Type of blocking issue
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// Description
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// The specific API or feature causing the block
    /// </summary>
    public required string Cause { get; init; }

    /// <summary>
    /// How to resolve this issue
    /// </summary>
    public required string Resolution { get; init; }

    /// <summary>
    /// Estimated effort to resolve in hours
    /// </summary>
    public double EstimatedHours { get; init; }

    /// <summary>
    /// Files affected
    /// </summary>
    public List<string> AffectedFiles { get; init; } = [];
}

/// <summary>
/// Package migration information.
/// </summary>
public record PackageMigration
{
    /// <summary>
    /// Old package name
    /// </summary>
    public required string OldPackage { get; init; }

    /// <summary>
    /// Old package version
    /// </summary>
    public required string OldVersion { get; init; }

    /// <summary>
    /// New package name (may be different)
    /// </summary>
    public required string NewPackage { get; init; }

    /// <summary>
    /// New package version
    /// </summary>
    public required string NewVersion { get; init; }

    /// <summary>
    /// Whether this is a simple version upgrade
    /// </summary>
    public bool IsVersionUpgrade { get; init; }

    /// <summary>
    /// Breaking changes in the new version
    /// </summary>
    public List<string> BreakingChanges { get; init; } = [];

    /// <summary>
    /// Notes about the migration
    /// </summary>
    public string? Notes { get; init; }
}

/// <summary>
/// Risk assessment for the migration.
/// </summary>
public record RiskAssessment
{
    /// <summary>
    /// Overall risk level: Low, Medium, High, Critical
    /// </summary>
    public string OverallRisk { get; init; } = "Medium";

    /// <summary>
    /// Technical risks
    /// </summary>
    public List<Risk> TechnicalRisks { get; init; } = [];

    /// <summary>
    /// Business risks
    /// </summary>
    public List<Risk> BusinessRisks { get; init; } = [];

    /// <summary>
    /// Mitigation strategies
    /// </summary>
    public List<string> MitigationStrategies { get; init; } = [];

    /// <summary>
    /// Recommended testing approach
    /// </summary>
    public List<string> TestingRecommendations { get; init; } = [];
}

/// <summary>
/// A specific risk.
/// </summary>
public record Risk
{
    /// <summary>
    /// Risk description
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Likelihood: Low, Medium, High
    /// </summary>
    public required string Likelihood { get; init; }

    /// <summary>
    /// Impact: Low, Medium, High
    /// </summary>
    public required string Impact { get; init; }

    /// <summary>
    /// Mitigation strategy
    /// </summary>
    public required string Mitigation { get; init; }
}

/// <summary>
/// Migration summary statistics.
/// </summary>
public record MigrationSummary
{
    public int TotalFiles { get; init; }
    public int FilesRequiringChanges { get; init; }
    public int DeprecatedApiUsages { get; init; }
    public int PlatformSpecificIssues { get; init; }
    public int BlockingIssueCount { get; init; }
    public int PackagesToMigrate { get; init; }
    public int TotalSteps { get; init; }
    public Dictionary<string, int> IssuesByCategory { get; init; } = [];
    public Dictionary<MigrationPhase, double> HoursByPhase { get; init; } = [];
}

/// <summary>
/// Complete migration analysis result.
/// </summary>
public record MigrationAnalysisResult
{
    /// <summary>
    /// Detected deprecated API usages
    /// </summary>
    public List<DeprecatedApiUsage> DeprecatedApis { get; init; } = [];

    /// <summary>
    /// Platform-specific code detections
    /// </summary>
    public List<PlatformSpecificCode> PlatformSpecificCode { get; init; } = [];

    /// <summary>
    /// Compatibility check result
    /// </summary>
    public CompatibilityResult? Compatibility { get; init; }

    /// <summary>
    /// Migration plan
    /// </summary>
    public MigrationPlan? Plan { get; init; }

    /// <summary>
    /// Analysis summary
    /// </summary>
    public MigrationAnalysisSummary Summary { get; init; } = new();

    /// <summary>
    /// When the analysis was performed
    /// </summary>
    public DateTime AnalyzedAt { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Summary of migration analysis.
/// </summary>
public record MigrationAnalysisSummary
{
    public int TotalDeprecatedApiUsages { get; init; }
    public int TotalPlatformSpecificIssues { get; init; }
    public int SecurityRisks { get; init; }
    public int BlockingIssues { get; init; }
    public MigrationComplexity OverallComplexity { get; init; }
    public string MigrationReadiness { get; init; } = "Unknown"; // Ready, NeedsWork, MajorEffort, NotRecommended
    public Dictionary<string, int> ApiUsagesByCategory { get; init; } = [];
    public Dictionary<string, int> PlatformIssuesByType { get; init; } = [];
}
