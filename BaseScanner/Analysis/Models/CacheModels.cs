using System.Text.Json.Serialization;

namespace BaseScanner.Analysis.Models;

/// <summary>
/// Root cache structure for incremental analysis.
/// Stored at .basescanner/cache/analysis-cache.json
/// </summary>
public record AnalysisCacheData
{
    /// <summary>Cache format version for compatibility checking.</summary>
    public required int Version { get; init; }

    /// <summary>When the cache was last updated.</summary>
    public required DateTime LastUpdated { get; init; }

    /// <summary>Project path this cache is for.</summary>
    public required string ProjectPath { get; init; }

    /// <summary>Per-file cache entries keyed by absolute file path.</summary>
    public Dictionary<string, FileCacheEntry> Files { get; init; } = [];

    /// <summary>Global dependency graph.</summary>
    public DependencyGraph DependencyGraph { get; init; } = new();
}

/// <summary>
/// Cache entry for a single file.
/// </summary>
public record FileCacheEntry
{
    /// <summary>Absolute path to the file.</summary>
    public required string FilePath { get; init; }

    /// <summary>SHA256 hash of file content.</summary>
    public required string ContentHash { get; init; }

    /// <summary>When this file was last analyzed.</summary>
    public required DateTime LastAnalyzedAt { get; init; }

    /// <summary>File size at time of analysis.</summary>
    public required long FileSize { get; init; }

    /// <summary>Cached analysis results for this file.</summary>
    public FileAnalysisResult? Results { get; init; }

    /// <summary>Types/symbols defined in this file.</summary>
    public List<SymbolDefinition> DefinedSymbols { get; init; } = [];

    /// <summary>Types/symbols referenced by this file.</summary>
    public List<SymbolReference> ReferencedSymbols { get; init; } = [];
}

/// <summary>
/// Analysis results cached per file.
/// </summary>
public record FileAnalysisResult
{
    /// <summary>Performance issues found in this file.</summary>
    public List<CachedIssue> PerformanceIssues { get; init; } = [];

    /// <summary>Exception handling issues.</summary>
    public List<CachedIssue> ExceptionIssues { get; init; } = [];

    /// <summary>Resource leak issues.</summary>
    public List<CachedIssue> ResourceIssues { get; init; } = [];

    /// <summary>Magic values found.</summary>
    public List<CachedMagicValue> MagicValues { get; init; } = [];

    /// <summary>Refactoring opportunities.</summary>
    public CachedRefactoringResult? Refactoring { get; init; }

    /// <summary>Safety issues (null safety, immutability, logging).</summary>
    public List<CachedIssue> SafetyIssues { get; init; } = [];

    /// <summary>Security vulnerabilities.</summary>
    public List<CachedSecurityIssue> SecurityIssues { get; init; } = [];

    /// <summary>Optimization opportunities.</summary>
    public List<CachedOptimization> Optimizations { get; init; } = [];

    /// <summary>File-level metrics.</summary>
    public CachedFileMetrics? Metrics { get; init; }
}

/// <summary>
/// A cached issue with location information.
/// </summary>
public record CachedIssue
{
    public required string Type { get; init; }
    public required string Severity { get; init; }
    public required string Message { get; init; }
    public required int Line { get; init; }
    public required int EndLine { get; init; }
    public string? CodeSnippet { get; init; }
}

/// <summary>
/// Cached magic value entry.
/// </summary>
public record CachedMagicValue
{
    public required string Type { get; init; }
    public required string Value { get; init; }
    public required int Line { get; init; }
}

/// <summary>
/// Cached refactoring opportunities for a file.
/// </summary>
public record CachedRefactoringResult
{
    public List<CachedLongMethod> LongMethods { get; init; } = [];
    public List<CachedGodClass> GodClasses { get; init; } = [];
    public List<CachedFeatureEnvy> FeatureEnvy { get; init; } = [];
}

/// <summary>
/// Cached long method info.
/// </summary>
public record CachedLongMethod
{
    public required int Line { get; init; }
    public required string ClassName { get; init; }
    public required string MethodName { get; init; }
    public required int LineCount { get; init; }
    public required int Complexity { get; init; }
}

/// <summary>
/// Cached god class info.
/// </summary>
public record CachedGodClass
{
    public required int Line { get; init; }
    public required string ClassName { get; init; }
    public required int MethodCount { get; init; }
    public required int FieldCount { get; init; }
    public required double LCOM { get; init; }
}

/// <summary>
/// Cached feature envy info.
/// </summary>
public record CachedFeatureEnvy
{
    public required int Line { get; init; }
    public required string ClassName { get; init; }
    public required string MethodName { get; init; }
    public required string EnviedClass { get; init; }
    public required double EnvyRatio { get; init; }
}

/// <summary>
/// Cached security issue.
/// </summary>
public record CachedSecurityIssue
{
    public required string VulnerabilityType { get; init; }
    public required string Severity { get; init; }
    public required string CweId { get; init; }
    public required int StartLine { get; init; }
    public required int EndLine { get; init; }
    public required string Description { get; init; }
    public required string Confidence { get; init; }
}

/// <summary>
/// Cached optimization opportunity.
/// </summary>
public record CachedOptimization
{
    public required string Category { get; init; }
    public required string Type { get; init; }
    public required int StartLine { get; init; }
    public required int EndLine { get; init; }
    public required string Description { get; init; }
    public required string Confidence { get; init; }
}

/// <summary>
/// Cached file-level metrics.
/// </summary>
public record CachedFileMetrics
{
    public required int TotalLines { get; init; }
    public required int CodeLines { get; init; }
    public required int CommentLines { get; init; }
    public required int MethodCount { get; init; }
    public required int ClassCount { get; init; }
    public required double AverageComplexity { get; init; }
    public required int MaxComplexity { get; init; }
}

/// <summary>
/// Symbol defined in a file.
/// </summary>
public record SymbolDefinition
{
    /// <summary>Fully qualified name of the symbol.</summary>
    public required string FullyQualifiedName { get; init; }

    /// <summary>Symbol kind: Type, Method, Property, Field, etc.</summary>
    public required string Kind { get; init; }

    /// <summary>Line where the symbol is defined.</summary>
    public required int Line { get; init; }

    /// <summary>Accessibility: Public, Internal, Private, etc.</summary>
    public required string Accessibility { get; init; }
}

/// <summary>
/// Symbol referenced from a file.
/// </summary>
public record SymbolReference
{
    /// <summary>Fully qualified name of the referenced symbol.</summary>
    public required string FullyQualifiedName { get; init; }

    /// <summary>Kind of symbol being referenced.</summary>
    public required string Kind { get; init; }

    /// <summary>Lines where this symbol is referenced.</summary>
    public List<int> ReferenceLines { get; init; } = [];
}

/// <summary>
/// Dependency graph tracking relationships between files.
/// </summary>
public record DependencyGraph
{
    /// <summary>
    /// Map from file path to list of files it depends on (files it references symbols from).
    /// </summary>
    public Dictionary<string, List<string>> Dependencies { get; init; } = [];

    /// <summary>
    /// Map from file path to list of files that depend on it (files that reference its symbols).
    /// </summary>
    public Dictionary<string, List<string>> Dependents { get; init; } = [];

    /// <summary>
    /// Map from fully qualified type name to the file that defines it.
    /// </summary>
    public Dictionary<string, string> TypeToFile { get; init; } = [];
}

/// <summary>
/// Result of change detection.
/// </summary>
public record ChangeDetectionResult
{
    /// <summary>Files that have been modified since last analysis.</summary>
    public List<string> ChangedFiles { get; init; } = [];

    /// <summary>New files that were not in the cache.</summary>
    public List<string> NewFiles { get; init; } = [];

    /// <summary>Files that were deleted.</summary>
    public List<string> DeletedFiles { get; init; } = [];

    /// <summary>Files unchanged since last analysis.</summary>
    public List<string> UnchangedFiles { get; init; } = [];

    /// <summary>Files affected by changes (via dependency graph).</summary>
    public List<string> AffectedFiles { get; init; } = [];

    /// <summary>Total files that need re-analysis.</summary>
    public HashSet<string> FilesToAnalyze => [.. ChangedFiles, .. NewFiles, .. AffectedFiles];

    /// <summary>Whether any changes were detected.</summary>
    public bool HasChanges => ChangedFiles.Count > 0 || NewFiles.Count > 0 || DeletedFiles.Count > 0;
}

/// <summary>
/// Result of incremental analysis.
/// </summary>
public record IncrementalAnalysisResult
{
    /// <summary>Whether incremental analysis was used.</summary>
    public required bool IsIncremental { get; init; }

    /// <summary>Number of files analyzed in this run.</summary>
    public required int FilesAnalyzed { get; init; }

    /// <summary>Number of files retrieved from cache.</summary>
    public required int FilesCached { get; init; }

    /// <summary>Total number of files in the project.</summary>
    public required int TotalFiles { get; init; }

    /// <summary>Time saved compared to full analysis (estimated).</summary>
    public TimeSpan? TimeSaved { get; init; }

    /// <summary>Change detection information.</summary>
    public ChangeDetectionResult? Changes { get; init; }

    /// <summary>Merged analysis results.</summary>
    public required MergedAnalysisResults Results { get; init; }
}

/// <summary>
/// Merged results from cached and fresh analysis.
/// </summary>
public record MergedAnalysisResults
{
    public List<CachedIssue> PerformanceIssues { get; init; } = [];
    public List<CachedIssue> ExceptionIssues { get; init; } = [];
    public List<CachedIssue> ResourceIssues { get; init; } = [];
    public List<CachedSecurityIssue> SecurityIssues { get; init; } = [];
    public List<CachedOptimization> Optimizations { get; init; } = [];
    public CachedRefactoringResult? Refactoring { get; init; }
    public AggregatedMetrics? Metrics { get; init; }
}

/// <summary>
/// Aggregated metrics across all files.
/// </summary>
public record AggregatedMetrics
{
    public required int TotalFiles { get; init; }
    public required int TotalLines { get; init; }
    public required int TotalMethods { get; init; }
    public required int TotalClasses { get; init; }
    public required double AverageComplexity { get; init; }
    public required int MaxComplexity { get; init; }
    public required int MethodsAboveComplexityThreshold { get; init; }
}

/// <summary>
/// Options for incremental analysis.
/// </summary>
public record IncrementalAnalysisOptions
{
    /// <summary>Enable incremental analysis (default: true).</summary>
    public bool UseIncremental { get; init; } = true;

    /// <summary>Force full analysis ignoring cache.</summary>
    public bool NoCache { get; init; } = false;

    /// <summary>Clear the cache before analysis.</summary>
    public bool ClearCache { get; init; } = false;

    /// <summary>Maximum age of cached results before invalidation.</summary>
    public TimeSpan MaxCacheAge { get; init; } = TimeSpan.FromDays(7);

    /// <summary>Whether to update the dependency graph.</summary>
    public bool UpdateDependencyGraph { get; init; } = true;
}
