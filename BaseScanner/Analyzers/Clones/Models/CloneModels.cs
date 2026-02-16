using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace BaseScanner.Analyzers.Clones.Models;

/// <summary>
/// Types of code clones based on similarity level.
/// </summary>
public enum CloneType
{
    /// <summary>
    /// Type 1: Exact clones - identical except for whitespace and comments.
    /// </summary>
    Type1_Exact = 1,

    /// <summary>
    /// Type 2: Renamed clones - identical structure with different identifiers/literals.
    /// </summary>
    Type2_Renamed = 2,

    /// <summary>
    /// Type 3: Near clones - similar with small modifications (added/removed/changed statements).
    /// </summary>
    Type3_NearMiss = 3,

    /// <summary>
    /// Type 4: Semantic clones - different syntax but equivalent behavior/logic.
    /// </summary>
    Type4_Semantic = 4
}

/// <summary>
/// A fragment of code that may be part of a clone.
/// </summary>
public record CodeFragment
{
    /// <summary>
    /// Unique identifier for this fragment.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// Path to the source file.
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
    /// Starting character position in the file.
    /// </summary>
    public int StartPosition { get; init; }

    /// <summary>
    /// Ending character position in the file.
    /// </summary>
    public int EndPosition { get; init; }

    /// <summary>
    /// The actual source code text.
    /// </summary>
    public string SourceCode { get; init; } = "";

    /// <summary>
    /// Normalized code representation for comparison.
    /// </summary>
    public string NormalizedCode { get; init; } = "";

    /// <summary>
    /// Containing method name, if applicable.
    /// </summary>
    public string? ContainingMethod { get; init; }

    /// <summary>
    /// Containing class name, if applicable.
    /// </summary>
    public string? ContainingClass { get; init; }

    /// <summary>
    /// Number of tokens in this fragment.
    /// </summary>
    public int TokenCount { get; init; }

    /// <summary>
    /// Number of lines of code.
    /// </summary>
    public int LineCount => EndLine - StartLine + 1;

    /// <summary>
    /// Semantic hash for quick comparison.
    /// </summary>
    public long SemanticHash { get; init; }

    /// <summary>
    /// Normalized hash (identifiers replaced with placeholders).
    /// </summary>
    public long NormalizedHash { get; init; }

    /// <summary>
    /// Token n-gram fingerprints.
    /// </summary>
    public List<long> TokenFingerprints { get; init; } = [];

    /// <summary>
    /// AST subtree hashes.
    /// </summary>
    public List<long> AstHashes { get; init; } = [];

    /// <summary>
    /// Control flow graph signature for semantic comparison.
    /// </summary>
    public string ControlFlowSignature { get; init; } = "";
}

/// <summary>
/// A pair of code fragments that are clones of each other.
/// </summary>
public record ClonePair
{
    /// <summary>
    /// First fragment in the clone pair.
    /// </summary>
    public required CodeFragment Fragment1 { get; init; }

    /// <summary>
    /// Second fragment in the clone pair.
    /// </summary>
    public required CodeFragment Fragment2 { get; init; }

    /// <summary>
    /// Type of clone relationship.
    /// </summary>
    public required CloneType CloneType { get; init; }

    /// <summary>
    /// Similarity score (0.0 to 1.0).
    /// </summary>
    public required double Similarity { get; init; }

    /// <summary>
    /// Edit distance between fragments (for Type 3 clones).
    /// </summary>
    public int EditDistance { get; init; }

    /// <summary>
    /// Differences between the fragments.
    /// </summary>
    public List<CloneDifference> Differences { get; init; } = [];
}

/// <summary>
/// A difference between two clone fragments.
/// </summary>
public record CloneDifference
{
    /// <summary>
    /// Type of difference.
    /// </summary>
    public required DifferenceType Type { get; init; }

    /// <summary>
    /// Location in fragment 1.
    /// </summary>
    public int Fragment1Line { get; init; }

    /// <summary>
    /// Location in fragment 2.
    /// </summary>
    public int Fragment2Line { get; init; }

    /// <summary>
    /// Original value in fragment 1.
    /// </summary>
    public string? Fragment1Value { get; init; }

    /// <summary>
    /// Corresponding value in fragment 2.
    /// </summary>
    public string? Fragment2Value { get; init; }

    /// <summary>
    /// Description of the difference.
    /// </summary>
    public string Description { get; init; } = "";
}

/// <summary>
/// Type of difference between clone fragments.
/// </summary>
public enum DifferenceType
{
    IdentifierRenamed,
    LiteralChanged,
    StatementAdded,
    StatementRemoved,
    StatementModified,
    TypeChanged,
    OperatorChanged,
    OrderChanged
}

/// <summary>
/// A class of clones - a group of related clone fragments.
/// </summary>
public record CloneClass
{
    /// <summary>
    /// Unique identifier for this clone class.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// The type of clones in this class.
    /// </summary>
    public required CloneType CloneType { get; init; }

    /// <summary>
    /// All fragments that are part of this clone class.
    /// </summary>
    public required List<CodeFragment> Fragments { get; init; }

    /// <summary>
    /// Representative fragment (canonical form).
    /// </summary>
    public CodeFragment? Representative { get; init; }

    /// <summary>
    /// Average similarity between all pairs in this class.
    /// </summary>
    public double AverageSimilarity { get; init; }

    /// <summary>
    /// Total lines of code across all instances.
    /// </summary>
    public int TotalLines => Fragments.Sum(f => f.LineCount);

    /// <summary>
    /// Number of instances in this clone class.
    /// </summary>
    public int InstanceCount => Fragments.Count;

    /// <summary>
    /// Number of unique files containing instances.
    /// </summary>
    public int FileCount => Fragments.Select(f => f.FilePath).Distinct().Count();

    /// <summary>
    /// Potential savings if extracted to a shared method.
    /// </summary>
    public int PotentialSavingsLines => TotalLines - (Representative?.LineCount ?? Fragments.FirstOrDefault()?.LineCount ?? 0);
}

/// <summary>
/// An opportunity to extract cloned code into a shared method/class.
/// </summary>
public record ExtractionOpportunity
{
    /// <summary>
    /// The clone class that can be extracted.
    /// </summary>
    public required CloneClass CloneClass { get; init; }

    /// <summary>
    /// Confidence score for this extraction (0.0 to 1.0).
    /// </summary>
    public required double Confidence { get; init; }

    /// <summary>
    /// Suggested name for the extracted method/class.
    /// </summary>
    public required string SuggestedName { get; init; }

    /// <summary>
    /// Type of extraction recommended.
    /// </summary>
    public required ExtractionType ExtractionType { get; init; }

    /// <summary>
    /// Estimated lines of code saved.
    /// </summary>
    public int EstimatedLinesSaved { get; init; }

    /// <summary>
    /// Parameters that would be needed for the extracted method.
    /// </summary>
    public List<SuggestedParameter> SuggestedParameters { get; init; } = [];

    /// <summary>
    /// Suggested return type.
    /// </summary>
    public string? SuggestedReturnType { get; init; }

    /// <summary>
    /// Description of the refactoring.
    /// </summary>
    public string Description { get; init; } = "";

    /// <summary>
    /// Complexity of the extraction.
    /// </summary>
    public ExtractionComplexity Complexity { get; init; }

    /// <summary>
    /// Risks associated with this extraction.
    /// </summary>
    public List<string> Risks { get; init; } = [];
}

/// <summary>
/// A suggested parameter for an extracted method.
/// </summary>
public record SuggestedParameter
{
    /// <summary>
    /// Parameter name.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Parameter type.
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// Whether the parameter varies between clone instances.
    /// </summary>
    public bool VariesBetweenInstances { get; init; }

    /// <summary>
    /// Sample values from different clone instances.
    /// </summary>
    public List<string> SampleValues { get; init; } = [];
}

/// <summary>
/// Type of extraction for refactoring clones.
/// </summary>
public enum ExtractionType
{
    ExtractMethod,
    ExtractLocalFunction,
    ExtractClass,
    ExtractBaseClass,
    ExtractExtensionMethod,
    ExtractUtilityMethod,
    UseTemplateMethod,
    UseStrategyPattern
}

/// <summary>
/// Complexity level of an extraction.
/// </summary>
public enum ExtractionComplexity
{
    Simple,
    Moderate,
    Complex,
    Risky
}

/// <summary>
/// Complete results from clone detection analysis.
/// </summary>
public record CloneDetectionResult
{
    /// <summary>
    /// Project or solution that was analyzed.
    /// </summary>
    public required string AnalyzedPath { get; init; }

    /// <summary>
    /// When the analysis was performed.
    /// </summary>
    public required DateTime AnalyzedAt { get; init; }

    /// <summary>
    /// Total files analyzed.
    /// </summary>
    public int FilesAnalyzed { get; init; }

    /// <summary>
    /// Total lines of code analyzed.
    /// </summary>
    public int TotalLinesAnalyzed { get; init; }

    /// <summary>
    /// All detected clone pairs.
    /// </summary>
    public List<ClonePair> ClonePairs { get; init; } = [];

    /// <summary>
    /// Clone classes (groups of related clones).
    /// </summary>
    public List<CloneClass> CloneClasses { get; init; } = [];

    /// <summary>
    /// Extraction opportunities for refactoring.
    /// </summary>
    public List<ExtractionOpportunity> ExtractionOpportunities { get; init; } = [];

    /// <summary>
    /// Summary metrics.
    /// </summary>
    public CloneMetrics Metrics { get; init; } = new();

    /// <summary>
    /// Breakdown by clone type.
    /// </summary>
    public Dictionary<CloneType, CloneTypeStatistics> ByType { get; init; } = [];

    /// <summary>
    /// Warnings or issues during analysis.
    /// </summary>
    public List<string> Warnings { get; init; } = [];

    /// <summary>
    /// Analysis duration.
    /// </summary>
    public TimeSpan Duration { get; init; }
}

/// <summary>
/// Metrics about code clones.
/// </summary>
public record CloneMetrics
{
    /// <summary>
    /// Total number of clone pairs detected.
    /// </summary>
    public int TotalClonePairs { get; init; }

    /// <summary>
    /// Total number of clone classes.
    /// </summary>
    public int TotalCloneClasses { get; init; }

    /// <summary>
    /// Total lines involved in clones.
    /// </summary>
    public int ClonedLines { get; init; }

    /// <summary>
    /// Percentage of code that is cloned (clone coverage).
    /// </summary>
    public double CloneCoverage { get; init; }

    /// <summary>
    /// Average clone size in lines.
    /// </summary>
    public double AverageCloneSize { get; init; }

    /// <summary>
    /// Largest clone size in lines.
    /// </summary>
    public int LargestCloneSize { get; init; }

    /// <summary>
    /// Average similarity across all clone pairs.
    /// </summary>
    public double AverageSimilarity { get; init; }

    /// <summary>
    /// Number of files containing clones.
    /// </summary>
    public int FilesWithClones { get; init; }

    /// <summary>
    /// Potential lines saved by refactoring all clones.
    /// </summary>
    public int PotentialLinesSaved { get; init; }

    /// <summary>
    /// Clone density (clones per 1000 lines).
    /// </summary>
    public double CloneDensity { get; init; }
}

/// <summary>
/// Statistics for a specific clone type.
/// </summary>
public record CloneTypeStatistics
{
    /// <summary>
    /// The clone type.
    /// </summary>
    public required CloneType Type { get; init; }

    /// <summary>
    /// Number of clone pairs of this type.
    /// </summary>
    public int PairCount { get; init; }

    /// <summary>
    /// Number of clone classes of this type.
    /// </summary>
    public int ClassCount { get; init; }

    /// <summary>
    /// Total lines involved.
    /// </summary>
    public int TotalLines { get; init; }

    /// <summary>
    /// Average similarity for this type.
    /// </summary>
    public double AverageSimilarity { get; init; }

    /// <summary>
    /// Percentage of all clones that are this type.
    /// </summary>
    public double Percentage { get; init; }
}

/// <summary>
/// Options for configuring clone detection.
/// </summary>
public record CloneDetectionOptions
{
    /// <summary>
    /// Minimum number of tokens for a fragment to be considered.
    /// </summary>
    public int MinTokens { get; init; } = 50;

    /// <summary>
    /// Minimum number of lines for a fragment to be considered.
    /// </summary>
    public int MinLines { get; init; } = 5;

    /// <summary>
    /// Maximum number of lines for a single fragment.
    /// </summary>
    public int MaxLines { get; init; } = 200;

    /// <summary>
    /// Minimum similarity threshold (0.0 to 1.0).
    /// </summary>
    public double MinSimilarity { get; init; } = 0.70;

    /// <summary>
    /// Whether to detect Type 1 (exact) clones.
    /// </summary>
    public bool DetectType1 { get; init; } = true;

    /// <summary>
    /// Whether to detect Type 2 (renamed) clones.
    /// </summary>
    public bool DetectType2 { get; init; } = true;

    /// <summary>
    /// Whether to detect Type 3 (near-miss) clones.
    /// </summary>
    public bool DetectType3 { get; init; } = true;

    /// <summary>
    /// Whether to detect Type 4 (semantic) clones.
    /// </summary>
    public bool DetectType4 { get; init; } = true;

    /// <summary>
    /// Maximum edit distance for Type 3 clones.
    /// </summary>
    public int MaxEditDistance { get; init; } = 10;

    /// <summary>
    /// N-gram size for token fingerprinting.
    /// </summary>
    public int NGramSize { get; init; } = 5;

    /// <summary>
    /// Number of hash functions for MinHash.
    /// </summary>
    public int MinHashFunctions { get; init; } = 100;

    /// <summary>
    /// Whether to analyze only method bodies.
    /// </summary>
    public bool MethodLevelOnly { get; init; } = false;

    /// <summary>
    /// Whether to include generated code.
    /// </summary>
    public bool IncludeGeneratedCode { get; init; } = false;

    /// <summary>
    /// File patterns to exclude.
    /// </summary>
    public List<string> ExcludePatterns { get; init; } = [
        "*.Designer.cs",
        "*.g.cs",
        "*.Generated.cs",
        "AssemblyInfo.cs"
    ];

    /// <summary>
    /// Whether to suggest extraction opportunities.
    /// </summary>
    public bool SuggestExtractions { get; init; } = true;

    /// <summary>
    /// Maximum number of clone pairs to return.
    /// </summary>
    public int MaxResults { get; init; } = 1000;
}

/// <summary>
/// Normalized representation of a syntax node for comparison.
/// </summary>
public record NormalizedNode
{
    /// <summary>
    /// The kind of syntax node.
    /// </summary>
    public required string NodeKind { get; init; }

    /// <summary>
    /// Normalized token sequence.
    /// </summary>
    public List<string> Tokens { get; init; } = [];

    /// <summary>
    /// Child nodes (normalized).
    /// </summary>
    public List<NormalizedNode> Children { get; init; } = [];

    /// <summary>
    /// Hash of this normalized structure.
    /// </summary>
    public long StructureHash { get; init; }
}

/// <summary>
/// Control flow graph node for semantic comparison.
/// </summary>
public record ControlFlowNode
{
    /// <summary>
    /// Unique identifier for this node.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// Type of node (entry, exit, statement, branch, loop, etc.).
    /// </summary>
    public required string NodeType { get; init; }

    /// <summary>
    /// Abstract operation (assignment, call, condition, return, etc.).
    /// </summary>
    public string Operation { get; init; } = "";

    /// <summary>
    /// Successor nodes.
    /// </summary>
    public List<string> Successors { get; init; } = [];

    /// <summary>
    /// Predecessor nodes.
    /// </summary>
    public List<string> Predecessors { get; init; } = [];

    /// <summary>
    /// Whether this is a branch point.
    /// </summary>
    public bool IsBranch { get; init; }

    /// <summary>
    /// Whether this is a loop header.
    /// </summary>
    public bool IsLoopHeader { get; init; }
}

/// <summary>
/// Control flow graph for semantic clone detection.
/// </summary>
public record ControlFlowGraph
{
    /// <summary>
    /// Entry node.
    /// </summary>
    public required ControlFlowNode Entry { get; init; }

    /// <summary>
    /// Exit node.
    /// </summary>
    public required ControlFlowNode Exit { get; init; }

    /// <summary>
    /// All nodes in the graph.
    /// </summary>
    public List<ControlFlowNode> Nodes { get; init; } = [];

    /// <summary>
    /// Signature for comparison.
    /// </summary>
    public string Signature { get; init; } = "";

    /// <summary>
    /// Number of branch points.
    /// </summary>
    public int BranchCount => Nodes.Count(n => n.IsBranch);

    /// <summary>
    /// Number of loop structures.
    /// </summary>
    public int LoopCount => Nodes.Count(n => n.IsLoopHeader);
}
