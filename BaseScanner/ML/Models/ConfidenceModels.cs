namespace BaseScanner.ML.Models;

/// <summary>
/// Features extracted from a code suggestion for confidence scoring.
/// </summary>
public record SuggestionFeatures
{
    /// <summary>
    /// Unique identifier for this suggestion.
    /// </summary>
    public required string SuggestionId { get; init; }

    /// <summary>
    /// The type of optimization/suggestion (e.g., "LinqCountToAny", "StringConcatenation").
    /// </summary>
    public required string PatternType { get; init; }

    /// <summary>
    /// File path where the suggestion applies.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Starting line number of the code.
    /// </summary>
    public int StartLine { get; init; }

    /// <summary>
    /// Ending line number of the code.
    /// </summary>
    public int EndLine { get; init; }

    /// <summary>
    /// Cyclomatic complexity of the containing method.
    /// Higher complexity = more risk in applying changes.
    /// </summary>
    public int MethodComplexity { get; init; }

    /// <summary>
    /// How deeply nested the code is (inside if/for/while/etc).
    /// Higher nesting = harder to reason about.
    /// </summary>
    public int NestingDepth { get; init; }

    /// <summary>
    /// Total lines in the containing method.
    /// </summary>
    public int MethodLength { get; init; }

    /// <summary>
    /// How often this pattern appears across the entire project.
    /// Higher frequency = more familiar pattern.
    /// </summary>
    public int PatternFrequencyInProject { get; init; }

    /// <summary>
    /// How often this pattern appears in the current file.
    /// </summary>
    public int PatternFrequencyInFile { get; init; }

    /// <summary>
    /// Historical application rate for this pattern type (0.0 to 1.0).
    /// </summary>
    public double WasAppliedBefore { get; init; }

    /// <summary>
    /// Historical reversion rate for this pattern type (0.0 to 1.0).
    /// </summary>
    public double WasRevertedBefore { get; init; }

    /// <summary>
    /// Whether this code is in a test file.
    /// </summary>
    public bool IsInTestCode { get; init; }

    /// <summary>
    /// Whether this code appears to be generated (e.g., .g.cs, .Designer.cs).
    /// </summary>
    public bool IsInGeneratedCode { get; init; }

    /// <summary>
    /// Whether there's a comment near this code that might explain its current form.
    /// </summary>
    public bool HasRelatedComment { get; init; }

    /// <summary>
    /// The original code being suggested for change.
    /// </summary>
    public string CurrentCode { get; init; } = string.Empty;

    /// <summary>
    /// The suggested replacement code.
    /// </summary>
    public string SuggestedCode { get; init; } = string.Empty;
}

/// <summary>
/// Result of confidence scoring for a suggestion.
/// </summary>
public record ConfidenceResult
{
    /// <summary>
    /// The suggestion ID this result applies to.
    /// </summary>
    public required string SuggestionId { get; init; }

    /// <summary>
    /// Confidence score between 0.0 and 1.0.
    /// Higher = more confident the suggestion should be applied.
    /// </summary>
    public required double Score { get; init; }

    /// <summary>
    /// Qualitative confidence level.
    /// </summary>
    public ConfidenceLevel Level => Score switch
    {
        >= 0.8 => ConfidenceLevel.VeryHigh,
        >= 0.65 => ConfidenceLevel.High,
        >= 0.5 => ConfidenceLevel.Medium,
        >= 0.35 => ConfidenceLevel.Low,
        _ => ConfidenceLevel.VeryLow
    };

    /// <summary>
    /// Factors that increased confidence.
    /// </summary>
    public List<string> PositiveFactors { get; init; } = [];

    /// <summary>
    /// Factors that decreased confidence.
    /// </summary>
    public List<string> NegativeFactors { get; init; } = [];

    /// <summary>
    /// Recommendations for the user.
    /// </summary>
    public List<string> Recommendations { get; init; } = [];
}

/// <summary>
/// Qualitative confidence levels.
/// </summary>
public enum ConfidenceLevel
{
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh
}

/// <summary>
/// Record of user feedback on a suggestion.
/// </summary>
public record FeedbackRecord
{
    /// <summary>
    /// Unique identifier for this feedback record.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// The suggestion ID this feedback is for.
    /// </summary>
    public required string SuggestionId { get; init; }

    /// <summary>
    /// The pattern type (e.g., "LinqCountToAny").
    /// </summary>
    public required string PatternType { get; init; }

    /// <summary>
    /// File path where the suggestion was.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// The action taken by the user.
    /// </summary>
    public required FeedbackAction Action { get; init; }

    /// <summary>
    /// When the feedback was recorded.
    /// </summary>
    public required DateTime Timestamp { get; init; }

    /// <summary>
    /// Features at the time of the suggestion.
    /// </summary>
    public SuggestionFeatures? Features { get; init; }

    /// <summary>
    /// Confidence score at the time (if available).
    /// </summary>
    public double? ConfidenceScore { get; init; }

    /// <summary>
    /// Optional user comment.
    /// </summary>
    public string? Comment { get; init; }
}

/// <summary>
/// Types of user actions on suggestions.
/// </summary>
public enum FeedbackAction
{
    /// <summary>
    /// User applied the suggestion.
    /// </summary>
    Applied,

    /// <summary>
    /// User explicitly rejected the suggestion.
    /// </summary>
    Rejected,

    /// <summary>
    /// User applied but later reverted the change.
    /// </summary>
    Reverted,

    /// <summary>
    /// User skipped without explicit decision.
    /// </summary>
    Skipped
}

/// <summary>
/// Aggregated statistics for a pattern type.
/// </summary>
public record PatternStatistics
{
    /// <summary>
    /// The pattern type these statistics are for.
    /// </summary>
    public required string PatternType { get; init; }

    /// <summary>
    /// Total number of times this pattern was suggested.
    /// </summary>
    public int TotalSuggestions { get; init; }

    /// <summary>
    /// Number of times the suggestion was applied.
    /// </summary>
    public int AppliedCount { get; init; }

    /// <summary>
    /// Number of times the suggestion was rejected.
    /// </summary>
    public int RejectedCount { get; init; }

    /// <summary>
    /// Number of times the suggestion was reverted after applying.
    /// </summary>
    public int RevertedCount { get; init; }

    /// <summary>
    /// Number of times the suggestion was skipped.
    /// </summary>
    public int SkippedCount { get; init; }

    /// <summary>
    /// Application rate (applied / (applied + rejected)).
    /// </summary>
    public double ApplicationRate =>
        (AppliedCount + RejectedCount) > 0
            ? (double)AppliedCount / (AppliedCount + RejectedCount)
            : 0.5;

    /// <summary>
    /// Reversion rate (reverted / applied).
    /// </summary>
    public double ReversionRate =>
        AppliedCount > 0
            ? (double)RevertedCount / AppliedCount
            : 0.0;

    /// <summary>
    /// Net success rate (applied - reverted) / total decisions.
    /// </summary>
    public double NetSuccessRate
    {
        get
        {
            var totalDecisions = AppliedCount + RejectedCount;
            if (totalDecisions == 0) return 0.5;
            return (double)(AppliedCount - RevertedCount) / totalDecisions;
        }
    }

    /// <summary>
    /// When these statistics were last updated.
    /// </summary>
    public DateTime LastUpdated { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Feedback store data structure for JSON serialization.
/// </summary>
public record FeedbackStoreData
{
    /// <summary>
    /// Version of the feedback store format.
    /// </summary>
    public int Version { get; init; } = 1;

    /// <summary>
    /// All feedback records.
    /// </summary>
    public List<FeedbackRecord> Records { get; init; } = [];

    /// <summary>
    /// Cached pattern statistics.
    /// </summary>
    public Dictionary<string, PatternStatistics> PatternStats { get; init; } = new();

    /// <summary>
    /// When the store was last updated.
    /// </summary>
    public DateTime LastUpdated { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Result of learning from feedback.
/// </summary>
public record LearningResult
{
    /// <summary>
    /// Number of records processed.
    /// </summary>
    public int RecordsProcessed { get; init; }

    /// <summary>
    /// Number of patterns with updated statistics.
    /// </summary>
    public int PatternsUpdated { get; init; }

    /// <summary>
    /// Insights derived from the learning process.
    /// </summary>
    public List<LearningInsight> Insights { get; init; } = [];
}

/// <summary>
/// An insight derived from feedback analysis.
/// </summary>
public record LearningInsight
{
    /// <summary>
    /// Type of insight.
    /// </summary>
    public required InsightType Type { get; init; }

    /// <summary>
    /// Pattern type this insight relates to (if applicable).
    /// </summary>
    public string? PatternType { get; init; }

    /// <summary>
    /// Human-readable description of the insight.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Recommended action based on this insight.
    /// </summary>
    public string? Recommendation { get; init; }

    /// <summary>
    /// Confidence in this insight (0.0 to 1.0).
    /// </summary>
    public double Confidence { get; init; }
}

/// <summary>
/// Types of learning insights.
/// </summary>
public enum InsightType
{
    /// <summary>
    /// A pattern is consistently accepted.
    /// </summary>
    HighAcceptancePattern,

    /// <summary>
    /// A pattern is consistently rejected.
    /// </summary>
    HighRejectionPattern,

    /// <summary>
    /// A pattern is often reverted after application.
    /// </summary>
    HighReversionPattern,

    /// <summary>
    /// Certain conditions correlate with rejection.
    /// </summary>
    ConditionCorrelation,

    /// <summary>
    /// Confidence model may need adjustment.
    /// </summary>
    ModelCalibrationNeeded,

    /// <summary>
    /// Insufficient data for reliable statistics.
    /// </summary>
    InsufficientData
}
