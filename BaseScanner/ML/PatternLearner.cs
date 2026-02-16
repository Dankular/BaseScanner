using BaseScanner.ML.Models;

namespace BaseScanner.ML;

/// <summary>
/// Learns from user feedback to improve confidence scoring.
/// Analyzes patterns in user decisions to derive insights and recommendations.
/// </summary>
public class PatternLearner
{
    private readonly FeedbackStore _feedbackStore;

    /// <summary>
    /// Minimum number of samples needed for reliable statistics.
    /// </summary>
    public int MinimumSamples { get; set; } = 5;

    /// <summary>
    /// Threshold for considering a pattern as high acceptance.
    /// </summary>
    public double HighAcceptanceThreshold { get; set; } = 0.8;

    /// <summary>
    /// Threshold for considering a pattern as high rejection.
    /// </summary>
    public double HighRejectionThreshold { get; set; } = 0.3;

    /// <summary>
    /// Threshold for considering reversion rate as concerning.
    /// </summary>
    public double HighReversionThreshold { get; set; } = 0.2;

    public PatternLearner(FeedbackStore feedbackStore)
    {
        _feedbackStore = feedbackStore;
    }

    /// <summary>
    /// Analyzes all feedback and generates insights.
    /// </summary>
    public LearningResult Learn()
    {
        var records = _feedbackStore.GetAllRecords();
        var patternStats = _feedbackStore.GetAllPatternStatistics();

        var insights = new List<LearningInsight>();

        // Analyze each pattern
        foreach (var (patternType, stats) in patternStats)
        {
            var patternInsights = AnalyzePattern(patternType, stats, records);
            insights.AddRange(patternInsights);
        }

        // Check for global insights
        insights.AddRange(AnalyzeGlobalPatterns(records, patternStats));

        return new LearningResult
        {
            RecordsProcessed = records.Count,
            PatternsUpdated = patternStats.Count,
            Insights = insights
        };
    }

    /// <summary>
    /// Gets the learned weight modifier for a pattern type.
    /// Returns a value between 0.5 and 1.5 to adjust base confidence.
    /// </summary>
    public double GetPatternWeightModifier(string patternType)
    {
        var stats = _feedbackStore.GetPatternStatistics(patternType);
        if (stats == null || !HasSufficientData(stats))
        {
            return 1.0; // No adjustment if insufficient data
        }

        // Calculate modifier based on net success rate
        // Range: 0.5 (often rejected/reverted) to 1.5 (often accepted successfully)
        var netSuccess = stats.NetSuccessRate;
        return 0.5 + netSuccess; // Maps [0, 1] to [0.5, 1.5]
    }

    /// <summary>
    /// Predicts whether a suggestion is likely to be accepted based on learned patterns.
    /// </summary>
    public (double likelihood, string reasoning) PredictAcceptance(SuggestionFeatures features)
    {
        var stats = _feedbackStore.GetPatternStatistics(features.PatternType);
        var reasons = new List<string>();
        double baseLikelihood = 0.5;

        if (stats != null && HasSufficientData(stats))
        {
            baseLikelihood = stats.ApplicationRate;
            reasons.Add($"Pattern '{features.PatternType}' has {stats.ApplicationRate:P0} historical acceptance rate");

            if (stats.ReversionRate > 0.1)
            {
                reasons.Add($"Warning: {stats.ReversionRate:P0} of applied changes were reverted");
            }
        }
        else
        {
            reasons.Add("Insufficient historical data for this pattern type");
        }

        // Adjust based on code characteristics
        if (features.IsInTestCode)
        {
            baseLikelihood *= 0.9;
            reasons.Add("Slightly lower acceptance in test code");
        }

        if (features.IsInGeneratedCode)
        {
            baseLikelihood *= 0.7;
            reasons.Add("Lower acceptance in generated code");
        }

        if (features.HasRelatedComment)
        {
            baseLikelihood *= 0.85;
            reasons.Add("Existing comment suggests intentional code");
        }

        if (features.MethodComplexity > 20)
        {
            baseLikelihood *= 0.9;
            reasons.Add("High complexity increases review caution");
        }

        if (features.NestingDepth > 3)
        {
            baseLikelihood *= 0.95;
            reasons.Add("Deep nesting may indicate complex logic");
        }

        return (Math.Clamp(baseLikelihood, 0.0, 1.0), string.Join("; ", reasons));
    }

    /// <summary>
    /// Finds patterns that correlate with rejection in the given context.
    /// </summary>
    public List<CorrelationFinding> FindRejectionCorrelations()
    {
        var findings = new List<CorrelationFinding>();
        var records = _feedbackStore.GetAllRecords();

        // Group by various features and look for correlations
        var groupings = new Dictionary<string, Func<FeedbackRecord, string>>
        {
            ["High Complexity"] = r => r.Features?.MethodComplexity > 15 ? "complex" : "simple",
            ["Deep Nesting"] = r => r.Features?.NestingDepth > 2 ? "deep" : "shallow",
            ["Test Code"] = r => r.Features?.IsInTestCode == true ? "test" : "prod",
            ["Generated Code"] = r => r.Features?.IsInGeneratedCode == true ? "generated" : "manual",
            ["Has Comment"] = r => r.Features?.HasRelatedComment == true ? "commented" : "uncommented",
            ["Long Method"] = r => r.Features?.MethodLength > 50 ? "long" : "short"
        };

        foreach (var (groupName, groupFn) in groupings)
        {
            var grouped = records
                .Where(r => r.Features != null && r.Action != FeedbackAction.Skipped)
                .GroupBy(groupFn)
                .Where(g => g.Count() >= MinimumSamples)
                .ToList();

            if (grouped.Count < 2) continue;

            var acceptanceRates = grouped
                .Select(g => new
                {
                    Group = g.Key,
                    Rate = g.Count(r => r.Action == FeedbackAction.Applied) / (double)g.Count(r =>
                        r.Action == FeedbackAction.Applied || r.Action == FeedbackAction.Rejected)
                })
                .ToList();

            var maxDiff = acceptanceRates.Max(r => r.Rate) - acceptanceRates.Min(r => r.Rate);

            if (maxDiff > 0.2) // Significant difference
            {
                var lowerGroup = acceptanceRates.MinBy(r => r.Rate);
                findings.Add(new CorrelationFinding
                {
                    Factor = groupName,
                    Condition = lowerGroup!.Group,
                    AcceptanceRate = lowerGroup.Rate,
                    SampleSize = grouped.First(g => g.Key == lowerGroup.Group).Count(),
                    Impact = maxDiff
                });
            }
        }

        return findings.OrderByDescending(f => f.Impact).ToList();
    }

    /// <summary>
    /// Gets recommendations for improving suggestion acceptance.
    /// </summary>
    public List<string> GetRecommendations()
    {
        var recommendations = new List<string>();
        var patternStats = _feedbackStore.GetAllPatternStatistics();
        var summary = _feedbackStore.GetSummary();

        // Check overall metrics
        if (summary.OverallReversionRate > 0.15)
        {
            recommendations.Add(
                $"High reversion rate ({summary.OverallReversionRate:P0}). Consider adding more validation before suggesting changes.");
        }

        if (summary.OverallApplicationRate < 0.4)
        {
            recommendations.Add(
                $"Low acceptance rate ({summary.OverallApplicationRate:P0}). Consider filtering out low-confidence suggestions.");
        }

        // Check individual patterns
        foreach (var (patternType, stats) in patternStats)
        {
            if (!HasSufficientData(stats)) continue;

            if (stats.ApplicationRate < HighRejectionThreshold)
            {
                recommendations.Add(
                    $"Pattern '{patternType}' is frequently rejected ({stats.ApplicationRate:P0} acceptance). " +
                    "Consider disabling or improving detection criteria.");
            }

            if (stats.ReversionRate > HighReversionThreshold)
            {
                recommendations.Add(
                    $"Pattern '{patternType}' is often reverted ({stats.ReversionRate:P0}). " +
                    "The suggested changes may introduce issues.");
            }
        }

        // Check correlations
        var correlations = FindRejectionCorrelations();
        foreach (var corr in correlations.Take(3))
        {
            recommendations.Add(
                $"Suggestions in '{corr.Condition}' contexts have {corr.AcceptanceRate:P0} acceptance rate. " +
                $"Consider adjusting confidence for {corr.Factor.ToLower()} code.");
        }

        return recommendations;
    }

    private IEnumerable<LearningInsight> AnalyzePattern(
        string patternType,
        PatternStatistics stats,
        IReadOnlyList<FeedbackRecord> allRecords)
    {
        var insights = new List<LearningInsight>();

        if (!HasSufficientData(stats))
        {
            insights.Add(new LearningInsight
            {
                Type = InsightType.InsufficientData,
                PatternType = patternType,
                Description = $"Pattern '{patternType}' has only {stats.AppliedCount + stats.RejectedCount} decisions. " +
                             $"Need at least {MinimumSamples} for reliable statistics.",
                Confidence = 1.0
            });
            return insights;
        }

        // High acceptance pattern
        if (stats.ApplicationRate >= HighAcceptanceThreshold)
        {
            insights.Add(new LearningInsight
            {
                Type = InsightType.HighAcceptancePattern,
                PatternType = patternType,
                Description = $"Pattern '{patternType}' has {stats.ApplicationRate:P0} acceptance rate. " +
                             "Users consistently find these suggestions valuable.",
                Recommendation = "Consider increasing confidence scores for this pattern.",
                Confidence = CalculateInsightConfidence(stats)
            });
        }

        // High rejection pattern
        if (stats.ApplicationRate <= HighRejectionThreshold)
        {
            insights.Add(new LearningInsight
            {
                Type = InsightType.HighRejectionPattern,
                PatternType = patternType,
                Description = $"Pattern '{patternType}' has only {stats.ApplicationRate:P0} acceptance rate. " +
                             "Users frequently reject these suggestions.",
                Recommendation = "Consider reviewing detection criteria or reducing confidence for this pattern.",
                Confidence = CalculateInsightConfidence(stats)
            });
        }

        // High reversion pattern
        if (stats.ReversionRate >= HighReversionThreshold)
        {
            insights.Add(new LearningInsight
            {
                Type = InsightType.HighReversionPattern,
                PatternType = patternType,
                Description = $"Pattern '{patternType}' has {stats.ReversionRate:P0} reversion rate. " +
                             "Applied changes are often undone.",
                Recommendation = "Investigate why users revert these changes. The suggestions may cause issues.",
                Confidence = CalculateInsightConfidence(stats)
            });
        }

        return insights;
    }

    private IEnumerable<LearningInsight> AnalyzeGlobalPatterns(
        IReadOnlyList<FeedbackRecord> records,
        IReadOnlyDictionary<string, PatternStatistics> patternStats)
    {
        var insights = new List<LearningInsight>();

        if (records.Count < MinimumSamples)
        {
            return insights;
        }

        // Check if confidence scores correlate with decisions
        var recordsWithConfidence = records
            .Where(r => r.ConfidenceScore.HasValue && r.Action != FeedbackAction.Skipped)
            .ToList();

        if (recordsWithConfidence.Count >= MinimumSamples)
        {
            var highConfidenceAcceptance = recordsWithConfidence
                .Where(r => r.ConfidenceScore >= 0.7)
                .Where(r => r.Action == FeedbackAction.Applied || r.Action == FeedbackAction.Rejected)
                .Select(r => r.Action == FeedbackAction.Applied ? 1.0 : 0.0)
                .DefaultIfEmpty(0.5)
                .Average();

            var lowConfidenceAcceptance = recordsWithConfidence
                .Where(r => r.ConfidenceScore < 0.5)
                .Where(r => r.Action == FeedbackAction.Applied || r.Action == FeedbackAction.Rejected)
                .Select(r => r.Action == FeedbackAction.Applied ? 1.0 : 0.0)
                .DefaultIfEmpty(0.5)
                .Average();

            // Check if confidence is well-calibrated
            if (highConfidenceAcceptance < 0.6 || lowConfidenceAcceptance > 0.5)
            {
                insights.Add(new LearningInsight
                {
                    Type = InsightType.ModelCalibrationNeeded,
                    Description = $"Confidence scores may need recalibration. " +
                                 $"High confidence suggestions have {highConfidenceAcceptance:P0} acceptance, " +
                                 $"low confidence have {lowConfidenceAcceptance:P0}.",
                    Recommendation = "Review confidence calculation weights based on learned patterns.",
                    Confidence = 0.8
                });
            }
        }

        return insights;
    }

    private bool HasSufficientData(PatternStatistics stats)
    {
        return (stats.AppliedCount + stats.RejectedCount) >= MinimumSamples;
    }

    private double CalculateInsightConfidence(PatternStatistics stats)
    {
        // Confidence increases with sample size, capped at 0.95
        var sampleSize = stats.AppliedCount + stats.RejectedCount;
        return Math.Min(0.95, 0.5 + (sampleSize / 100.0));
    }
}

/// <summary>
/// Represents a correlation found between a factor and acceptance rate.
/// </summary>
public record CorrelationFinding
{
    /// <summary>
    /// The factor being analyzed (e.g., "High Complexity").
    /// </summary>
    public required string Factor { get; init; }

    /// <summary>
    /// The condition within that factor (e.g., "complex").
    /// </summary>
    public required string Condition { get; init; }

    /// <summary>
    /// Acceptance rate for this condition.
    /// </summary>
    public double AcceptanceRate { get; init; }

    /// <summary>
    /// Number of samples in this group.
    /// </summary>
    public int SampleSize { get; init; }

    /// <summary>
    /// Difference from the baseline acceptance rate.
    /// </summary>
    public double Impact { get; init; }
}
