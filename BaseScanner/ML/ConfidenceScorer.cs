using Microsoft.CodeAnalysis;
using BaseScanner.Analyzers;
using BaseScanner.ML.Models;

namespace BaseScanner.ML;

/// <summary>
/// Calculates confidence scores for code suggestions using heuristics and learned patterns.
/// </summary>
public class ConfidenceScorer
{
    private readonly FeedbackStore _feedbackStore;
    private readonly PatternLearner _patternLearner;
    private readonly FeatureExtractor _featureExtractor;

    /// <summary>
    /// Creates a new confidence scorer for the specified project directory.
    /// </summary>
    public ConfidenceScorer(string projectDirectory)
    {
        _feedbackStore = new FeedbackStore(projectDirectory);
        _patternLearner = new PatternLearner(_feedbackStore);
        _featureExtractor = new FeatureExtractor();
    }

    /// <summary>
    /// Creates a confidence scorer with explicit dependencies (for testing).
    /// </summary>
    public ConfidenceScorer(
        FeedbackStore feedbackStore,
        PatternLearner patternLearner,
        FeatureExtractor featureExtractor)
    {
        _feedbackStore = feedbackStore;
        _patternLearner = patternLearner;
        _featureExtractor = featureExtractor;
    }

    /// <summary>
    /// Calculates confidence score for a single optimization opportunity.
    /// </summary>
    public async Task<ConfidenceResult> ScoreAsync(
        OptimizationOpportunity opportunity,
        Document? document = null,
        SemanticModel? semanticModel = null,
        SyntaxNode? root = null)
    {
        // Extract features
        var features = await _featureExtractor.ExtractFeaturesAsync(
            opportunity, document, semanticModel, root);

        // Get historical statistics
        var stats = _feedbackStore.GetPatternStatistics(opportunity.Type);
        features = _featureExtractor.UpdateWithHistory(features, stats);

        // Calculate score
        return CalculateScore(features);
    }

    /// <summary>
    /// Calculates confidence scores for multiple optimization opportunities.
    /// </summary>
    public async Task<List<ConfidenceResult>> ScoreAsync(
        IEnumerable<OptimizationOpportunity> opportunities,
        Project? project = null)
    {
        var oppList = opportunities.ToList();
        var features = await _featureExtractor.ExtractFeaturesAsync(oppList, project);

        // Update features with historical data
        var updatedFeatures = features.Select(f =>
        {
            var stats = _feedbackStore.GetPatternStatistics(f.PatternType);
            return _featureExtractor.UpdateWithHistory(f, stats);
        }).ToList();

        return updatedFeatures.Select(CalculateScore).ToList();
    }

    /// <summary>
    /// Calculates confidence score for pre-extracted features.
    /// </summary>
    public ConfidenceResult Score(SuggestionFeatures features)
    {
        // Update with historical data if not already done
        var stats = _feedbackStore.GetPatternStatistics(features.PatternType);
        var updatedFeatures = _featureExtractor.UpdateWithHistory(features, stats);

        return CalculateScore(updatedFeatures);
    }

    /// <summary>
    /// Records user feedback when a suggestion is applied.
    /// </summary>
    public void RecordApplied(SuggestionFeatures features, double? confidenceScore = null)
    {
        _feedbackStore.RecordApplied(features, confidenceScore);
    }

    /// <summary>
    /// Records user feedback when a suggestion is rejected.
    /// </summary>
    public void RecordRejected(SuggestionFeatures features, double? confidenceScore = null)
    {
        _feedbackStore.RecordRejected(features, confidenceScore);
    }

    /// <summary>
    /// Records user feedback when a suggestion is reverted.
    /// </summary>
    public void RecordReverted(SuggestionFeatures features, double? confidenceScore = null)
    {
        _feedbackStore.RecordReverted(features, confidenceScore);
    }

    /// <summary>
    /// Records feedback by suggestion ID (simpler API).
    /// </summary>
    public void RecordFeedback(
        string suggestionId,
        string patternType,
        string filePath,
        FeedbackAction action,
        double? confidenceScore = null)
    {
        _feedbackStore.RecordFeedback(suggestionId, patternType, filePath, action, confidenceScore);
    }

    /// <summary>
    /// Runs learning analysis and returns insights.
    /// </summary>
    public LearningResult Learn()
    {
        return _patternLearner.Learn();
    }

    /// <summary>
    /// Gets recommendations for improving suggestion quality.
    /// </summary>
    public List<string> GetRecommendations()
    {
        return _patternLearner.GetRecommendations();
    }

    /// <summary>
    /// Gets the feedback store for direct access.
    /// </summary>
    public FeedbackStore FeedbackStore => _feedbackStore;

    /// <summary>
    /// Gets the pattern learner for direct access.
    /// </summary>
    public PatternLearner PatternLearner => _patternLearner;

    /// <summary>
    /// Gets the feature extractor for direct access.
    /// </summary>
    public FeatureExtractor FeatureExtractor => _featureExtractor;

    /// <summary>
    /// Core confidence calculation using heuristics and learned patterns.
    /// </summary>
    private ConfidenceResult CalculateScore(SuggestionFeatures features)
    {
        var positiveFactors = new List<string>();
        var negativeFactors = new List<string>();
        var recommendations = new List<string>();

        // Start with base score
        double score = 0.5;

        // Pattern frequency in project (familiarity)
        if (features.PatternFrequencyInProject > 5)
        {
            score += 0.1;
            positiveFactors.Add($"Common pattern in project ({features.PatternFrequencyInProject} occurrences)");
        }
        else if (features.PatternFrequencyInProject == 1)
        {
            negativeFactors.Add("Unique pattern in project - may be intentional");
        }

        // Historical application rate
        if (features.WasAppliedBefore > 0.6)
        {
            score += 0.15;
            positiveFactors.Add($"Pattern is often accepted ({features.WasAppliedBefore:P0} historical acceptance)");
        }
        else if (features.WasAppliedBefore < 0.4 && features.WasAppliedBefore > 0.0)
        {
            score -= 0.1;
            negativeFactors.Add($"Pattern is often rejected ({features.WasAppliedBefore:P0} historical acceptance)");
        }

        // Test code (typically more forgiving)
        if (!features.IsInTestCode)
        {
            score += 0.05;
            positiveFactors.Add("Production code - higher value from optimization");
        }
        else
        {
            negativeFactors.Add("Test code - clarity may be more important than optimization");
        }

        // Generated code (should not be modified)
        if (features.IsInGeneratedCode)
        {
            score -= 0.25;
            negativeFactors.Add("Generated code - changes may be overwritten");
            recommendations.Add("Consider fixing the generation template instead");
        }

        // Method complexity (high complexity = more risky changes)
        if (features.MethodComplexity > 20)
        {
            score -= 0.1;
            negativeFactors.Add($"High method complexity ({features.MethodComplexity}) - careful review needed");
            recommendations.Add("Consider simplifying the method before applying optimizations");
        }
        else if (features.MethodComplexity <= 5)
        {
            score += 0.05;
            positiveFactors.Add("Low complexity - safe to modify");
        }

        // Historical reversion rate
        if (features.WasRevertedBefore > 0.1)
        {
            score -= 0.2;
            negativeFactors.Add($"Pattern is often reverted ({features.WasRevertedBefore:P0} reversion rate)");
            recommendations.Add("Investigate why previous applications were reverted");
        }

        // Related comment (suggests intentional code)
        if (features.HasRelatedComment)
        {
            score -= 0.1;
            negativeFactors.Add("Code has explanatory comment - may be intentionally written this way");
            recommendations.Add("Review the comment before applying changes");
        }

        // Deep nesting (harder to reason about)
        if (features.NestingDepth > 3)
        {
            score -= 0.05;
            negativeFactors.Add($"Deeply nested code (depth: {features.NestingDepth}) - complex context");
        }

        // Long method (might indicate code smell, but also more value from optimization)
        if (features.MethodLength > 100)
        {
            negativeFactors.Add($"Very long method ({features.MethodLength} lines) - consider refactoring first");
            recommendations.Add("Method is very long - consider breaking it down");
        }
        else if (features.MethodLength > 50)
        {
            positiveFactors.Add("Long method could benefit from optimization");
        }

        // Apply learned weight modifier
        var weightModifier = _patternLearner.GetPatternWeightModifier(features.PatternType);
        if (Math.Abs(weightModifier - 1.0) > 0.1)
        {
            var adjustedScore = score * weightModifier;
            if (weightModifier > 1.0)
            {
                positiveFactors.Add($"Learned pattern weight boosts confidence (+{(weightModifier - 1) * 100:F0}%)");
            }
            else
            {
                negativeFactors.Add($"Learned pattern weight reduces confidence ({(1 - weightModifier) * 100:F0}%)");
            }
            score = adjustedScore;
        }

        // Clamp final score
        score = Math.Clamp(score, 0.0, 1.0);

        // Add general recommendations based on score
        if (score < 0.4)
        {
            recommendations.Add("Low confidence - manual review strongly recommended");
        }
        else if (score >= 0.8)
        {
            recommendations.Add("High confidence - safe to apply");
        }

        return new ConfidenceResult
        {
            SuggestionId = features.SuggestionId,
            Score = score,
            PositiveFactors = positiveFactors,
            NegativeFactors = negativeFactors,
            Recommendations = recommendations
        };
    }
}

/// <summary>
/// Extension methods for confidence scoring integration.
/// </summary>
public static class ConfidenceScorerExtensions
{
    /// <summary>
    /// Enhances optimization opportunities with confidence scores.
    /// </summary>
    public static async Task<List<ScoredOpportunity>> WithConfidenceScoresAsync(
        this IEnumerable<OptimizationOpportunity> opportunities,
        ConfidenceScorer scorer,
        Project? project = null)
    {
        var oppList = opportunities.ToList();
        var scores = await scorer.ScoreAsync(oppList, project);

        return oppList.Zip(scores, (opp, score) => new ScoredOpportunity
        {
            Opportunity = opp,
            Confidence = score
        }).ToList();
    }

    /// <summary>
    /// Filters opportunities by minimum confidence level.
    /// </summary>
    public static IEnumerable<ScoredOpportunity> WithMinimumConfidence(
        this IEnumerable<ScoredOpportunity> scored,
        ConfidenceLevel minimumLevel)
    {
        return scored.Where(s => s.Confidence.Level >= minimumLevel);
    }

    /// <summary>
    /// Orders opportunities by confidence score (highest first).
    /// </summary>
    public static IEnumerable<ScoredOpportunity> OrderByConfidence(
        this IEnumerable<ScoredOpportunity> scored)
    {
        return scored.OrderByDescending(s => s.Confidence.Score);
    }
}

/// <summary>
/// An optimization opportunity paired with its confidence score.
/// </summary>
public record ScoredOpportunity
{
    /// <summary>
    /// The optimization opportunity.
    /// </summary>
    public required OptimizationOpportunity Opportunity { get; init; }

    /// <summary>
    /// Confidence score for this opportunity.
    /// </summary>
    public required ConfidenceResult Confidence { get; init; }
}
