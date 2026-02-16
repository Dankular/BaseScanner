using BaseScanner.Analyzers.Debt.Models;

namespace BaseScanner.Analyzers.Debt;

/// <summary>
/// Ranks debt items by payoff (Impact * Frequency / Effort) and categorizes them.
/// </summary>
public class PriorityRanker
{
    // Thresholds for classification
    private const double QuickWinPayoffThreshold = 2.0;
    private const double QuickWinEffortMax = 35.0;
    private const double MajorProjectImpactMin = 60.0;
    private const double MajorProjectEffortMin = 50.0;

    /// <summary>
    /// Rank and categorize debt items.
    /// </summary>
    public RankingResult RankItems(List<DebtItem> items)
    {
        // Calculate overall statistics
        var totalItems = items.Count;
        var totalDebt = items.Sum(i => i.TimeToFixMinutes);
        var totalInterest = items.Sum(i => i.InterestPerWeek);

        // Re-rank all items based on payoff
        var rankedItems = items
            .Select(i => RecalculateItem(i))
            .OrderByDescending(i => GetRankingScore(i))
            .ToList();

        // Categorize into buckets
        var quickWins = new List<DebtItem>();
        var majorProjects = new List<DebtItem>();
        var lowPriority = new List<DebtItem>();
        var critical = new List<DebtItem>();

        foreach (var item in rankedItems)
        {
            switch (item.Priority)
            {
                case DebtPriority.Critical:
                    critical.Add(item);
                    break;
                case DebtPriority.QuickWin:
                    quickWins.Add(item);
                    break;
                case DebtPriority.MajorProject:
                    majorProjects.Add(item);
                    break;
                default:
                    lowPriority.Add(item);
                    break;
            }
        }

        // Calculate rating
        var rating = CalculateRating(rankedItems, totalDebt, totalInterest);
        var score = CalculateScore(rankedItems);

        // Build summary
        var summary = BuildSummary(rankedItems);

        // Calculate file hotspots
        var fileHotspots = CalculateFileHotspots(rankedItems);

        return new RankingResult
        {
            Rating = rating,
            Score = score,
            TotalDebtMinutes = totalDebt,
            DebtInterestPerWeek = totalInterest,
            AllItems = rankedItems,
            QuickWins = quickWins.Take(20).ToList(),
            MajorProjects = majorProjects.Take(15).ToList(),
            LowPriority = lowPriority.Take(30).ToList(),
            Critical = critical,
            Summary = summary,
            FileHotspots = fileHotspots
        };
    }

    private DebtItem RecalculateItem(DebtItem item)
    {
        // Recalculate payoff with updated formula
        var payoff = CalculatePayoff(item);

        // Reclassify priority based on updated metrics
        var priority = ClassifyPriority(item, payoff);

        return item with
        {
            PayoffScore = payoff,
            Priority = priority
        };
    }

    private double CalculatePayoff(DebtItem item)
    {
        // Payoff formula: (Impact * Frequency * SeverityMultiplier) / (Effort + 1)
        var severityMultiplier = item.Severity switch
        {
            "Critical" => 3.0,
            "High" => 2.0,
            "Medium" => 1.0,
            "Low" => 0.5,
            _ => 1.0
        };

        var basePayoff = (item.ImpactScore * item.Frequency * severityMultiplier) / (item.EffortScore + 1);

        // Boost for items with high interest (ongoing cost)
        var interestBoost = item.InterestPerWeek > 10 ? 1.2 : item.InterestPerWeek > 5 ? 1.1 : 1.0;

        return basePayoff * interestBoost;
    }

    private double GetRankingScore(DebtItem item)
    {
        // Primary ranking by priority tier, then by payoff
        var priorityBoost = item.Priority switch
        {
            DebtPriority.Critical => 10000,
            DebtPriority.QuickWin => 1000,
            DebtPriority.MajorProject => 100,
            _ => 0
        };

        return priorityBoost + item.PayoffScore;
    }

    private DebtPriority ClassifyPriority(DebtItem item, double payoff)
    {
        // Critical security issues remain critical
        if (item.Category == DebtCategory.Security && item.Severity == "Critical")
            return DebtPriority.Critical;

        // High severity security issues are also critical
        if (item.Category == DebtCategory.Security && item.Severity == "High")
            return DebtPriority.Critical;

        // Quick wins: high payoff AND low effort
        if (payoff >= QuickWinPayoffThreshold && item.EffortScore <= QuickWinEffortMax)
            return DebtPriority.QuickWin;

        // Also quick wins: very high frequency items (even if moderate effort)
        if (item.Frequency >= 5 && item.EffortScore <= 40)
            return DebtPriority.QuickWin;

        // Major projects: high impact but requires significant effort
        if (item.ImpactScore >= MajorProjectImpactMin && item.EffortScore >= MajorProjectEffortMin)
            return DebtPriority.MajorProject;

        // Also major projects: god classes and circular dependencies
        if (item.Type is DebtType.GodClass or DebtType.CircularDependency)
            return DebtPriority.MajorProject;

        // Default to low priority
        return DebtPriority.LowPriority;
    }

    private string CalculateRating(List<DebtItem> items, int totalDebt, int totalInterest)
    {
        if (items.Count == 0) return "A";

        // Calculate weighted score based on severity distribution and debt ratio
        var criticalCount = items.Count(i => i.Severity == "Critical");
        var highCount = items.Count(i => i.Severity == "High");
        var mediumCount = items.Count(i => i.Severity == "Medium");

        // Calculate debt ratio (minutes per item, normalized)
        var avgDebtPerItem = totalDebt / (double)items.Count;

        // Security weight
        var securityIssues = items.Count(i => i.Category == DebtCategory.Security);

        // Scoring factors
        var criticalPenalty = criticalCount * 20;
        var highPenalty = highCount * 10;
        var mediumPenalty = mediumCount * 3;
        var securityPenalty = securityIssues * 5;
        var debtPenalty = Math.Min(avgDebtPerItem / 10, 30);

        var totalPenalty = criticalPenalty + highPenalty + mediumPenalty + securityPenalty + debtPenalty;

        // Rating thresholds
        return totalPenalty switch
        {
            <= 10 => "A",    // Excellent - minimal debt
            <= 30 => "B",    // Good - manageable debt
            <= 60 => "C",    // Fair - noticeable debt
            <= 100 => "D",   // Poor - significant debt
            _ => "E"         // Critical - severe debt
        };
    }

    private double CalculateScore(List<DebtItem> items)
    {
        if (items.Count == 0) return 0;

        // Score is 0-100, lower is better
        // Based on weighted severity and volume

        var severityScore = items.Sum(i => i.Severity switch
        {
            "Critical" => 10.0,
            "High" => 5.0,
            "Medium" => 2.0,
            "Low" => 0.5,
            _ => 1.0
        });

        // Normalize by item count and cap at 100
        var normalizedScore = Math.Min((severityScore / items.Count) * 20, 100);

        // Add volume factor (more items = higher score)
        var volumeFactor = Math.Min(items.Count / 50.0 * 20, 30);

        return Math.Min(normalizedScore + volumeFactor, 100);
    }

    private DebtSummary BuildSummary(List<DebtItem> items)
    {
        var debtByCategory = items
            .GroupBy(i => i.Category)
            .ToDictionary(g => g.Key, g => g.Sum(i => i.TimeToFixMinutes));

        var itemsByCategory = items
            .GroupBy(i => i.Category)
            .ToDictionary(g => g.Key, g => g.Count());

        var debtBySeverity = items
            .GroupBy(i => i.Severity)
            .ToDictionary(g => g.Key, g => g.Sum(i => i.TimeToFixMinutes));

        return new DebtSummary
        {
            TotalItems = items.Count,
            CriticalItems = items.Count(i => i.Severity == "Critical"),
            HighItems = items.Count(i => i.Severity == "High"),
            MediumItems = items.Count(i => i.Severity == "Medium"),
            LowItems = items.Count(i => i.Severity == "Low"),
            DebtByCategory = debtByCategory,
            ItemsByCategory = itemsByCategory,
            DebtBySeverity = debtBySeverity
        };
    }

    private List<FileDebt> CalculateFileHotspots(List<DebtItem> items)
    {
        return items
            .Where(i => !string.IsNullOrEmpty(i.FilePath))
            .GroupBy(i => i.FilePath)
            .Select(g => new FileDebt
            {
                FilePath = g.Key,
                TotalDebtMinutes = g.Sum(i => i.TimeToFixMinutes),
                ItemCount = g.Count(),
                CriticalCount = g.Count(i => i.Severity == "Critical"),
                HighCount = g.Count(i => i.Severity == "High"),
                AveragePayoff = g.Average(i => i.PayoffScore),
                TopIssueTypes = g
                    .GroupBy(i => i.Type)
                    .OrderByDescending(t => t.Count())
                    .Take(3)
                    .Select(t => t.Key)
                    .ToList()
            })
            .OrderByDescending(f => f.CriticalCount)
            .ThenByDescending(f => f.HighCount)
            .ThenByDescending(f => f.TotalDebtMinutes)
            .Take(15)
            .ToList();
    }
}

/// <summary>
/// Result of priority ranking.
/// </summary>
public record RankingResult
{
    public required string Rating { get; init; }
    public required double Score { get; init; }
    public required int TotalDebtMinutes { get; init; }
    public required int DebtInterestPerWeek { get; init; }
    public required List<DebtItem> AllItems { get; init; }
    public required List<DebtItem> QuickWins { get; init; }
    public required List<DebtItem> MajorProjects { get; init; }
    public required List<DebtItem> LowPriority { get; init; }
    public required List<DebtItem> Critical { get; init; }
    public required DebtSummary Summary { get; init; }
    public required List<FileDebt> FileHotspots { get; init; }
}
