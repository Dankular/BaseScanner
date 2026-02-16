using Microsoft.CodeAnalysis;
using BaseScanner.Analyzers.Debt.Models;
using BaseScanner.Services;

namespace BaseScanner.Analyzers.Debt;

/// <summary>
/// Main coordinator for technical debt analysis.
/// Aggregates issues from all analyzers, calculates debt, ranks by payoff,
/// and tracks trends over time.
/// </summary>
public class TechnicalDebtScorer
{
    private readonly DebtCalculator _calculator;
    private readonly PriorityRanker _ranker;
    private readonly DebtTrendAnalyzer _trendAnalyzer;

    public TechnicalDebtScorer()
    {
        _calculator = new DebtCalculator();
        _ranker = new PriorityRanker();
        _trendAnalyzer = new DebtTrendAnalyzer();
    }

    /// <summary>
    /// Perform complete technical debt analysis on a project.
    /// </summary>
    /// <param name="project">The Roslyn project to analyze</param>
    /// <param name="analysisResult">Pre-computed analysis result from AnalysisService</param>
    /// <returns>Complete technical debt analysis result</returns>
    public async Task<TechnicalDebtResult> AnalyzeAsync(Project project, AnalysisResult analysisResult)
    {
        var projectDirectory = Path.GetDirectoryName(project.FilePath) ?? "";

        // Step 1: Calculate debt items from all analyzer results
        var debtItems = _calculator.CalculateDebt(analysisResult, projectDirectory);

        // Step 2: Rank and categorize items
        var ranking = _ranker.RankItems(debtItems);

        // Step 3: Analyze trends over git history
        var trend = await _trendAnalyzer.AnalyzeTrendAsync(projectDirectory, debtItems);

        // Step 4: Build final result
        return new TechnicalDebtResult
        {
            Rating = ranking.Rating,
            Score = ranking.Score,
            TotalDebtMinutes = ranking.TotalDebtMinutes,
            DebtInterestPerWeek = ranking.DebtInterestPerWeek,
            Summary = ranking.Summary,
            Items = ranking.AllItems.Take(100).ToList(),
            QuickWins = ranking.QuickWins,
            MajorProjects = ranking.MajorProjects,
            LowPriority = ranking.LowPriority,
            Trend = trend,
            FileHotspots = ranking.FileHotspots
        };
    }

    /// <summary>
    /// Run a full analysis including all analyzer passes.
    /// Use this when you don't have a pre-computed AnalysisResult.
    /// </summary>
    public async Task<TechnicalDebtResult> AnalyzeFullAsync(Project project)
    {
        var projectPath = project.FilePath ?? "";
        var projectDirectory = Path.GetDirectoryName(projectPath) ?? "";

        // Run all analyzers
        var analysisService = new AnalysisService();
        var analysisResult = await analysisService.AnalyzeAsync(projectPath, AnalysisOptions.All);

        return await AnalyzeAsync(project, analysisResult);
    }

    /// <summary>
    /// Generate a human-readable report of the technical debt analysis.
    /// </summary>
    public string GenerateReport(TechnicalDebtResult result)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("=".PadRight(70, '='));
        sb.AppendLine("  TECHNICAL DEBT ANALYSIS REPORT");
        sb.AppendLine("=".PadRight(70, '='));
        sb.AppendLine();

        // Overall rating
        var ratingEmoji = result.Rating switch
        {
            "A" => "[EXCELLENT]",
            "B" => "[GOOD]",
            "C" => "[FAIR]",
            "D" => "[POOR]",
            _ => "[CRITICAL]"
        };

        sb.AppendLine($"  DEBT RATING: {result.Rating} {ratingEmoji}");
        sb.AppendLine($"  DEBT SCORE:  {result.Score:F1}/100 (lower is better)");
        sb.AppendLine();

        // Summary metrics
        var hours = result.TotalDebtMinutes / 60.0;
        var days = hours / 8.0;
        sb.AppendLine($"  TOTAL DEBT:     {result.TotalDebtMinutes:N0} minutes ({hours:F1} hours / {days:F1} days)");
        sb.AppendLine($"  WEEKLY COST:    {result.DebtInterestPerWeek:N0} minutes/week if not addressed");
        sb.AppendLine($"  TOTAL ITEMS:    {result.Summary.TotalItems}");
        sb.AppendLine();

        // Severity breakdown
        sb.AppendLine("  SEVERITY BREAKDOWN:");
        sb.AppendLine($"    Critical: {result.Summary.CriticalItems}");
        sb.AppendLine($"    High:     {result.Summary.HighItems}");
        sb.AppendLine($"    Medium:   {result.Summary.MediumItems}");
        sb.AppendLine($"    Low:      {result.Summary.LowItems}");
        sb.AppendLine();

        // Category breakdown
        if (result.Summary.DebtByCategory.Count > 0)
        {
            sb.AppendLine("  DEBT BY CATEGORY:");
            foreach (var (category, minutes) in result.Summary.DebtByCategory.OrderByDescending(kv => kv.Value))
            {
                var count = result.Summary.ItemsByCategory.GetValueOrDefault(category, 0);
                sb.AppendLine($"    {category,-20} {minutes,6} min ({count} items)");
            }
            sb.AppendLine();
        }

        // Critical items (always show)
        var criticalItems = result.Items.Where(i => i.Severity == "Critical").ToList();
        if (criticalItems.Count > 0)
        {
            sb.AppendLine("  CRITICAL ISSUES (Must Fix):");
            foreach (var item in criticalItems.Take(5))
            {
                sb.AppendLine($"    [{item.Category}] {item.Description}");
                sb.AppendLine($"      Location: {item.FilePath}:{item.Line}");
                sb.AppendLine($"      Fix Time: {item.TimeToFixMinutes} min");
            }
            sb.AppendLine();
        }

        // Quick wins
        if (result.QuickWins.Count > 0)
        {
            sb.AppendLine("  QUICK WINS (High Payoff, Low Effort):");
            foreach (var item in result.QuickWins.Take(5))
            {
                sb.AppendLine($"    [{item.Type}] {TruncateDescription(item.Description, 60)}");
                sb.AppendLine($"      Payoff: {item.PayoffScore:F1} | Fix Time: {item.TimeToFixMinutes} min");
            }
            sb.AppendLine();
        }

        // Major projects
        if (result.MajorProjects.Count > 0)
        {
            sb.AppendLine("  MAJOR PROJECTS (Plan for Sprints):");
            foreach (var item in result.MajorProjects.Take(3))
            {
                sb.AppendLine($"    [{item.Type}] {TruncateDescription(item.Description, 60)}");
                sb.AppendLine($"      Fix Time: {item.TimeToFixMinutes} min | Impact: {item.ImpactScore:F0}");
            }
            sb.AppendLine();
        }

        // File hotspots
        if (result.FileHotspots.Count > 0)
        {
            sb.AppendLine("  FILE HOTSPOTS (Most Debt):");
            foreach (var file in result.FileHotspots.Take(5))
            {
                var fileName = Path.GetFileName(file.FilePath);
                sb.AppendLine($"    {fileName,-35} {file.TotalDebtMinutes,5} min ({file.ItemCount} items)");
            }
            sb.AppendLine();
        }

        // Trend
        if (result.Trend.GitAvailable)
        {
            var trendIcon = result.Trend.Direction switch
            {
                TrendDirection.Improving => "[IMPROVING]",
                TrendDirection.Worsening => "[WORSENING]",
                TrendDirection.Stable => "[STABLE]",
                _ => "[UNKNOWN]"
            };

            sb.AppendLine($"  TREND: {result.Trend.Direction} {trendIcon}");
            if (result.Trend.PercentageChange != 0)
            {
                var sign = result.Trend.PercentageChange > 0 ? "+" : "";
                sb.AppendLine($"    Change: {sign}{result.Trend.PercentageChange:F1}% over analysis period");
            }

            if (result.Trend.ImprovingFiles.Count > 0)
            {
                sb.AppendLine($"    Improving: {string.Join(", ", result.Trend.ImprovingFiles.Take(3).Select(Path.GetFileName))}");
            }
            if (result.Trend.WorseningFiles.Count > 0)
            {
                sb.AppendLine($"    Worsening: {string.Join(", ", result.Trend.WorseningFiles.Take(3).Select(Path.GetFileName))}");
            }
            sb.AppendLine();
        }

        // Recommendations
        sb.AppendLine("  RECOMMENDATIONS:");
        if (result.Summary.CriticalItems > 0)
        {
            sb.AppendLine("    1. Address critical security issues immediately");
        }
        if (result.QuickWins.Count > 0)
        {
            sb.AppendLine($"    2. Tackle quick wins first - {result.QuickWins.Count} items with high ROI");
        }
        if (result.MajorProjects.Count > 0)
        {
            sb.AppendLine($"    3. Plan {result.MajorProjects.Count} major refactoring projects");
        }
        if (result.Trend.Direction == TrendDirection.Worsening)
        {
            sb.AppendLine("    4. Debt is increasing - prioritize paying down before adding features");
        }

        sb.AppendLine();
        sb.AppendLine($"  Generated: {result.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine("=".PadRight(70, '='));

        return sb.ToString();
    }

    /// <summary>
    /// Get a summary suitable for JSON serialization.
    /// </summary>
    public TechnicalDebtResultDto ToDto(TechnicalDebtResult result, string projectDirectory)
    {
        return new TechnicalDebtResultDto
        {
            Rating = result.Rating,
            Score = result.Score,
            TotalDebtMinutes = result.TotalDebtMinutes,
            TotalDebtHours = result.TotalDebtMinutes / 60.0,
            DebtInterestPerWeek = result.DebtInterestPerWeek,
            Summary = new DebtSummaryDto
            {
                TotalItems = result.Summary.TotalItems,
                CriticalItems = result.Summary.CriticalItems,
                HighItems = result.Summary.HighItems,
                MediumItems = result.Summary.MediumItems,
                LowItems = result.Summary.LowItems,
                DebtByCategory = result.Summary.DebtByCategory,
                ItemsByCategory = result.Summary.ItemsByCategory
            },
            QuickWins = result.QuickWins.Take(10).Select(i => ToItemDto(i, projectDirectory)).ToList(),
            MajorProjects = result.MajorProjects.Take(10).Select(i => ToItemDto(i, projectDirectory)).ToList(),
            LowPriority = result.LowPriority.Take(20).Select(i => ToItemDto(i, projectDirectory)).ToList(),
            FileHotspots = result.FileHotspots.Select(f => new FileDebtDto
            {
                FilePath = f.FilePath,
                TotalDebtMinutes = f.TotalDebtMinutes,
                ItemCount = f.ItemCount,
                CriticalCount = f.CriticalCount,
                HighCount = f.HighCount,
                TopIssueTypes = f.TopIssueTypes
            }).ToList(),
            Trend = new DebtTrendDto
            {
                Direction = result.Trend.Direction.ToString(),
                PercentageChange = result.Trend.PercentageChange,
                ImprovingFiles = result.Trend.ImprovingFiles,
                WorseningFiles = result.Trend.WorseningFiles,
                Projections = result.Trend.Projections.Select(p => new TrendProjectionDto
                {
                    MonthsFromNow = p.MonthsFromNow,
                    ProjectedDebtMinutes = p.ProjectedDebtMinutes,
                    ProjectedScore = p.ProjectedScore
                }).ToList()
            },
            GeneratedAt = result.GeneratedAt
        };
    }

    private DebtItemDto ToItemDto(DebtItem item, string projectDirectory)
    {
        return new DebtItemDto
        {
            Id = item.Id,
            Category = item.Category,
            Type = item.Type,
            Severity = item.Severity,
            Description = item.Description,
            FilePath = item.FilePath,
            Line = item.Line,
            TimeToFixMinutes = item.TimeToFixMinutes,
            InterestPerWeek = item.InterestPerWeek,
            ImpactScore = item.ImpactScore,
            EffortScore = item.EffortScore,
            PayoffScore = item.PayoffScore,
            Priority = item.Priority.ToString(),
            Suggestion = item.Suggestion,
            CweId = item.CweId,
            Source = item.Source
        };
    }

    private string TruncateDescription(string desc, int maxLength)
    {
        if (string.IsNullOrEmpty(desc)) return "";
        return desc.Length <= maxLength ? desc : desc[..maxLength] + "...";
    }
}

// DTO types for JSON serialization

public record TechnicalDebtResultDto
{
    public required string Rating { get; init; }
    public required double Score { get; init; }
    public required int TotalDebtMinutes { get; init; }
    public required double TotalDebtHours { get; init; }
    public required int DebtInterestPerWeek { get; init; }
    public required DebtSummaryDto Summary { get; init; }
    public List<DebtItemDto> QuickWins { get; init; } = [];
    public List<DebtItemDto> MajorProjects { get; init; } = [];
    public List<DebtItemDto> LowPriority { get; init; } = [];
    public List<FileDebtDto> FileHotspots { get; init; } = [];
    public required DebtTrendDto Trend { get; init; }
    public DateTime GeneratedAt { get; init; }
}

public record DebtSummaryDto
{
    public int TotalItems { get; init; }
    public int CriticalItems { get; init; }
    public int HighItems { get; init; }
    public int MediumItems { get; init; }
    public int LowItems { get; init; }
    public Dictionary<string, int> DebtByCategory { get; init; } = [];
    public Dictionary<string, int> ItemsByCategory { get; init; } = [];
}

public record DebtItemDto
{
    public required string Id { get; init; }
    public required string Category { get; init; }
    public required string Type { get; init; }
    public required string Severity { get; init; }
    public required string Description { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required int TimeToFixMinutes { get; init; }
    public required int InterestPerWeek { get; init; }
    public required double ImpactScore { get; init; }
    public required double EffortScore { get; init; }
    public required double PayoffScore { get; init; }
    public required string Priority { get; init; }
    public string? Suggestion { get; init; }
    public string? CweId { get; init; }
    public required string Source { get; init; }
}

public record FileDebtDto
{
    public required string FilePath { get; init; }
    public required int TotalDebtMinutes { get; init; }
    public required int ItemCount { get; init; }
    public required int CriticalCount { get; init; }
    public required int HighCount { get; init; }
    public List<string> TopIssueTypes { get; init; } = [];
}

public record DebtTrendDto
{
    public required string Direction { get; init; }
    public double PercentageChange { get; init; }
    public List<string> ImprovingFiles { get; init; } = [];
    public List<string> WorseningFiles { get; init; } = [];
    public List<TrendProjectionDto> Projections { get; init; } = [];
}

public record TrendProjectionDto
{
    public required int MonthsFromNow { get; init; }
    public required int ProjectedDebtMinutes { get; init; }
    public required double ProjectedScore { get; init; }
}
