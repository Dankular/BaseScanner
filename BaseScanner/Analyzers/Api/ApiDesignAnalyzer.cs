using Microsoft.CodeAnalysis;
using BaseScanner.Analyzers.Api.Models;

namespace BaseScanner.Analyzers.Api;

/// <summary>
/// Main orchestrator for API design analysis.
/// Coordinates consistency, breaking change, REST, and versioning analyzers.
/// </summary>
public class ApiDesignAnalyzer
{
    private readonly ConsistencyAnalyzer _consistencyAnalyzer;
    private readonly BreakingChangeDetector _breakingChangeDetector;
    private readonly RestAnalyzer _restAnalyzer;
    private readonly VersioningAnalyzer _versioningAnalyzer;

    public ApiDesignAnalyzer()
    {
        _consistencyAnalyzer = new ConsistencyAnalyzer();
        _breakingChangeDetector = new BreakingChangeDetector();
        _restAnalyzer = new RestAnalyzer();
        _versioningAnalyzer = new VersioningAnalyzer();
    }

    /// <summary>
    /// Analyze a project for API design issues.
    /// </summary>
    public async Task<ApiDesignResult> AnalyzeAsync(Project project)
    {
        // Run all analyzers in parallel
        var consistencyTask = _consistencyAnalyzer.AnalyzeAsync(project);
        var breakingChangeTask = _breakingChangeDetector.AnalyzeAsync(project);
        var restTask = _restAnalyzer.AnalyzeAsync(project);
        var versioningTask = _versioningAnalyzer.AnalyzeAsync(project);

        await Task.WhenAll(consistencyTask, breakingChangeTask, restTask, versioningTask);

        var consistencyIssues = await consistencyTask;
        var breakingChanges = await breakingChangeTask;
        var restIssues = await restTask;
        var versioningIssues = await versioningTask;

        // Combine all issues into a unified result
        var allIssues = new List<ApiDesignIssue>();

        // Add consistency issues
        allIssues.AddRange(consistencyIssues);

        // Convert breaking changes to ApiDesignIssue
        allIssues.AddRange(breakingChanges.Select(bc => new ApiDesignIssue
        {
            Category = "BreakingChange",
            IssueType = bc.ChangeType.ToString(),
            Severity = bc.Severity,
            Message = bc.Description,
            FilePath = bc.FilePath,
            Line = bc.Line,
            AffectedElement = bc.AffectedMember,
            Recommendation = bc.Mitigation,
            ImpactScore = GetBreakingChangeImpact(bc.ChangeType)
        }));

        // Convert REST issues to ApiDesignIssue
        allIssues.AddRange(restIssues.Select(ri => new ApiDesignIssue
        {
            Category = "REST",
            IssueType = ri.IssueType.ToString(),
            Severity = ri.Severity,
            Message = ri.Message,
            FilePath = ri.FilePath,
            Line = ri.Line,
            AffectedElement = $"{ri.Controller}.{ri.Action} ({ri.HttpMethod} {ri.Route})",
            Recommendation = ri.Recommendation,
            ImpactScore = GetRestIssueImpact(ri.IssueType)
        }));

        // Convert versioning issues to ApiDesignIssue
        allIssues.AddRange(versioningIssues.Select(vi => new ApiDesignIssue
        {
            Category = "Versioning",
            IssueType = vi.IssueType.ToString(),
            Severity = vi.Severity,
            Message = vi.Message,
            FilePath = vi.FilePath,
            Line = vi.Line,
            AffectedElement = vi.AffectedElement,
            Recommendation = vi.Recommendation,
            ImpactScore = GetVersioningIssueImpact(vi.IssueType)
        }));

        // Sort all issues by severity and then by file/line
        allIssues = allIssues
            .OrderByDescending(i => GetSeverityOrder(i.Severity))
            .ThenByDescending(i => i.ImpactScore)
            .ThenBy(i => i.FilePath)
            .ThenBy(i => i.Line)
            .ToList();

        return new ApiDesignResult
        {
            Issues = allIssues,
            BreakingChanges = breakingChanges,
            RestIssues = restIssues,
            VersioningIssues = versioningIssues,
            Summary = BuildSummary(allIssues, breakingChanges, restIssues, versioningIssues)
        };
    }

    /// <summary>
    /// Analyze only for consistency issues (faster analysis).
    /// </summary>
    public async Task<List<ApiDesignIssue>> AnalyzeConsistencyAsync(Project project)
    {
        return await _consistencyAnalyzer.AnalyzeAsync(project);
    }

    /// <summary>
    /// Analyze only for breaking change risks.
    /// </summary>
    public async Task<List<BreakingChange>> AnalyzeBreakingChangesAsync(Project project)
    {
        return await _breakingChangeDetector.AnalyzeAsync(project);
    }

    /// <summary>
    /// Analyze only REST API design.
    /// </summary>
    public async Task<List<RestEndpointIssue>> AnalyzeRestAsync(Project project)
    {
        return await _restAnalyzer.AnalyzeAsync(project);
    }

    /// <summary>
    /// Analyze only API versioning.
    /// </summary>
    public async Task<List<VersioningIssue>> AnalyzeVersioningAsync(Project project)
    {
        return await _versioningAnalyzer.AnalyzeAsync(project);
    }

    private ApiDesignSummary BuildSummary(
        List<ApiDesignIssue> allIssues,
        List<BreakingChange> breakingChanges,
        List<RestEndpointIssue> restIssues,
        List<VersioningIssue> versioningIssues)
    {
        var issuesByCategory = allIssues
            .GroupBy(i => i.Category)
            .ToDictionary(g => g.Key, g => g.Count());

        var issuesByType = allIssues
            .GroupBy(i => i.IssueType)
            .ToDictionary(g => g.Key, g => g.Count());

        var criticalCount = allIssues.Count(i => i.Severity == "Critical");
        var highCount = allIssues.Count(i => i.Severity == "High");
        var mediumCount = allIssues.Count(i => i.Severity == "Medium");
        var lowCount = allIssues.Count(i => i.Severity == "Low");

        // Calculate API health score (0-100)
        var healthScore = CalculateHealthScore(allIssues, breakingChanges);

        return new ApiDesignSummary
        {
            TotalIssues = allIssues.Count,
            ConsistencyIssues = allIssues.Count(i => i.Category == "Consistency"),
            BreakingChangeRisks = breakingChanges.Count,
            RestIssues = restIssues.Count,
            VersioningIssues = versioningIssues.Count,
            CriticalCount = criticalCount,
            HighCount = highCount,
            MediumCount = mediumCount,
            LowCount = lowCount,
            IssuesByCategory = issuesByCategory,
            IssuesByType = issuesByType,
            ApiHealthScore = healthScore
        };
    }

    private double CalculateHealthScore(List<ApiDesignIssue> issues, List<BreakingChange> breakingChanges)
    {
        // Start with perfect score
        double score = 100.0;

        // Deduct points based on issue severity
        foreach (var issue in issues)
        {
            switch (issue.Severity)
            {
                case "Critical":
                    score -= 10.0;
                    break;
                case "High":
                    score -= 5.0;
                    break;
                case "Medium":
                    score -= 2.0;
                    break;
                case "Low":
                    score -= 0.5;
                    break;
            }
        }

        // Extra deduction for high-impact breaking changes
        foreach (var bc in breakingChanges.Where(b => b.Severity == "Critical"))
        {
            score -= 5.0;
        }

        // Ensure score doesn't go below 0
        return Math.Max(0, Math.Round(score, 1));
    }

    private int GetBreakingChangeImpact(BreakingChangeType changeType)
    {
        return changeType switch
        {
            BreakingChangeType.RemovedPublicMember => 10,
            BreakingChangeType.ChangedSignature => 9,
            BreakingChangeType.ChangedReturnType => 9,
            BreakingChangeType.RemovedInterface => 10,
            BreakingChangeType.ChangedBaseClass => 8,
            BreakingChangeType.RemovedOptionalParameter => 6,
            BreakingChangeType.AddedRequiredParameter => 8,
            BreakingChangeType.ChangedException => 5,
            BreakingChangeType.SealedClass => 6,
            BreakingChangeType.RemovedVirtual => 7,
            BreakingChangeType.ChangedAccessibility => 8,
            BreakingChangeType.RemovedOverload => 7,
            _ => 5
        };
    }

    private int GetRestIssueImpact(RestIssueType issueType)
    {
        return issueType switch
        {
            RestIssueType.VerbMismatch => 8,
            RestIssueType.InconsistentRoute => 6,
            RestIssueType.MissingResponseType => 4,
            RestIssueType.InappropriateStatusCode => 5,
            RestIssueType.MissingAuthorization => 9,
            RestIssueType.InconsistentNaming => 4,
            RestIssueType.MissingVersioning => 5,
            RestIssueType.InvalidRouteParameter => 7,
            RestIssueType.MixedRoutingStyles => 4,
            RestIssueType.MissingContentType => 3,
            _ => 5
        };
    }

    private int GetVersioningIssueImpact(VersioningIssueType issueType)
    {
        return issueType switch
        {
            VersioningIssueType.MissingVersioning => 6,
            VersioningIssueType.InconsistentVersioning => 5,
            VersioningIssueType.DeprecatedWithoutReplacement => 7,
            VersioningIssueType.MissingDeprecation => 4,
            VersioningIssueType.VersionInUrl => 2,
            VersioningIssueType.MultipleVersionAttributes => 3,
            VersioningIssueType.InvalidVersionFormat => 3,
            _ => 4
        };
    }

    private int GetSeverityOrder(string severity) => severity switch
    {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0
    };
}
