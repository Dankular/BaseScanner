using Microsoft.CodeAnalysis;
using BaseScanner.Analyzers.Migration.Models;
using BaseScanner.Analyzers.Migration.Detectors;
using System.Text;
using System.Text.Json;

namespace BaseScanner.Analyzers.Migration;

/// <summary>
/// Main coordinator for .NET migration analysis.
/// Orchestrates the analysis of deprecated APIs, platform-specific code,
/// compatibility checking, and migration planning.
/// </summary>
public class MigrationAssistant
{
    private readonly ApiMappingDatabase _mappingDatabase;
    private readonly DeprecatedApiDetector _deprecatedApiDetector;
    private readonly PlatformSpecificDetector _platformDetector;
    private readonly CompatibilityChecker _compatibilityChecker;
    private readonly MigrationPlanner _planner;

    public MigrationAssistant()
    {
        _mappingDatabase = new ApiMappingDatabase();
        _deprecatedApiDetector = new DeprecatedApiDetector(_mappingDatabase);
        _platformDetector = new PlatformSpecificDetector();
        _compatibilityChecker = new CompatibilityChecker(_mappingDatabase);
        _planner = new MigrationPlanner(_mappingDatabase);
    }

    /// <summary>
    /// Gets the API mapping database for direct queries.
    /// </summary>
    public ApiMappingDatabase MappingDatabase => _mappingDatabase;

    /// <summary>
    /// Performs a complete migration analysis on a project.
    /// </summary>
    public async Task<MigrationAnalysisResult> AnalyzeAsync(
        Project project,
        string targetFramework = "net8.0",
        bool generatePlan = true,
        IProgress<string>? progress = null)
    {
        progress?.Report("Starting migration analysis...");

        // Step 1: Detect deprecated API usage
        progress?.Report("Detecting deprecated API usage...");
        var deprecatedApis = await _deprecatedApiDetector.DetectInProjectAsync(project);

        // Step 2: Detect platform-specific code
        progress?.Report("Detecting platform-specific code...");
        var platformIssues = await _platformDetector.DetectInProjectAsync(project);

        // Step 3: Check compatibility
        progress?.Report("Checking framework compatibility...");
        var compatibility = await _compatibilityChecker.CheckCompatibilityAsync(project, targetFramework);

        // Step 4: Generate migration plan (optional)
        MigrationPlan? plan = null;
        if (generatePlan)
        {
            progress?.Report("Generating migration plan...");
            plan = await _planner.GeneratePlanAsync(project, DetectSourceFramework(project), targetFramework);
        }

        // Build summary
        var summary = BuildAnalysisSummary(deprecatedApis, platformIssues, compatibility);

        progress?.Report("Migration analysis complete.");

        return new MigrationAnalysisResult
        {
            DeprecatedApis = deprecatedApis,
            PlatformSpecificCode = platformIssues,
            Compatibility = compatibility,
            Plan = plan,
            Summary = summary,
            AnalyzedAt = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Analyzes a specific file for migration issues.
    /// </summary>
    public async Task<(List<DeprecatedApiUsage> DeprecatedApis, List<PlatformSpecificCode> PlatformIssues)> AnalyzeFileAsync(
        Document document)
    {
        var syntaxRoot = await document.GetSyntaxRootAsync();
        var semanticModel = await document.GetSemanticModelAsync();

        if (syntaxRoot == null || semanticModel == null)
        {
            return ([], []);
        }

        var deprecatedApis = await _deprecatedApiDetector.DetectAsync(document, semanticModel, syntaxRoot);
        var platformIssues = await _platformDetector.DetectAsync(document, semanticModel, syntaxRoot);

        return (deprecatedApis, platformIssues);
    }

    /// <summary>
    /// Gets a quick migration readiness assessment.
    /// </summary>
    public async Task<MigrationReadinessReport> GetReadinessReportAsync(
        Project project,
        string targetFramework = "net8.0")
    {
        var result = await AnalyzeAsync(project, targetFramework, generatePlan: false);

        var blockingApiCount = _deprecatedApiDetector.GetBlockingIssues(result.DeprecatedApis).Count;
        var blockingPlatformCount = PlatformSpecificDetector.GetBlockingIssues(result.PlatformSpecificCode).Count;
        var securityRiskCount = _deprecatedApiDetector.GetSecurityRisks(result.DeprecatedApis).Count;

        var totalBlocking = blockingApiCount + blockingPlatformCount;

        var readiness = (totalBlocking, result.DeprecatedApis.Count, result.PlatformSpecificCode.Count) switch
        {
            (0, < 10, < 5) => MigrationReadiness.Ready,
            (0, < 50, < 20) => MigrationReadiness.NeedsMinorWork,
            (< 5, < 100, _) => MigrationReadiness.NeedsMajorWork,
            _ => MigrationReadiness.NotRecommended
        };

        return new MigrationReadinessReport
        {
            ProjectName = project.Name,
            TargetFramework = targetFramework,
            Readiness = readiness,
            DeprecatedApiCount = result.DeprecatedApis.Count,
            PlatformSpecificCount = result.PlatformSpecificCode.Count,
            BlockingIssueCount = totalBlocking,
            SecurityRiskCount = securityRiskCount,
            CompatibilityScore = result.Compatibility?.Summary.CompatibilityScore ?? 0,
            TopIssues = GetTopIssues(result, 5),
            Recommendations = GetRecommendations(readiness, result)
        };
    }

    /// <summary>
    /// Generates a detailed migration report in markdown format.
    /// </summary>
    public async Task<string> GenerateReportAsync(
        Project project,
        string targetFramework = "net8.0",
        ReportFormat format = ReportFormat.Markdown)
    {
        var result = await AnalyzeAsync(project, targetFramework);

        return format switch
        {
            ReportFormat.Markdown => GenerateMarkdownReport(result),
            ReportFormat.Json => GenerateJsonReport(result),
            ReportFormat.Text => GenerateTextReport(result),
            _ => GenerateMarkdownReport(result)
        };
    }

    /// <summary>
    /// Checks if a specific API needs migration.
    /// </summary>
    public ApiMigrationInfo CheckApi(string api)
    {
        if (_mappingDatabase.TryGetMapping(api, out var mapping) && mapping != null)
        {
            return new ApiMigrationInfo
            {
                Api = api,
                NeedsMigration = true,
                Mapping = mapping,
                IsSecurityRisk = mapping.IsSecurityRisk,
                IsBlockingIssue = mapping.IsBlockingIssue
            };
        }

        return new ApiMigrationInfo
        {
            Api = api,
            NeedsMigration = false
        };
    }

    /// <summary>
    /// Gets all API mappings for a category.
    /// </summary>
    public IEnumerable<ApiMapping> GetMappingsForCategory(string category)
    {
        return _mappingDatabase.GetMappingsForCategory(category);
    }

    /// <summary>
    /// Gets all available categories.
    /// </summary>
    public IEnumerable<string> GetCategories()
    {
        return _mappingDatabase.GetCategories();
    }

    /// <summary>
    /// Gets mapping database statistics.
    /// </summary>
    public MappingDatabaseStatistics GetDatabaseStatistics()
    {
        return _mappingDatabase.GetStatistics();
    }

    private static string DetectSourceFramework(Project project)
    {
        // Try to detect from project properties
        // Default to net472 if cannot determine
        return "net472";
    }

    private MigrationAnalysisSummary BuildAnalysisSummary(
        List<DeprecatedApiUsage> deprecatedApis,
        List<PlatformSpecificCode> platformIssues,
        CompatibilityResult compatibility)
    {
        var blockingApis = _deprecatedApiDetector.GetBlockingIssues(deprecatedApis);
        var securityRisks = _deprecatedApiDetector.GetSecurityRisks(deprecatedApis);
        var blockingPlatform = PlatformSpecificDetector.GetBlockingIssues(platformIssues);

        var totalBlocking = blockingApis.Count + blockingPlatform.Count;

        var complexity = (totalBlocking, deprecatedApis.Count, platformIssues.Count) switch
        {
            (> 10, _, _) => MigrationComplexity.VeryHigh,
            (> 5, _, _) => MigrationComplexity.High,
            (_, > 100, _) => MigrationComplexity.High,
            (_, > 50, > 20) => MigrationComplexity.Medium,
            (_, > 20, _) => MigrationComplexity.Medium,
            _ => MigrationComplexity.Low
        };

        var readiness = (totalBlocking, complexity) switch
        {
            (0, MigrationComplexity.Low) => "Ready",
            (0, MigrationComplexity.Medium) => "NeedsWork",
            (< 5, _) => "MajorEffort",
            _ => "NotRecommended"
        };

        return new MigrationAnalysisSummary
        {
            TotalDeprecatedApiUsages = deprecatedApis.Count,
            TotalPlatformSpecificIssues = platformIssues.Count,
            SecurityRisks = securityRisks.Count,
            BlockingIssues = totalBlocking,
            OverallComplexity = complexity,
            MigrationReadiness = readiness,
            ApiUsagesByCategory = DeprecatedApiDetector.GroupByCategory(deprecatedApis)
                .ToDictionary(g => g.Key, g => g.Value.Count),
            PlatformIssuesByType = PlatformSpecificDetector.GroupByType(platformIssues)
                .ToDictionary(g => g.Key, g => g.Value.Count)
        };
    }

    private List<string> GetTopIssues(MigrationAnalysisResult result, int count)
    {
        var issues = new List<(string Issue, int Priority)>();

        // Add blocking API issues
        var blockingApis = _deprecatedApiDetector.GetBlockingIssues(result.DeprecatedApis);
        foreach (var group in blockingApis.GroupBy(a => a.Api).Take(count))
        {
            issues.Add(($"BLOCKING: {group.Key} ({group.Count()} usages) - {group.First().Mapping?.Reason ?? "Not available in target framework"}", 1));
        }

        // Add security risks
        var securityRisks = _deprecatedApiDetector.GetSecurityRisks(result.DeprecatedApis);
        foreach (var group in securityRisks.GroupBy(a => a.Api).Take(count))
        {
            issues.Add(($"SECURITY: {group.Key} ({group.Count()} usages) - {group.First().Mapping?.Reason ?? "Security risk"}", 2));
        }

        // Add platform-blocking issues
        var platformBlocking = PlatformSpecificDetector.GetBlockingIssues(result.PlatformSpecificCode);
        foreach (var group in platformBlocking.GroupBy(p => p.Type).Take(count))
        {
            issues.Add(($"PLATFORM: {group.Key} ({group.Count()} occurrences) - Not cross-platform", 3));
        }

        // Add high-frequency deprecated APIs
        var topDeprecated = result.DeprecatedApis
            .Where(a => a.Mapping != null && !a.Mapping.IsBlockingIssue && !a.Mapping.IsSecurityRisk)
            .GroupBy(a => a.Api)
            .OrderByDescending(g => g.Count())
            .Take(count);

        foreach (var group in topDeprecated)
        {
            issues.Add(($"DEPRECATED: {group.Key} ({group.Count()} usages)", 4));
        }

        return issues
            .OrderBy(i => i.Priority)
            .ThenByDescending(i => i.Issue.Contains("(") ? int.Parse(i.Issue.Split('(')[1].Split(' ')[0]) : 0)
            .Take(count)
            .Select(i => i.Issue)
            .ToList();
    }

    private List<string> GetRecommendations(MigrationReadiness readiness, MigrationAnalysisResult result)
    {
        var recommendations = new List<string>();

        switch (readiness)
        {
            case MigrationReadiness.Ready:
                recommendations.Add("Project is ready for migration with minimal changes.");
                recommendations.Add("Run the migration assistant's plan generator for detailed steps.");
                break;

            case MigrationReadiness.NeedsMinorWork:
                recommendations.Add("Project needs some API updates before migration.");
                recommendations.Add("Start by addressing deprecated API usage.");
                recommendations.Add("Review platform-specific code for cross-platform compatibility.");
                break;

            case MigrationReadiness.NeedsMajorWork:
                recommendations.Add("Project requires significant work before migration.");
                recommendations.Add("Address blocking issues first before other changes.");
                recommendations.Add("Consider a phased migration approach.");
                recommendations.Add("Allocate adequate testing time for API changes.");
                break;

            case MigrationReadiness.NotRecommended:
                recommendations.Add("Migration is not recommended at this time.");
                recommendations.Add("Too many blocking issues need resolution first.");
                recommendations.Add("Consider refactoring incrementally before attempting migration.");
                recommendations.Add("Consult with team about migration timeline and resources.");
                break;
        }

        // Add specific recommendations based on findings
        var securityRisks = _deprecatedApiDetector.GetSecurityRisks(result.DeprecatedApis);
        if (securityRisks.Any())
        {
            recommendations.Add($"PRIORITY: Address {securityRisks.Count} security-risk APIs (e.g., BinaryFormatter) regardless of migration.");
        }

        var comIssues = result.PlatformSpecificCode.Where(p => p.Type == "COM");
        if (comIssues.Any())
        {
            recommendations.Add("COM interop detected - evaluate if COM dependencies can be replaced with managed alternatives.");
        }

        return recommendations;
    }

    private string GenerateMarkdownReport(MigrationAnalysisResult result)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# .NET Migration Analysis Report");
        sb.AppendLine();
        sb.AppendLine($"**Generated:** {result.AnalyzedAt:yyyy-MM-dd HH:mm:ss} UTC");
        if (result.Plan != null)
        {
            sb.AppendLine($"**Project:** {result.Plan.ProjectName}");
            sb.AppendLine($"**Target Framework:** {result.Plan.TargetFramework}");
        }
        sb.AppendLine();

        // Summary
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine($"- **Migration Readiness:** {result.Summary.MigrationReadiness}");
        sb.AppendLine($"- **Overall Complexity:** {result.Summary.OverallComplexity}");
        sb.AppendLine($"- **Deprecated API Usages:** {result.Summary.TotalDeprecatedApiUsages}");
        sb.AppendLine($"- **Platform-Specific Issues:** {result.Summary.TotalPlatformSpecificIssues}");
        sb.AppendLine($"- **Blocking Issues:** {result.Summary.BlockingIssues}");
        sb.AppendLine($"- **Security Risks:** {result.Summary.SecurityRisks}");
        sb.AppendLine();

        if (result.Compatibility != null)
        {
            sb.AppendLine($"- **Compatibility Score:** {result.Compatibility.Summary.CompatibilityScore:P0}");
            sb.AppendLine();
        }

        // Blocking Issues
        if (result.Plan?.BlockingIssues.Any() == true)
        {
            sb.AppendLine("## Blocking Issues");
            sb.AppendLine();
            sb.AppendLine("These issues must be resolved before migration:");
            sb.AppendLine();

            foreach (var issue in result.Plan.BlockingIssues)
            {
                sb.AppendLine($"### {issue.Type}: {issue.Cause}");
                sb.AppendLine();
                sb.AppendLine($"**Description:** {issue.Description}");
                sb.AppendLine();
                sb.AppendLine($"**Resolution:** {issue.Resolution}");
                sb.AppendLine();
                sb.AppendLine($"**Estimated Effort:** {issue.EstimatedHours:F1} hours");
                sb.AppendLine();

                if (issue.AffectedFiles.Any())
                {
                    sb.AppendLine("**Affected Files:**");
                    foreach (var file in issue.AffectedFiles.Take(5))
                    {
                        sb.AppendLine($"- `{Path.GetFileName(file)}`");
                    }
                    if (issue.AffectedFiles.Count > 5)
                    {
                        sb.AppendLine($"- ... and {issue.AffectedFiles.Count - 5} more");
                    }
                    sb.AppendLine();
                }
            }
        }

        // Deprecated APIs by Category
        if (result.Summary.ApiUsagesByCategory.Any())
        {
            sb.AppendLine("## Deprecated API Usage by Category");
            sb.AppendLine();
            sb.AppendLine("| Category | Count |");
            sb.AppendLine("|----------|-------|");

            foreach (var (category, count) in result.Summary.ApiUsagesByCategory.OrderByDescending(c => c.Value))
            {
                sb.AppendLine($"| {category} | {count} |");
            }
            sb.AppendLine();
        }

        // Top Deprecated APIs
        if (result.DeprecatedApis.Any())
        {
            sb.AppendLine("## Top Deprecated APIs");
            sb.AppendLine();

            var topApis = result.DeprecatedApis
                .GroupBy(a => a.Api)
                .OrderByDescending(g => g.Count())
                .Take(10);

            sb.AppendLine("| API | Usages | Category | New API |");
            sb.AppendLine("|-----|--------|----------|---------|");

            foreach (var group in topApis)
            {
                var first = group.First();
                var newApi = first.Mapping?.NewApi ?? "Manual migration required";
                var category = first.Mapping?.Category ?? "Unknown";
                sb.AppendLine($"| `{ShortenApi(group.Key)}` | {group.Count()} | {category} | `{ShortenApi(newApi)}` |");
            }
            sb.AppendLine();
        }

        // Platform-Specific Issues
        if (result.Summary.PlatformIssuesByType.Any())
        {
            sb.AppendLine("## Platform-Specific Code");
            sb.AppendLine();
            sb.AppendLine("| Type | Count | Impact |");
            sb.AppendLine("|------|-------|--------|");

            foreach (var (type, count) in result.Summary.PlatformIssuesByType.OrderByDescending(t => t.Value))
            {
                var impact = result.PlatformSpecificCode
                    .Where(p => p.Type == type)
                    .Select(p => p.Impact)
                    .GroupBy(i => i)
                    .OrderByDescending(g => g.Count())
                    .First().Key;

                sb.AppendLine($"| {type} | {count} | {impact} |");
            }
            sb.AppendLine();
        }

        // Migration Plan
        if (result.Plan != null)
        {
            sb.AppendLine("## Migration Plan");
            sb.AppendLine();
            sb.AppendLine($"**Total Estimated Effort:** {result.Plan.TotalEstimatedHours:F1} hours");
            sb.AppendLine();
            sb.AppendLine($"**Estimate Confidence:** {result.Plan.EstimateConfidence}");
            sb.AppendLine();

            var phases = result.Plan.Steps.GroupBy(s => s.Phase);

            foreach (var phase in phases)
            {
                sb.AppendLine($"### Phase: {phase.Key}");
                sb.AppendLine();

                foreach (var step in phase)
                {
                    sb.AppendLine($"#### {step.Order}. {step.Title}");
                    sb.AppendLine();
                    sb.AppendLine($"- **Estimated Hours:** {step.EstimatedHours:F1}");
                    sb.AppendLine($"- **Risk Level:** {step.RiskLevel}");
                    sb.AppendLine($"- **Can Be Automated:** {(step.CanBeAutomated ? "Yes" : "No")}");
                    sb.AppendLine();
                    sb.AppendLine(step.Description);
                    sb.AppendLine();

                    if (step.Actions.Any())
                    {
                        sb.AppendLine("**Actions:**");
                        foreach (var action in step.Actions)
                        {
                            sb.AppendLine($"- {action}");
                        }
                        sb.AppendLine();
                    }
                }
            }

            // Risks
            if (result.Plan.Risks.TechnicalRisks.Any() || result.Plan.Risks.BusinessRisks.Any())
            {
                sb.AppendLine("## Risk Assessment");
                sb.AppendLine();
                sb.AppendLine($"**Overall Risk:** {result.Plan.Risks.OverallRisk}");
                sb.AppendLine();

                if (result.Plan.Risks.TechnicalRisks.Any())
                {
                    sb.AppendLine("### Technical Risks");
                    sb.AppendLine();
                    foreach (var risk in result.Plan.Risks.TechnicalRisks)
                    {
                        sb.AppendLine($"- **{risk.Description}**");
                        sb.AppendLine($"  - Likelihood: {risk.Likelihood}, Impact: {risk.Impact}");
                        sb.AppendLine($"  - Mitigation: {risk.Mitigation}");
                    }
                    sb.AppendLine();
                }

                if (result.Plan.Risks.MitigationStrategies.Any())
                {
                    sb.AppendLine("### Mitigation Strategies");
                    sb.AppendLine();
                    foreach (var strategy in result.Plan.Risks.MitigationStrategies)
                    {
                        sb.AppendLine($"- {strategy}");
                    }
                    sb.AppendLine();
                }
            }
        }

        return sb.ToString();
    }

    private string GenerateJsonReport(MigrationAnalysisResult result)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };

        return JsonSerializer.Serialize(result, options);
    }

    private string GenerateTextReport(MigrationAnalysisResult result)
    {
        var sb = new StringBuilder();

        sb.AppendLine(".NET MIGRATION ANALYSIS REPORT");
        sb.AppendLine(new string('=', 60));
        sb.AppendLine();

        sb.AppendLine($"Generated: {result.AnalyzedAt:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine();

        sb.AppendLine("SUMMARY");
        sb.AppendLine(new string('-', 40));
        sb.AppendLine($"Migration Readiness:      {result.Summary.MigrationReadiness}");
        sb.AppendLine($"Overall Complexity:       {result.Summary.OverallComplexity}");
        sb.AppendLine($"Deprecated API Usages:    {result.Summary.TotalDeprecatedApiUsages}");
        sb.AppendLine($"Platform-Specific Issues: {result.Summary.TotalPlatformSpecificIssues}");
        sb.AppendLine($"Blocking Issues:          {result.Summary.BlockingIssues}");
        sb.AppendLine($"Security Risks:           {result.Summary.SecurityRisks}");
        sb.AppendLine();

        if (result.Plan != null)
        {
            sb.AppendLine("MIGRATION EFFORT");
            sb.AppendLine(new string('-', 40));
            sb.AppendLine($"Estimated Hours: {result.Plan.TotalEstimatedHours:F1}");
            sb.AppendLine($"Confidence:      {result.Plan.EstimateConfidence}");
            sb.AppendLine($"Risk Level:      {result.Plan.Risks.OverallRisk}");
            sb.AppendLine();

            sb.AppendLine(_planner.GetPlanSummary(result.Plan));
        }

        return sb.ToString();
    }

    private static string ShortenApi(string api)
    {
        if (api.Length <= 40) return api;

        // Try to shorten by removing common prefixes
        var prefixes = new[] { "System.", "Microsoft.", "System.Collections.Generic." };
        foreach (var prefix in prefixes)
        {
            if (api.StartsWith(prefix) && api.Length - prefix.Length >= 10)
            {
                return "..." + api.Substring(prefix.Length);
            }
        }

        return api.Substring(0, 37) + "...";
    }
}

/// <summary>
/// Migration readiness levels.
/// </summary>
public enum MigrationReadiness
{
    /// <summary>Project is ready for migration with minimal changes</summary>
    Ready,
    /// <summary>Project needs some work but migration is straightforward</summary>
    NeedsMinorWork,
    /// <summary>Project requires significant work before migration</summary>
    NeedsMajorWork,
    /// <summary>Migration is not recommended without major refactoring first</summary>
    NotRecommended
}

/// <summary>
/// Report output formats.
/// </summary>
public enum ReportFormat
{
    Markdown,
    Json,
    Text
}

/// <summary>
/// Quick readiness report.
/// </summary>
public record MigrationReadinessReport
{
    public required string ProjectName { get; init; }
    public required string TargetFramework { get; init; }
    public required MigrationReadiness Readiness { get; init; }
    public int DeprecatedApiCount { get; init; }
    public int PlatformSpecificCount { get; init; }
    public int BlockingIssueCount { get; init; }
    public int SecurityRiskCount { get; init; }
    public double CompatibilityScore { get; init; }
    public List<string> TopIssues { get; init; } = [];
    public List<string> Recommendations { get; init; } = [];
}

/// <summary>
/// Information about a specific API's migration status.
/// </summary>
public record ApiMigrationInfo
{
    public required string Api { get; init; }
    public bool NeedsMigration { get; init; }
    public ApiMapping? Mapping { get; init; }
    public bool IsSecurityRisk { get; init; }
    public bool IsBlockingIssue { get; init; }
}
