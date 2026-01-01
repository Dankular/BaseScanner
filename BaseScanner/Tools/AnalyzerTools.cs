using System.ComponentModel;
using System.Text.Json;
using ModelContextProtocol.Server;
using BaseScanner.Services;
using BaseScanner.Analyzers.Security;
using BaseScanner.Analysis;
using BaseScanner.Transformers;

namespace BaseScanner.Tools;

[McpServerToolType]
public static class AnalyzerTools
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    [McpServerTool]
    [Description("Analyze a C# project for code quality issues, refactoring opportunities, architecture concerns, safety issues, and optimization opportunities using Roslyn compiler analysis.")]
    public static async Task<string> AnalyzeCsharpProject(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Comma-separated list of analyses to run. Options: unused_files, deep, sentiment, perf, exceptions, resources, deps, magic, git, refactor, arch, safety, optimize, all. Default: all")]
        string analyses = "all")
    {
        try
        {
            var options = AnalysisOptions.Parse(analyses);
            var service = new AnalysisService();
            var result = await service.AnalyzeAsync(projectPath, options);
            return JsonSerializer.Serialize(result, JsonOptions);
        }
        catch (FileNotFoundException ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
        catch (ArgumentException ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = $"Analysis failed: {ex.Message}" }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Get a quick summary of C# project health without detailed analysis. Faster than full analysis.")]
    public static async Task<string> QuickProjectScan(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath)
    {
        try
        {
            var options = new AnalysisOptions
            {
                UnusedFiles = true,
                PerformanceAnalysis = true,
                ExceptionAnalysis = true,
                RefactoringAnalysis = true
            };

            var service = new AnalysisService();
            var result = await service.AnalyzeAsync(projectPath, options);

            // Return just the summary for quick insights
            var quickSummary = new
            {
                projectPath = result.ProjectPath,
                summary = result.Summary,
                unusedFiles = result.UnusedFiles,
                topIssues = new
                {
                    criticalPerformanceIssues = result.PerformanceIssues?
                        .Where(i => i.Severity == "Critical")
                        .Take(5)
                        .Select(i => new { i.FilePath, i.Line, i.Message })
                        .ToList(),
                    godClasses = result.Refactoring?.GodClasses
                        .Take(5)
                        .Select(g => new { g.FilePath, g.ClassName, g.MethodCount, g.LCOM })
                        .ToList(),
                    longMethods = result.Refactoring?.LongMethods
                        .Take(5)
                        .Select(m => new { m.FilePath, m.ClassName, m.MethodName, m.LineCount, m.Complexity })
                        .ToList()
                }
            };

            return JsonSerializer.Serialize(quickSummary, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("List available analysis types and their descriptions.")]
    public static string ListAnalysisTypes()
    {
        var analysisTypes = new[]
        {
            new { name = "unused_files", description = "Find .cs files not included in project compilation" },
            new { name = "deep", description = "Usage counting, deprecated code detection, dead code analysis" },
            new { name = "sentiment", description = "Code quality scoring, complexity metrics, duplicate detection" },
            new { name = "perf", description = "Async issues, performance anti-patterns (async void, blocking calls)" },
            new { name = "exceptions", description = "Empty catch blocks, swallowed exceptions, lost stack traces" },
            new { name = "resources", description = "IDisposable leaks, missing using statements, event handler leaks" },
            new { name = "deps", description = "Circular dependencies, high coupling metrics" },
            new { name = "magic", description = "Magic numbers and strings that should be constants" },
            new { name = "git", description = "Git history analysis, file churn, hotspots, stale code" },
            new { name = "refactor", description = "Long methods, god classes, feature envy, parameter smells" },
            new { name = "arch", description = "Public API surface, call graph, inheritance depth, interface segregation" },
            new { name = "safety", description = "Null safety issues, immutability opportunities, logging coverage" },
            new { name = "optimize", description = "Code optimization opportunities with generated refactored code suggestions" },
            new { name = "all", description = "Run all analysis types" }
        };

        return JsonSerializer.Serialize(new { analysisTypes }, JsonOptions);
    }

    [McpServerTool]
    [Description("Analyze C# code for optimization opportunities and generate refactored code suggestions with semantic safety guarantees.")]
    public static async Task<string> AnalyzeOptimizations(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Category filter: performance, readability, modernization, all. Default: all")]
        string category = "all",
        [Description("Minimum confidence level: high, medium, low. Default: medium")]
        string minConfidence = "medium")
    {
        try
        {
            var options = new AnalysisOptions { OptimizationAnalysis = true };
            var service = new AnalysisService();
            var result = await service.AnalyzeAsync(projectPath, options);

            if (result.Optimizations == null)
            {
                return JsonSerializer.Serialize(new { message = "No optimization opportunities found" }, JsonOptions);
            }

            // Filter by category
            var opportunities = result.Optimizations.Opportunities.AsEnumerable();

            if (category != "all")
            {
                opportunities = opportunities.Where(o =>
                    o.Category.Equals(category, StringComparison.OrdinalIgnoreCase));
            }

            // Filter by confidence
            var confidenceLevel = minConfidence.ToLowerInvariant() switch
            {
                "high" => new[] { "High" },
                "medium" => new[] { "High", "Medium" },
                _ => new[] { "High", "Medium", "Low" }
            };
            opportunities = opportunities.Where(o => confidenceLevel.Contains(o.Confidence));

            var filtered = new
            {
                summary = result.Optimizations.Summary,
                opportunities = opportunities.ToList()
            };

            return JsonSerializer.Serialize(filtered, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Analyze C# code for security vulnerabilities including injection flaws, hardcoded secrets, weak cryptography, and authentication issues. Returns CWE references and remediation guidance.")]
    public static async Task<string> AnalyzeSecurity(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Minimum severity to report: critical, high, medium, low, all. Default: all")]
        string severity = "all")
    {
        try
        {
            var options = new AnalysisOptions { SecurityAnalysis = true };
            var service = new AnalysisService();
            var result = await service.AnalyzeAsync(projectPath, options);

            if (result.Security == null)
            {
                return JsonSerializer.Serialize(new { message = "No security vulnerabilities found" }, JsonOptions);
            }

            // Filter by severity
            var vulnerabilities = result.Security.Vulnerabilities.AsEnumerable();

            if (severity != "all")
            {
                var severityOrder = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
                {
                    ["critical"] = 4,
                    ["high"] = 3,
                    ["medium"] = 2,
                    ["low"] = 1
                };

                if (severityOrder.TryGetValue(severity, out var minLevel))
                {
                    vulnerabilities = vulnerabilities.Where(v =>
                        severityOrder.TryGetValue(v.Severity, out var level) && level >= minLevel);
                }
            }

            var filtered = new
            {
                summary = new
                {
                    result.Security.TotalVulnerabilities,
                    result.Security.CriticalCount,
                    result.Security.HighCount,
                    result.Security.MediumCount,
                    result.Security.LowCount,
                    result.Security.VulnerabilitiesByType,
                    result.Security.VulnerabilitiesByCwe
                },
                vulnerabilities = vulnerabilities.ToList()
            };

            return JsonSerializer.Serialize(filtered, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Get a comprehensive project health dashboard with metrics including health score, complexity, maintainability index, technical debt, and hotspots.")]
    public static async Task<string> GetProjectDashboard(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath)
    {
        try
        {
            var options = new AnalysisOptions { DashboardAnalysis = true };
            var service = new AnalysisService();
            var result = await service.AnalyzeAsync(projectPath, options);

            if (result.Metrics == null)
            {
                return JsonSerializer.Serialize(new { error = "Unable to generate metrics dashboard" }, JsonOptions);
            }

            var dashboard = new
            {
                projectPath = result.ProjectPath,
                healthScore = result.Metrics.HealthScore,
                metrics = new
                {
                    result.Metrics.TotalFiles,
                    result.Metrics.TotalLines,
                    result.Metrics.TotalMethods,
                    result.Metrics.TotalClasses,
                    result.Metrics.AverageCyclomaticComplexity,
                    result.Metrics.MaxCyclomaticComplexity,
                    result.Metrics.MethodsAboveComplexityThreshold,
                    result.Metrics.MaintainabilityIndex,
                    technicalDebtHours = result.Metrics.TechnicalDebtMinutes / 60.0
                },
                issuesSummary = new
                {
                    result.Metrics.IssuesByCategory,
                    result.Metrics.IssuesBySeverity
                },
                hotspots = result.Metrics.Hotspots.Take(10).ToList()
            };

            return JsonSerializer.Serialize(dashboard, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Preview code transformations without applying them. Shows what changes would be made for optimization opportunities.")]
    public static async Task<string> PreviewTransformations(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Category filter: performance, readability, modernization, all. Default: all")]
        string category = "all",
        [Description("Minimum confidence level: high, medium, low. Default: high")]
        string minConfidence = "high",
        [Description("Maximum number of transformations to preview. Default: 20")]
        int maxTransformations = 20)
    {
        try
        {
            var filter = new TransformationFilter
            {
                Categories = category == "all" ? [] : [category],
                MinConfidence = minConfidence,
                MaxTransformations = maxTransformations
            };

            var service = new TransformationService();
            var preview = await service.PreviewAsync(projectPath, filter);

            return JsonSerializer.Serialize(new
            {
                preview.TotalOpportunities,
                preview.FilteredCount,
                transformations = preview.Transformations.Select(t => new
                {
                    t.FilePath,
                    t.StartLine,
                    t.EndLine,
                    t.Category,
                    t.Type,
                    t.Description,
                    t.CurrentCode,
                    t.SuggestedCode,
                    t.Confidence,
                    t.IsSemanticallySafe
                }).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Apply code transformations to optimize the codebase. Creates a backup before applying changes that can be rolled back.")]
    public static async Task<string> ApplyTransformations(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Category filter: performance, readability, modernization, all. Default: all")]
        string category = "all",
        [Description("Minimum confidence level: high, medium, low. Default: high")]
        string minConfidence = "high",
        [Description("Whether to create a backup before applying. Default: true")]
        bool createBackup = true,
        [Description("Maximum number of transformations to apply. Default: 50")]
        int maxTransformations = 50)
    {
        try
        {
            var filter = new TransformationFilter
            {
                Categories = category == "all" ? [] : [category],
                MinConfidence = minConfidence,
                MaxTransformations = maxTransformations
            };

            var options = new TransformationOptions
            {
                CreateBackup = createBackup,
                ValidateAfterTransform = true,
                StopOnFirstError = false
            };

            var service = new TransformationService();
            var result = await service.ApplyAsync(projectPath, filter, options);

            return JsonSerializer.Serialize(new
            {
                result.Success,
                result.TransformationsApplied,
                result.TransformationsFailed,
                result.FilesModified,
                result.BackupId,
                errors = result.Errors,
                appliedTransformations = result.AppliedTransformations.Select(t => new
                {
                    t.FilePath,
                    t.Type,
                    t.Description
                }).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Rollback previously applied transformations by restoring from backup.")]
    public static async Task<string> RollbackTransformations(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Specific backup ID to restore. If not provided, restores the most recent backup.")]
        string? backupId = null)
    {
        try
        {
            var service = new TransformationService();
            var result = await service.RollbackAsync(projectPath, backupId);

            return JsonSerializer.Serialize(new
            {
                result.Success,
                result.BackupId,
                result.FilesRestored,
                result.Message
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("List available transformation backups that can be used for rollback.")]
    public static async Task<string> ListTransformationBackups(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath)
    {
        try
        {
            var backupService = new BackupService(projectPath);
            var backups = await backupService.ListBackupsAsync();

            return JsonSerializer.Serialize(new
            {
                backups = backups.Select(b => new
                {
                    b.BackupId,
                    b.Timestamp,
                    b.FileCount,
                    b.Description
                }).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Analyze taint flow from untrusted sources to security-sensitive sinks. Helps identify potential injection vulnerabilities.")]
    public static async Task<string> AnalyzeTaintFlow(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Source type filter: user_input, environment, file, network, database, all. Default: all")]
        string sourceType = "all")
    {
        try
        {
            var taintTracker = new TaintTracker();
            var config = TaintConfiguration.Default;

            // Filter sources if specified
            if (sourceType != "all")
            {
                config = config with
                {
                    Sources = config.Sources
                        .Where(s => s.Category.Equals(sourceType, StringComparison.OrdinalIgnoreCase))
                        .ToList()
                };
            }

            var flows = await taintTracker.TrackAsync(projectPath, config);

            var result = new
            {
                totalFlows = flows.Count,
                unsanitizedFlows = flows.Count(f => !f.IsSanitized),
                sanitizedFlows = flows.Count(f => f.IsSanitized),
                flowsBySeverity = flows
                    .GroupBy(f => f.Severity)
                    .ToDictionary(g => g.Key, g => g.Count()),
                flows = flows.Select(f => new
                {
                    f.SourceType,
                    f.SourceLocation,
                    f.SinkType,
                    f.SinkLocation,
                    f.Severity,
                    f.IsSanitized,
                    f.SanitizerLocation,
                    path = f.DataFlowPath
                }).ToList()
            };

            return JsonSerializer.Serialize(result, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Analyze project trends over time using git history. Shows metric changes, regressions, and hotspots.")]
    public static async Task<string> AnalyzeTrends(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Number of recent commits to analyze. Default: 10")]
        int commitCount = 10)
    {
        try
        {
            var trendAnalyzer = new TrendAnalyzer(projectPath);
            var gitTrends = await trendAnalyzer.AnalyzeGitTrendsAsync(commitCount);
            var regressions = await trendAnalyzer.DetectRegressionsAsync();

            var result = new
            {
                gitAnalysis = new
                {
                    gitTrends.AnalyzedCommits,
                    gitTrends.TotalFilesChanged,
                    gitTrends.TotalAdditions,
                    gitTrends.TotalDeletions,
                    hotspots = gitTrends.Hotspots,
                    authorContributions = gitTrends.AuthorContributions
                },
                regressions = regressions.Select(r => new
                {
                    r.Type,
                    r.Severity,
                    r.Message,
                    r.BaselineValue,
                    r.CurrentValue,
                    r.BaselineCommit,
                    r.CurrentCommit
                }).ToList()
            };

            return JsonSerializer.Serialize(result, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }
}
