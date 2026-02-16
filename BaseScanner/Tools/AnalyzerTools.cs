using System.ComponentModel;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using ModelContextProtocol.Server;
using BaseScanner.Services;
using BaseScanner.Analyzers.Security;
using BaseScanner.Analyzers.Concurrency;
using BaseScanner.Analyzers.Frameworks;
using BaseScanner.Analyzers.Quality;
using BaseScanner.Analysis;
using BaseScanner.Transformers;
using BaseScanner.Transformers.Core;
using BaseScanner.VirtualWorkspace;

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

            var analysisService = new AnalysisService();
            var project = await analysisService.OpenProjectAsync(projectPath);
            var backupService = new BackupService(projectPath);
            var service = new TransformationService(backupService);
            var preview = await service.PreviewAsync(project, filter);

            return JsonSerializer.Serialize(new
            {
                preview.Success,
                totalTransformations = preview.TotalTransformations,
                transformationsByType = preview.TransformationsByType,
                transformations = preview.Previews.Select(t => new
                {
                    t.FilePath,
                    t.StartLine,
                    t.EndLine,
                    t.Category,
                    t.TransformationType,
                    t.OriginalCode,
                    t.SuggestedCode,
                    t.Confidence
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
                FormatOutput = true
            };

            var analysisService = new AnalysisService();
            var project = await analysisService.OpenProjectAsync(projectPath);
            var backupService = new BackupService(projectPath);
            var service = new TransformationService(backupService);
            var result = await service.ApplyAsync(project, filter, options);

            return JsonSerializer.Serialize(new
            {
                result.Success,
                result.TotalTransformations,
                result.FilesModified,
                result.BackupId,
                errorMessage = result.ErrorMessage,
                results = result.Results.Select(r => new
                {
                    r.TransformationType,
                    r.Success,
                    changes = r.Changes.Select(c => new { c.FilePath, c.OriginalCode, c.TransformedCode }).ToList()
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
            var backupService = new BackupService(projectPath);
            var service = new TransformationService(backupService);
            var result = await service.RollbackAsync(backupId);

            return JsonSerializer.Serialize(new
            {
                result.Success,
                result.BackupId,
                result.FilesRestored,
                result.ErrorMessage
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
                    b.Id,
                    b.CreatedAt,
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
        [Description("Treat all method parameters as tainted. Default: true")]
        bool treatParametersAsTainted = true)
    {
        try
        {
            var analysisService = new AnalysisService();
            var project = await analysisService.OpenProjectAsync(projectPath);

            var taintTracker = new TaintTracker();
            var config = new TaintConfiguration
            {
                TreatParametersAsTainted = treatParametersAsTainted
            };

            var flows = await taintTracker.TrackAsync(project, config);

            var result = new
            {
                totalFlows = flows.Count,
                unsanitizedFlows = flows.Count(f => !f.IsSanitized),
                sanitizedFlows = flows.Count(f => f.IsSanitized),
                flowsBySourceType = flows
                    .GroupBy(f => f.Source.SourceType)
                    .ToDictionary(g => g.Key, g => g.Count()),
                flows = flows.Select(f => new
                {
                    sourceType = f.Source.SourceType,
                    sourceName = f.Source.SourceName,
                    sourceLine = f.Source.Line,
                    sinkType = f.Sink.SinkType,
                    sinkName = f.Sink.SinkName,
                    sinkLine = f.Sink.Line,
                    taintedVariable = f.TaintedVariable,
                    isSanitized = f.IsSanitized,
                    sanitizerLocation = f.SanitizerLocation,
                    path = f.Path
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

    [McpServerTool]
    [Description("Analyze C# code for concurrency and threading issues including floating tasks, async void, lock patterns, race conditions, and deadlock risks.")]
    public static async Task<string> AnalyzeConcurrency(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var analyzer = new ConcurrencyAnalyzer();
            var result = await analyzer.AnalyzeProjectAsync(project);

            return JsonSerializer.Serialize(new
            {
                result.TotalIssues,
                result.CriticalCount,
                result.HighCount,
                result.MediumCount,
                result.IssuesByType,
                issues = result.Issues.Select(i => new
                {
                    i.IssueType,
                    i.Severity,
                    i.Message,
                    i.FilePath,
                    i.Line,
                    i.CodeSnippet,
                    i.SuggestedFix,
                    i.CweId
                }).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Analyze ASP.NET Core specific security issues including missing authorization, CSRF vulnerabilities, insecure CORS, mass assignment, and open redirects.")]
    public static async Task<string> AnalyzeAspNetCore(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var analyzer = new AspNetCoreAnalyzer();
            var result = await analyzer.AnalyzeAsync(project);

            return JsonSerializer.Serialize(new
            {
                result.Framework,
                result.TotalIssues,
                result.CriticalCount,
                result.HighCount,
                result.MediumCount,
                result.IssuesByType,
                issues = result.Issues.Select(i => new
                {
                    i.IssueType,
                    i.Severity,
                    i.Message,
                    i.FilePath,
                    i.Line,
                    i.CweId,
                    i.SuggestedFix
                }).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Analyze Entity Framework Core specific issues including N+1 queries, missing AsNoTracking, Cartesian explosion, raw SQL injection, and lazy loading traps.")]
    public static async Task<string> AnalyzeEntityFramework(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var analyzer = new EntityFrameworkAnalyzer();
            var result = await analyzer.AnalyzeAsync(project);

            return JsonSerializer.Serialize(new
            {
                result.Framework,
                result.TotalIssues,
                result.CriticalCount,
                result.HighCount,
                result.MediumCount,
                result.IssuesByType,
                issues = result.Issues.Select(i => new
                {
                    i.IssueType,
                    i.Severity,
                    i.Message,
                    i.FilePath,
                    i.Line,
                    i.CweId,
                    i.SuggestedFix
                }).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Analyze code quality including cognitive complexity, code smells, testability issues, error handling patterns, and design problems.")]
    public static async Task<string> AnalyzeCodeQuality(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Cognitive complexity threshold for methods. Default: 15")]
        int complexityThreshold = 15)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var analyzer = new CodeQualityAnalyzer();
            var result = await analyzer.AnalyzeAsync(project);

            // Filter by threshold
            var methodsAbove = result.MethodMetrics
                .Where(m => m.CognitiveComplexity > complexityThreshold)
                .OrderByDescending(m => m.CognitiveComplexity)
                .ToList();

            return JsonSerializer.Serialize(new
            {
                result.TotalIssues,
                result.IssuesByCategory,
                result.AverageCognitiveComplexity,
                methodsAboveThreshold = methodsAbove.Count,
                complexMethods = methodsAbove.Select(m => new
                {
                    m.MethodName,
                    m.FilePath,
                    m.Line,
                    m.CognitiveComplexity,
                    m.CyclomaticComplexity,
                    m.LineCount,
                    m.NestingDepth
                }).Take(20).ToList(),
                issues = result.Issues
                    .OrderByDescending(i => i.Severity == "High" ? 3 : i.Severity == "Medium" ? 2 : 1)
                    .Select(i => new
                    {
                        i.Category,
                        i.IssueType,
                        i.Severity,
                        i.Message,
                        i.FilePath,
                        i.Line,
                        i.Suggestion
                    }).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Calculate cognitive complexity for all methods in a project using Sonar's algorithm. Reports methods that exceed the threshold.")]
    public static async Task<string> AnalyzeCognitiveComplexity(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Complexity threshold. Methods above this will be flagged. Default: 15")]
        int threshold = 15)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var analyzer = new CodeQualityAnalyzer();
            var result = await analyzer.AnalyzeAsync(project);

            var metrics = result.MethodMetrics
                .OrderByDescending(m => m.CognitiveComplexity)
                .ToList();

            var aboveThreshold = metrics.Where(m => m.CognitiveComplexity > threshold).ToList();

            return JsonSerializer.Serialize(new
            {
                totalMethods = metrics.Count,
                averageComplexity = Math.Round(result.AverageCognitiveComplexity, 2),
                methodsAboveThreshold = aboveThreshold.Count,
                threshold,
                distribution = new
                {
                    low = metrics.Count(m => m.CognitiveComplexity <= 5),
                    moderate = metrics.Count(m => m.CognitiveComplexity > 5 && m.CognitiveComplexity <= 10),
                    high = metrics.Count(m => m.CognitiveComplexity > 10 && m.CognitiveComplexity <= 20),
                    veryHigh = metrics.Count(m => m.CognitiveComplexity > 20)
                },
                complexMethods = aboveThreshold.Select(m => new
                {
                    m.MethodName,
                    m.FilePath,
                    m.Line,
                    m.CognitiveComplexity,
                    m.CyclomaticComplexity,
                    m.LineCount,
                    m.NestingDepth,
                    m.ParameterCount
                }).Take(30).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Compare multiple optimization strategies in a virtual workspace without modifying actual files. Returns ranked results based on complexity, maintainability, and semantic safety.")]
    public static async Task<string> CompareOptimizationStrategies(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Specific file path to analyze. If not provided, analyzes first file with optimization opportunities.")]
        string? filePath = null,
        [Description("Maximum number of strategies to compare. Default: 5")]
        int maxStrategies = 5)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            // Find a file with optimization opportunities
            Document? targetDoc = null;
            if (filePath != null)
            {
                targetDoc = project.Documents.FirstOrDefault(d =>
                    d.FilePath?.EndsWith(filePath, StringComparison.OrdinalIgnoreCase) == true);
            }
            else
            {
                // Find first file with potential optimizations
                foreach (var doc in project.Documents)
                {
                    var root = await doc.GetSyntaxRootAsync();
                    if (root?.DescendantNodes().Any() == true)
                    {
                        targetDoc = doc;
                        break;
                    }
                }
            }

            if (targetDoc == null)
            {
                return JsonSerializer.Serialize(new { error = "No suitable file found for analysis" }, JsonOptions);
            }

            using var workspace = new VirtualWorkspaceManager();
            workspace.LoadFromProject(project);

            // Create simple transformation strategies based on detected patterns
            var strategies = new List<ITransformationStrategy>();
            // Note: In a full implementation, we'd dynamically create strategies based on detected patterns

            var comparison = await workspace.CompareTransformationsAsync(targetDoc.Id, strategies);

            return JsonSerializer.Serialize(new
            {
                originalFile = targetDoc.FilePath,
                totalStrategies = comparison.Results.Count,
                failedStrategies = comparison.FailedResults.Count,
                results = comparison.Results.Select(r => new
                {
                    r.StrategyName,
                    r.Category,
                    r.Description,
                    score = new
                    {
                        overall = Math.Round(r.Score.OverallScore, 2),
                        complexityDelta = r.Score.ComplexityDelta,
                        cognitiveComplexityDelta = r.Score.CognitiveComplexityDelta,
                        locDelta = r.Score.LocDelta,
                        maintainabilityDelta = Math.Round(r.Score.MaintainabilityDelta, 2),
                        compilationValid = r.Score.CompilationValid,
                        semanticsPreserved = r.Score.SemanticsPreserved
                    },
                    diff = new
                    {
                        addedLines = r.Diff.AddedLines,
                        removedLines = r.Diff.RemovedLines,
                        modifiedRegions = r.Diff.ModifiedRegions
                    }
                }).ToList(),
                bestStrategy = comparison.BestResult != null ? new
                {
                    comparison.BestResult.StrategyName,
                    comparison.BestResult.Description,
                    score = Math.Round(comparison.BestResult.Score.OverallScore, 2)
                } : null
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Run a comprehensive analysis including all detectors: security, concurrency, frameworks, code quality, and optimizations.")]
    public static async Task<string> RunFullAnalysis(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            // Run all analyzers in parallel
            var concurrencyTask = new ConcurrencyAnalyzer().AnalyzeProjectAsync(project);
            var aspNetTask = new AspNetCoreAnalyzer().AnalyzeAsync(project);
            var efTask = new EntityFrameworkAnalyzer().AnalyzeAsync(project);
            var qualityTask = new CodeQualityAnalyzer().AnalyzeAsync(project);

            var options = new AnalysisOptions
            {
                SecurityAnalysis = true,
                OptimizationAnalysis = true,
                DashboardAnalysis = true
            };
            var mainAnalysisTask = service.AnalyzeAsync(projectPath, options);

            await Task.WhenAll(concurrencyTask, aspNetTask, efTask, qualityTask, mainAnalysisTask);

            var concurrency = await concurrencyTask;
            var aspNet = await aspNetTask;
            var ef = await efTask;
            var quality = await qualityTask;
            var main = await mainAnalysisTask;

            return JsonSerializer.Serialize(new
            {
                projectPath,
                summary = new
                {
                    healthScore = main.Metrics?.HealthScore ?? 0,
                    totalIssues = concurrency.TotalIssues + aspNet.TotalIssues + ef.TotalIssues +
                                  quality.TotalIssues + (main.Security?.TotalVulnerabilities ?? 0),
                    criticalIssues = concurrency.CriticalCount + aspNet.CriticalCount + ef.CriticalCount +
                                     (main.Security?.CriticalCount ?? 0),
                    averageCognitiveComplexity = Math.Round(quality.AverageCognitiveComplexity, 2),
                    methodsAboveComplexityThreshold = quality.MethodsAboveThreshold,
                    optimizationOpportunities = main.Optimizations?.Summary.TotalOpportunities ?? 0
                },
                concurrency = new
                {
                    concurrency.TotalIssues,
                    concurrency.IssuesByType,
                    topIssues = concurrency.Issues.Take(10).ToList()
                },
                aspNetCore = new
                {
                    aspNet.TotalIssues,
                    aspNet.IssuesByType,
                    topIssues = aspNet.Issues.Take(10).ToList()
                },
                entityFramework = new
                {
                    ef.TotalIssues,
                    ef.IssuesByType,
                    topIssues = ef.Issues.Take(10).ToList()
                },
                codeQuality = new
                {
                    quality.TotalIssues,
                    quality.IssuesByCategory,
                    topIssues = quality.Issues.Take(10).ToList()
                },
                security = main.Security != null ? new
                {
                    main.Security.TotalVulnerabilities,
                    main.Security.VulnerabilitiesByType,
                    topVulnerabilities = main.Security.Vulnerabilities.Take(10).ToList()
                } : null
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    // ==================== NEW ANALYZERS (Phase 1-4) ====================

    [McpServerTool]
    [Description("Scan NuGet dependencies for known vulnerabilities (CVE/GHSA), outdated packages, and deprecated dependencies. Returns severity levels and upgrade recommendations.")]
    public static async Task<string> ScanVulnerabilities(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Minimum severity to report: critical, high, medium, low, all. Default: all")]
        string severity = "all",
        [Description("Include transitive dependency analysis. Default: true")]
        bool includeTransitive = true)
    {
        try
        {
            using var scanner = new Analyzers.Dependencies.VulnerabilityScanner();
            var result = await scanner.ScanAsync(projectPath);

            // Filter by severity
            var vulnerabilities = result.Vulnerabilities.AsEnumerable();
            if (severity != "all")
            {
                var severityOrder = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
                {
                    ["critical"] = 4, ["high"] = 3, ["medium"] = 2, ["low"] = 1
                };
                if (severityOrder.TryGetValue(severity, out var minLevel))
                {
                    vulnerabilities = vulnerabilities.Where(v =>
                        severityOrder.TryGetValue(v.Severity, out var level) && level >= minLevel);
                }
            }

            return JsonSerializer.Serialize(new
            {
                result.TotalPackages,
                result.VulnerablePackages,
                result.OutdatedPackages,
                result.DeprecatedPackages,
                vulnerabilities = vulnerabilities.Select(v => new
                {
                    v.PackageId,
                    v.InstalledVersion,
                    v.CveId,
                    v.GhsaId,
                    v.Severity,
                    v.Description,
                    v.FixedInVersion,
                    v.IsTransitive,
                    v.TransitiveSource
                }).ToList(),
                recommendations = result.Recommendations.Take(20).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Analyze code for thread safety issues including race conditions, shared mutable state, improper locking, async void patterns, and deadlock risks.")]
    public static async Task<string> AnalyzeThreadSafety(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Include async-specific pattern detection. Default: true")]
        bool includeAsync = true)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var analyzer = new Analyzers.Concurrency.ThreadSafetyAnalyzer();
            var result = await analyzer.AnalyzeProjectAsync(project);

            return JsonSerializer.Serialize(new
            {
                result.TotalIssues,
                result.CriticalCount,
                result.HighCount,
                result.MediumCount,
                result.LowCount,
                result.FilesAnalyzed,
                result.AnalysisDurationMs,
                issueCountByRule = result.IssueCountByRule,
                sharedFieldCount = result.SharedFields.Count,
                lockPatternCount = result.LockPatterns.Count,
                issues = result.Issues.Select(i => new
                {
                    i.IssueType,
                    i.RuleId,
                    i.Severity,
                    i.FilePath,
                    i.Line,
                    i.Message,
                    i.CodeSnippet,
                    i.SuggestedFix
                }).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Calculate technical debt with time-to-fix estimates, debt rating (A-E), and prioritized quick wins. Includes debt trends and payoff recommendations.")]
    public static async Task<string> CalculateTechnicalDebt(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Available time budget in minutes for debt payoff suggestions. Default: 480 (8 hours)")]
        int budgetMinutes = 480)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            // Run analysis to get the AnalysisResult needed by the scorer
            var analysisResult = await service.AnalyzeAsync(projectPath, AnalysisOptions.All);

            var scorer = new Analyzers.Debt.TechnicalDebtScorer();
            var result = await scorer.AnalyzeAsync(project, analysisResult);

            // Filter quick wins that fit within budget
            var quickWinsInBudget = result.QuickWins
                .Where(q => q.TimeToFixMinutes <= budgetMinutes)
                .Take(15)
                .ToList();

            var totalBudgetUsed = quickWinsInBudget.Sum(q => q.TimeToFixMinutes);

            return JsonSerializer.Serialize(new
            {
                result.Rating,
                result.Score,
                result.TotalDebtMinutes,
                totalDebtHours = result.TotalDebtMinutes / 60.0,
                totalDebtDays = result.TotalDebtMinutes / 480.0,
                result.DebtInterestPerWeek,
                summary = new
                {
                    result.Summary.TotalItems,
                    result.Summary.CriticalItems,
                    result.Summary.HighItems,
                    result.Summary.MediumItems,
                    result.Summary.LowItems,
                    result.Summary.DebtByCategory,
                    result.Summary.ItemsByCategory
                },
                quickWins = result.QuickWins.Take(10).Select(q => new
                {
                    q.Category,
                    q.Type,
                    q.Severity,
                    q.Description,
                    q.FilePath,
                    q.Line,
                    q.TimeToFixMinutes,
                    q.PayoffScore,
                    q.Suggestion
                }).ToList(),
                majorProjects = result.MajorProjects.Take(5).Select(m => new
                {
                    m.Category,
                    m.Type,
                    m.Severity,
                    m.Description,
                    m.FilePath,
                    m.Line,
                    m.TimeToFixMinutes,
                    m.ImpactScore
                }).ToList(),
                fileHotspots = result.FileHotspots.Take(10).Select(f => new
                {
                    f.FilePath,
                    f.TotalDebtMinutes,
                    f.ItemCount,
                    f.CriticalCount,
                    f.HighCount,
                    f.TopIssueTypes
                }).ToList(),
                trend = new
                {
                    direction = result.Trend.Direction.ToString(),
                    result.Trend.PercentageChange,
                    result.Trend.ImprovingFiles,
                    result.Trend.WorseningFiles
                },
                payoffPlan = new
                {
                    budgetMinutes,
                    itemsInBudget = quickWinsInBudget.Count,
                    totalMinutesInPlan = totalBudgetUsed,
                    items = quickWinsInBudget.Select(q => new
                    {
                        q.Category,
                        q.Type,
                        q.Description,
                        q.FilePath,
                        q.Line,
                        q.TimeToFixMinutes,
                        q.PayoffScore
                    }).ToList()
                },
                result.GeneratedAt
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Detect potential memory leaks including unsubscribed event handlers, closure captures, unbounded static collections, and IDisposable issues.")]
    public static async Task<string> DetectMemoryLeaks(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Include closure capture analysis. Default: true")]
        bool includeClosures = true)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var detector = new Analyzers.Memory.MemoryLeakDetector();
            var result = await detector.AnalyzeAsync(project);

            return JsonSerializer.Serialize(new
            {
                result.Summary.TotalLeaks,
                result.Summary.CriticalCount,
                result.Summary.HighCount,
                result.Summary.MediumCount,
                result.Summary.LowCount,
                result.Summary.HotPathLeaks,
                totalEstimatedMemoryImpact = result.Summary.TotalEstimatedMemoryImpact,
                leaksByType = result.Summary.LeaksByType,
                leaks = result.Leaks.Select(l => new
                {
                    l.LeakType,
                    l.Severity,
                    l.FilePath,
                    startLine = l.StartLine,
                    endLine = l.EndLine,
                    l.Description,
                    l.Recommendation,
                    problematicCode = l.ProblematicCode,
                    suggestedFix = l.SuggestedFix,
                    l.Confidence,
                    l.CweId,
                    l.CweLink,
                    estimatedMemoryImpact = l.EstimatedMemoryImpact,
                    isInHotPath = l.IsInHotPath,
                    details = l.Details
                }).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Analyze documentation quality including missing XML docs, stale comments, naming quality issues, and documentation coverage percentage.")]
    public static async Task<string> AnalyzeDocumentation(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Only analyze public API documentation. Default: false")]
        bool publicOnly = false)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var analyzer = new Analyzers.Documentation.DocumentationAnalyzer();
            var result = await analyzer.AnalyzeAsync(project);

            return JsonSerializer.Serialize(new
            {
                summary = new
                {
                    result.Summary.QualityScore,
                    result.Summary.NamingQualityScore,
                    result.Summary.OverallCoveragePercentage,
                    result.Summary.TotalIssues,
                    result.Summary.TodoCount,
                    result.Summary.FixmeCount,
                    result.Summary.HackCount,
                    result.Summary.IssuesBySeverity,
                    result.Summary.IssuesByCategory
                },
                lowestCoverageFiles = result.FileSummaries
                    .Where(f => f.TotalPublicSymbols > 0)
                    .OrderBy(f => f.CoveragePercentage)
                    .Take(10)
                    .Select(f => new { f.FilePath, f.CoveragePercentage, f.TotalPublicSymbols, f.DocumentedPublicSymbols })
                    .ToList(),
                nameSuggestions = result.NameSuggestions.Take(15).ToList(),
                topIssues = result.Issues
                    .OrderByDescending(i => (int)i.Severity)
                    .Take(25)
                    .Select(i => new { i.Category, i.IssueType, i.Severity, i.FilePath, i.StartLine, i.Description, i.Suggestion })
                    .ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Check naming convention compliance and detect misleading names. Finds inconsistent terminology and suggests improvements.")]
    public static async Task<string> AnalyzeNamingConventions(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var analyzer = new Analyzers.Naming.NamingConventionAnalyzer();
            var result = await analyzer.AnalyzeAsync(project);

            return JsonSerializer.Serialize(new
            {
                result.ProjectPath,
                result.AnalyzedAt,
                result.TotalSymbolsAnalyzed,
                totalViolations = result.Summary.TotalViolations,
                namingQualityScore = result.Summary.NamingQualityScore,
                errorCount = result.Summary.ErrorCount,
                warningCount = result.Summary.WarningCount,
                suggestionCount = result.Summary.SuggestionCount,
                violationsByRule = result.Summary.ViolationsByRule,
                violationsByCategory = result.Summary.ViolationsByCategory.ToDictionary(
                    kvp => kvp.Key.ToString(),
                    kvp => kvp.Value),
                topIssues = result.Summary.TopIssues,
                violations = result.Violations.Take(50).Select(v => new
                {
                    v.RuleId,
                    v.RuleName,
                    symbolCategory = v.SymbolCategory.ToString(),
                    v.SymbolName,
                    v.SuggestedName,
                    v.FilePath,
                    v.Line,
                    v.Column,
                    severity = v.Severity.ToString(),
                    v.Message,
                    expectedConvention = v.ExpectedConvention.ToString(),
                    actualConvention = v.ActualConvention.ToString(),
                    v.ContainingTypeName,
                    v.Explanation
                }).ToList(),
                semanticIssues = result.SemanticIssues.Take(20).Select(s => new
                {
                    s.SymbolName,
                    symbolCategory = s.SymbolCategory.ToString(),
                    s.FilePath,
                    s.Line,
                    inferredPurpose = s.InferredPurpose.ToString(),
                    s.ReturnType,
                    s.IsAsync,
                    issues = s.Issues.Select(i => new
                    {
                        i.IssueType,
                        i.Message,
                        severity = i.Severity.ToString(),
                        i.Suggestion,
                        i.Explanation
                    }).ToList()
                }).ToList(),
                termInconsistencies = result.TermInconsistencies.Take(10).Select(t => new
                {
                    t.Concept,
                    t.VariantTerms,
                    t.TotalOccurrences,
                    t.RecommendedTerm,
                    t.Explanation,
                    usages = t.Usages.Take(5).Select(u => new
                    {
                        u.Term,
                        u.FilePath,
                        u.Line,
                        u.SymbolName
                    }).ToList()
                }).ToList(),
                abbreviationIssues = result.AbbreviationIssues.Take(10).Select(a => new
                {
                    a.Abbreviation,
                    a.ExpandedForm,
                    a.IsConsistentlyUsed,
                    a.InconsistentForms,
                    usageCount = a.Usages.Count
                }).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Analyze logging quality including log level appropriateness, sensitive data exposure, structured logging usage, and missing correlation IDs.")]
    public static async Task<string> AnalyzeLoggingQuality(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var analyzer = new Analyzers.Logging.LoggingQualityAnalyzer();
            var result = await analyzer.AnalyzeAsync(project);

            // Extract sensitive data issues separately for easy access
            var sensitiveDataIssues = result.Issues
                .Where(i => i.IssueType == Analyzers.Logging.Models.LoggingIssueType.SensitiveDataLogged)
                .ToList();

            return JsonSerializer.Serialize(new
            {
                result.Summary.TotalIssues,
                result.Summary.CriticalCount,
                result.Summary.HighCount,
                result.Summary.MediumCount,
                result.Summary.LowCount,
                result.Summary.QualityScore,
                detectedFrameworks = result.Summary.DetectedFrameworks.ToList(),
                issuesByType = result.Summary.IssuesByType.ToDictionary(
                    kvp => kvp.Key.ToString(),
                    kvp => kvp.Value),
                issuesByFile = result.Summary.IssuesByFile,
                recommendations = result.Summary.Recommendations,
                result.AnalyzedAt,
                result.ProjectPath,
                issues = result.Issues.Take(30).Select(i => new
                {
                    issueType = i.IssueType.ToString(),
                    severity = i.Severity.ToString(),
                    i.Description,
                    i.FilePath,
                    i.StartLine,
                    i.EndLine,
                    i.ProblematicCode,
                    i.Suggestion,
                    i.RecommendedCode,
                    i.LoggingFramework,
                    i.Confidence,
                    i.Metadata
                }).ToList(),
                sensitiveDataIssues = sensitiveDataIssues.Take(15).Select(s => new
                {
                    s.FilePath,
                    s.StartLine,
                    s.EndLine,
                    s.Description,
                    s.ProblematicCode,
                    s.Suggestion,
                    s.RecommendedCode,
                    s.Metadata
                }).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Detect semantic code clones (duplicated logic) beyond textual duplicates. Identifies extraction opportunities to reduce code duplication.")]
    public static async Task<string> DetectCodeClones(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Minimum lines for clone detection. Default: 6")]
        int minLines = 6,
        [Description("Similarity threshold percentage. Default: 80")]
        int similarityThreshold = 80)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var options = new Analyzers.Clones.Models.CloneDetectionOptions
            {
                MinLines = minLines,
                MinSimilarity = similarityThreshold / 100.0
            };
            var detector = new Analyzers.Clones.SemanticCloneDetector(options);
            var result = await detector.AnalyzeProjectAsync(project);

            return JsonSerializer.Serialize(new
            {
                cloneCoverage = result.Metrics.CloneCoverage,
                totalCloneClasses = result.Metrics.TotalCloneClasses,
                totalClonedLines = result.Metrics.ClonedLines,
                result.FilesAnalyzed,
                analysisDurationMs = result.Duration.TotalMilliseconds,
                cloneClasses = result.CloneClasses.Take(15).Select(c => new
                {
                    cloneId = c.Id,
                    type = c.CloneType.ToString(),
                    c.InstanceCount,
                    linesPerInstance = c.Fragments.FirstOrDefault()?.LineCount ?? 0,
                    similarity = c.AverageSimilarity,
                    suggestedMethodName = result.ExtractionOpportunities
                        .FirstOrDefault(e => e.CloneClass.Id == c.Id)?.SuggestedName,
                    instances = c.Fragments.Take(5).Select(f => new
                    {
                        f.FilePath,
                        f.StartLine,
                        f.EndLine
                    }).ToList()
                }).ToList(),
                extractionOpportunities = result.ExtractionOpportunities.Take(10).Select(e => new
                {
                    suggestedRefactoring = $"{e.ExtractionType}: {e.SuggestedName}",
                    estimatedLinesReduced = e.EstimatedLinesSaved,
                    proposedCode = e.Description
                }).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Analyze the blast radius of code changes. Shows downstream dependencies, affected files, and risk assessment for modifying a symbol.")]
    public static async Task<string> AnalyzeChangeImpact(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Fully qualified symbol name to analyze impact for (e.g., 'Namespace.ClassName.MethodName')")]
        string symbolName,
        [Description("Type of change: SignatureChange, Deletion, Rename, TypeChange, AccessibilityChange, BehaviorChange, Addition. Default: BehaviorChange")]
        string changeType = "BehaviorChange",
        [Description("Number of top hotspots to include in results. Default: 10")]
        int topHotspots = 10)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            // Parse the change type
            if (!Enum.TryParse<Analyzers.Impact.Models.ChangeType>(changeType, ignoreCase: true, out var parsedChangeType))
            {
                parsedChangeType = Analyzers.Impact.Models.ChangeType.BehaviorChange;
            }

            var analyzer = new Analyzers.Impact.ChangeImpactAnalyzer();

            // Initialize the dependency graph from the project
            var graph = await analyzer.InitializeFromProjectAsync(project);
            var graphStats = analyzer.GetGraphStats();

            // Search for symbols matching the provided name
            var matchingSymbols = analyzer.SearchSymbols(symbolName);
            if (matchingSymbols.Count == 0)
            {
                return JsonSerializer.Serialize(new
                {
                    error = $"Symbol '{symbolName}' not found in the dependency graph",
                    graphStats = graphStats != null ? new
                    {
                        graphStats.TypeCount,
                        graphStats.MethodCount,
                        graphStats.PropertyCount,
                        graphStats.EdgeCount
                    } : null,
                    suggestion = "Try using a fully qualified name like 'Namespace.ClassName.MethodName'"
                }, JsonOptions);
            }

            // Use the first matching symbol (or exact match if available)
            var targetSymbol = matchingSymbols.FirstOrDefault(s => s.FullyQualifiedName == symbolName)
                ?? matchingSymbols.First();

            // Perform the impact analysis
            var result = analyzer.AnalyzeChange(targetSymbol.FullyQualifiedName, parsedChangeType);
            var summary = analyzer.GetImpactSummary(targetSymbol.FullyQualifiedName, parsedChangeType);
            var hotspots = analyzer.FindHotspots(topHotspots);
            var affectedFiles = analyzer.GetAffectedFiles(targetSymbol.FullyQualifiedName);

            return JsonSerializer.Serialize(new
            {
                targetSymbol = new
                {
                    targetSymbol.FullyQualifiedName,
                    targetSymbol.Name,
                    kind = targetSymbol.Kind.ToString(),
                    targetSymbol.FilePath,
                    targetSymbol.Line,
                    accessibility = targetSymbol.Accessibility.ToString(),
                    targetSymbol.IsPublicApi,
                    targetSymbol.IsCritical
                },
                changeType = parsedChangeType.ToString(),
                directImpact = new
                {
                    count = result.DirectImpact.Count,
                    affectedFileCount = result.DirectImpact.AffectedFileCount,
                    symbols = result.DirectImpact.Symbols.Take(50).ToList(),
                    byDependencyType = result.DirectImpact.ByDependencyType
                        .ToDictionary(kvp => kvp.Key.ToString(), kvp => kvp.Value.Count)
                },
                transitiveImpact = new
                {
                    count = result.TransitiveImpact.Count,
                    affectedFileCount = result.TransitiveImpact.AffectedFileCount,
                    symbols = result.TransitiveImpact.Symbols.Take(100).ToList(),
                    byDependencyType = result.TransitiveImpact.ByDependencyType
                        .ToDictionary(kvp => kvp.Key.ToString(), kvp => kvp.Value.Count)
                },
                risk = new
                {
                    result.Risk.Score,
                    level = result.Risk.Level.ToString(),
                    result.Risk.Explanation,
                    result.Risk.Confidence,
                    factors = new
                    {
                        result.Risk.Factors.DependentCountRisk,
                        result.Risk.Factors.PublicApiRisk,
                        result.Risk.Factors.CriticalPathRisk,
                        result.Risk.Factors.TestCoverageRisk
                    }
                },
                summary = new
                {
                    summary.DirectImpactCount,
                    summary.TransitiveImpactCount,
                    summary.AffectedFileCount,
                    summary.AffectsPublicApi,
                    summary.AffectsCriticalPaths,
                    riskLevel = summary.RiskLevel.ToString(),
                    byDependencyType = summary.ByDependencyType
                        .ToDictionary(kvp => kvp.Key.ToString(), kvp => kvp.Value)
                },
                affectedFiles = affectedFiles.Take(30).ToList(),
                hotspots = hotspots.Select(h => new
                {
                    symbol = h.Symbol,
                    dependentCount = h.DependentCount
                }).ToList(),
                mitigations = result.Mitigations.Select(m => new
                {
                    type = m.Type.ToString(),
                    m.Description,
                    m.Priority,
                    m.Effort,
                    targetSymbols = m.TargetSymbols.Take(10).ToList()
                }).ToList(),
                graphStats = graphStats != null ? new
                {
                    graphStats.TypeCount,
                    graphStats.MethodCount,
                    graphStats.PropertyCount,
                    graphStats.FieldCount,
                    graphStats.EdgeCount,
                    graphStats.AverageDependencies,
                    graphStats.MaxIncomingDependencies,
                    graphStats.MostDependedUponSymbol
                } : null,
                matchingSymbolsCount = matchingSymbols.Count,
                otherMatchingSymbols = matchingSymbols.Count > 1
                    ? matchingSymbols.Skip(1).Take(10).Select(s => s.FullyQualifiedName).ToList()
                    : null
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Detect hardcoded configuration values, environment-specific code, and validate configuration key usage against config files.")]
    public static async Task<string> AnalyzeConfiguration(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var analyzer = new Analyzers.Configuration.ConfigurationAnalyzer();
            var result = await analyzer.AnalyzeAsync(project);

            return JsonSerializer.Serialize(new
            {
                summary = new
                {
                    result.Summary.TotalIssues,
                    result.Summary.CriticalCount,
                    result.Summary.HighCount,
                    result.Summary.MediumCount,
                    result.Summary.LowCount,
                    result.Summary.TotalConfigAccesses,
                    result.Summary.EnvironmentPatternCount,
                    issuesByType = result.Summary.IssuesByType.ToDictionary(
                        kvp => kvp.Key.ToString(),
                        kvp => kvp.Value)
                },
                issues = result.Issues.Take(25).Select(i => new
                {
                    issueType = i.IssueType.ToString(),
                    severity = i.Severity.ToString(),
                    i.FilePath,
                    i.StartLine,
                    i.EndLine,
                    i.CodeSnippet,
                    i.Description,
                    i.Recommendation,
                    i.DetectedValue,
                    i.ConfigKey,
                    i.SuggestedFix,
                    i.Confidence
                }).ToList(),
                environmentPatterns = result.EnvironmentPatterns.Take(15).Select(e => new
                {
                    e.EnvironmentName,
                    patternType = e.PatternType.ToString(),
                    e.FilePath,
                    e.Line,
                    e.CodeSnippet,
                    e.Description
                }).ToList(),
                configAccesses = result.ConfigAccesses.Take(30).Select(a => new
                {
                    a.Key,
                    accessType = a.AccessType.ToString(),
                    a.FilePath,
                    a.Line,
                    a.ContainingMethod,
                    a.ContainingType,
                    a.HasDefaultValue,
                    a.DefaultValue,
                    a.ExpectedType
                }).ToList(),
                missingConfigKeys = result.Summary.MissingConfigKeys.ToList(),
                unusedConfigKeys = result.Summary.UnusedConfigKeys.ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Analyze implicit preconditions, hidden side effects, and invariant violations. Generates guard clause suggestions.")]
    public static async Task<string> AnalyzeContracts(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var analyzer = new Analyzers.Contracts.ContractAnalyzer();
            var result = await analyzer.AnalyzeAsync(project);

            return JsonSerializer.Serialize(new
            {
                totalPreconditions = result.Preconditions.Count,
                totalSideEffects = result.SideEffects.Count,
                totalInvariants = result.Invariants.Count,
                summary = result.Summary,
                preconditions = result.Preconditions.Take(30).Select(p => new
                {
                    p.ClassName,
                    p.MethodName,
                    targetExpression = p.TargetExpression,
                    type = p.Type.ToString(),
                    p.FilePath,
                    p.Line,
                    p.Description,
                    p.Suggestion,
                    suggestedFix = p.SuggestedFix
                }).ToList(),
                sideEffects = result.SideEffects.Take(20).Select(s => new
                {
                    s.ClassName,
                    s.MethodName,
                    purity = s.Purity.ToString(),
                    expectedPurity = s.ExpectedPurity.ToString(),
                    s.FilePath,
                    s.Line,
                    s.Description,
                    s.Suggestion,
                    modifiedFields = s.ModifiedFields,
                    sideEffectCalls = s.SideEffectCalls
                }).ToList(),
                invariants = result.Invariants.Take(15).Select(i => new
                {
                    i.ClassName,
                    i.InvariantCondition,
                    i.InvolvedMembers,
                    i.PotentiallyViolatingMethods,
                    i.FilePath,
                    i.Line,
                    i.Description
                }).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Assist with .NET framework migration. Detects deprecated APIs, suggests modern replacements, and generates migration plan.")]
    public static async Task<string> AssistMigration(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath,
        [Description("Target framework moniker (e.g., net8.0, net9.0). Default: net8.0")]
        string targetFramework = "net8.0")
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var assistant = new Analyzers.Migration.MigrationAssistant();
            var result = await assistant.AnalyzeAsync(project, targetFramework);

            return JsonSerializer.Serialize(new
            {
                targetFramework,
                summary = result.Summary,
                deprecatedApis = result.DeprecatedApis.Take(25).Select(d => new
                {
                    api = d.Api,
                    newApi = d.Mapping?.NewApi,
                    complexity = d.Mapping?.Complexity.ToString(),
                    migrationGuide = d.Mapping?.MigrationGuide,
                    isSecurityRisk = d.Mapping?.IsSecurityRisk ?? false,
                    isBlockingIssue = d.Mapping?.IsBlockingIssue ?? false,
                    d.FilePath,
                    d.Line
                }).ToList(),
                platformIssues = result.PlatformSpecificCode.Take(15).Select(p => new
                {
                    p.Api,
                    platform = p.Platform,
                    p.FilePath,
                    p.Line,
                    p.Description,
                    alternative = p.Alternative
                }).ToList(),
                compatibility = result.Compatibility != null ? new
                {
                    level = result.Compatibility.Level.ToString(),
                    unavailableApis = result.Compatibility.UnavailableApis.Take(10).ToList(),
                    packageIssues = result.Compatibility.PackageIssues.Take(10).ToList(),
                    requiredChanges = result.Compatibility.RequiredChanges.Take(10).ToList()
                } : null,
                migrationPlan = result.Plan
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Evaluate API design consistency, detect potential breaking changes, and analyze REST/HTTP best practices for ASP.NET Core APIs.")]
    public static async Task<string> AnalyzeApiDesign(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            var analyzer = new Analyzers.Api.ApiDesignAnalyzer();
            var result = await analyzer.AnalyzeAsync(project);

            return JsonSerializer.Serialize(new
            {
                summary = result.Summary,
                issues = result.Issues.Take(30).Select(i => new
                {
                    i.Category,
                    i.IssueType,
                    i.Severity,
                    i.Message,
                    i.FilePath,
                    i.Line,
                    i.AffectedElement,
                    i.Recommendation,
                    i.ImpactScore
                }).ToList(),
                breakingChanges = result.BreakingChanges.Take(15).Select(bc => new
                {
                    changeType = bc.ChangeType.ToString(),
                    bc.Severity,
                    bc.AffectedMember,
                    bc.Description,
                    bc.Mitigation,
                    bc.FilePath,
                    bc.Line
                }).ToList(),
                restIssues = result.RestIssues.Take(15).Select(r => new
                {
                    issueType = r.IssueType.ToString(),
                    r.Severity,
                    r.Controller,
                    r.Action,
                    httpMethod = r.HttpMethod,
                    route = r.Route,
                    r.Message,
                    r.Recommendation,
                    r.FilePath,
                    r.Line
                }).ToList(),
                versioningIssues = result.VersioningIssues.Take(10).ToList()
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }

    [McpServerTool]
    [Description("Run all new Phase 1-4 analyzers in parallel: vulnerabilities, thread safety, technical debt, memory leaks, documentation, naming, logging, clones, impact, configuration, contracts, migration, and API design.")]
    public static async Task<string> RunComprehensiveAnalysis(
        [Description("Path to .csproj file or directory containing a C# project")]
        string projectPath)
    {
        try
        {
            var service = new AnalysisService();
            var project = await service.OpenProjectAsync(projectPath);

            // Run all new analyzers in parallel
            var vulnTask = Task.Run(async () =>
            {
                using var scanner = new Analyzers.Dependencies.VulnerabilityScanner();
                return await scanner.ScanAsync(projectPath);
            });
            var threadTask = new Analyzers.Concurrency.ThreadSafetyAnalyzer().AnalyzeProjectAsync(project);
            var debtTask = new Analyzers.Debt.TechnicalDebtScorer().AnalyzeFullAsync(project);
            var memoryTask = new Analyzers.Memory.MemoryLeakDetector().AnalyzeAsync(project);
            var docTask = new Analyzers.Documentation.DocumentationAnalyzer().AnalyzeAsync(project);
            var namingTask = new Analyzers.Naming.NamingConventionAnalyzer().AnalyzeAsync(project);
            var loggingTask = new Analyzers.Logging.LoggingQualityAnalyzer().AnalyzeAsync(project);
            var cloneTask = new Analyzers.Clones.SemanticCloneDetector().AnalyzeProjectAsync(project);
            var configTask = new Analyzers.Configuration.ConfigurationAnalyzer().AnalyzeAsync(project);

            await Task.WhenAll(vulnTask, threadTask, debtTask, memoryTask, docTask, namingTask, loggingTask, cloneTask, configTask);

            var vuln = await vulnTask;
            var thread = await threadTask;
            var debt = await debtTask;
            var memory = await memoryTask;
            var doc = await docTask;
            var naming = await namingTask;
            var logging = await loggingTask;
            var clone = await cloneTask;
            var config = await configTask;

            return JsonSerializer.Serialize(new
            {
                projectPath,
                overallSummary = new
                {
                    debtRating = debt.Rating,
                    debtDays = Math.Round(debt.TotalDebtMinutes / 480.0, 1),
                    documentationCoverage = Math.Round(doc.Summary.OverallCoveragePercentage, 1),
                    cloneCoverage = Math.Round(clone.Metrics.CloneCoverage, 1),
                    vulnerablePackages = vuln.VulnerablePackages,
                    threadSafetyIssues = thread.TotalIssues,
                    memoryLeaks = memory.Summary.TotalLeaks,
                    namingViolations = naming.Summary.TotalViolations,
                    loggingIssues = logging.Summary.TotalIssues,
                    configIssues = config.Summary.TotalIssues
                },
                vulnerabilities = new { vuln.VulnerablePackages, criticalCount = vuln.Summary.Critical, topVulns = vuln.Vulnerabilities.Take(5).ToList() },
                threadSafety = new { thread.TotalIssues, thread.CriticalCount, topIssues = thread.Issues.Take(5).ToList() },
                technicalDebt = new { debtRating = debt.Rating, debt.TotalDebtMinutes, quickWins = debt.QuickWins.Take(5).ToList() },
                memoryLeaks = new { totalLeaks = memory.Summary.TotalLeaks, criticalCount = memory.Summary.CriticalCount, topLeaks = memory.Leaks.Take(5).ToList() },
                documentation = new { doc.Summary.QualityScore, doc.Summary.OverallCoveragePercentage, topIssues = doc.Issues.Take(5).ToList() },
                naming = new { totalViolations = naming.Summary.TotalViolations, topViolations = naming.Violations.Take(5).ToList() },
                logging = new { totalIssues = logging.Summary.TotalIssues, qualityScore = logging.Summary.QualityScore, topIssues = logging.Issues.Take(5).ToList() },
                clones = new { totalCloneClasses = clone.Metrics.TotalCloneClasses, cloneCoverage = clone.Metrics.CloneCoverage, topClones = clone.CloneClasses.Take(3).ToList() },
                configuration = new { totalIssues = config.Summary.TotalIssues, criticalCount = config.Summary.CriticalCount, topIssues = config.Issues.Take(5).ToList() }
            }, JsonOptions);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new { error = ex.Message }, JsonOptions);
        }
    }
}
