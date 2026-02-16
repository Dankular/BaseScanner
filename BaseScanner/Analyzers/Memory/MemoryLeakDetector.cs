using Microsoft.CodeAnalysis;
using BaseScanner.Context;
using BaseScanner.Analyzers.Memory.Detectors;
using System.Collections.Concurrent;

namespace BaseScanner.Analyzers.Memory;

/// <summary>
/// Main orchestrator for memory leak detection.
/// Coordinates multiple specialized detectors to find various types of memory leaks.
/// </summary>
public class MemoryLeakDetector
{
    private readonly List<IMemoryLeakDetector> _detectors;

    public MemoryLeakDetector()
    {
        _detectors = new List<IMemoryLeakDetector>
        {
            new EventHandlerLeakDetector(),
            new ClosureCaptureDetector(),
            new StaticCollectionDetector(),
            new LargeObjectDetector(),
            new CacheLeakDetector()
        };
    }

    /// <summary>
    /// Analyze a project for memory leaks.
    /// </summary>
    /// <param name="project">The Roslyn project to analyze</param>
    /// <returns>Complete analysis result with all detected leaks and summary</returns>
    public async Task<MemoryLeakResult> AnalyzeAsync(Project project)
    {
        var leaks = new ConcurrentBag<MemoryLeak>();

        // Build code context for cross-file analysis
        var context = await BuildCodeContextAsync(project);

        // Analyze each document in parallel
        await Parallel.ForEachAsync(
            project.Documents,
            new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
            async (document, ct) =>
            {
                if (document.FilePath == null)
                    return;

                // Skip generated files
                if (IsGeneratedFile(document.FilePath))
                    return;

                var semanticModel = await document.GetSemanticModelAsync(ct);
                var syntaxRoot = await document.GetSyntaxRootAsync(ct);

                if (semanticModel == null || syntaxRoot == null)
                    return;

                // Run all detectors
                foreach (var detector in _detectors)
                {
                    try
                    {
                        var detected = await detector.DetectAsync(document, semanticModel, syntaxRoot, context);
                        foreach (var leak in detected)
                        {
                            leaks.Add(leak);
                        }
                    }
                    catch (Exception)
                    {
                        // Log but continue with other detectors
                    }
                }
            });

        var leakList = leaks
            .OrderByDescending(l => GetSeverityOrder(l.Severity))
            .ThenBy(l => l.FilePath)
            .ThenBy(l => l.StartLine)
            .ToList();

        return new MemoryLeakResult
        {
            Leaks = leakList,
            Summary = BuildSummary(leakList)
        };
    }

    /// <summary>
    /// Analyze a single document for memory leaks.
    /// Useful for incremental analysis in IDE scenarios.
    /// </summary>
    public async Task<List<MemoryLeak>> AnalyzeDocumentAsync(
        Document document,
        CodeContext? context = null)
    {
        var leaks = new List<MemoryLeak>();

        if (document.FilePath == null)
            return leaks;

        if (IsGeneratedFile(document.FilePath))
            return leaks;

        var semanticModel = await document.GetSemanticModelAsync();
        var syntaxRoot = await document.GetSyntaxRootAsync();

        if (semanticModel == null || syntaxRoot == null)
            return leaks;

        // Use a minimal context if none provided
        context ??= new CodeContext
        {
            ProjectPath = document.Project.FilePath ?? "",
            BuiltAt = DateTime.UtcNow
        };

        foreach (var detector in _detectors)
        {
            try
            {
                var detected = await detector.DetectAsync(document, semanticModel, syntaxRoot, context);
                leaks.AddRange(detected);
            }
            catch (Exception)
            {
                // Continue with other detectors
            }
        }

        return leaks
            .OrderByDescending(l => GetSeverityOrder(l.Severity))
            .ThenBy(l => l.StartLine)
            .ToList();
    }

    /// <summary>
    /// Get available detector categories.
    /// </summary>
    public IEnumerable<string> GetDetectorCategories()
    {
        return _detectors.Select(d => d.Category);
    }

    /// <summary>
    /// Run analysis with specific detector categories only.
    /// </summary>
    public async Task<MemoryLeakResult> AnalyzeAsync(
        Project project,
        IEnumerable<string> categories)
    {
        var categorySet = new HashSet<string>(categories, StringComparer.OrdinalIgnoreCase);
        var selectedDetectors = _detectors.Where(d => categorySet.Contains(d.Category)).ToList();

        if (selectedDetectors.Count == 0)
            return new MemoryLeakResult();

        var leaks = new ConcurrentBag<MemoryLeak>();
        var context = await BuildCodeContextAsync(project);

        await Parallel.ForEachAsync(
            project.Documents,
            new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
            async (document, ct) =>
            {
                if (document.FilePath == null || IsGeneratedFile(document.FilePath))
                    return;

                var semanticModel = await document.GetSemanticModelAsync(ct);
                var syntaxRoot = await document.GetSyntaxRootAsync(ct);

                if (semanticModel == null || syntaxRoot == null)
                    return;

                foreach (var detector in selectedDetectors)
                {
                    try
                    {
                        var detected = await detector.DetectAsync(document, semanticModel, syntaxRoot, context);
                        foreach (var leak in detected)
                        {
                            leaks.Add(leak);
                        }
                    }
                    catch (Exception)
                    {
                        // Continue with other detectors
                    }
                }
            });

        var leakList = leaks
            .OrderByDescending(l => GetSeverityOrder(l.Severity))
            .ThenBy(l => l.FilePath)
            .ThenBy(l => l.StartLine)
            .ToList();

        return new MemoryLeakResult
        {
            Leaks = leakList,
            Summary = BuildSummary(leakList)
        };
    }

    private async Task<CodeContext> BuildCodeContextAsync(Project project)
    {
        var callGraph = new CallGraph();

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null)
                continue;

            var semanticModel = await document.GetSemanticModelAsync();
            var syntaxRoot = await document.GetSyntaxRootAsync();

            if (semanticModel == null || syntaxRoot == null)
                continue;

            // Extract method information for cross-file analysis
            foreach (var method in syntaxRoot.DescendantNodes()
                .OfType<Microsoft.CodeAnalysis.CSharp.Syntax.MethodDeclarationSyntax>())
            {
                var symbol = semanticModel.GetDeclaredSymbol(method);
                if (symbol == null)
                    continue;

                var fqn = symbol.ToDisplayString();
                callGraph.AddMethod(fqn);

                // Track method calls
                foreach (var invocation in method.DescendantNodes()
                    .OfType<Microsoft.CodeAnalysis.CSharp.Syntax.InvocationExpressionSyntax>())
                {
                    var calledSymbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                    if (calledSymbol != null)
                    {
                        callGraph.AddEdge(fqn, calledSymbol.ToDisplayString());
                    }
                }
            }
        }

        return new CodeContext
        {
            ProjectPath = project.FilePath ?? "",
            BuiltAt = DateTime.UtcNow,
            CallGraph = callGraph
        };
    }

    private bool IsGeneratedFile(string filePath)
    {
        var fileName = Path.GetFileName(filePath);
        return fileName.EndsWith(".g.cs") ||
               fileName.EndsWith(".Designer.cs") ||
               fileName.EndsWith(".generated.cs") ||
               filePath.Contains("obj" + Path.DirectorySeparatorChar);
    }

    private int GetSeverityOrder(string severity) => severity switch
    {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0
    };

    private MemoryLeakSummary BuildSummary(List<MemoryLeak> leaks)
    {
        return new MemoryLeakSummary
        {
            TotalLeaks = leaks.Count,
            CriticalCount = leaks.Count(l => l.Severity == "Critical"),
            HighCount = leaks.Count(l => l.Severity == "High"),
            MediumCount = leaks.Count(l => l.Severity == "Medium"),
            LowCount = leaks.Count(l => l.Severity == "Low"),
            LeaksByType = leaks
                .GroupBy(l => l.LeakType)
                .ToDictionary(g => g.Key, g => g.Count()),
            TotalEstimatedMemoryImpact = leaks
                .Where(l => l.EstimatedMemoryImpact.HasValue)
                .Sum(l => l.EstimatedMemoryImpact!.Value),
            HotPathLeaks = leaks.Count(l => l.IsInHotPath)
        };
    }

    /// <summary>
    /// Format analysis results as a human-readable report.
    /// </summary>
    public static string FormatReport(MemoryLeakResult result)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("=== Memory Leak Analysis Report ===");
        sb.AppendLine();

        // Summary
        sb.AppendLine("SUMMARY");
        sb.AppendLine(new string('-', 40));
        sb.AppendLine($"Total issues found: {result.Summary.TotalLeaks}");
        sb.AppendLine($"  Critical: {result.Summary.CriticalCount}");
        sb.AppendLine($"  High:     {result.Summary.HighCount}");
        sb.AppendLine($"  Medium:   {result.Summary.MediumCount}");
        sb.AppendLine($"  Low:      {result.Summary.LowCount}");
        sb.AppendLine($"Hot path issues: {result.Summary.HotPathLeaks}");

        if (result.Summary.TotalEstimatedMemoryImpact > 0)
        {
            sb.AppendLine($"Estimated memory impact: {FormatBytes(result.Summary.TotalEstimatedMemoryImpact)}");
        }

        sb.AppendLine();
        sb.AppendLine("BY TYPE");
        sb.AppendLine(new string('-', 40));
        foreach (var kvp in result.Summary.LeaksByType.OrderByDescending(x => x.Value))
        {
            sb.AppendLine($"  {kvp.Key}: {kvp.Value}");
        }

        sb.AppendLine();

        // Detailed findings
        if (result.Leaks.Count > 0)
        {
            sb.AppendLine("DETAILED FINDINGS");
            sb.AppendLine(new string('=', 60));

            var groupedByFile = result.Leaks.GroupBy(l => l.FilePath);
            foreach (var fileGroup in groupedByFile)
            {
                sb.AppendLine();
                sb.AppendLine($"File: {fileGroup.Key}");
                sb.AppendLine(new string('-', 40));

                foreach (var leak in fileGroup)
                {
                    sb.AppendLine();
                    sb.AppendLine($"  [{leak.Severity}] {leak.LeakType} (Line {leak.StartLine})");
                    sb.AppendLine($"  {leak.Description}");
                    sb.AppendLine($"  Recommendation: {leak.Recommendation}");

                    if (leak.Details.Count > 0)
                    {
                        sb.AppendLine($"  Details:");
                        foreach (var detail in leak.Details.Take(5))
                        {
                            sb.AppendLine($"    - {detail}");
                        }
                    }
                }
            }
        }

        return sb.ToString();
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes >= 1024 * 1024)
            return $"{bytes / (1024.0 * 1024.0):F2} MB";
        if (bytes >= 1024)
            return $"{bytes / 1024.0:F2} KB";
        return $"{bytes} bytes";
    }
}
