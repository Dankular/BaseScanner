using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Testing.Models;
using BaseScanner.Analyzers.Testing.Detectors;
using BaseScanner.Context;
using System.Collections.Concurrent;

namespace BaseScanner.Analyzers.Testing;

/// <summary>
/// Main coordinator for test coverage analysis.
/// Orchestrates coverage parsing, gap detection, smell detection, and quality analysis.
/// </summary>
public class TestCoverageAnalyzer
{
    private readonly List<ITestDetector> _detectors;
    private readonly CoverageParser _coverageParser;

    public TestCoverageAnalyzer()
    {
        _coverageParser = new CoverageParser();
        _detectors = new List<ITestDetector>
        {
            new CoverageGapDetector(),
            new TestSmellDetector(),
            new TestQualityDetector(),
            new CriticalPathDetector()
        };
    }

    /// <summary>
    /// Analyze test coverage for a project.
    /// </summary>
    /// <param name="project">The Roslyn project to analyze.</param>
    /// <param name="coverageReportPath">Optional path to a coverage report file.</param>
    /// <returns>Comprehensive test coverage analysis result.</returns>
    public async Task<TestCoverageResult> AnalyzeAsync(Project project, string? coverageReportPath = null)
    {
        // Parse coverage data if available
        RawCoverageData? coverageData = null;
        if (!string.IsNullOrEmpty(coverageReportPath) && File.Exists(coverageReportPath))
        {
            try
            {
                coverageData = await _coverageParser.ParseAsync(coverageReportPath);
            }
            catch (Exception)
            {
                // Log but continue without coverage data
            }
        }

        // Build code context
        var context = await BuildCodeContextAsync(project);

        // Run all detectors in parallel
        var detectionResults = new ConcurrentBag<TestDetectionResult>();

        await Parallel.ForEachAsync(
            _detectors,
            new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
            async (detector, ct) =>
            {
                try
                {
                    var result = await detector.DetectAsync(project, coverageData, context);
                    detectionResults.Add(result);
                }
                catch (Exception)
                {
                    // Log but continue with other detectors
                }
            });

        // Aggregate results
        var allSmells = detectionResults.SelectMany(r => r.Smells).ToList();
        var allQualityIssues = detectionResults.SelectMany(r => r.QualityIssues).ToList();
        var allCriticalPaths = detectionResults.SelectMany(r => r.CriticalPaths).ToList();
        var allUncoveredMethods = detectionResults.SelectMany(r => r.UncoveredMethods)
            .DistinctBy(m => $"{m.FilePath}:{m.StartLine}")
            .ToList();
        var allUncoveredBranches = detectionResults.SelectMany(r => r.UncoveredBranches).ToList();

        // Calculate statistics
        var statistics = await CalculateStatisticsAsync(project, coverageData);
        var coverageByNamespace = await CalculateNamespaceCoverageAsync(project, coverageData);

        // Build summary
        var summary = BuildSummary(
            statistics,
            allSmells,
            allQualityIssues,
            allCriticalPaths,
            allUncoveredMethods);

        return new TestCoverageResult
        {
            Statistics = statistics,
            UncoveredMethods = allUncoveredMethods
                .OrderByDescending(m => PriorityOrder(m.Priority))
                .ThenBy(m => m.FilePath)
                .ToList(),
            UncoveredBranches = allUncoveredBranches
                .OrderBy(b => b.FilePath)
                .ThenBy(b => b.Line)
                .ToList(),
            TestSmells = allSmells
                .OrderBy(s => TestIssueSeverity.ToSortOrder(s.Severity))
                .ThenBy(s => s.FilePath)
                .ToList(),
            QualityIssues = allQualityIssues
                .OrderBy(i => TestIssueSeverity.ToSortOrder(i.Severity))
                .ThenBy(i => i.FilePath)
                .ToList(),
            CriticalPaths = allCriticalPaths
                .OrderBy(p => TestIssueSeverity.ToSortOrder(p.Severity))
                .ThenBy(p => p.FilePath)
                .ToList(),
            CoverageByNamespace = coverageByNamespace,
            Summary = summary
        };
    }

    /// <summary>
    /// Analyze test coverage for a project with multiple coverage report files.
    /// </summary>
    public async Task<TestCoverageResult> AnalyzeAsync(Project project, IEnumerable<string> coverageReportPaths)
    {
        // Merge coverage data from multiple files
        var mergedModules = new List<ModuleCoverageData>();
        CoverageReportFormat format = CoverageReportFormat.Unknown;
        var generatedAt = DateTime.UtcNow;

        foreach (var path in coverageReportPaths.Where(File.Exists))
        {
            try
            {
                var data = await _coverageParser.ParseAsync(path);
                mergedModules.AddRange(data.Modules);
                if (format == CoverageReportFormat.Unknown)
                    format = data.Format;
            }
            catch (Exception)
            {
                // Log but continue
            }
        }

        // Create merged coverage data
        var mergedCoverage = mergedModules.Any()
            ? new RawCoverageData
            {
                Format = format,
                GeneratedAt = generatedAt,
                Modules = MergeModules(mergedModules)
            }
            : null;

        // Build code context
        var context = await BuildCodeContextAsync(project);

        // Run all detectors
        var detectionResults = new ConcurrentBag<TestDetectionResult>();

        await Parallel.ForEachAsync(
            _detectors,
            new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
            async (detector, ct) =>
            {
                try
                {
                    var result = await detector.DetectAsync(project, mergedCoverage, context);
                    detectionResults.Add(result);
                }
                catch (Exception)
                {
                    // Log but continue
                }
            });

        // Aggregate and return results
        var allSmells = detectionResults.SelectMany(r => r.Smells).ToList();
        var allQualityIssues = detectionResults.SelectMany(r => r.QualityIssues).ToList();
        var allCriticalPaths = detectionResults.SelectMany(r => r.CriticalPaths).ToList();
        var allUncoveredMethods = detectionResults.SelectMany(r => r.UncoveredMethods)
            .DistinctBy(m => $"{m.FilePath}:{m.StartLine}")
            .ToList();
        var allUncoveredBranches = detectionResults.SelectMany(r => r.UncoveredBranches).ToList();

        var statistics = await CalculateStatisticsAsync(project, mergedCoverage);
        var coverageByNamespace = await CalculateNamespaceCoverageAsync(project, mergedCoverage);
        var summary = BuildSummary(statistics, allSmells, allQualityIssues, allCriticalPaths, allUncoveredMethods);

        return new TestCoverageResult
        {
            Statistics = statistics,
            UncoveredMethods = allUncoveredMethods
                .OrderByDescending(m => PriorityOrder(m.Priority))
                .ToList(),
            UncoveredBranches = allUncoveredBranches,
            TestSmells = allSmells,
            QualityIssues = allQualityIssues,
            CriticalPaths = allCriticalPaths,
            CoverageByNamespace = coverageByNamespace,
            Summary = summary
        };
    }

    private List<ModuleCoverageData> MergeModules(List<ModuleCoverageData> modules)
    {
        return modules
            .GroupBy(m => m.ModuleName)
            .Select(g => new ModuleCoverageData
            {
                ModuleName = g.Key,
                AssemblyPath = g.First().AssemblyPath,
                Files = g.SelectMany(m => m.Files)
                    .GroupBy(f => NormalizePath(f.FilePath))
                    .Select(fg => new FileCoverageData
                    {
                        FilePath = fg.First().FilePath,
                        Classes = fg.SelectMany(f => f.Classes).ToList(),
                        LineHits = fg.SelectMany(f => f.LineHits)
                            .GroupBy(kv => kv.Key)
                            .ToDictionary(kvg => kvg.Key, kvg => kvg.Max(kv => kv.Value))
                    })
                    .ToList()
            })
            .ToList();
    }

    private async Task<CoverageStatistics> CalculateStatisticsAsync(Project project, RawCoverageData? coverageData)
    {
        var totalLines = 0;
        var coveredLines = 0;
        var totalBranches = 0;
        var coveredBranches = 0;
        var totalMethods = 0;
        var coveredMethods = 0;
        var totalClasses = 0;
        var coveredClasses = 0;

        if (coverageData != null)
        {
            foreach (var module in coverageData.Modules)
            {
                foreach (var file in module.Files)
                {
                    totalLines += file.LineHits.Count;
                    coveredLines += file.LineHits.Count(kv => kv.Value > 0);

                    foreach (var cls in file.Classes)
                    {
                        totalClasses++;
                        var classCovered = false;

                        foreach (var method in cls.Methods)
                        {
                            totalMethods++;
                            totalBranches += method.BranchPointsTotal;
                            coveredBranches += method.BranchPointsCovered;

                            if (method.SequencePointsCovered > 0)
                            {
                                coveredMethods++;
                                classCovered = true;
                            }
                        }

                        if (classCovered)
                            coveredClasses++;
                    }
                }
            }
        }
        else
        {
            // Calculate from source code analysis
            foreach (var document in project.Documents)
            {
                if (ShouldSkipFile(document.FilePath))
                    continue;

                var root = await document.GetSyntaxRootAsync();
                if (root == null)
                    continue;

                foreach (var classDecl in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
                {
                    totalClasses++;
                    foreach (var method in classDecl.Members.OfType<MethodDeclarationSyntax>())
                    {
                        totalMethods++;
                        var span = method.GetLocation().GetLineSpan();
                        totalLines += span.EndLinePosition.Line - span.StartLinePosition.Line + 1;
                    }
                }
            }
        }

        return new CoverageStatistics
        {
            TotalLines = totalLines,
            CoveredLines = coveredLines,
            TotalBranches = totalBranches,
            CoveredBranches = coveredBranches,
            TotalMethods = totalMethods,
            CoveredMethods = coveredMethods,
            TotalClasses = totalClasses,
            CoveredClasses = coveredClasses
        };
    }

    private async Task<Dictionary<string, NamespaceCoverage>> CalculateNamespaceCoverageAsync(
        Project project, RawCoverageData? coverageData)
    {
        var namespaces = new Dictionary<string, NamespaceCoverageBuilder>();

        if (coverageData != null)
        {
            foreach (var module in coverageData.Modules)
            {
                foreach (var file in module.Files)
                {
                    foreach (var cls in file.Classes)
                    {
                        var ns = cls.Namespace;
                        if (string.IsNullOrEmpty(ns))
                            ns = "Global";

                        if (!namespaces.ContainsKey(ns))
                            namespaces[ns] = new NamespaceCoverageBuilder { Namespace = ns };

                        var builder = namespaces[ns];

                        var classCoverage = new ClassCoverage
                        {
                            ClassName = cls.ClassName,
                            FullName = $"{ns}.{cls.ClassName}",
                            FilePath = file.FilePath,
                            TotalLines = cls.Methods.Sum(m => m.SequencePointsTotal),
                            CoveredLines = cls.Methods.Sum(m => m.SequencePointsCovered),
                            TotalMethods = cls.Methods.Count,
                            CoveredMethods = cls.Methods.Count(m => m.SequencePointsCovered > 0),
                            TotalBranches = cls.Methods.Sum(m => m.BranchPointsTotal),
                            CoveredBranches = cls.Methods.Sum(m => m.BranchPointsCovered),
                            Methods = cls.Methods.Select(m => new MethodCoverage
                            {
                                MethodName = m.MethodName,
                                FullName = m.FullName,
                                FilePath = file.FilePath,
                                StartLine = m.StartLine,
                                EndLine = m.EndLine,
                                TotalLines = m.SequencePointsTotal,
                                CoveredLines = m.SequencePointsCovered,
                                TotalBranches = m.BranchPointsTotal,
                                CoveredBranches = m.BranchPointsCovered,
                                CyclomaticComplexity = m.CyclomaticComplexity,
                                Branches = m.BranchPoints.Select(bp => new BranchCoverage
                                {
                                    Line = bp.Line,
                                    Offset = bp.Offset,
                                    PathIndex = bp.Path,
                                    IsCovered = bp.HitCount > 0,
                                    HitCount = bp.HitCount,
                                    Type = BranchType.Unknown
                                }).ToList()
                            }).ToList()
                        };

                        builder.Classes.Add(classCoverage);
                        builder.TotalLines += classCoverage.TotalLines;
                        builder.CoveredLines += classCoverage.CoveredLines;
                        builder.TotalMethods += classCoverage.TotalMethods;
                        builder.CoveredMethods += classCoverage.CoveredMethods;
                        builder.TotalBranches += classCoverage.TotalBranches;
                        builder.CoveredBranches += classCoverage.CoveredBranches;
                    }
                }
            }
        }
        else
        {
            // Calculate from source code (without actual coverage)
            foreach (var document in project.Documents)
            {
                if (ShouldSkipFile(document.FilePath))
                    continue;

                var semanticModel = await document.GetSemanticModelAsync();
                var root = await document.GetSyntaxRootAsync();

                if (semanticModel == null || root == null)
                    continue;

                foreach (var classDecl in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
                {
                    var classSymbol = semanticModel.GetDeclaredSymbol(classDecl);
                    if (classSymbol == null)
                        continue;

                    var ns = classSymbol.ContainingNamespace?.ToDisplayString() ?? "Global";

                    if (!namespaces.ContainsKey(ns))
                        namespaces[ns] = new NamespaceCoverageBuilder { Namespace = ns };

                    var builder = namespaces[ns];
                    var methods = classDecl.Members.OfType<MethodDeclarationSyntax>().ToList();
                    var lineCount = 0;

                    foreach (var method in methods)
                    {
                        var span = method.GetLocation().GetLineSpan();
                        lineCount += span.EndLinePosition.Line - span.StartLinePosition.Line + 1;
                    }

                    builder.TotalLines += lineCount;
                    builder.TotalMethods += methods.Count;
                }
            }
        }

        return namespaces.ToDictionary(
            kvp => kvp.Key,
            kvp => new NamespaceCoverage
            {
                Namespace = kvp.Value.Namespace,
                TotalLines = kvp.Value.TotalLines,
                CoveredLines = kvp.Value.CoveredLines,
                TotalMethods = kvp.Value.TotalMethods,
                CoveredMethods = kvp.Value.CoveredMethods,
                TotalBranches = kvp.Value.TotalBranches,
                CoveredBranches = kvp.Value.CoveredBranches,
                Classes = kvp.Value.Classes
            });
    }

    private TestCoverageSummary BuildSummary(
        CoverageStatistics statistics,
        List<TestSmell> smells,
        List<TestQualityIssue> qualityIssues,
        List<CriticalPathWithoutTests> criticalPaths,
        List<UncoveredMethod> uncoveredMethods)
    {
        var criticalSmells = smells.Count(s => s.Severity == TestIssueSeverity.Critical);
        var highSmells = smells.Count(s => s.Severity == TestIssueSeverity.High);
        var criticalPaths_count = criticalPaths.Count(p => p.Severity == TestIssueSeverity.Critical);
        var highPriorityUncovered = uncoveredMethods.Count(m =>
            m.Priority == UncoveredPriority.Critical || m.Priority == UncoveredPriority.High);

        var grade = TestGrade.Calculate(
            statistics.LineCoverage,
            criticalSmells + criticalPaths_count,
            highSmells + highPriorityUncovered);

        var recommendations = GenerateRecommendations(
            statistics, smells, qualityIssues, criticalPaths, uncoveredMethods);

        return new TestCoverageSummary
        {
            OverallLineCoverage = statistics.LineCoverage,
            OverallBranchCoverage = statistics.BranchCoverage,
            OverallMethodCoverage = statistics.MethodCoverage,
            TotalTestSmells = smells.Count,
            TotalQualityIssues = qualityIssues.Count,
            CriticalUncoveredPaths = criticalPaths_count,
            HighPriorityUncoveredMethods = highPriorityUncovered,
            OverallGrade = grade,
            SmellsByType = smells
                .GroupBy(s => s.SmellType)
                .ToDictionary(g => g.Key, g => g.Count()),
            CriticalPathsByType = criticalPaths
                .GroupBy(p => p.PathType)
                .ToDictionary(g => g.Key, g => g.Count()),
            TopRecommendations = recommendations
        };
    }

    private List<string> GenerateRecommendations(
        CoverageStatistics statistics,
        List<TestSmell> smells,
        List<TestQualityIssue> qualityIssues,
        List<CriticalPathWithoutTests> criticalPaths,
        List<UncoveredMethod> uncoveredMethods)
    {
        var recommendations = new List<string>();

        // Coverage-based recommendations
        if (statistics.LineCoverage < 80)
        {
            recommendations.Add($"Increase line coverage from {statistics.LineCoverage:F1}% to at least 80%");
        }

        if (statistics.BranchCoverage < 70 && statistics.TotalBranches > 0)
        {
            recommendations.Add($"Improve branch coverage from {statistics.BranchCoverage:F1}% to at least 70%");
        }

        // Critical path recommendations
        var authPaths = criticalPaths.Where(p =>
            p.PathType == CriticalPathType.Authentication ||
            p.PathType == CriticalPathType.Authorization).ToList();
        if (authPaths.Any())
        {
            recommendations.Add($"Add tests for {authPaths.Count} authentication/authorization code paths");
        }

        var sqlPaths = criticalPaths.Where(p => p.PathType == CriticalPathType.SqlQuery).ToList();
        if (sqlPaths.Any())
        {
            recommendations.Add($"Add tests for {sqlPaths.Count} SQL query methods to prevent SQL injection");
        }

        // Smell-based recommendations
        var emptyTests = smells.Count(s => s.SmellType == TestSmellType.EmptyTest);
        if (emptyTests > 0)
        {
            recommendations.Add($"Implement {emptyTests} empty test methods or remove them");
        }

        var noAssertions = smells.Count(s => s.SmellType == TestSmellType.NoAssertions);
        if (noAssertions > 0)
        {
            recommendations.Add($"Add assertions to {noAssertions} tests that verify no behavior");
        }

        var flakyPatterns = smells.Count(s =>
            s.SmellType == TestSmellType.ThreadSleep ||
            s.SmellType == TestSmellType.DateTimeNow);
        if (flakyPatterns > 0)
        {
            recommendations.Add($"Fix {flakyPatterns} tests with flaky patterns (Thread.Sleep, DateTime.Now)");
        }

        // Quality issue recommendations
        var weakAssertions = qualityIssues.Count(i => i.IssueType == TestQualityIssueType.WeakAssertion);
        if (weakAssertions > 0)
        {
            recommendations.Add($"Strengthen {weakAssertions} weak assertions with more specific checks");
        }

        // Uncovered method recommendations
        var publicUncovered = uncoveredMethods.Count(m => m.IsPublic);
        if (publicUncovered > 0)
        {
            recommendations.Add($"Add tests for {publicUncovered} public API methods without coverage");
        }

        var securityUncovered = uncoveredMethods.Count(m => m.HasSecurityImplications);
        if (securityUncovered > 0)
        {
            recommendations.Add($"Prioritize testing {securityUncovered} security-sensitive methods");
        }

        return recommendations.Take(10).ToList();
    }

    private async Task<CodeContext> BuildCodeContextAsync(Project project)
    {
        var callGraph = new CallGraph();

        foreach (var document in project.Documents)
        {
            if (ShouldSkipFile(document.FilePath))
                continue;

            var semanticModel = await document.GetSemanticModelAsync();
            var root = await document.GetSyntaxRootAsync();

            if (semanticModel == null || root == null)
                continue;

            foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                var symbol = semanticModel.GetDeclaredSymbol(method);
                if (symbol == null)
                    continue;

                var fqn = symbol.ToDisplayString();
                callGraph.AddMethod(fqn);

                foreach (var invocation in method.DescendantNodes()
                    .OfType<InvocationExpressionSyntax>())
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

    private bool ShouldSkipFile(string? filePath)
    {
        if (string.IsNullOrEmpty(filePath))
            return true;

        var fileName = Path.GetFileName(filePath);
        return fileName.EndsWith(".g.cs") ||
               fileName.EndsWith(".Designer.cs") ||
               fileName.EndsWith(".generated.cs") ||
               filePath.Contains("obj" + Path.DirectorySeparatorChar) ||
               filePath.Contains("bin" + Path.DirectorySeparatorChar);
    }

    private string NormalizePath(string path)
    {
        return path.Replace('\\', '/').ToLowerInvariant();
    }

    private int PriorityOrder(UncoveredPriority priority) => priority switch
    {
        UncoveredPriority.Critical => 3,
        UncoveredPriority.High => 2,
        UncoveredPriority.Medium => 1,
        UncoveredPriority.Low => 0,
        _ => 0
    };

    private class NamespaceCoverageBuilder
    {
        public string Namespace { get; set; } = "";
        public int TotalLines { get; set; }
        public int CoveredLines { get; set; }
        public int TotalMethods { get; set; }
        public int CoveredMethods { get; set; }
        public int TotalBranches { get; set; }
        public int CoveredBranches { get; set; }
        public List<ClassCoverage> Classes { get; } = new();
    }
}
