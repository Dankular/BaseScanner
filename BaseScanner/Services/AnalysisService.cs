using Microsoft.Build.Locator;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.MSBuild;
using BaseScanner.Analyzers;
using BaseScanner.Analyzers.Security;
using BaseScanner.Analysis;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;

namespace BaseScanner.Services;

public record AnalysisOptions
{
    // Solution/Project path handling
    public bool IsSolution { get; init; }
    public string? SolutionPath { get; init; }
    
    // Existing analyzers
    public bool UnusedFiles { get; init; } = true;
    public bool DeepAnalysis { get; init; }
    public bool SentimentAnalysis { get; init; }
    public bool PerformanceAnalysis { get; init; }
    public bool ExceptionAnalysis { get; init; }
    public bool ResourceAnalysis { get; init; }
    public bool DependencyAnalysis { get; init; }
    public bool MagicValueAnalysis { get; init; }
    public bool GitAnalysis { get; init; }
    public bool RefactoringAnalysis { get; init; }
    public bool ArchitectureAnalysis { get; init; }
    public bool SafetyAnalysis { get; init; }
    public bool OptimizationAnalysis { get; init; }
    public bool SecurityAnalysis { get; init; }
    public bool DashboardAnalysis { get; init; }

    // NEW: Phase 1-4 Analyzers
    public bool TestCoverageAnalysis { get; init; }
    public bool DocumentationAnalysis { get; init; }
    public bool VulnerabilityAnalysis { get; init; }
    public bool CloneAnalysis { get; init; }
    public bool ImpactAnalysis { get; init; }
    public bool TechnicalDebtAnalysis { get; init; }
    public bool ThreadSafetyAnalysis { get; init; }
    public bool MemoryLeakAnalysis { get; init; }
    public bool MigrationAnalysis { get; init; }
    public bool NamingAnalysis { get; init; }
    public bool ContractAnalysis { get; init; }
    public bool ConfigurationAnalysis { get; init; }
    public bool LoggingAnalysis { get; init; }
    public bool ApiDesignAnalysis { get; init; }

    // Analysis modifiers
    public string? CoverageFilePath { get; init; }
    public string? TargetFramework { get; init; }
    public string? ImpactSymbol { get; init; }

    public static AnalysisOptions All => new()
    {
        UnusedFiles = true,
        DeepAnalysis = true,
        SentimentAnalysis = true,
        PerformanceAnalysis = true,
        ExceptionAnalysis = true,
        ResourceAnalysis = true,
        DependencyAnalysis = true,
        MagicValueAnalysis = true,
        GitAnalysis = true,
        RefactoringAnalysis = true,
        ArchitectureAnalysis = true,
        SafetyAnalysis = true,
        OptimizationAnalysis = true,
        SecurityAnalysis = true,
        DashboardAnalysis = true,
        // New analyzers
        TestCoverageAnalysis = true,
        DocumentationAnalysis = true,
        VulnerabilityAnalysis = true,
        CloneAnalysis = true,
        ImpactAnalysis = true,
        TechnicalDebtAnalysis = true,
        ThreadSafetyAnalysis = true,
        MemoryLeakAnalysis = true,
        MigrationAnalysis = true,
        NamingAnalysis = true,
        ContractAnalysis = true,
        ConfigurationAnalysis = true,
        LoggingAnalysis = true,
        ApiDesignAnalysis = true
    };

    public static AnalysisOptions Parse(string analyses)
    {
        if (string.IsNullOrWhiteSpace(analyses))
            return new AnalysisOptions();

        var parts = analyses.ToLowerInvariant().Split(',', StringSplitOptions.RemoveEmptyEntries);

        if (parts.Contains("all"))
            return All;

        return new AnalysisOptions
        {
            UnusedFiles = parts.Contains("unused_files") || parts.Length == 0,
            DeepAnalysis = parts.Contains("deep"),
            SentimentAnalysis = parts.Contains("sentiment"),
            PerformanceAnalysis = parts.Contains("perf"),
            ExceptionAnalysis = parts.Contains("exceptions"),
            ResourceAnalysis = parts.Contains("resources"),
            DependencyAnalysis = parts.Contains("deps"),
            MagicValueAnalysis = parts.Contains("magic"),
            GitAnalysis = parts.Contains("git"),
            RefactoringAnalysis = parts.Contains("refactor"),
            ArchitectureAnalysis = parts.Contains("arch"),
            SafetyAnalysis = parts.Contains("safety"),
            OptimizationAnalysis = parts.Contains("optimize") || parts.Contains("optimizations"),
            SecurityAnalysis = parts.Contains("security"),
            DashboardAnalysis = parts.Contains("dashboard") || parts.Contains("metrics"),
            // New analyzers
            TestCoverageAnalysis = parts.Contains("test-coverage") || parts.Contains("coverage"),
            DocumentationAnalysis = parts.Contains("docs") || parts.Contains("documentation"),
            VulnerabilityAnalysis = parts.Contains("vulnerabilities") || parts.Contains("vuln"),
            CloneAnalysis = parts.Contains("clones") || parts.Contains("duplicates"),
            ImpactAnalysis = parts.Contains("impact"),
            TechnicalDebtAnalysis = parts.Contains("debt") || parts.Contains("technical-debt"),
            ThreadSafetyAnalysis = parts.Contains("thread-safety") || parts.Contains("threading"),
            MemoryLeakAnalysis = parts.Contains("memory") || parts.Contains("memory-leaks"),
            MigrationAnalysis = parts.Contains("migration"),
            NamingAnalysis = parts.Contains("naming") || parts.Contains("conventions"),
            ContractAnalysis = parts.Contains("contracts") || parts.Contains("invariants"),
            ConfigurationAnalysis = parts.Contains("config") || parts.Contains("configuration"),
            LoggingAnalysis = parts.Contains("logging"),
            ApiDesignAnalysis = parts.Contains("api-design") || parts.Contains("api")
        };
    }
}

public class AnalysisService
{
    private static bool _msBuildRegistered = false;
    private static readonly object _registrationLock = new();

    public static void EnsureMSBuildRegistered()
    {
        lock (_registrationLock)
        {
            if (!_msBuildRegistered)
            {
                // Check if MSBuild can still be registered (no assemblies loaded yet)
                if (MSBuildLocator.CanRegister)
                {
                    MSBuildLocator.RegisterDefaults();
                }
                _msBuildRegistered = true;
            }
        }
    }

    /// <summary>
    /// Open a project for analysis without running full analysis.
    /// Useful for custom analyzers that need direct access to the Roslyn project.
    /// </summary>
    public async Task<Project> OpenProjectAsync(string projectPath)
    {
        EnsureMSBuildRegistered();

        var resolvedPath = ResolveProjectPath(projectPath);
        var workspace = MSBuildWorkspace.Create();
        var project = await workspace.OpenProjectAsync(resolvedPath);

        return project;
    }

    /// <summary>
    /// Open a solution file and return all projects within it.
    /// This enables cross-project reference analysis.
    /// </summary>
    public async Task<List<Project>> OpenSolutionAsync(string solutionPath)
    {
        EnsureMSBuildRegistered();

        var resolvedPath = ResolveSolutionPath(solutionPath);
        var workspace = MSBuildWorkspace.Create();
#pragma warning disable CS0618
        workspace.WorkspaceFailed += (sender, e) => { /* Suppress warnings */ };
#pragma warning restore CS0618

        var solution = await workspace.OpenSolutionAsync(resolvedPath);
        
        return solution.Projects.ToList();
    }

    private static string ResolveSolutionPath(string solutionPath)
    {
        if (File.Exists(solutionPath) && solutionPath.EndsWith(".sln", StringComparison.OrdinalIgnoreCase))
        {
            return solutionPath;
        }

        if (Directory.Exists(solutionPath))
        {
            var slnFiles = Directory.GetFiles(solutionPath, "*.sln");
            if (slnFiles.Length == 1)
            {
                return slnFiles[0];
            }
            else if (slnFiles.Length > 1)
            {
                throw new ArgumentException($"Multiple .sln files found in directory. Please specify one: {string.Join(", ", slnFiles.Select(Path.GetFileName))}");
            }
            else
            {
                throw new FileNotFoundException("No .sln file found in directory: " + solutionPath);
            }
        }

        throw new FileNotFoundException("Solution path not found: " + solutionPath);
    }

    private static string ResolveProjectPath(string projectPath)
    {
        if (File.Exists(projectPath) && projectPath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase))
        {
            return projectPath;
        }

        if (Directory.Exists(projectPath))
        {
            var csprojFiles = Directory.GetFiles(projectPath, "*.csproj");
            if (csprojFiles.Length == 1)
            {
                return csprojFiles[0];
            }
            else if (csprojFiles.Length > 1)
            {
                throw new ArgumentException($"Multiple .csproj files found in directory. Please specify one: {string.Join(", ", csprojFiles.Select(Path.GetFileName))}");
            }
            else
            {
                throw new FileNotFoundException("No .csproj file found in directory: " + projectPath);
            }
        }

        throw new FileNotFoundException("Project path not found: " + projectPath);
    }

    public async Task<AnalysisResult> AnalyzeAsync(string projectPath, AnalysisOptions options)
    {
        EnsureMSBuildRegistered();

        // Check if it's a solution file
        bool isSolution = File.Exists(projectPath) && projectPath.EndsWith(".sln", StringComparison.OrdinalIgnoreCase);
        
        if (isSolution)
        {
            return await AnalyzeSolutionAsync(projectPath, options);
        }

        // Resolve project path
        if (Directory.Exists(projectPath))
        {
            var csprojFiles = Directory.GetFiles(projectPath, "*.csproj");
            if (csprojFiles.Length == 0)
                throw new ArgumentException($"No .csproj file found in: {projectPath}");
            if (csprojFiles.Length > 1)
                throw new ArgumentException($"Multiple .csproj files found in: {projectPath}. Please specify one.");
            projectPath = csprojFiles[0];
        }

        if (!File.Exists(projectPath))
            throw new FileNotFoundException($"Project file not found: {projectPath}");

        var projectDirectory = Path.GetDirectoryName(projectPath)!;

        // Get all .cs files on disk
        var allCsFilesOnDisk = Directory.GetFiles(projectDirectory, "*.cs", SearchOption.AllDirectories)
            .Select(f => Path.GetFullPath(f))
            .Where(f => !f.Contains(Path.Combine(projectDirectory, "obj") + Path.DirectorySeparatorChar) &&
                        !f.Contains(Path.Combine(projectDirectory, "bin") + Path.DirectorySeparatorChar))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Load project
        using var workspace = MSBuildWorkspace.Create();
#pragma warning disable CS0618
        workspace.WorkspaceFailed += (sender, e) => { /* Suppress warnings */ };
#pragma warning restore CS0618

        var project = await workspace.OpenProjectAsync(projectPath);

        var compiledFiles = project.Documents
            .Where(d => d.FilePath != null)
            .Select(d => Path.GetFullPath(d.FilePath!))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Build result
        var summary = new AnalysisSummary
        {
            TotalFilesOnDisk = allCsFilesOnDisk.Count,
            FilesInCompilation = compiledFiles.Count
        };

        var unusedFiles = allCsFilesOnDisk.Where(f => !compiledFiles.Contains(f))
            .Select(f => Path.GetRelativePath(projectDirectory, f)).ToList();
        var missingFiles = compiledFiles.Where(f => !File.Exists(f))
            .Select(f => Path.GetRelativePath(projectDirectory, f)).ToList();

        var result = new AnalysisResult
        {
            ProjectPath = projectPath,
            Summary = summary with
            {
                UnusedFiles = unusedFiles.Count,
                MissingFiles = missingFiles.Count
            },
            UnusedFiles = unusedFiles,
            MissingFiles = missingFiles
        };

        // Run optional analyses
        if (options.DeepAnalysis)
        {
            var compilation = await project.GetCompilationAsync();
            if (compilation != null)
            {
                var (deprecated, dead, lowUsage) = await AnalyzeDeepAsync(project, compilation, projectDirectory);
                result = result with
                {
                    DeprecatedCode = deprecated,
                    DeadCode = dead,
                    LowUsageCode = lowUsage
                };
            }
        }

        if (options.SentimentAnalysis)
        {
            result = result with { Sentiment = await AnalyzeSentimentAsync(project, projectDirectory) };
        }

        if (options.PerformanceAnalysis)
        {
            var analyzer = new AsyncPerformanceAnalyzer();
            var issues = await analyzer.AnalyzeAsync(project);
            result = result with
            {
                PerformanceIssues = issues.Select(i => new IssueItem
                {
                    Type = i.Type,
                    Severity = i.Severity,
                    Message = i.Message,
                    FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                    Line = i.Line,
                    CodeSnippet = i.CodeSnippet
                }).ToList()
            };
        }

        if (options.ExceptionAnalysis)
        {
            var analyzer = new ExceptionHandlingAnalyzer();
            var issues = await analyzer.AnalyzeAsync(project);
            result = result with
            {
                ExceptionHandlingIssues = issues.Select(i => new IssueItem
                {
                    Type = i.Type,
                    Severity = i.Severity,
                    Message = i.Message,
                    FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                    Line = i.Line,
                    CodeSnippet = i.CodeSnippet
                }).ToList()
            };
        }

        if (options.ResourceAnalysis)
        {
            var analyzer = new ResourceLeakAnalyzer();
            var issues = await analyzer.AnalyzeAsync(project);
            result = result with
            {
                ResourceLeakIssues = issues.Select(i => new IssueItem
                {
                    Type = i.Type,
                    Severity = i.Severity,
                    Message = i.Message,
                    FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                    Line = i.Line,
                    CodeSnippet = i.CodeSnippet
                }).ToList()
            };
        }

        if (options.DependencyAnalysis)
        {
            var analyzer = new DependencyAnalyzer();
            var (issues, metrics, cycles) = await analyzer.AnalyzeAsync(project);
            result = result with
            {
                Dependencies = new DependencyResult
                {
                    CircularDependencies = cycles.Select(c => new CircularDependencyItem
                    {
                        Type = c.Type,
                        Cycle = c.Cycle
                    }).ToList(),
                    HighCouplingTypes = metrics.Where(m => m.EfferentCoupling > 10)
                        .OrderByDescending(m => m.EfferentCoupling)
                        .Take(20)
                        .Select(m => new CouplingItem
                        {
                            TypeName = m.TypeName,
                            FilePath = !string.IsNullOrEmpty(m.FilePath) ? Path.GetRelativePath(projectDirectory, m.FilePath) : "",
                            EfferentCoupling = m.EfferentCoupling,
                            AfferentCoupling = m.AfferentCoupling,
                            Instability = m.Instability
                        }).ToList()
                }
            };
        }

        if (options.MagicValueAnalysis)
        {
            var analyzer = new MagicValueAnalyzer();
            var issues = await analyzer.AnalyzeAsync(project);
            result = result with
            {
                MagicValues = issues.GroupBy(i => (i.Type, i.Value))
                    .Select(g => new MagicValueItem
                    {
                        Type = g.Key.Type,
                        Value = g.Key.Value,
                        Occurrences = g.First().Occurrences,
                        Locations = g.Select(i => new LocationItem
                        {
                            FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                            Line = i.Line
                        }).Take(5).ToList()
                    }).Take(30).ToList()
            };
        }

        if (options.GitAnalysis)
        {
            var analyzer = new GitChurnAnalyzer();
            var (issues, churns, hotspots, gitAvailable) = await analyzer.AnalyzeAsync(projectDirectory);
            result = result with
            {
                GitChurn = new GitChurnResult
                {
                    GitAvailable = gitAvailable,
                    TopChurnedFiles = churns.Take(20).Select(c => new FileChurnItem
                    {
                        FilePath = c.RelativePath,
                        CommitCount = c.CommitCount,
                        TotalChurn = c.TotalChurn,
                        DaysSinceLastChange = c.DaysSinceLastChange
                    }).ToList(),
                    Hotspots = hotspots.Take(15).Select(h => new HotspotItem
                    {
                        FilePath = h.FilePath,
                        Score = h.HotspotScore,
                        ChurnCount = h.ChurnCount,
                        Reason = h.Reason
                    }).ToList(),
                    StaleFiles = churns.Where(c => c.DaysSinceLastChange > 365)
                        .OrderByDescending(c => c.DaysSinceLastChange)
                        .Take(15)
                        .Select(c => new FileChurnItem
                        {
                            FilePath = c.RelativePath,
                            CommitCount = c.CommitCount,
                            TotalChurn = c.TotalChurn,
                            DaysSinceLastChange = c.DaysSinceLastChange
                        }).ToList()
                }
            };
        }

        if (options.RefactoringAnalysis)
        {
            var analyzer = new RefactoringAnalyzer();
            var (longMethods, godClasses, featureEnvies, parameterSmells, dataClumps) = await analyzer.AnalyzeAsync(project);
            result = result with
            {
                Refactoring = new RefactoringResult
                {
                    LongMethods = longMethods.Take(30).Select(m => new LongMethodItem
                    {
                        FilePath = Path.GetRelativePath(projectDirectory, m.FilePath),
                        Line = m.StartLine,
                        ClassName = m.ClassName,
                        MethodName = m.MethodName,
                        LineCount = m.LineCount,
                        Complexity = m.CyclomaticComplexity,
                        ExtractCandidates = m.ExtractCandidates.Take(5).Select(c => new ExtractCandidateItem
                        {
                            StartLine = c.StartLine,
                            EndLine = c.EndLine,
                            SuggestedName = c.SuggestedName,
                            Reason = c.Reason
                        }).ToList()
                    }).ToList(),
                    GodClasses = godClasses.Take(15).Select(g => new GodClassItem
                    {
                        FilePath = Path.GetRelativePath(projectDirectory, g.FilePath),
                        Line = g.Line,
                        ClassName = g.ClassName,
                        MethodCount = g.MethodCount,
                        FieldCount = g.FieldCount,
                        LCOM = g.LCOM,
                        Responsibilities = g.Responsibilities.Take(5).ToList()
                    }).ToList(),
                    FeatureEnvy = featureEnvies.Take(20).Select(e => new FeatureEnvyItem
                    {
                        FilePath = Path.GetRelativePath(projectDirectory, e.FilePath),
                        Line = e.Line,
                        ClassName = e.ClassName,
                        MethodName = e.MethodName,
                        EnviedClass = e.EnviedClass,
                        EnviedMemberAccess = e.EnviedMemberAccess,
                        EnvyRatio = e.EnvyRatio
                    }).ToList(),
                    ParameterSmells = parameterSmells.Take(20).Select(p => new ParameterSmellItem
                    {
                        FilePath = Path.GetRelativePath(projectDirectory, p.FilePath),
                        Line = p.Line,
                        ClassName = p.ClassName,
                        MethodName = p.MethodName,
                        ParameterCount = p.ParameterCount,
                        SmellType = p.SmellType,
                        Suggestion = p.Suggestion
                    }).ToList(),
                    DataClumps = dataClumps.Take(15).Select(d => new DataClumpItem
                    {
                        Parameters = d.Parameters,
                        Occurrences = d.Occurrences.Count,
                        SuggestedClassName = d.SuggestedClassName,
                        Locations = d.Occurrences.Take(5).Select(o => $"{o.ClassName}.{o.MethodName}").ToList()
                    }).ToList()
                }
            };
        }

        if (options.ArchitectureAnalysis)
        {
            var analyzer = new ArchitectureAnalyzer();
            var (publicApi, callGraph, inheritanceIssues, interfaceIssues) = await analyzer.AnalyzeAsync(project);
            var entryPoints = callGraph.Where(c => c.IsEntryPoint).ToList();
            var deadEnds = callGraph.Where(c => c.IsDeadEnd && !string.IsNullOrEmpty(c.FilePath)).ToList();

            result = result with
            {
                Architecture = new ArchitectureResult
                {
                    PublicApi = publicApi.Take(50).Select(a => new PublicApiItem
                    {
                        TypeName = a.TypeName,
                        MemberName = a.MemberName,
                        MemberType = a.MemberType,
                        FilePath = Path.GetRelativePath(projectDirectory, a.FilePath),
                        Line = a.Line,
                        BreakingChangeRisk = a.BreakingChangeRisk
                    }).ToList(),
                    EntryPoints = entryPoints.Take(20).Select(e => new EntryPointItem
                    {
                        TypeName = e.TypeName,
                        MethodName = e.MethodName,
                        OutgoingCalls = e.OutgoingCalls
                    }).ToList(),
                    DeadEnds = deadEnds.Take(15).Select(d => new DeadEndItem
                    {
                        FilePath = Path.GetRelativePath(projectDirectory, d.FilePath),
                        Line = d.Line,
                        TypeName = d.TypeName,
                        MethodName = d.MethodName,
                        IncomingCalls = d.IncomingCalls
                    }).ToList(),
                    DeepInheritance = inheritanceIssues.Where(i => i.InheritanceDepth > 3).Take(15).Select(i => new InheritanceItem
                    {
                        TypeName = i.TypeName,
                        Depth = i.InheritanceDepth,
                        Chain = i.InheritanceChain.Take(5).ToList()
                    }).ToList(),
                    CompositionCandidates = inheritanceIssues.Where(i => i.HasCompositionOpportunity).Take(15).Select(i => new CompositionCandidateItem
                    {
                        FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                        Line = i.Line,
                        TypeName = i.TypeName,
                        Suggestion = i.CompositionSuggestion
                    }).ToList(),
                    InterfaceIssues = interfaceIssues.Take(15).Select(i => new InterfaceIssueItem
                    {
                        FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                        Line = i.Line,
                        InterfaceName = i.InterfaceName,
                        MemberCount = i.MemberCount,
                        SuggestedSplits = i.SuggestedSplits
                    }).ToList()
                }
            };
        }

        if (options.SafetyAnalysis)
        {
            var analyzer = new CodeSafetyAnalyzer();
            var (nullIssues, immutabilityIssues, loggingGaps, loggingCoverage) = await analyzer.AnalyzeAsync(project);

            result = result with
            {
                Safety = new SafetyResult
                {
                    NullIssues = nullIssues.Take(50).Select(n => new NullSafetyItem
                    {
                        Type = n.Type,
                        Severity = n.Severity,
                        FilePath = Path.GetRelativePath(projectDirectory, n.FilePath),
                        Line = n.Line,
                        Description = n.Description
                    }).ToList(),
                    ImmutabilityIssues = immutabilityIssues.Take(50).Select(i => new ImmutabilityItem
                    {
                        Type = i.Type,
                        FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                        Line = i.Line,
                        MemberName = i.MemberName,
                        Suggestion = i.Suggestion
                    }).ToList(),
                    LoggingGaps = loggingGaps.Take(30).Select(l => new LoggingGapItem
                    {
                        FilePath = Path.GetRelativePath(projectDirectory, l.FilePath),
                        Line = l.Line,
                        ClassName = l.ClassName,
                        MethodName = l.MethodName,
                        GapType = l.GapType,
                        Description = l.Description
                    }).ToList(),
                    AverageLoggingCoverage = loggingCoverage.Count > 0 ? loggingCoverage.Average(c => c.CoveragePercent) : 0,
                    ClassesWithLowCoverage = loggingCoverage.Count(c => c.CoveragePercent < 20)
                }
            };
        }

        if (options.OptimizationAnalysis)
        {
            var analyzer = new OptimizationAnalyzer();
            var optimizations = await analyzer.AnalyzeAsync(project);
            result = result with { Optimizations = optimizations };
        }

        if (options.SecurityAnalysis)
        {
            var analyzer = new SecurityAnalyzer();
            var securityResult = await analyzer.AnalyzeAsync(project);
            result = result with
            {
                Security = new SecurityAnalysisResult
                {
                    TotalVulnerabilities = securityResult.Vulnerabilities.Count,
                    CriticalCount = securityResult.Summary.CriticalCount,
                    HighCount = securityResult.Summary.HighCount,
                    MediumCount = securityResult.Summary.MediumCount,
                    LowCount = securityResult.Summary.LowCount,
                    Vulnerabilities = securityResult.Vulnerabilities.Take(100).Select(v => new SecurityIssueItem
                    {
                        VulnerabilityType = v.VulnerabilityType,
                        Severity = v.Severity,
                        CweId = v.CweId,
                        FilePath = Path.GetRelativePath(projectDirectory, v.FilePath),
                        StartLine = v.StartLine,
                        EndLine = v.EndLine,
                        Description = v.Description,
                        Recommendation = v.Recommendation,
                        VulnerableCode = v.VulnerableCode,
                        SecureCode = v.SecureCode,
                        Confidence = v.Confidence
                    }).ToList(),
                    VulnerabilitiesByType = securityResult.Summary.VulnerabilitiesByType,
                    VulnerabilitiesByCwe = securityResult.Summary.VulnerabilitiesByCwe
                }
            };
        }

        if (options.DashboardAnalysis)
        {
            var dashboard = new MetricsDashboard();
            var metrics = await dashboard.GenerateDashboardAsync(project);
            result = result with
            {
                Metrics = new MetricsDashboardResult
                {
                    HealthScore = metrics.HealthScore,
                    TotalFiles = metrics.TotalFiles,
                    TotalLines = metrics.TotalLines,
                    TotalMethods = metrics.TotalMethods,
                    TotalClasses = metrics.TotalClasses,
                    AverageCyclomaticComplexity = metrics.AverageCyclomaticComplexity,
                    MaxCyclomaticComplexity = metrics.MaxCyclomaticComplexity,
                    MethodsAboveComplexityThreshold = metrics.MethodsAboveThreshold,
                    MaintainabilityIndex = metrics.MaintainabilityIndex,
                    TechnicalDebtMinutes = metrics.TechnicalDebtMinutes,
                    Hotspots = metrics.Hotspots.Take(10).Select(h => new HotspotFileItem
                    {
                        FilePath = Path.GetRelativePath(projectDirectory, h.FilePath),
                        IssueCount = h.IssueCount,
                        CriticalOrHighCount = h.CriticalOrHigh,
                        Lines = h.Lines,
                        Methods = h.Methods
                    }).ToList(),
                    IssuesByCategory = metrics.IssuesByCategory,
                    IssuesBySeverity = metrics.IssuesBySeverity
                }
            };
        }

        // ============================================================================
        // NEW ANALYZERS (Phase 1-4)
        // ============================================================================

        if (options.VulnerabilityAnalysis)
        {
            try
            {
                using var scanner = new Analyzers.Dependencies.VulnerabilityScanner();
                var vulnResult = await scanner.ScanAsync(projectPath);
                result = result with
                {
                    Vulnerabilities = new VulnerabilityResultDto
                    {
                        TotalPackages = vulnResult.TotalPackages,
                        VulnerablePackages = vulnResult.VulnerablePackages,
                        OutdatedPackages = vulnResult.OutdatedPackages,
                        DeprecatedPackages = vulnResult.DeprecatedPackages,
                        Vulnerabilities = vulnResult.Vulnerabilities.Take(50).Select(v => new PackageVulnerabilityDto
                        {
                            PackageId = v.PackageId,
                            InstalledVersion = v.InstalledVersion,
                            CveId = v.CveId,
                            GhsaId = v.GhsaId,
                            Severity = v.Severity,
                            CvssScore = v.CvssScore,
                            Description = v.Description,
                            FixedInVersion = v.FixedInVersion,
                            IsTransitive = v.IsTransitive,
                            AdvisoryUrl = v.AdvisoryUrl
                        }).ToList(),
                        Outdated = vulnResult.Outdated.Take(30).Select(o => new OutdatedPackageDto
                        {
                            PackageId = o.PackageId,
                            InstalledVersion = o.InstalledVersion,
                            LatestVersion = o.LatestVersion,
                            MajorVersionsBehind = o.MajorVersionsBehind,
                            UpdateUrgency = o.UpdateUrgency
                        }).ToList(),
                        Recommendations = vulnResult.Recommendations.Take(20).Select(r => new UpgradeRecommendationDto
                        {
                            PackageId = r.PackageId,
                            CurrentVersion = r.CurrentVersion,
                            RecommendedVersion = r.RecommendedVersion,
                            Reason = r.Reason,
                            Priority = r.Priority
                        }).ToList(),
                        Summary = new VulnerabilitySummaryDto
                        {
                            Critical = vulnResult.Summary.Critical,
                            High = vulnResult.Summary.High,
                            Medium = vulnResult.Summary.Medium,
                            Low = vulnResult.Summary.Low,
                            RiskScore = vulnResult.Summary.RiskScore,
                            RiskLevel = vulnResult.Summary.RiskLevel
                        }
                    }
                };
            }
            catch { /* Continue if vulnerability scanning fails */ }
        }

        if (options.MemoryLeakAnalysis)
        {
            try
            {
                var detector = new Analyzers.Memory.MemoryLeakDetector();
                var memResult = await detector.AnalyzeAsync(project);
                result = result with
                {
                    MemoryLeaks = new MemoryLeakResultDto
                    {
                        TotalLeaks = memResult.Summary.TotalLeaks,
                        Leaks = memResult.Leaks.Take(50).Select(l => new MemoryLeakDto
                        {
                            LeakType = l.LeakType,
                            Severity = l.Severity,
                            FilePath = Path.GetRelativePath(projectDirectory, l.FilePath),
                            Line = l.StartLine,
                            Description = l.Description,
                            LeakedResource = l.ProblematicCode ?? "",
                            Recommendation = l.Recommendation,
                            FixCode = l.SuggestedFix
                        }).ToList()
                    }
                };
            }
            catch { /* Continue if memory analysis fails */ }
        }

        if (options.LoggingAnalysis)
        {
            try
            {
                var analyzer = new Analyzers.Logging.LoggingQualityAnalyzer();
                var logResult = await analyzer.AnalyzeAsync(project);
                result = result with
                {
                    LoggingQuality = new LoggingQualityResultDto
                    {
                        TotalLogStatements = logResult.Summary.TotalIssues,
                        Issues = logResult.Issues.Take(50).Select(i => new LoggingIssueDto
                        {
                            IssueType = i.IssueType.ToString(),
                            Severity = i.Severity.ToString(),
                            FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                            Line = i.StartLine,
                            CurrentCode = i.ProblematicCode ?? "",
                            Recommendation = i.Suggestion ?? "",
                            SuggestedCode = i.RecommendedCode
                        }).ToList(),
                        SensitiveDataLogs = logResult.Issues
                            .Where(i => i.IssueType == Analyzers.Logging.Models.LoggingIssueType.SensitiveDataLogged)
                            .Take(20)
                            .Select(i => new SensitiveLogDto
                            {
                                SensitiveType = i.Metadata.GetValueOrDefault("SensitiveType", "Unknown"),
                                FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                                Line = i.StartLine,
                                VariableName = i.Metadata.GetValueOrDefault("VariableName", ""),
                                Recommendation = i.Suggestion ?? "Remove sensitive data from logs"
                            }).ToList(),
                        StructuredLoggingPercentage = logResult.Summary.QualityScore
                    }
                };
            }
            catch { /* Continue if logging analysis fails */ }
        }

        if (options.ConfigurationAnalysis)
        {
            try
            {
                var analyzer = new Analyzers.Configuration.ConfigurationAnalyzer();
                var configResult = await analyzer.AnalyzeAsync(project);
                result = result with
                {
                    Configuration = new ConfigurationResultDto
                    {
                        HardcodedValues = configResult.Issues
                            .Where(i => i.IssueType == Analyzers.Configuration.Models.ConfigurationIssueType.HardcodedConnection ||
                                       i.IssueType == Analyzers.Configuration.Models.ConfigurationIssueType.HardcodedUrl ||
                                       i.IssueType == Analyzers.Configuration.Models.ConfigurationIssueType.HardcodedPath ||
                                       i.IssueType == Analyzers.Configuration.Models.ConfigurationIssueType.HardcodedCredential)
                            .Take(30)
                            .Select(i => new HardcodedConfigDto
                            {
                                ValueType = i.IssueType.ToString(),
                                Value = i.DetectedValue ?? "",
                                FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                                Line = i.StartLine,
                                SuggestedConfigKey = i.ConfigKey ?? "",
                                Recommendation = i.Recommendation
                            }).ToList(),
                        EnvironmentCode = configResult.EnvironmentPatterns.Take(20).Select(p => new EnvironmentCodeDto
                        {
                            IssueType = p.PatternType.ToString(),
                            FilePath = Path.GetRelativePath(projectDirectory, p.FilePath),
                            Line = p.Line,
                            Environment = p.EnvironmentName,
                            Description = p.Description
                        }).ToList(),
                        MissingConfigKeys = configResult.Summary.MissingConfigKeys.Take(20).Select(k => new ConfigKeyDto
                        {
                            Key = k,
                            Source = "Code"
                        }).ToList(),
                        UnusedConfigKeys = configResult.Summary.UnusedConfigKeys.Take(20).Select(k => new ConfigKeyDto
                        {
                            Key = k,
                            Source = "Configuration"
                        }).ToList()
                    }
                };
            }
            catch { /* Continue if configuration analysis fails */ }
        }

        if (options.NamingAnalysis)
        {
            try
            {
                var analyzer = new Analyzers.Naming.NamingConventionAnalyzer();
                var namingResult = await analyzer.AnalyzeAsync(project);
                result = result with
                {
                    Naming = new NamingResultDto
                    {
                        TotalViolations = namingResult.Summary.TotalViolations,
                        Violations = namingResult.Violations.Take(50).Select(v => new NamingViolationDto
                        {
                            Rule = v.RuleId,
                            ElementType = v.SymbolCategory.ToString(),
                            CurrentName = v.SymbolName,
                            SuggestedName = v.SuggestedName ?? "",
                            FilePath = Path.GetRelativePath(projectDirectory, v.FilePath),
                            Line = v.Line
                        }).ToList(),
                        MisleadingNames = namingResult.SemanticIssues.SelectMany(s => s.Issues.Select(i => new { Issue = i, Parent = s })).Take(20).Select(x => new MisleadingNameDto
                        {
                            MemberName = x.Parent.SymbolName,
                            MemberType = x.Issue.IssueType,
                            FilePath = Path.GetRelativePath(projectDirectory, x.Parent.FilePath),
                            Line = x.Parent.Line,
                            Issue = x.Issue.Message,
                            Suggestion = x.Issue.Suggestion ?? ""
                        }).ToList(),
                        InconsistentTerms = namingResult.TermInconsistencies.Take(10).Select(t => new InconsistentTermDto
                        {
                            Term = t.Concept,
                            Variations = t.VariantTerms,
                            OccurrenceCount = t.TotalOccurrences,
                            Recommendation = t.RecommendedTerm ?? ""
                        }).ToList(),
                        ViolationsByRule = namingResult.Summary.ViolationsByRule
                    }
                };
            }
            catch { /* Continue if naming analysis fails */ }
        }

        if (options.TechnicalDebtAnalysis)
        {
            try
            {
                var scorer = new Analyzers.Debt.TechnicalDebtScorer();
                var debtResult = await scorer.AnalyzeAsync(project, result);
                result = result with
                {
                    TechnicalDebt = new TechnicalDebtResultDto
                    {
                        TotalDebtMinutes = debtResult.TotalDebtMinutes,
                        TotalDebtDays = debtResult.TotalDebtMinutes / 480.0,
                        DebtRatio = debtResult.Score / 100.0,
                        DebtRating = debtResult.Rating,
                        QuickWins = debtResult.QuickWins.Take(10).Select(i => new Services.DebtItemDto
                        {
                            Category = i.Category,
                            IssueType = i.Type,
                            FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                            Line = i.Line,
                            Description = i.Description,
                            EstimatedMinutes = i.TimeToFixMinutes,
                            Interest = i.InterestPerWeek,
                            Priority = (int)i.Priority
                        }).ToList(),
                        MajorProjects = debtResult.MajorProjects.Take(10).Select(i => new Services.DebtItemDto
                        {
                            Category = i.Category,
                            IssueType = i.Type,
                            FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                            Line = i.Line,
                            Description = i.Description,
                            EstimatedMinutes = i.TimeToFixMinutes,
                            Interest = i.InterestPerWeek,
                            Priority = (int)i.Priority
                        }).ToList(),
                        DebtByCategory = debtResult.Summary.DebtByCategory.ToDictionary(kv => kv.Key, kv => (double)kv.Value),
                        Trend = new Services.DebtTrendDto
                        {
                            WeeklyChange = 0,
                            MonthlyChange = debtResult.Trend.PercentageChange,
                            TrendDirection = debtResult.Trend.Direction.ToString()
                        }
                    }
                };
            }
            catch { /* Continue if debt analysis fails */ }
        }

        if (options.ThreadSafetyAnalysis)
        {
            try
            {
                var analyzer = new Analyzers.Concurrency.ThreadSafetyAnalyzer();
                var issues = new List<ThreadSafetyIssueDto>();
                var sharedState = new List<SharedStateDto>();

                foreach (var document in project.Documents)
                {
                    if (document.FilePath == null) continue;
                    var semanticModel = await document.GetSemanticModelAsync();
                    var root = await document.GetSyntaxRootAsync();
                    if (semanticModel == null || root == null) continue;

                    var docResult = await analyzer.AnalyzeAsync(document, semanticModel, root);
                    issues.AddRange(docResult.Issues.Take(20).Select(i => new ThreadSafetyIssueDto
                    {
                        IssueType = i.IssueType,
                        Severity = i.Severity,
                        FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                        Line = i.Line,
                        Description = i.Message,
                        SharedResource = i.MemberName ?? "",
                        AccessingMethods = new List<string> { i.MethodName ?? "" }.Where(m => !string.IsNullOrEmpty(m)).ToList(),
                        Recommendation = i.SuggestedFix ?? "",
                        FixCode = i.SuggestedFix
                    }));
                }

                result = result with
                {
                    ThreadSafety = new ThreadSafetyResultDto
                    {
                        TotalIssues = issues.Count,
                        Issues = issues.Take(50).ToList(),
                        SharedState = sharedState
                    }
                };
            }
            catch { /* Continue if thread safety analysis fails */ }
        }

        if (options.DocumentationAnalysis)
        {
            try
            {
                var analyzer = new Analyzers.Documentation.DocumentationAnalyzer();
                var docResult = await analyzer.AnalyzeAsync(project);
                result = result with
                {
                    Documentation = new DocumentationResultDto
                    {
                        DocumentationCoverage = docResult.Summary.OverallCoveragePercentage,
                        TotalPublicMembers = docResult.Summary.TotalPublicSymbols,
                        DocumentedMembers = docResult.Summary.DocumentedPublicSymbols,
                        MissingDocs = docResult.Issues
                            .Where(i => i.IssueType == Analyzers.Documentation.Models.DocumentationIssueType.MissingPublicDoc)
                            .Take(30)
                            .Select(i => new MissingDocDto
                            {
                                MemberType = i.SymbolKind,
                                MemberName = i.SymbolName,
                                FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                                Line = i.StartLine,
                                Severity = i.Severity.ToString()
                            }).ToList(),
                        StaleDocs = docResult.Issues
                            .Where(i => i.IssueType == Analyzers.Documentation.Models.DocumentationIssueType.StaleComment)
                            .Take(20)
                            .Select(i => new StaleDocDto
                            {
                                IssueType = i.IssueType.ToString(),
                                FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                                Line = i.StartLine,
                                Description = i.Description,
                                Suggestion = i.Suggestion
                            }).ToList(),
                        UnresolvedTodos = docResult.Issues
                            .Where(i => i.IssueType == Analyzers.Documentation.Models.DocumentationIssueType.TodoComment)
                            .Take(20)
                            .Select(i => new TodoCommentDto
                            {
                                CommentType = "TODO",
                                Text = i.Description,
                                FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                                Line = i.StartLine
                            }).ToList(),
                        CoverageByNamespace = new Dictionary<string, double>()
                    }
                };
            }
            catch { /* Continue if documentation analysis fails */ }
        }

        if (options.CloneAnalysis)
        {
            try
            {
                var detector = new Analyzers.Clones.SemanticCloneDetector();
                var cloneResult = await detector.AnalyzeProjectAsync(project);
                result = result with
                {
                    Clones = new CloneAnalysisResultDto
                    {
                        CloneCoverage = cloneResult.Metrics.CloneCoverage,
                        TotalCloneClasses = cloneResult.CloneClasses.Count,
                        TotalClonedLines = cloneResult.CloneClasses.Sum(c => c.TotalLines),
                        CloneClasses = cloneResult.CloneClasses.Take(20).Select(c => new CloneClassDto
                        {
                            CloneId = c.Id,
                            CloneType = c.CloneType.ToString(),
                            InstanceCount = c.InstanceCount,
                            LinesPerInstance = c.Fragments.FirstOrDefault()?.LineCount ?? 0,
                            Similarity = c.AverageSimilarity,
                            Instances = c.Fragments.Take(5).Select(i => new CloneInstanceDto
                            {
                                FilePath = Path.GetRelativePath(projectDirectory, i.FilePath),
                                StartLine = i.StartLine,
                                EndLine = i.EndLine,
                                CodeSnippet = i.NormalizedCode?.Length > 200 ? i.NormalizedCode[..200] + "..." : i.NormalizedCode
                            }).ToList(),
                            SuggestedMethodName = cloneResult.ExtractionOpportunities.FirstOrDefault(e => e.CloneClass.Id == c.Id)?.SuggestedName ?? ""
                        }).ToList(),
                        ExtractionOpportunities = cloneResult.ExtractionOpportunities.Take(10).Select(e => new ExtractionOpportunityDto
                        {
                            CloneId = e.CloneClass.Id,
                            SuggestedRefactoring = e.ExtractionType.ToString(),
                            EstimatedLinesReduced = e.EstimatedLinesSaved,
                            ProposedCode = e.SuggestedName
                        }).ToList()
                    }
                };
            }
            catch { /* Continue if clone analysis fails */ }
        }

        if (options.ImpactAnalysis && !string.IsNullOrEmpty(options.ImpactSymbol))
        {
            try
            {
                var analyzer = new Analyzers.Impact.ChangeImpactAnalyzer();
                await analyzer.InitializeFromProjectAsync(project);
                var impactResult = analyzer.AnalyzeChange(options.ImpactSymbol, Analyzers.Impact.Models.ChangeType.BehaviorChange);

                // Build impacted files from direct and transitive impacts
                var allImpactedFiles = impactResult.DirectImpact.ByFile
                    .Concat(impactResult.TransitiveImpact.ByFile)
                    .GroupBy(kvp => kvp.Key)
                    .ToDictionary(g => g.Key, g => g.SelectMany(x => x.Value).Distinct().ToList());

                result = result with
                {
                    Impact = new ImpactAnalysisResultDto
                    {
                        TargetSymbol = options.ImpactSymbol,
                        DirectDependents = impactResult.DirectImpact.Count,
                        TransitiveDependents = impactResult.TransitiveImpact.Count,
                        RiskLevel = impactResult.Risk.Level.ToString(),
                        ImpactedFiles = allImpactedFiles.Take(20).Select(kvp => new ImpactedFileDto
                        {
                            FilePath = Path.GetRelativePath(projectDirectory, kvp.Key),
                            ImpactedSymbols = kvp.Value.Count,
                            ImpactType = "Transitive"
                        }).ToList(),
                        ImpactChains = [], // Chains not available in this model
                        TestsToRun = [], // Tests not available in this model
                        ImpactByNamespace = [] // Namespace breakdown not available
                    }
                };
            }
            catch { /* Continue if impact analysis fails */ }
        }

        // Update summary totals
        result = result with
        {
            Summary = result.Summary with
            {
                PerformanceIssues = result.PerformanceIssues?.Count ?? 0,
                ExceptionIssues = result.ExceptionHandlingIssues?.Count ?? 0,
                ResourceIssues = result.ResourceLeakIssues?.Count ?? 0,
                MagicValues = result.MagicValues?.Count ?? 0,
                LongMethods = result.Refactoring?.LongMethods.Count ?? 0,
                GodClasses = result.Refactoring?.GodClasses.Count ?? 0,
                NullSafetyIssues = result.Safety?.NullIssues.Count ?? 0,
                ImmutabilityOpportunities = result.Safety?.ImmutabilityIssues.Count ?? 0,
                LoggingGaps = result.Safety?.LoggingGaps.Count ?? 0,
                OptimizationOpportunities = result.Optimizations?.Opportunities.Count ?? 0,
                TotalIssues = (result.PerformanceIssues?.Count ?? 0) +
                              (result.ExceptionHandlingIssues?.Count ?? 0) +
                              (result.ResourceLeakIssues?.Count ?? 0) +
                              (result.Refactoring?.LongMethods.Count ?? 0) +
                              (result.Refactoring?.GodClasses.Count ?? 0) +
                              (result.Safety?.NullIssues.Count ?? 0) +
                              (result.Optimizations?.Opportunities.Count ?? 0)
            }
        };

        return result;
    }

    private async Task<(List<DeprecatedCodeItem>, List<UsageItem>, List<UsageItem>)> AnalyzeDeepAsync(
        Project project, Compilation compilation, string projectDirectory)
    {
        var deprecated = new List<DeprecatedCodeItem>();
        var usageCounts = new ConcurrentDictionary<ISymbol, int>(SymbolEqualityComparer.Default);
        var symbolLocations = new ConcurrentDictionary<ISymbol, (string FilePath, int Line, string Kind)>(SymbolEqualityComparer.Default);

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null) continue;

            var semanticModel = await document.GetSemanticModelAsync();
            var syntaxRoot = await document.GetSyntaxRootAsync();
            if (semanticModel == null || syntaxRoot == null) continue;

            // Find deprecated items
            var declarations = syntaxRoot.DescendantNodes()
                .Where(n => n is TypeDeclarationSyntax or MethodDeclarationSyntax or PropertyDeclarationSyntax);

            foreach (var declaration in declarations)
            {
                ISymbol? symbol = declaration switch
                {
                    TypeDeclarationSyntax typeDecl => semanticModel.GetDeclaredSymbol(typeDecl),
                    MethodDeclarationSyntax methodDecl => semanticModel.GetDeclaredSymbol(methodDecl),
                    PropertyDeclarationSyntax propDecl => semanticModel.GetDeclaredSymbol(propDecl),
                    _ => null
                };

                if (symbol == null) continue;

                var obsoleteAttr = symbol.GetAttributes()
                    .FirstOrDefault(a => a.AttributeClass?.Name == "ObsoleteAttribute");

                if (obsoleteAttr != null)
                {
                    var message = obsoleteAttr.ConstructorArguments.FirstOrDefault().Value?.ToString() ?? "";
                    var isError = obsoleteAttr.ConstructorArguments.Length > 1 &&
                                 obsoleteAttr.ConstructorArguments[1].Value is true;

                    deprecated.Add(new DeprecatedCodeItem
                    {
                        SymbolKind = GetSymbolKind(symbol),
                        SymbolName = symbol.Name,
                        FilePath = Path.GetRelativePath(projectDirectory, document.FilePath),
                        Line = declaration.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        Message = message,
                        IsError = isError,
                        Replacement = ExtractReplacement(message)
                    });
                }

                // Track usage
                if (!IsGeneratedCode(symbol))
                {
                    usageCounts.TryAdd(symbol, 0);
                    symbolLocations.TryAdd(symbol, (document.FilePath, declaration.GetLocation().GetLineSpan().StartLinePosition.Line + 1, GetSymbolKind(symbol)));
                }
            }
        }

        // Count references
        foreach (var symbol in usageCounts.Keys.ToList())
        {
            try
            {
                var references = await SymbolFinder.FindReferencesAsync(symbol, project.Solution);
                usageCounts[symbol] = references.Sum(r => r.Locations.Count());
            }
            catch { }
        }

        var deadCode = usageCounts.Where(kv => kv.Value == 0)
            .Select(kv =>
            {
                var loc = symbolLocations.GetValueOrDefault(kv.Key);
                return new UsageItem
                {
                    SymbolKind = loc.Kind ?? "Unknown",
                    SymbolName = kv.Key.Name,
                    FilePath = !string.IsNullOrEmpty(loc.FilePath) ? Path.GetRelativePath(projectDirectory, loc.FilePath) : "",
                    Line = loc.Line,
                    ReferenceCount = 0
                };
            }).Where(u => !string.IsNullOrEmpty(u.FilePath)).Take(50).ToList();

        var lowUsage = usageCounts.Where(kv => kv.Value >= 1 && kv.Value <= 2)
            .Select(kv =>
            {
                var loc = symbolLocations.GetValueOrDefault(kv.Key);
                return new UsageItem
                {
                    SymbolKind = loc.Kind ?? "Unknown",
                    SymbolName = kv.Key.Name,
                    FilePath = !string.IsNullOrEmpty(loc.FilePath) ? Path.GetRelativePath(projectDirectory, loc.FilePath) : "",
                    Line = loc.Line,
                    ReferenceCount = kv.Value
                };
            }).Where(u => !string.IsNullOrEmpty(u.FilePath)).Take(50).ToList();

        return (deprecated, deadCode, lowUsage);
    }

    private async Task<SentimentResult> AnalyzeSentimentAsync(Project project, string projectDirectory)
    {
        var analyzer = new CodeSentimentAnalyzer();
        var blocks = await analyzer.AnalyzeProjectAsync(project);
        var similarGroups = analyzer.FindSimilarBlocks(blocks);

        var qualityDistribution = blocks.GroupBy(b => b.QualityRating)
            .ToDictionary(g => g.Key, g => g.Count());

        var markerCounts = blocks.SelectMany(b => b.SentimentMarkers)
            .GroupBy(m => m)
            .ToDictionary(g => g.Key, g => g.Count());

        return new SentimentResult
        {
            TotalBlocks = blocks.Count,
            AverageQualityScore = blocks.Count > 0 ? blocks.Average(b => b.QualityScore) : 0,
            AverageComplexity = blocks.Count > 0 ? blocks.Average(b => b.CyclomaticComplexity) : 0,
            HighComplexityCount = blocks.Count(b => b.CyclomaticComplexity > 15),
            ProblematicCount = blocks.Count(b => b.QualityScore < 40),
            DuplicateGroups = similarGroups.Count(g => g.SimilarityScore >= 1.0),
            SimilarGroups = similarGroups.Count(g => g.SimilarityScore < 1.0),
            QualityDistribution = qualityDistribution,
            MarkerCounts = markerCounts,
            ProblematicBlocks = blocks.Where(b => b.QualityScore < 40).Take(15).Select(b => new CodeBlockItem
            {
                FilePath = Path.GetRelativePath(projectDirectory, b.FilePath),
                Line = b.StartLine,
                BlockType = b.BlockType.ToString(),
                ContainingType = b.ContainingType,
                Name = b.Name,
                QualityScore = b.QualityScore,
                QualityRating = b.QualityRating,
                CyclomaticComplexity = b.CyclomaticComplexity,
                NestingDepth = b.NestingDepth,
                LineCount = b.LineCount,
                SentimentMarkers = b.SentimentMarkers
            }).ToList(),
            HighComplexityBlocks = blocks.Where(b => b.CyclomaticComplexity > 15).Take(15).Select(b => new CodeBlockItem
            {
                FilePath = Path.GetRelativePath(projectDirectory, b.FilePath),
                Line = b.StartLine,
                BlockType = b.BlockType.ToString(),
                ContainingType = b.ContainingType,
                Name = b.Name,
                QualityScore = b.QualityScore,
                QualityRating = b.QualityRating,
                CyclomaticComplexity = b.CyclomaticComplexity,
                NestingDepth = b.NestingDepth,
                LineCount = b.LineCount,
                SentimentMarkers = b.SentimentMarkers
            }).ToList()
        };
    }

    private static string GetSymbolKind(ISymbol symbol) => symbol.Kind switch
    {
        SymbolKind.NamedType => ((INamedTypeSymbol)symbol).TypeKind switch
        {
            TypeKind.Class => "Class",
            TypeKind.Interface => "Interface",
            TypeKind.Struct => "Struct",
            TypeKind.Enum => "Enum",
            _ => "Type"
        },
        SymbolKind.Method => "Method",
        SymbolKind.Property => "Property",
        SymbolKind.Field => "Field",
        _ => symbol.Kind.ToString()
    };

    private static bool IsGeneratedCode(ISymbol symbol) =>
        symbol.GetAttributes().Any(a =>
            a.AttributeClass?.Name == "GeneratedCodeAttribute" ||
            a.AttributeClass?.Name == "CompilerGeneratedAttribute");

    private static string? ExtractReplacement(string message)
    {
        if (string.IsNullOrEmpty(message)) return null;
        var match = Regex.Match(message, @"[Uu]se\s+(\w+(?:\.\w+)*)\s+instead", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : null;
    }

    /// <summary>
    /// Analyze a solution file - loads all projects and performs cross-project analysis.
    /// This enables finding dead code across the entire solution.
    /// </summary>
    private async Task<AnalysisResult> AnalyzeSolutionAsync(string solutionPath, AnalysisOptions options)
    {
        var resolvedPath = ResolveSolutionPath(solutionPath);
        var solutionDirectory = Path.GetDirectoryName(resolvedPath)!;

        Console.WriteLine($"Loading solution: {Path.GetFileName(resolvedPath)}");
        
        using var workspace = MSBuildWorkspace.Create();
#pragma warning disable CS0618
        workspace.WorkspaceFailed += (sender, e) => { /* Suppress warnings */ };
#pragma warning restore CS0618

        var solution = await workspace.OpenSolutionAsync(resolvedPath);
        var projects = solution.Projects.ToList();
        
        Console.WriteLine($"Found {projects.Count} projects in solution");
        
        // Get all .cs files on disk across all project directories
        var allCsFilesOnDisk = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var project in projects)
        {
            var projectDir = Path.GetDirectoryName(project.FilePath);
            if (projectDir != null && Directory.Exists(projectDir))
            {
                var files = Directory.GetFiles(projectDir, "*.cs", SearchOption.AllDirectories)
                    .Where(f => !f.Contains(Path.Combine(projectDir, "obj")) &&
                                !f.Contains(Path.Combine(projectDir, "bin")));
                foreach (var f in files)
                {
                    allCsFilesOnDisk.Add(Path.GetFullPath(f));
                }
            }
        }

        // Get all compiled files from all projects
        var compiledFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var project in projects)
        {
            var docs = project.Documents.Where(d => d.FilePath != null);
            foreach (var doc in docs)
            {
                compiledFiles.Add(Path.GetFullPath(doc.FilePath!));
            }
        }

        // Build result
        var summary = new AnalysisSummary
        {
            TotalFilesOnDisk = allCsFilesOnDisk.Count,
            FilesInCompilation = compiledFiles.Count
        };

        var unusedFiles = allCsFilesOnDisk.Where(f => !compiledFiles.Contains(f))
            .Select(f => Path.GetRelativePath(solutionDirectory, f)).ToList();
        var missingFiles = compiledFiles.Where(f => !File.Exists(f))
            .Select(f => Path.GetRelativePath(solutionDirectory, f)).ToList();

        var result = new AnalysisResult
        {
            ProjectPath = solutionPath,
            Summary = summary with
            {
                UnusedFiles = unusedFiles.Count,
                MissingFiles = missingFiles.Count
            },
            UnusedFiles = unusedFiles,
            MissingFiles = missingFiles
        };

        // Run deep analysis across all projects
        if (options.DeepAnalysis)
        {
            Console.WriteLine("Performing deep cross-project analysis...");
            
            // Get all compilations
            var compilations = new List<Compilation>();
            foreach (var project in projects)
            {
                var comp = await project.GetCompilationAsync();
                if (comp != null)
                    compilations.Add(comp);
            }

            if (compilations.Count > 0)
            {
                var (deprecated, dead, lowUsage) = await AnalyzeSolutionDeepAsync(solution, compilations, solutionDirectory);
                result = result with
                {
                    DeprecatedCode = deprecated,
                    DeadCode = dead,
                    LowUsageCode = lowUsage
                };
            }
        }

        return result;
    }

    /// <summary>
    /// Perform deep analysis across all projects in a solution.
    /// This tracks references across project boundaries using SymbolFinder.
    /// </summary>
    private async Task<(List<DeprecatedCodeItem> deprecated, List<UsageItem> dead, List<UsageItem> lowUsage)> 
        AnalyzeSolutionDeepAsync(Solution solution, List<Compilation> compilations, string solutionDirectory)
    {
        var deprecated = new List<DeprecatedCodeItem>();
        var dead = new List<UsageItem>();
        var lowUsage = new List<UsageItem>();

        Console.WriteLine("  Collecting symbols from all projects...");
        
        // Collect all symbols we want to analyze (public/internal types and members)
        var symbolsToAnalyze = new List<ISymbol>();
        
        foreach (var project in solution.Projects)
        {
            var comp = await project.GetCompilationAsync();
            if (comp == null) continue;

            // Get all named types in this compilation
            var visitor = new SymbolCollector();
            visitor.Visit(comp.Assembly.GlobalNamespace);
            symbolsToAnalyze.AddRange(visitor.Symbols);
        }

        Console.WriteLine($"  Analyzing {symbolsToAnalyze.Count} symbols for references...");

        // Use SymbolFinder to find references for each symbol across the entire solution
        var referenceCount = new ConcurrentDictionary<ISymbol, int>(SymbolEqualityComparer.Default);
        
        var tasks = symbolsToAnalyze.Select(async symbol =>
        {
            try
            {
                // Use SymbolFinder.FindReferencesAsync for accurate cross-project reference counting
                var references = await SymbolFinder.FindReferencesAsync(symbol, solution);
                var count = references.SelectMany(r => r.Locations).Count();
                
                // Subtract 1 for the definition itself (if it's counted)
                if (count > 0 && references.Any(r => r.Definition?.Equals(symbol, SymbolEqualityComparer.Default) == true))
                {
                    count = Math.Max(0, count - 1);
                }
                
                referenceCount[symbol] = count;
            }
            catch
            {
                // Symbol finder can fail for some symbols, skip them
                referenceCount[symbol] = -1; // Mark as unknown
            }
        });

        await Task.WhenAll(tasks);

        Console.WriteLine($"  Classifying symbols by usage...");

        // Classify symbols as dead or low usage
        foreach (var kvp in referenceCount.Where(k => k.Value >= 0))
        {
            var symbol = kvp.Key;
            var count = kvp.Value;

            if (IsGeneratedCode(symbol)) continue;

            var location = symbol.Locations.FirstOrDefault();
            if (location == null || !location.IsInSource) continue;

            var filePath = location.SourceTree?.FilePath;
            var line = location.GetLineSpan().StartLinePosition.Line + 1;

            if (filePath != null)
            {
                var relativePath = Path.GetRelativePath(solutionDirectory, filePath);

                if (count == 0)
                {
                    var kind = GetSymbolKind(symbol);
                    dead.Add(new UsageItem
                    {
                        FilePath = relativePath,
                        Line = line,
                        SymbolName = symbol.Name,
                        SymbolKind = kind,
                        ReferenceCount = 0
                    });
                }
                else if (count <= 2)
                {
                    var kind = GetSymbolKind(symbol);
                    lowUsage.Add(new UsageItem
                    {
                        FilePath = relativePath,
                        Line = line,
                        SymbolName = symbol.Name,
                        SymbolKind = kind,
                        ReferenceCount = count
                    });
                }
            }
        }

        Console.WriteLine($"  Found {dead.Count} dead code items, {lowUsage.Count} low usage items");
        
        return (deprecated, dead, lowUsage);
    }

    private async Task<SemanticModel?> GetSemanticModelForProject(Project project)
    {
        var comp = await project.GetCompilationAsync();
        if (comp == null) return null;

        var syntaxTree = comp.SyntaxTrees.FirstOrDefault();
        if (syntaxTree == null) return null;

        return comp.GetSemanticModel(syntaxTree);
    }

    private void CollectSymbols(INamespaceSymbol namespaceSymbol, Dictionary<string, ISymbol> symbolIndex)
    {
        foreach (var type in namespaceSymbol.GetTypeMembers())
        {
            // Index public types
            if (type.DeclaredAccessibility == Accessibility.Public)
            {
                var key = type.Name;
                if (!symbolIndex.ContainsKey(key))
                    symbolIndex[key] = type;
            }

            // Also index public members
            foreach (var member in type.GetMembers())
            {
                if (member.DeclaredAccessibility == Accessibility.Public)
                {
                    var key = $"{type.Name}.{member.Name}";
                    if (!symbolIndex.ContainsKey(key))
                        symbolIndex[key] = member;
                }
            }
        }

        // Recurse into nested namespaces
        foreach (var nested in namespaceSymbol.GetNamespaceMembers())
        {
            CollectSymbols(nested, symbolIndex);
        }
    }

    /// <summary>
    /// Visitor class to collect all symbols from a namespace recursively.
    /// </summary>
    private class SymbolCollector : SymbolVisitor
    {
        public List<ISymbol> Symbols { get; } = new List<ISymbol>();

        public override void VisitNamespace(INamespaceSymbol symbol)
        {
            // Visit all types in this namespace
            foreach (var type in symbol.GetTypeMembers())
            {
                type.Accept(this);
            }

            // Recurse into nested namespaces
            foreach (var ns in symbol.GetNamespaceMembers())
            {
                ns.Accept(this);
            }
        }

        public override void VisitNamedType(INamedTypeSymbol symbol)
        {
            // Skip compiler-generated types
            if (symbol.IsImplicitlyDeclared) return;
            if (symbol.Name.Contains("<")) return; // Anonymous types
            
            // Add the type itself if it's public or internal
            if (symbol.DeclaredAccessibility == Accessibility.Public || 
                symbol.DeclaredAccessibility == Accessibility.Internal)
            {
                Symbols.Add(symbol);
            }

            // Add all members (methods, properties, fields)
            foreach (var member in symbol.GetMembers())
            {
                if (member.IsImplicitlyDeclared) continue;
                if (member.Name.Contains("<")) continue; // Compiler-generated

                if (member.DeclaredAccessibility == Accessibility.Public || 
                    member.DeclaredAccessibility == Accessibility.Internal ||
                    member.DeclaredAccessibility == Accessibility.Private)
                {
                    Symbols.Add(member);
                }
            }

            // Visit nested types
            foreach (var nested in symbol.GetTypeMembers())
            {
                nested.Accept(this);
            }
        }
    }
}
