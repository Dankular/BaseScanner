using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using BaseScanner.Analyzers.Impact.Models;
using BaseScanner.Context;
using ImpactSymbolKind = BaseScanner.Analyzers.Impact.Models.SymbolKind;

namespace BaseScanner.Analyzers.Impact;

/// <summary>
/// Main coordinator for change impact analysis.
/// Provides a high-level API for analyzing the impact of code changes.
/// </summary>
public class ChangeImpactAnalyzer
{
    private readonly ImpactAnalysisOptions _options;
    private readonly DependencyGraphBuilder _graphBuilder;
    private readonly ImpactCalculator _impactCalculator;
    private readonly WhatIfAnalyzer _whatIfAnalyzer;

    private DependencyGraph? _cachedGraph;
    private string? _cachedProjectPath;

    public ChangeImpactAnalyzer(ImpactAnalysisOptions? options = null)
    {
        _options = options ?? new ImpactAnalysisOptions();
        _graphBuilder = new DependencyGraphBuilder(_options);
        _impactCalculator = new ImpactCalculator(_options);
        _whatIfAnalyzer = new WhatIfAnalyzer(_options);
    }

    /// <summary>
    /// Initializes the analyzer by building the dependency graph from a project.
    /// </summary>
    public async Task<DependencyGraph> InitializeFromProjectAsync(Project project)
    {
        _cachedGraph = await _graphBuilder.BuildFromProjectAsync(project);
        _cachedProjectPath = project.FilePath ?? project.Name;
        return _cachedGraph;
    }

    /// <summary>
    /// Initializes the analyzer by building the dependency graph from a solution.
    /// </summary>
    public async Task<DependencyGraph> InitializeFromSolutionAsync(Solution solution)
    {
        _cachedGraph = await _graphBuilder.BuildFromSolutionAsync(solution);
        _cachedProjectPath = solution.FilePath ?? "Solution";
        return _cachedGraph;
    }

    /// <summary>
    /// Gets the current dependency graph.
    /// </summary>
    public DependencyGraph? GetGraph() => _cachedGraph;

    /// <summary>
    /// Gets statistics about the dependency graph.
    /// </summary>
    public DependencyGraphStats? GetGraphStats()
    {
        if (_cachedGraph == null) return null;
        return _graphBuilder.GetStats(_cachedGraph);
    }

    /// <summary>
    /// Analyzes the impact of changing a specific symbol.
    /// </summary>
    public ImpactAnalysisResult AnalyzeChange(string symbolFullName, ChangeType changeType)
    {
        EnsureGraphInitialized();
        return _impactCalculator.CalculateImpact(_cachedGraph!, symbolFullName, changeType);
    }

    /// <summary>
    /// Analyzes the impact of multiple changes together.
    /// </summary>
    public BatchImpactResult AnalyzeBatchChanges(IEnumerable<(string Symbol, ChangeType ChangeType)> changes)
    {
        EnsureGraphInitialized();
        return _impactCalculator.CalculateBatchImpact(_cachedGraph!, changes);
    }

    /// <summary>
    /// Performs what-if analysis for a method signature change.
    /// </summary>
    public async Task<WhatIfResult> WhatIfSignatureChangeAsync(
        Project project,
        string methodFullName,
        string newSignature)
    {
        EnsureGraphInitialized();
        return await _whatIfAnalyzer.AnalyzeSignatureChangeAsync(_cachedGraph!, project, methodFullName, newSignature);
    }

    /// <summary>
    /// Performs what-if analysis for deleting a symbol.
    /// </summary>
    public async Task<WhatIfResult> WhatIfDeletionAsync(Project project, string symbolFullName)
    {
        EnsureGraphInitialized();
        return await _whatIfAnalyzer.AnalyzeDeletionAsync(_cachedGraph!, project, symbolFullName);
    }

    /// <summary>
    /// Performs what-if analysis for renaming a symbol.
    /// </summary>
    public async Task<WhatIfResult> WhatIfRenameAsync(Project project, string symbolFullName, string newName)
    {
        EnsureGraphInitialized();
        return await _whatIfAnalyzer.AnalyzeRenameAsync(_cachedGraph!, project, symbolFullName, newName);
    }

    /// <summary>
    /// Performs a quick impact check without full analysis.
    /// </summary>
    public QuickImpactCheck QuickCheck(string symbolFullName)
    {
        EnsureGraphInitialized();
        return _whatIfAnalyzer.PerformQuickCheck(_cachedGraph!, symbolFullName);
    }

    /// <summary>
    /// Gets all symbols that would be impacted by changing the given symbol.
    /// </summary>
    public ImmutableHashSet<string> GetImpactedSymbols(string symbolFullName, bool includeTransitive = true)
    {
        EnsureGraphInitialized();

        var directImpact = _impactCalculator.CalculateDirectImpact(_cachedGraph!, symbolFullName);

        if (!includeTransitive)
        {
            return directImpact.Symbols;
        }

        var transitiveImpact = _impactCalculator.CalculateTransitiveImpact(_cachedGraph!, symbolFullName);
        return transitiveImpact.Symbols;
    }

    /// <summary>
    /// Gets the impacted symbols with their depth from the changed symbol.
    /// </summary>
    public Dictionary<string, int> GetImpactedSymbolsWithDepth(string symbolFullName)
    {
        EnsureGraphInitialized();
        return _impactCalculator.CalculateTransitiveImpactWithDepth(_cachedGraph!, symbolFullName);
    }

    /// <summary>
    /// Gets files that would be affected by a change to the given symbol.
    /// </summary>
    public ImmutableHashSet<string> GetAffectedFiles(string symbolFullName)
    {
        EnsureGraphInitialized();

        var impact = _impactCalculator.CalculateTransitiveImpact(_cachedGraph!, symbolFullName);
        return impact.ByFile.Keys.ToImmutableHashSet();
    }

    /// <summary>
    /// Finds the dependency path between two symbols.
    /// </summary>
    public List<string>? FindDependencyPath(string fromSymbol, string toSymbol)
    {
        EnsureGraphInitialized();
        return _impactCalculator.FindDependencyPath(_cachedGraph!, fromSymbol, toSymbol);
    }

    /// <summary>
    /// Finds the most depended-upon symbols (hotspots).
    /// </summary>
    public List<(string Symbol, int DependentCount)> FindHotspots(int topN = 10)
    {
        EnsureGraphInitialized();
        return _impactCalculator.FindHotspots(_cachedGraph!, topN);
    }

    /// <summary>
    /// Gets an impact summary for a change.
    /// </summary>
    public ImpactSummary GetImpactSummary(string symbolFullName, ChangeType changeType)
    {
        EnsureGraphInitialized();

        var result = _impactCalculator.CalculateImpact(_cachedGraph!, symbolFullName, changeType);
        return _impactCalculator.GetSummary(result, _cachedGraph!);
    }

    /// <summary>
    /// Generates a full impact report for a change.
    /// </summary>
    public ImpactReport GenerateReport(string symbolFullName, ChangeType changeType)
    {
        EnsureGraphInitialized();

        var result = _impactCalculator.CalculateImpact(_cachedGraph!, symbolFullName, changeType);
        var summary = _impactCalculator.GetSummary(result, _cachedGraph!);
        var hotspots = _impactCalculator.FindHotspots(_cachedGraph!, 5);

        return new ImpactReport
        {
            Symbol = symbolFullName,
            ChangeType = changeType,
            AnalysisResult = result,
            Summary = summary,
            GeneratedAt = DateTime.UtcNow,
            RelatedHotspots = hotspots.Where(h => result.TransitiveImpact.Symbols.Contains(h.Symbol)).ToList(),
            DependencyPaths = GenerateSamplePaths(symbolFullName, result.DirectImpact.Symbols.Take(5))
        };
    }

    /// <summary>
    /// Analyzes which public API surfaces are at risk.
    /// </summary>
    public PublicApiImpact AnalyzePublicApiImpact(string symbolFullName)
    {
        EnsureGraphInitialized();

        var impact = _impactCalculator.CalculateTransitiveImpact(_cachedGraph!, symbolFullName);

        var publicSymbols = impact.Symbols
            .Where(s => _cachedGraph!.Nodes.TryGetValue(s, out var n) && n.IsPublicApi)
            .ToImmutableHashSet();

        var publicMethods = publicSymbols
            .Where(s => _cachedGraph!.Nodes.TryGetValue(s, out var n) && n.Kind == ImpactSymbolKind.Method)
            .ToList();

        var publicTypes = publicSymbols
            .Where(s => _cachedGraph!.Nodes.TryGetValue(s, out var n) && n.Kind == ImpactSymbolKind.Type)
            .ToList();

        var publicProperties = publicSymbols
            .Where(s => _cachedGraph!.Nodes.TryGetValue(s, out var n) && n.Kind == ImpactSymbolKind.Property)
            .ToList();

        return new PublicApiImpact
        {
            TotalPublicSymbolsAffected = publicSymbols.Count,
            PublicMethodsAffected = publicMethods,
            PublicTypesAffected = publicTypes,
            PublicPropertiesAffected = publicProperties,
            BreakingChangeRisk = publicSymbols.Count > 0 ? RiskLevel.High : RiskLevel.Low
        };
    }

    /// <summary>
    /// Compares the impact of different approaches to making a change.
    /// </summary>
    public async Task<ChangeApproachComparison> CompareApproachesAsync(
        Project project,
        string symbolFullName,
        ChangeType desiredChange)
    {
        EnsureGraphInitialized();

        var approaches = await _whatIfAnalyzer.CompareSafetyApproachesAsync(
            _cachedGraph!, project, symbolFullName, desiredChange);

        var safestApproach = approaches.FirstOrDefault();

        return new ChangeApproachComparison
        {
            Symbol = symbolFullName,
            DesiredChange = desiredChange,
            ApproachResults = approaches,
            SafestApproach = safestApproach,
            Recommendation = GenerateApproachRecommendation(approaches)
        };
    }

    /// <summary>
    /// Validates that a symbol exists in the graph.
    /// </summary>
    public bool SymbolExists(string symbolFullName)
    {
        EnsureGraphInitialized();
        return _cachedGraph!.Nodes.ContainsKey(symbolFullName);
    }

    /// <summary>
    /// Gets information about a symbol from the graph.
    /// </summary>
    public DependencyNode? GetSymbolInfo(string symbolFullName)
    {
        EnsureGraphInitialized();
        return _cachedGraph!.Nodes.TryGetValue(symbolFullName, out var node) ? node : null;
    }

    /// <summary>
    /// Gets all dependents of a symbol by dependency type.
    /// </summary>
    public ImmutableDictionary<DependencyType, ImmutableHashSet<string>> GetDependentsByType(string symbolFullName)
    {
        EnsureGraphInitialized();

        var impact = _impactCalculator.CalculateDirectImpact(_cachedGraph!, symbolFullName);
        return impact.ByDependencyType;
    }

    /// <summary>
    /// Gets all dependencies of a symbol (what it depends on).
    /// </summary>
    public ImmutableList<DependencyEdge> GetDependencies(string symbolFullName)
    {
        EnsureGraphInitialized();

        if (_cachedGraph!.OutgoingEdges.TryGetValue(symbolFullName, out var edges))
        {
            return edges;
        }

        return ImmutableList<DependencyEdge>.Empty;
    }

    /// <summary>
    /// Gets all dependents of a symbol (what depends on it).
    /// </summary>
    public ImmutableList<DependencyEdge> GetDependents(string symbolFullName)
    {
        EnsureGraphInitialized();

        if (_cachedGraph!.IncomingEdges.TryGetValue(symbolFullName, out var edges))
        {
            return edges;
        }

        return ImmutableList<DependencyEdge>.Empty;
    }

    /// <summary>
    /// Searches for symbols matching a pattern.
    /// </summary>
    public List<DependencyNode> SearchSymbols(string pattern, ImpactSymbolKind? kindFilter = null)
    {
        EnsureGraphInitialized();

        var query = _cachedGraph!.Nodes.Values
            .Where(n => n.FullyQualifiedName.Contains(pattern, StringComparison.OrdinalIgnoreCase) ||
                        n.Name.Contains(pattern, StringComparison.OrdinalIgnoreCase));

        if (kindFilter.HasValue)
        {
            query = query.Where(n => n.Kind == kindFilter.Value);
        }

        return query.ToList();
    }

    /// <summary>
    /// Integrates with the existing CallGraph from Context.
    /// </summary>
    public void IntegrateWithCallGraph(CallGraph callGraph)
    {
        EnsureGraphInitialized();

        // Add method call relationships from the existing CallGraph
        foreach (var method in callGraph.GetAllMethods())
        {
            foreach (var callee in callGraph.GetCallees(method))
            {
                // These are already tracked in our graph, but we can use this
                // to verify or enhance our analysis
            }
        }
    }

    /// <summary>
    /// Exports the dependency graph data for external use.
    /// </summary>
    public DependencyGraphExport ExportGraph()
    {
        EnsureGraphInitialized();

        return new DependencyGraphExport
        {
            ProjectPath = _cachedProjectPath!,
            GeneratedAt = DateTime.UtcNow,
            NodeCount = _cachedGraph!.NodeCount,
            EdgeCount = _cachedGraph.EdgeCount,
            Nodes = _cachedGraph.Nodes.Values.ToList(),
            Edges = _cachedGraph.OutgoingEdges.Values.SelectMany(e => e).ToList(),
            Stats = _graphBuilder.GetStats(_cachedGraph)
        };
    }

    private void EnsureGraphInitialized()
    {
        if (_cachedGraph == null)
        {
            throw new InvalidOperationException(
                "Dependency graph not initialized. Call InitializeFromProjectAsync or InitializeFromSolutionAsync first.");
        }
    }

    private Dictionary<string, List<string>> GenerateSamplePaths(
        string fromSymbol,
        IEnumerable<string> toSymbols)
    {
        var paths = new Dictionary<string, List<string>>();

        foreach (var toSymbol in toSymbols)
        {
            var path = FindDependencyPath(fromSymbol, toSymbol);
            if (path != null)
            {
                paths[toSymbol] = path;
            }
        }

        return paths;
    }

    private string GenerateApproachRecommendation(List<WhatIfResult> approaches)
    {
        if (approaches.Count == 0)
        {
            return "No approaches to compare.";
        }

        var safest = approaches.First();

        if (!safest.WouldBreakCompilation && safest.Impact.Risk.Level == RiskLevel.Low)
        {
            return $"Recommended: {safest.Scenario.Description} - Low risk with no compilation breaks.";
        }

        if (!safest.WouldBreakCompilation)
        {
            return $"Recommended: {safest.Scenario.Description} - No compilation breaks but consider impact level.";
        }

        return $"All approaches carry risk. Safest: {safest.Scenario.Description} with {safest.PredictedErrors.Count} predicted error(s).";
    }
}

/// <summary>
/// Full impact report for a change.
/// </summary>
public record ImpactReport
{
    public required string Symbol { get; init; }
    public required ChangeType ChangeType { get; init; }
    public required ImpactAnalysisResult AnalysisResult { get; init; }
    public required ImpactSummary Summary { get; init; }
    public required DateTime GeneratedAt { get; init; }
    public List<(string Symbol, int DependentCount)> RelatedHotspots { get; init; } = [];
    public Dictionary<string, List<string>> DependencyPaths { get; init; } = [];
}

/// <summary>
/// Public API impact analysis.
/// </summary>
public record PublicApiImpact
{
    public int TotalPublicSymbolsAffected { get; init; }
    public List<string> PublicMethodsAffected { get; init; } = [];
    public List<string> PublicTypesAffected { get; init; } = [];
    public List<string> PublicPropertiesAffected { get; init; } = [];
    public RiskLevel BreakingChangeRisk { get; init; }
}

/// <summary>
/// Comparison of different approaches to making a change.
/// </summary>
public record ChangeApproachComparison
{
    public required string Symbol { get; init; }
    public required ChangeType DesiredChange { get; init; }
    public required List<WhatIfResult> ApproachResults { get; init; }
    public WhatIfResult? SafestApproach { get; init; }
    public required string Recommendation { get; init; }
}

/// <summary>
/// Exported dependency graph data.
/// </summary>
public record DependencyGraphExport
{
    public required string ProjectPath { get; init; }
    public required DateTime GeneratedAt { get; init; }
    public int NodeCount { get; init; }
    public int EdgeCount { get; init; }
    public List<DependencyNode> Nodes { get; init; } = [];
    public List<DependencyEdge> Edges { get; init; } = [];
    public DependencyGraphStats? Stats { get; init; }
}
