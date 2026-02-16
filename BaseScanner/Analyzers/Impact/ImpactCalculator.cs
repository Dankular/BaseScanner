using System.Collections.Immutable;
using BaseScanner.Analyzers.Impact.Models;

namespace BaseScanner.Analyzers.Impact;

/// <summary>
/// Calculates the impact of changes to code symbols.
/// Computes direct and transitive dependencies, and assesses risk.
/// </summary>
public class ImpactCalculator
{
    private readonly ImpactAnalysisOptions _options;

    public ImpactCalculator(ImpactAnalysisOptions? options = null)
    {
        _options = options ?? new ImpactAnalysisOptions();
    }

    /// <summary>
    /// Calculates the full impact of a change to a symbol.
    /// </summary>
    public ImpactAnalysisResult CalculateImpact(
        DependencyGraph graph,
        string changedSymbol,
        ChangeType changeType)
    {
        var directImpact = CalculateDirectImpact(graph, changedSymbol);
        var transitiveImpact = CalculateTransitiveImpact(graph, changedSymbol);
        var risk = AssessRisk(graph, changedSymbol, changeType, directImpact, transitiveImpact);
        var mitigations = SuggestMitigations(graph, changedSymbol, changeType, risk);

        return new ImpactAnalysisResult
        {
            ChangedSymbol = changedSymbol,
            ChangeType = changeType,
            DirectImpact = directImpact,
            TransitiveImpact = transitiveImpact,
            Risk = risk,
            Mitigations = mitigations
        };
    }

    /// <summary>
    /// Calculates the impact of multiple changes together.
    /// </summary>
    public BatchImpactResult CalculateBatchImpact(
        DependencyGraph graph,
        IEnumerable<(string Symbol, ChangeType ChangeType)> changes)
    {
        var results = changes
            .Select(c => CalculateImpact(graph, c.Symbol, c.ChangeType))
            .ToList();

        // Combine all impacted symbols
        var allImpacted = results
            .SelectMany(r => r.TransitiveImpact.Symbols)
            .ToImmutableHashSet();

        // Find overlapping symbols (impacted by multiple changes)
        var symbolCounts = results
            .SelectMany(r => r.TransitiveImpact.Symbols)
            .GroupBy(s => s)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToImmutableHashSet();

        var combinedImpact = CombineImpactSets(results.Select(r => r.TransitiveImpact));
        var overallRisk = CalculateOverallRisk(results);

        return new BatchImpactResult
        {
            Results = results,
            CombinedImpact = combinedImpact,
            OverallRisk = overallRisk,
            OverlappingSymbols = symbolCounts
        };
    }

    /// <summary>
    /// Calculates direct dependents of a symbol (immediate impact).
    /// </summary>
    public ImpactSet CalculateDirectImpact(DependencyGraph graph, string symbol)
    {
        if (!graph.IncomingEdges.TryGetValue(symbol, out var edges))
        {
            return new ImpactSet();
        }

        var symbols = edges.Select(e => e.Source).ToImmutableHashSet();

        var byDependencyType = edges
            .GroupBy(e => e.Type)
            .ToImmutableDictionary(
                g => g.Key,
                g => g.Select(e => e.Source).ToImmutableHashSet());

        var byFile = edges
            .GroupBy(e => e.FilePath)
            .ToImmutableDictionary(
                g => g.Key,
                g => g.Select(e => e.Source).ToImmutableHashSet());

        return new ImpactSet
        {
            Symbols = symbols,
            ByDependencyType = byDependencyType,
            ByFile = byFile
        };
    }

    /// <summary>
    /// Calculates all transitive dependents of a symbol.
    /// </summary>
    public ImpactSet CalculateTransitiveImpact(DependencyGraph graph, string symbol)
    {
        var visited = new HashSet<string>();
        var allEdges = new List<DependencyEdge>();
        var queue = new Queue<(string Symbol, int Depth)>();

        queue.Enqueue((symbol, 0));

        while (queue.Count > 0)
        {
            var (current, depth) = queue.Dequeue();

            if (depth > _options.MaxTransitiveDepth)
                continue;

            if (!visited.Add(current))
                continue;

            if (graph.IncomingEdges.TryGetValue(current, out var edges))
            {
                allEdges.AddRange(edges);

                foreach (var edge in edges)
                {
                    if (!visited.Contains(edge.Source))
                    {
                        queue.Enqueue((edge.Source, depth + 1));
                    }
                }
            }
        }

        visited.Remove(symbol); // Remove the original symbol

        var byDependencyType = allEdges
            .GroupBy(e => e.Type)
            .ToImmutableDictionary(
                g => g.Key,
                g => g.Select(e => e.Source).ToImmutableHashSet());

        var byFile = allEdges
            .GroupBy(e => e.FilePath)
            .ToImmutableDictionary(
                g => g.Key,
                g => g.Select(e => e.Source).ToImmutableHashSet());

        return new ImpactSet
        {
            Symbols = visited.ToImmutableHashSet(),
            ByDependencyType = byDependencyType,
            ByFile = byFile
        };
    }

    /// <summary>
    /// Calculates transitive impact with depth information.
    /// </summary>
    public Dictionary<string, int> CalculateTransitiveImpactWithDepth(DependencyGraph graph, string symbol)
    {
        var depths = new Dictionary<string, int>();
        var queue = new Queue<(string Symbol, int Depth)>();

        queue.Enqueue((symbol, 0));

        while (queue.Count > 0)
        {
            var (current, depth) = queue.Dequeue();

            if (depth > _options.MaxTransitiveDepth)
                continue;

            if (depths.ContainsKey(current) && depths[current] <= depth)
                continue;

            depths[current] = depth;

            if (graph.IncomingEdges.TryGetValue(current, out var edges))
            {
                foreach (var edge in edges)
                {
                    if (!depths.ContainsKey(edge.Source) || depths[edge.Source] > depth + 1)
                    {
                        queue.Enqueue((edge.Source, depth + 1));
                    }
                }
            }
        }

        depths.Remove(symbol); // Remove the original symbol
        return depths;
    }

    /// <summary>
    /// Assesses the risk of a change.
    /// </summary>
    public RiskAssessment AssessRisk(
        DependencyGraph graph,
        string changedSymbol,
        ChangeType changeType,
        ImpactSet directImpact,
        ImpactSet transitiveImpact)
    {
        var factors = CalculateRiskFactors(graph, changedSymbol, changeType, directImpact, transitiveImpact);
        var totalScore = factors.DependentCountRisk +
                         factors.PublicApiRisk +
                         factors.CriticalPathRisk +
                         factors.TestCoverageRisk +
                         factors.Additional.Values.Sum();

        // Clamp to 0-100
        totalScore = Math.Max(0, Math.Min(100, totalScore));

        var level = totalScore switch
        {
            >= 75 => RiskLevel.Critical,
            >= 50 => RiskLevel.High,
            >= 25 => RiskLevel.Medium,
            _ => RiskLevel.Low
        };

        var explanation = GenerateRiskExplanation(factors, changeType, directImpact, transitiveImpact);

        return new RiskAssessment
        {
            Score = totalScore,
            Level = level,
            Factors = factors,
            Explanation = explanation
        };
    }

    private RiskFactors CalculateRiskFactors(
        DependencyGraph graph,
        string changedSymbol,
        ChangeType changeType,
        ImpactSet directImpact,
        ImpactSet transitiveImpact)
    {
        // Factor 1: Dependent count risk (0-25)
        var dependentCountRisk = CalculateDependentCountRisk(directImpact.Count, transitiveImpact.Count);

        // Factor 2: Public API risk (0-25)
        var publicApiRisk = CalculatePublicApiRisk(graph, changedSymbol, changeType);

        // Factor 3: Critical path risk (0-25)
        var criticalPathRisk = CalculateCriticalPathRisk(graph, changedSymbol, transitiveImpact);

        // Factor 4: Test coverage risk (0-25)
        var testCoverageRisk = _options.CalculateTestCoverageRisk
            ? CalculateTestCoverageRisk(graph, changedSymbol, transitiveImpact)
            : 0;

        // Additional factors
        var additional = new Dictionary<string, double>();

        // Increase risk for deletions and signature changes
        if (changeType == ChangeType.Deletion)
        {
            additional["deletion_penalty"] = 10;
        }
        else if (changeType == ChangeType.SignatureChange)
        {
            additional["signature_change_penalty"] = 7;
        }

        // Risk multiplier for cascading inheritance changes
        if (graph.IncomingEdges.TryGetValue(changedSymbol, out var edges))
        {
            var inheritanceImpact = edges.Count(e =>
                e.Type == DependencyType.Inheritance ||
                e.Type == DependencyType.InterfaceImplementation ||
                e.Type == DependencyType.Override);

            if (inheritanceImpact > 0)
            {
                additional["inheritance_cascade"] = Math.Min(15, inheritanceImpact * 3);
            }
        }

        return new RiskFactors
        {
            DependentCountRisk = dependentCountRisk,
            PublicApiRisk = publicApiRisk,
            CriticalPathRisk = criticalPathRisk,
            TestCoverageRisk = testCoverageRisk,
            Additional = additional
        };
    }

    private double CalculateDependentCountRisk(int directCount, int transitiveCount)
    {
        // Scale based on number of dependents
        // 0 dependents = 0 risk
        // 1-5 dependents = low risk
        // 6-20 dependents = medium risk
        // 20+ dependents = high risk

        var directRisk = directCount switch
        {
            0 => 0,
            <= 5 => 5,
            <= 10 => 10,
            <= 20 => 15,
            _ => 20
        };

        var transitiveRisk = transitiveCount switch
        {
            0 => 0,
            <= 10 => 1,
            <= 50 => 3,
            <= 100 => 4,
            _ => 5
        };

        return Math.Min(25, directRisk + transitiveRisk);
    }

    private double CalculatePublicApiRisk(DependencyGraph graph, string symbol, ChangeType changeType)
    {
        if (!graph.Nodes.TryGetValue(symbol, out var node))
            return 0;

        if (!node.IsPublicApi)
            return 0;

        // Public API changes are risky
        return changeType switch
        {
            ChangeType.Deletion => 25, // Maximum risk for public API deletion
            ChangeType.SignatureChange => 20,
            ChangeType.Rename => 20,
            ChangeType.AccessibilityChange => 15,
            ChangeType.TypeChange => 15,
            _ => 5
        };
    }

    private double CalculateCriticalPathRisk(
        DependencyGraph graph,
        string symbol,
        ImpactSet transitiveImpact)
    {
        // Check if the changed symbol is critical
        if (graph.Nodes.TryGetValue(symbol, out var node) && node.IsCritical)
        {
            return 15;
        }

        // Check if any transitively impacted symbols are critical
        var criticalImpacted = transitiveImpact.Symbols
            .Where(s => graph.Nodes.TryGetValue(s, out var n) && n.IsCritical)
            .Count();

        return Math.Min(25, criticalImpacted * 5);
    }

    private double CalculateTestCoverageRisk(
        DependencyGraph graph,
        string symbol,
        ImpactSet transitiveImpact)
    {
        var allSymbols = transitiveImpact.Symbols.Add(symbol);
        var coverages = allSymbols
            .Select(s => graph.Nodes.TryGetValue(s, out var n) ? n.TestCoverage : -1)
            .Where(c => c >= 0)
            .ToList();

        if (coverages.Count == 0)
            return 12.5; // Unknown coverage = medium risk

        var avgCoverage = coverages.Average();

        // Lower coverage = higher risk
        return avgCoverage switch
        {
            >= 80 => 0,
            >= 60 => 5,
            >= 40 => 10,
            >= 20 => 18,
            _ => 25
        };
    }

    private string GenerateRiskExplanation(
        RiskFactors factors,
        ChangeType changeType,
        ImpactSet directImpact,
        ImpactSet transitiveImpact)
    {
        var parts = new List<string>();

        if (directImpact.Count > 0)
        {
            parts.Add($"{directImpact.Count} direct dependent(s)");
        }

        if (transitiveImpact.Count > directImpact.Count)
        {
            parts.Add($"{transitiveImpact.Count} total impacted symbol(s)");
        }

        if (transitiveImpact.AffectedFileCount > 1)
        {
            parts.Add($"{transitiveImpact.AffectedFileCount} files affected");
        }

        if (factors.PublicApiRisk > 0)
        {
            parts.Add("affects public API");
        }

        if (factors.CriticalPathRisk > 0)
        {
            parts.Add("impacts critical paths");
        }

        if (factors.TestCoverageRisk > 15)
        {
            parts.Add("low test coverage");
        }

        if (factors.Additional.ContainsKey("inheritance_cascade"))
        {
            parts.Add("inheritance cascade risk");
        }

        if (parts.Count == 0)
        {
            return "Low impact change with minimal risk.";
        }

        return $"Risk factors: {string.Join(", ", parts)}.";
    }

    private List<MitigationAction> SuggestMitigations(
        DependencyGraph graph,
        string changedSymbol,
        ChangeType changeType,
        RiskAssessment risk)
    {
        var mitigations = new List<MitigationAction>();
        var priority = 1;

        // Always suggest review for high/critical risk
        if (risk.Level >= RiskLevel.High)
        {
            mitigations.Add(new MitigationAction
            {
                Type = MitigationType.ReviewBeforeCommit,
                Description = "This change should be reviewed by senior team members before committing.",
                Priority = priority++,
                Effort = "Low"
            });
        }

        // Test coverage mitigation
        if (risk.Factors.TestCoverageRisk > 10)
        {
            mitigations.Add(new MitigationAction
            {
                Type = MitigationType.AddTests,
                Description = "Add or update tests to cover the changed code and its dependents.",
                Priority = priority++,
                Effort = "Medium"
            });
        }

        // Public API deprecation
        if (risk.Factors.PublicApiRisk > 0 && changeType == ChangeType.Deletion)
        {
            mitigations.Add(new MitigationAction
            {
                Type = MitigationType.CreateDeprecationPlan,
                Description = "Consider deprecating this API first to give consumers time to migrate.",
                Priority = priority++,
                Effort = "Medium"
            });
        }

        // Documentation
        if (risk.Factors.PublicApiRisk > 0 && changeType is ChangeType.SignatureChange or ChangeType.Rename)
        {
            mitigations.Add(new MitigationAction
            {
                Type = MitigationType.UpdateDocumentation,
                Description = "Update documentation to reflect the API changes.",
                Priority = priority++,
                Effort = "Low"
            });
        }

        // Incremental rollout for critical changes
        if (risk.Level == RiskLevel.Critical)
        {
            mitigations.Add(new MitigationAction
            {
                Type = MitigationType.IncrementalRollout,
                Description = "Consider rolling out this change incrementally to catch issues early.",
                Priority = priority++,
                Effort = "High"
            });
        }

        // Notify team for significant changes
        if (risk.Score >= 50)
        {
            mitigations.Add(new MitigationAction
            {
                Type = MitigationType.NotifyTeam,
                Description = "Notify the team about this significant change that affects multiple components.",
                Priority = priority++,
                Effort = "Low"
            });
        }

        // Compatibility shim for breaking changes
        if (risk.Factors.PublicApiRisk > 15 && changeType == ChangeType.SignatureChange)
        {
            mitigations.Add(new MitigationAction
            {
                Type = MitigationType.AddCompatibilityShim,
                Description = "Add a compatibility shim to maintain backward compatibility.",
                Priority = priority++,
                Effort = "Medium"
            });
        }

        return mitigations;
    }

    private ImpactSet CombineImpactSets(IEnumerable<ImpactSet> sets)
    {
        var allSymbols = new HashSet<string>();
        var byType = new Dictionary<DependencyType, HashSet<string>>();
        var byFile = new Dictionary<string, HashSet<string>>();

        foreach (var set in sets)
        {
            allSymbols.UnionWith(set.Symbols);

            foreach (var kvp in set.ByDependencyType)
            {
                if (!byType.ContainsKey(kvp.Key))
                    byType[kvp.Key] = new HashSet<string>();
                byType[kvp.Key].UnionWith(kvp.Value);
            }

            foreach (var kvp in set.ByFile)
            {
                if (!byFile.ContainsKey(kvp.Key))
                    byFile[kvp.Key] = new HashSet<string>();
                byFile[kvp.Key].UnionWith(kvp.Value);
            }
        }

        return new ImpactSet
        {
            Symbols = allSymbols.ToImmutableHashSet(),
            ByDependencyType = byType.ToImmutableDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value.ToImmutableHashSet()),
            ByFile = byFile.ToImmutableDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value.ToImmutableHashSet())
        };
    }

    private RiskAssessment CalculateOverallRisk(List<ImpactAnalysisResult> results)
    {
        if (results.Count == 0)
        {
            return new RiskAssessment
            {
                Score = 0,
                Level = RiskLevel.Low,
                Factors = new RiskFactors(),
                Explanation = "No changes to analyze."
            };
        }

        // Take the maximum risk across all changes
        var maxRisk = results.OrderByDescending(r => r.Risk.Score).First().Risk;

        // Add a multiplier for batch changes
        var batchMultiplier = 1.0 + (results.Count - 1) * 0.1; // 10% increase per additional change
        var adjustedScore = Math.Min(100, maxRisk.Score * batchMultiplier);

        var level = adjustedScore switch
        {
            >= 75 => RiskLevel.Critical,
            >= 50 => RiskLevel.High,
            >= 25 => RiskLevel.Medium,
            _ => RiskLevel.Low
        };

        return new RiskAssessment
        {
            Score = adjustedScore,
            Level = level,
            Factors = maxRisk.Factors,
            Explanation = $"Batch of {results.Count} changes. {maxRisk.Explanation}",
            Confidence = 90 // Slightly lower confidence for batch analysis
        };
    }

    /// <summary>
    /// Gets a summary of impact analysis.
    /// </summary>
    public ImpactSummary GetSummary(ImpactAnalysisResult result, DependencyGraph graph)
    {
        var affectsPublicApi = result.TransitiveImpact.Symbols
            .Any(s => graph.Nodes.TryGetValue(s, out var n) && n.IsPublicApi);

        var affectsCritical = result.TransitiveImpact.Symbols
            .Any(s => graph.Nodes.TryGetValue(s, out var n) && n.IsCritical);

        var byType = result.TransitiveImpact.ByDependencyType
            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Count);

        return new ImpactSummary
        {
            DirectImpactCount = result.DirectImpact.Count,
            TransitiveImpactCount = result.TransitiveImpact.Count,
            AffectedFileCount = result.TransitiveImpact.AffectedFileCount,
            AffectsPublicApi = affectsPublicApi,
            AffectsCriticalPaths = affectsCritical,
            RiskLevel = result.Risk.Level,
            ByDependencyType = byType
        };
    }

    /// <summary>
    /// Finds the shortest path between two symbols in the dependency graph.
    /// </summary>
    public List<string>? FindDependencyPath(DependencyGraph graph, string from, string to)
    {
        var visited = new HashSet<string>();
        var queue = new Queue<List<string>>();

        queue.Enqueue(new List<string> { from });

        while (queue.Count > 0)
        {
            var path = queue.Dequeue();
            var current = path.Last();

            if (current == to)
                return path;

            if (!visited.Add(current))
                continue;

            if (graph.OutgoingEdges.TryGetValue(current, out var edges))
            {
                foreach (var edge in edges)
                {
                    if (!visited.Contains(edge.Target))
                    {
                        var newPath = new List<string>(path) { edge.Target };
                        queue.Enqueue(newPath);
                    }
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Identifies hotspots - symbols with many dependents.
    /// </summary>
    public List<(string Symbol, int DependentCount)> FindHotspots(DependencyGraph graph, int topN = 10)
    {
        return graph.IncomingEdges
            .OrderByDescending(kvp => kvp.Value.Count)
            .Take(topN)
            .Select(kvp => (kvp.Key, kvp.Value.Count))
            .ToList();
    }
}
