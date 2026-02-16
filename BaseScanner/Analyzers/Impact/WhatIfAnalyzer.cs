using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Impact.Models;
using ImpactSymbolKind = BaseScanner.Analyzers.Impact.Models.SymbolKind;

namespace BaseScanner.Analyzers.Impact;

/// <summary>
/// Performs hypothetical "what-if" analysis for code changes.
/// Simulates the effects of changes before they are made.
/// </summary>
public class WhatIfAnalyzer
{
    private readonly ImpactCalculator _impactCalculator;
    private readonly ImpactAnalysisOptions _options;

    public WhatIfAnalyzer(ImpactAnalysisOptions? options = null)
    {
        _options = options ?? new ImpactAnalysisOptions();
        _impactCalculator = new ImpactCalculator(_options);
    }

    /// <summary>
    /// Analyzes the impact of changing a method's signature.
    /// </summary>
    public async Task<WhatIfResult> AnalyzeSignatureChangeAsync(
        DependencyGraph graph,
        Project project,
        string methodFullName,
        string newSignature)
    {
        var scenario = new WhatIfScenario
        {
            TargetSymbol = methodFullName,
            ChangeType = ChangeType.SignatureChange,
            Description = $"Change signature of '{GetSimpleName(methodFullName)}' to '{newSignature}'",
            NewSignature = newSignature
        };

        var impact = _impactCalculator.CalculateImpact(graph, methodFullName, ChangeType.SignatureChange);
        var predictedErrors = await PredictSignatureChangeErrorsAsync(graph, project, methodFullName, newSignature);
        var requiredChanges = GenerateRequiredChangesForSignature(graph, methodFullName, predictedErrors);
        var recommendations = GenerateRecommendations(impact, predictedErrors);

        return new WhatIfResult
        {
            Scenario = scenario,
            Impact = impact,
            WouldBreakCompilation = predictedErrors.Count > 0,
            PredictedErrors = predictedErrors,
            RequiredChanges = requiredChanges,
            Recommendations = recommendations
        };
    }

    /// <summary>
    /// Analyzes the impact of deleting a symbol.
    /// </summary>
    public async Task<WhatIfResult> AnalyzeDeletionAsync(
        DependencyGraph graph,
        Project project,
        string symbolFullName)
    {
        var scenario = new WhatIfScenario
        {
            TargetSymbol = symbolFullName,
            ChangeType = ChangeType.Deletion,
            Description = $"Delete '{GetSimpleName(symbolFullName)}'"
        };

        var impact = _impactCalculator.CalculateImpact(graph, symbolFullName, ChangeType.Deletion);
        var predictedErrors = await PredictDeletionErrorsAsync(graph, project, symbolFullName);
        var requiredChanges = GenerateRequiredChangesForDeletion(graph, symbolFullName, predictedErrors);
        var recommendations = GenerateRecommendations(impact, predictedErrors);

        return new WhatIfResult
        {
            Scenario = scenario,
            Impact = impact,
            WouldBreakCompilation = predictedErrors.Count > 0,
            PredictedErrors = predictedErrors,
            RequiredChanges = requiredChanges,
            Recommendations = recommendations
        };
    }

    /// <summary>
    /// Analyzes the impact of renaming a symbol.
    /// </summary>
    public async Task<WhatIfResult> AnalyzeRenameAsync(
        DependencyGraph graph,
        Project project,
        string symbolFullName,
        string newName)
    {
        var scenario = new WhatIfScenario
        {
            TargetSymbol = symbolFullName,
            ChangeType = ChangeType.Rename,
            Description = $"Rename '{GetSimpleName(symbolFullName)}' to '{newName}'",
            NewName = newName
        };

        var impact = _impactCalculator.CalculateImpact(graph, symbolFullName, ChangeType.Rename);
        var predictedErrors = await PredictRenameErrorsAsync(graph, project, symbolFullName, newName);
        var requiredChanges = GenerateRequiredChangesForRename(graph, symbolFullName, newName, impact);
        var recommendations = GenerateRecommendations(impact, predictedErrors);

        return new WhatIfResult
        {
            Scenario = scenario,
            Impact = impact,
            WouldBreakCompilation = predictedErrors.Count > 0,
            PredictedErrors = predictedErrors,
            RequiredChanges = requiredChanges,
            Recommendations = recommendations
        };
    }

    /// <summary>
    /// Analyzes the impact of changing a symbol's accessibility.
    /// </summary>
    public async Task<WhatIfResult> AnalyzeAccessibilityChangeAsync(
        DependencyGraph graph,
        Project project,
        string symbolFullName,
        AccessibilityLevel newAccessibility)
    {
        var scenario = new WhatIfScenario
        {
            TargetSymbol = symbolFullName,
            ChangeType = ChangeType.AccessibilityChange,
            Description = $"Change accessibility of '{GetSimpleName(symbolFullName)}' to {newAccessibility}"
        };

        var impact = _impactCalculator.CalculateImpact(graph, symbolFullName, ChangeType.AccessibilityChange);
        var predictedErrors = await PredictAccessibilityChangeErrorsAsync(graph, project, symbolFullName, newAccessibility);
        var requiredChanges = GenerateRequiredChangesForAccessibility(graph, symbolFullName, newAccessibility, predictedErrors);
        var recommendations = GenerateRecommendations(impact, predictedErrors);

        return new WhatIfResult
        {
            Scenario = scenario,
            Impact = impact,
            WouldBreakCompilation = predictedErrors.Count > 0,
            PredictedErrors = predictedErrors,
            RequiredChanges = requiredChanges,
            Recommendations = recommendations
        };
    }

    /// <summary>
    /// Analyzes multiple what-if scenarios together.
    /// </summary>
    public async Task<List<WhatIfResult>> AnalyzeMultipleScenariosAsync(
        DependencyGraph graph,
        Project project,
        IEnumerable<WhatIfScenario> scenarios)
    {
        var results = new List<WhatIfResult>();

        foreach (var scenario in scenarios)
        {
            var result = scenario.ChangeType switch
            {
                ChangeType.SignatureChange when scenario.NewSignature != null =>
                    await AnalyzeSignatureChangeAsync(graph, project, scenario.TargetSymbol, scenario.NewSignature),
                ChangeType.Deletion =>
                    await AnalyzeDeletionAsync(graph, project, scenario.TargetSymbol),
                ChangeType.Rename when scenario.NewName != null =>
                    await AnalyzeRenameAsync(graph, project, scenario.TargetSymbol, scenario.NewName),
                _ => CreateDefaultResult(scenario, graph)
            };

            results.Add(result);
        }

        return results;
    }

    /// <summary>
    /// Finds the safest way to make a change by comparing different approaches.
    /// </summary>
    public async Task<List<WhatIfResult>> CompareSafetyApproachesAsync(
        DependencyGraph graph,
        Project project,
        string symbolFullName,
        ChangeType desiredChange)
    {
        var approaches = new List<WhatIfResult>();

        switch (desiredChange)
        {
            case ChangeType.Deletion:
                // Direct deletion
                approaches.Add(await AnalyzeDeletionAsync(graph, project, symbolFullName));

                // Deprecate first approach (simulate)
                var deprecationScenario = new WhatIfScenario
                {
                    TargetSymbol = symbolFullName,
                    ChangeType = ChangeType.BehaviorChange,
                    Description = $"Mark '{GetSimpleName(symbolFullName)}' as [Obsolete] first"
                };
                approaches.Add(CreateDefaultResult(deprecationScenario, graph));
                break;

            case ChangeType.Rename:
                // Direct rename
                approaches.Add(await AnalyzeRenameAsync(graph, project, symbolFullName, "NewName"));

                // Rename with compatibility alias
                var aliasScenario = new WhatIfScenario
                {
                    TargetSymbol = symbolFullName,
                    ChangeType = ChangeType.Rename,
                    Description = $"Rename with backward-compatible alias"
                };
                approaches.Add(CreateDefaultResult(aliasScenario, graph));
                break;

            case ChangeType.AccessibilityChange:
                // Try reducing to internal
                approaches.Add(await AnalyzeAccessibilityChangeAsync(graph, project, symbolFullName, AccessibilityLevel.Internal));

                // Try reducing to private
                approaches.Add(await AnalyzeAccessibilityChangeAsync(graph, project, symbolFullName, AccessibilityLevel.Private));
                break;
        }

        return approaches.OrderBy(a => a.Impact.Risk.Score).ToList();
    }

    private async Task<List<PredictedError>> PredictSignatureChangeErrorsAsync(
        DependencyGraph graph,
        Project project,
        string methodFullName,
        string newSignature)
    {
        var errors = new List<PredictedError>();

        // Find all direct callers
        if (!graph.IncomingEdges.TryGetValue(methodFullName, out var edges))
            return errors;

        var callEdges = edges.Where(e => e.Type == DependencyType.DirectCall).ToList();

        foreach (var edge in callEdges)
        {
            // Each caller would have a CS1501 (argument count) or CS1503 (argument type) error
            errors.Add(new PredictedError
            {
                ErrorCode = "CS1501",
                Message = $"No overload for method '{GetSimpleName(methodFullName)}' takes the current number of arguments",
                FilePath = edge.FilePath,
                Line = edge.Line,
                AffectedSymbol = edge.Source
            });
        }

        // Check for override errors
        var overrideEdges = edges.Where(e => e.Type == DependencyType.Override).ToList();
        foreach (var edge in overrideEdges)
        {
            errors.Add(new PredictedError
            {
                ErrorCode = "CS0115",
                Message = $"'{GetSimpleName(edge.Source)}': no suitable method found to override",
                FilePath = edge.FilePath,
                Line = edge.Line,
                AffectedSymbol = edge.Source
            });
        }

        return errors;
    }

    private async Task<List<PredictedError>> PredictDeletionErrorsAsync(
        DependencyGraph graph,
        Project project,
        string symbolFullName)
    {
        var errors = new List<PredictedError>();

        if (!graph.IncomingEdges.TryGetValue(symbolFullName, out var edges))
            return errors;

        // Determine the appropriate error code based on symbol kind
        var errorCode = "CS0103"; // Name does not exist in current context
        var symbolKind = graph.Nodes.TryGetValue(symbolFullName, out var node) ? node.Kind : ImpactSymbolKind.Type;

        foreach (var edge in edges)
        {
            var message = edge.Type switch
            {
                DependencyType.DirectCall => $"The name '{GetSimpleName(symbolFullName)}' does not exist in the current context",
                DependencyType.TypeUsage => $"The type or namespace name '{GetSimpleName(symbolFullName)}' could not be found",
                DependencyType.Inheritance => $"The type or namespace name '{GetSimpleName(symbolFullName)}' could not be found (base type)",
                DependencyType.InterfaceImplementation => $"The interface '{GetSimpleName(symbolFullName)}' could not be found",
                DependencyType.FieldAccess => $"'{GetSimpleName(symbolFullName)}' does not contain a definition for the accessed member",
                DependencyType.PropertyAccess => $"'{GetSimpleName(symbolFullName)}' does not contain a definition for the accessed property",
                DependencyType.EventSubscription => $"The event '{GetSimpleName(symbolFullName)}' does not exist",
                DependencyType.Override => $"'{GetSimpleName(edge.Source)}': no suitable method found to override",
                _ => $"The name '{GetSimpleName(symbolFullName)}' does not exist"
            };

            var code = edge.Type switch
            {
                DependencyType.TypeUsage or DependencyType.Inheritance or DependencyType.InterfaceImplementation => "CS0246",
                DependencyType.Override => "CS0115",
                _ => "CS0103"
            };

            errors.Add(new PredictedError
            {
                ErrorCode = code,
                Message = message,
                FilePath = edge.FilePath,
                Line = edge.Line,
                AffectedSymbol = edge.Source
            });
        }

        return errors;
    }

    private async Task<List<PredictedError>> PredictRenameErrorsAsync(
        DependencyGraph graph,
        Project project,
        string symbolFullName,
        string newName)
    {
        // Rename with refactoring tool typically has no errors
        // But without automatic refactoring, it's the same as deletion
        var errors = await PredictDeletionErrorsAsync(graph, project, symbolFullName);

        // Check for name conflicts
        var containingType = graph.Nodes.TryGetValue(symbolFullName, out var node) ? node.ContainingType : null;
        if (containingType != null)
        {
            var potentialConflict = $"{containingType}.{newName}";
            if (graph.Nodes.ContainsKey(potentialConflict))
            {
                errors.Insert(0, new PredictedError
                {
                    ErrorCode = "CS0102",
                    Message = $"The type '{containingType}' already contains a definition for '{newName}'",
                    FilePath = node?.FilePath ?? "",
                    Line = node?.Line ?? 0,
                    AffectedSymbol = symbolFullName
                });
            }
        }

        return errors;
    }

    private async Task<List<PredictedError>> PredictAccessibilityChangeErrorsAsync(
        DependencyGraph graph,
        Project project,
        string symbolFullName,
        AccessibilityLevel newAccessibility)
    {
        var errors = new List<PredictedError>();

        if (!graph.IncomingEdges.TryGetValue(symbolFullName, out var edges))
            return errors;

        if (!graph.Nodes.TryGetValue(symbolFullName, out var targetNode))
            return errors;

        foreach (var edge in edges)
        {
            if (!graph.Nodes.TryGetValue(edge.Source, out var sourceNode))
                continue;

            // Check if source would lose access
            var wouldLoseAccess = WouldLoseAccess(targetNode, sourceNode, newAccessibility);

            if (wouldLoseAccess)
            {
                errors.Add(new PredictedError
                {
                    ErrorCode = "CS0122",
                    Message = $"'{GetSimpleName(symbolFullName)}' is inaccessible due to its protection level",
                    FilePath = edge.FilePath,
                    Line = edge.Line,
                    AffectedSymbol = edge.Source
                });
            }
        }

        return errors;
    }

    private bool WouldLoseAccess(DependencyNode target, DependencyNode source, AccessibilityLevel newAccessibility)
    {
        // Simplified accessibility check
        if (newAccessibility == AccessibilityLevel.Private)
        {
            // Private: only accessible within same type
            return target.ContainingType != source.ContainingType;
        }

        if (newAccessibility == AccessibilityLevel.Protected)
        {
            // Protected: only accessible within same type or derived types
            // Simplified: assume different types means loss of access
            return target.ContainingType != source.ContainingType;
        }

        if (newAccessibility == AccessibilityLevel.Internal || newAccessibility == AccessibilityLevel.PrivateProtected)
        {
            // For now, assume same project = accessible
            return false;
        }

        return false;
    }

    private List<RequiredChange> GenerateRequiredChangesForSignature(
        DependencyGraph graph,
        string methodFullName,
        List<PredictedError> errors)
    {
        return errors.Select(e => new RequiredChange
        {
            FilePath = e.FilePath,
            Line = e.Line,
            Description = $"Update call to '{GetSimpleName(methodFullName)}' to match new signature",
            SymbolToUpdate = e.AffectedSymbol,
            CanAutoFix = true,
            SuggestedFix = "Update method call arguments"
        }).ToList();
    }

    private List<RequiredChange> GenerateRequiredChangesForDeletion(
        DependencyGraph graph,
        string symbolFullName,
        List<PredictedError> errors)
    {
        return errors.Select(e => new RequiredChange
        {
            FilePath = e.FilePath,
            Line = e.Line,
            Description = $"Remove or replace reference to '{GetSimpleName(symbolFullName)}'",
            SymbolToUpdate = e.AffectedSymbol,
            CanAutoFix = false,
            SuggestedFix = "Find alternative implementation or remove usage"
        }).ToList();
    }

    private List<RequiredChange> GenerateRequiredChangesForRename(
        DependencyGraph graph,
        string symbolFullName,
        string newName,
        ImpactAnalysisResult impact)
    {
        var changes = new List<RequiredChange>();

        foreach (var symbol in impact.DirectImpact.Symbols)
        {
            if (graph.Nodes.TryGetValue(symbol, out var node))
            {
                changes.Add(new RequiredChange
                {
                    FilePath = node.FilePath,
                    Line = node.Line,
                    Description = $"Update reference from '{GetSimpleName(symbolFullName)}' to '{newName}'",
                    SymbolToUpdate = symbol,
                    CanAutoFix = true,
                    SuggestedFix = $"Replace '{GetSimpleName(symbolFullName)}' with '{newName}'"
                });
            }
        }

        return changes;
    }

    private List<RequiredChange> GenerateRequiredChangesForAccessibility(
        DependencyGraph graph,
        string symbolFullName,
        AccessibilityLevel newAccessibility,
        List<PredictedError> errors)
    {
        return errors.Select(e => new RequiredChange
        {
            FilePath = e.FilePath,
            Line = e.Line,
            Description = $"Update code to handle reduced accessibility of '{GetSimpleName(symbolFullName)}'",
            SymbolToUpdate = e.AffectedSymbol,
            CanAutoFix = false,
            SuggestedFix = "Consider exposing through a public method or moving the caller"
        }).ToList();
    }

    private List<string> GenerateRecommendations(ImpactAnalysisResult impact, List<PredictedError> errors)
    {
        var recommendations = new List<string>();

        if (errors.Count == 0)
        {
            recommendations.Add("This change should not break compilation.");
        }
        else
        {
            recommendations.Add($"This change will cause {errors.Count} compilation error(s).");
        }

        if (impact.Risk.Level >= RiskLevel.High)
        {
            recommendations.Add("Consider breaking this change into smaller, incremental changes.");
        }

        if (impact.TransitiveImpact.AffectedFileCount > 5)
        {
            recommendations.Add("Many files are affected. Consider creating a migration plan.");
        }

        if (impact.Risk.Factors.PublicApiRisk > 0)
        {
            recommendations.Add("This affects public API. Consider maintaining backward compatibility.");
        }

        if (impact.DirectImpact.Count > 0 && errors.Count > 0)
        {
            var canAutoFix = errors.Count;
            recommendations.Add($"Use 'Rename' refactoring in IDE to automatically update {canAutoFix} reference(s).");
        }

        // Add mitigation suggestions
        foreach (var mitigation in impact.Mitigations.Take(3))
        {
            recommendations.Add($"[{mitigation.Type}] {mitigation.Description}");
        }

        return recommendations;
    }

    private WhatIfResult CreateDefaultResult(WhatIfScenario scenario, DependencyGraph graph)
    {
        var impact = _impactCalculator.CalculateImpact(graph, scenario.TargetSymbol, scenario.ChangeType);

        return new WhatIfResult
        {
            Scenario = scenario,
            Impact = impact,
            WouldBreakCompilation = false,
            PredictedErrors = new List<PredictedError>(),
            RequiredChanges = new List<RequiredChange>(),
            Recommendations = new List<string>
            {
                "Analysis based on dependency graph only. Manual verification recommended."
            }
        };
    }

    private static string GetSimpleName(string fullName)
    {
        var lastDot = fullName.LastIndexOf('.');
        if (lastDot < 0) return fullName;

        var paren = fullName.IndexOf('(');
        if (paren > 0 && paren > lastDot)
        {
            return fullName.Substring(lastDot + 1);
        }

        return fullName.Substring(lastDot + 1);
    }

    /// <summary>
    /// Performs a quick impact check without full analysis.
    /// </summary>
    public QuickImpactCheck PerformQuickCheck(DependencyGraph graph, string symbolFullName)
    {
        var hasDependents = graph.IncomingEdges.ContainsKey(symbolFullName) &&
                            graph.IncomingEdges[symbolFullName].Count > 0;

        var isPublicApi = graph.Nodes.TryGetValue(symbolFullName, out var node) && node.IsPublicApi;
        var isCritical = node?.IsCritical ?? false;
        var directDependentCount = graph.IncomingEdges.TryGetValue(symbolFullName, out var edges) ? edges.Count : 0;

        return new QuickImpactCheck
        {
            Symbol = symbolFullName,
            HasDependents = hasDependents,
            IsPublicApi = isPublicApi,
            IsCritical = isCritical,
            DirectDependentCount = directDependentCount,
            EstimatedRisk = EstimateRisk(hasDependents, isPublicApi, isCritical, directDependentCount)
        };
    }

    private RiskLevel EstimateRisk(bool hasDependents, bool isPublicApi, bool isCritical, int dependentCount)
    {
        if (isCritical || (isPublicApi && dependentCount > 10))
            return RiskLevel.Critical;

        if (isPublicApi || dependentCount > 5)
            return RiskLevel.High;

        if (hasDependents)
            return RiskLevel.Medium;

        return RiskLevel.Low;
    }
}

/// <summary>
/// Quick impact check result.
/// </summary>
public record QuickImpactCheck
{
    public required string Symbol { get; init; }
    public bool HasDependents { get; init; }
    public bool IsPublicApi { get; init; }
    public bool IsCritical { get; init; }
    public int DirectDependentCount { get; init; }
    public RiskLevel EstimatedRisk { get; init; }
}
