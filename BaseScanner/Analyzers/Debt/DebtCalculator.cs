using BaseScanner.Analyzers.Debt.Models;
using BaseScanner.Services;

namespace BaseScanner.Analyzers.Debt;

/// <summary>
/// Calculates and quantifies technical debt from analyzer results.
/// Converts various issue types into normalized debt items with time estimates.
/// </summary>
public class DebtCalculator
{
    /// <summary>
    /// Calculate debt items from a complete analysis result.
    /// </summary>
    public List<DebtItem> CalculateDebt(AnalysisResult analysisResult, string projectDirectory)
    {
        var debtItems = new List<DebtItem>();

        // Process each analyzer's results
        debtItems.AddRange(ProcessSecurityIssues(analysisResult.Security, projectDirectory));
        debtItems.AddRange(ProcessRefactoringIssues(analysisResult.Refactoring, projectDirectory));
        debtItems.AddRange(ProcessPerformanceIssues(analysisResult.PerformanceIssues, projectDirectory));
        debtItems.AddRange(ProcessExceptionIssues(analysisResult.ExceptionHandlingIssues, projectDirectory));
        debtItems.AddRange(ProcessResourceIssues(analysisResult.ResourceLeakIssues, projectDirectory));
        debtItems.AddRange(ProcessSafetyIssues(analysisResult.Safety, projectDirectory));
        debtItems.AddRange(ProcessOptimizationIssues(analysisResult.Optimizations, projectDirectory));
        debtItems.AddRange(ProcessArchitectureIssues(analysisResult.Architecture, projectDirectory));
        debtItems.AddRange(ProcessDependencyIssues(analysisResult.Dependencies, projectDirectory));
        debtItems.AddRange(ProcessMagicValues(analysisResult.MagicValues, projectDirectory));

        // Assign unique IDs
        for (int i = 0; i < debtItems.Count; i++)
        {
            if (string.IsNullOrEmpty(debtItems[i].Id))
            {
                debtItems[i] = debtItems[i] with { Id = $"DEBT-{i + 1:D5}" };
            }
        }

        return debtItems;
    }

    private List<DebtItem> ProcessSecurityIssues(SecurityAnalysisResult? security, string projectDirectory)
    {
        if (security == null) return [];

        return security.Vulnerabilities.Select(v =>
        {
            var timeToFix = DebtCost.GetSecurityCost(v.Severity);
            var interest = DebtInterest.GetSecurityInterest(v.Severity);
            var impact = CalculateSecurityImpact(v.Severity);
            var effort = CalculateEffort(timeToFix);

            return new DebtItem
            {
                Id = $"SEC-{v.CweId}-{v.StartLine}",
                Category = DebtCategory.Security,
                Type = v.VulnerabilityType,
                Severity = v.Severity,
                Description = v.Description,
                FilePath = v.FilePath,
                Line = v.StartLine,
                EndLine = v.EndLine,
                TimeToFixMinutes = timeToFix,
                InterestPerWeek = interest,
                ImpactScore = impact,
                EffortScore = effort,
                PayoffScore = CalculatePayoff(impact, 1, effort),
                Priority = ClassifyPriority(impact, effort, v.Severity),
                Suggestion = v.Recommendation,
                CweId = v.CweId,
                Source = "SecurityAnalyzer",
                Context = v.VulnerableCode
            };
        }).ToList();
    }

    private List<DebtItem> ProcessRefactoringIssues(RefactoringResult? refactoring, string projectDirectory)
    {
        if (refactoring == null) return [];

        var items = new List<DebtItem>();

        // Long methods
        foreach (var m in refactoring.LongMethods)
        {
            var complexity = m.Complexity;
            var timeToFix = CalculateLongMethodCost(m.LineCount, complexity);
            var interest = DebtInterest.LongMethod + (complexity > 15 ? 5 : 0);
            var impact = CalculateComplexityImpact(complexity, m.LineCount);
            var effort = CalculateEffort(timeToFix);

            items.Add(new DebtItem
            {
                Id = $"REF-LM-{m.ClassName}-{m.MethodName}",
                Category = DebtCategory.CodeSmells,
                Type = DebtType.LongMethod,
                Severity = complexity > 20 ? "High" : complexity > 10 ? "Medium" : "Low",
                Description = $"Method '{m.MethodName}' is {m.LineCount} lines with complexity {complexity}",
                FilePath = m.FilePath,
                Line = m.Line,
                TimeToFixMinutes = timeToFix,
                InterestPerWeek = interest,
                ImpactScore = impact,
                EffortScore = effort,
                PayoffScore = CalculatePayoff(impact, 1, effort),
                Priority = ClassifyPriority(impact, effort, complexity > 20 ? "High" : "Medium"),
                Suggestion = m.ExtractCandidates.Count > 0
                    ? $"Consider extracting: {string.Join(", ", m.ExtractCandidates.Take(3).Select(c => c.SuggestedName))}"
                    : "Split into smaller, focused methods",
                Source = "RefactoringAnalyzer",
                Context = $"Lines: {m.LineCount}, Complexity: {complexity}"
            });
        }

        // God classes
        foreach (var g in refactoring.GodClasses)
        {
            var timeToFix = CalculateGodClassCost(g.MethodCount, g.FieldCount, g.LCOM);
            var interest = DebtInterest.GodClass;
            var impact = CalculateGodClassImpact(g.MethodCount, g.LCOM);
            var effort = CalculateEffort(timeToFix);

            items.Add(new DebtItem
            {
                Id = $"REF-GC-{g.ClassName}",
                Category = DebtCategory.CodeSmells,
                Type = DebtType.GodClass,
                Severity = g.MethodCount > 30 || g.LCOM > 0.8 ? "High" : "Medium",
                Description = $"Class '{g.ClassName}' has {g.MethodCount} methods and low cohesion (LCOM: {g.LCOM:F2})",
                FilePath = g.FilePath,
                Line = g.Line,
                TimeToFixMinutes = timeToFix,
                InterestPerWeek = interest,
                ImpactScore = impact,
                EffortScore = effort,
                PayoffScore = CalculatePayoff(impact, 1, effort),
                Priority = ClassifyPriority(impact, effort, "High"),
                Suggestion = g.Responsibilities.Count > 0
                    ? $"Consider splitting by responsibility: {string.Join(", ", g.Responsibilities.Take(3))}"
                    : "Extract related functionality into focused classes",
                Source = "RefactoringAnalyzer",
                Context = $"Methods: {g.MethodCount}, Fields: {g.FieldCount}, LCOM: {g.LCOM:F2}"
            });
        }

        // Feature envy
        foreach (var f in refactoring.FeatureEnvy)
        {
            items.Add(new DebtItem
            {
                Id = $"REF-FE-{f.ClassName}-{f.MethodName}",
                Category = DebtCategory.CodeSmells,
                Type = DebtType.FeatureEnvy,
                Severity = f.EnvyRatio > 3 ? "Medium" : "Low",
                Description = $"Method '{f.MethodName}' uses {f.EnviedClass} more than its own class",
                FilePath = f.FilePath,
                Line = f.Line,
                TimeToFixMinutes = DebtCost.FeatureEnvy,
                InterestPerWeek = DebtInterest.FeatureEnvy,
                ImpactScore = 40,
                EffortScore = 30,
                PayoffScore = CalculatePayoff(40, 1, 30),
                Priority = DebtPriority.LowPriority,
                Suggestion = $"Consider moving method to {f.EnviedClass}",
                Source = "RefactoringAnalyzer",
                Context = $"Own access: {f.EnviedMemberAccess}, Envied access: {f.EnviedMemberAccess}"
            });
        }

        // Parameter smells
        foreach (var p in refactoring.ParameterSmells)
        {
            items.Add(new DebtItem
            {
                Id = $"REF-PS-{p.ClassName}-{p.MethodName}",
                Category = DebtCategory.CodeSmells,
                Type = DebtType.LongParameterList,
                Severity = p.ParameterCount > 7 ? "Medium" : "Low",
                Description = $"Method '{p.MethodName}' has {p.ParameterCount} parameters ({p.SmellType})",
                FilePath = p.FilePath,
                Line = p.Line,
                TimeToFixMinutes = DebtCost.LongParameterList,
                InterestPerWeek = DebtInterest.LongParameterList,
                ImpactScore = 30,
                EffortScore = 25,
                PayoffScore = CalculatePayoff(30, 1, 25),
                Priority = DebtPriority.LowPriority,
                Suggestion = p.Suggestion,
                Source = "RefactoringAnalyzer"
            });
        }

        // Data clumps
        foreach (var d in refactoring.DataClumps)
        {
            items.Add(new DebtItem
            {
                Id = $"REF-DC-{d.SuggestedClassName}",
                Category = DebtCategory.CodeSmells,
                Type = DebtType.DataClump,
                Severity = d.Occurrences > 5 ? "Medium" : "Low",
                Description = $"Parameter group appears {d.Occurrences} times: {string.Join(", ", d.Parameters.Take(3))}",
                FilePath = d.Locations.FirstOrDefault() ?? "",
                Line = 0,
                TimeToFixMinutes = DebtCost.DataClump,
                InterestPerWeek = DebtInterest.DataClump * d.Occurrences,
                ImpactScore = 35 + d.Occurrences * 2,
                EffortScore = 35,
                Frequency = d.Occurrences,
                PayoffScore = CalculatePayoff(35, d.Occurrences, 35),
                Priority = d.Occurrences > 5 ? DebtPriority.QuickWin : DebtPriority.LowPriority,
                Suggestion = $"Create class '{d.SuggestedClassName}' to encapsulate these parameters",
                Source = "RefactoringAnalyzer"
            });
        }

        return items;
    }

    private List<DebtItem> ProcessPerformanceIssues(List<IssueItem>? issues, string projectDirectory)
    {
        if (issues == null) return [];

        return issues.Select(i =>
        {
            var timeToFix = GetPerformanceCost(i.Type);
            var interest = GetPerformanceInterest(i.Severity);
            var impact = CalculatePerformanceImpact(i.Severity);
            var effort = CalculateEffort(timeToFix);

            return new DebtItem
            {
                Id = $"PERF-{i.Type}-{i.Line}",
                Category = DebtCategory.Performance,
                Type = i.Type,
                Severity = i.Severity,
                Description = i.Message,
                FilePath = i.FilePath,
                Line = i.Line,
                TimeToFixMinutes = timeToFix,
                InterestPerWeek = interest,
                ImpactScore = impact,
                EffortScore = effort,
                PayoffScore = CalculatePayoff(impact, 1, effort),
                Priority = ClassifyPriority(impact, effort, i.Severity),
                Source = "AsyncPerformanceAnalyzer",
                Context = i.CodeSnippet
            };
        }).ToList();
    }

    private List<DebtItem> ProcessExceptionIssues(List<IssueItem>? issues, string projectDirectory)
    {
        if (issues == null) return [];

        return issues.Select(i =>
        {
            var timeToFix = i.Severity == "High" ? 30 : 15;
            var interest = i.Severity == "High" ? 10 : 3;
            var impact = i.Severity == "High" ? 60 : 35;
            var effort = CalculateEffort(timeToFix);

            return new DebtItem
            {
                Id = $"EXC-{i.Type}-{i.Line}",
                Category = DebtCategory.Maintainability,
                Type = i.Type,
                Severity = i.Severity,
                Description = i.Message,
                FilePath = i.FilePath,
                Line = i.Line,
                TimeToFixMinutes = timeToFix,
                InterestPerWeek = interest,
                ImpactScore = impact,
                EffortScore = effort,
                PayoffScore = CalculatePayoff(impact, 1, effort),
                Priority = ClassifyPriority(impact, effort, i.Severity),
                Source = "ExceptionHandlingAnalyzer",
                Context = i.CodeSnippet
            };
        }).ToList();
    }

    private List<DebtItem> ProcessResourceIssues(List<IssueItem>? issues, string projectDirectory)
    {
        if (issues == null) return [];

        return issues.Select(i =>
        {
            var timeToFix = DebtCost.MissingDispose;
            var interest = 5;
            var impact = i.Severity == "High" ? 70 : 50;
            var effort = CalculateEffort(timeToFix);

            return new DebtItem
            {
                Id = $"RES-{i.Type}-{i.Line}",
                Category = DebtCategory.Performance,
                Type = DebtType.MissingDispose,
                Severity = i.Severity,
                Description = i.Message,
                FilePath = i.FilePath,
                Line = i.Line,
                TimeToFixMinutes = timeToFix,
                InterestPerWeek = interest,
                ImpactScore = impact,
                EffortScore = effort,
                PayoffScore = CalculatePayoff(impact, 1, effort),
                Priority = ClassifyPriority(impact, effort, i.Severity),
                Source = "ResourceLeakAnalyzer",
                Context = i.CodeSnippet
            };
        }).ToList();
    }

    private List<DebtItem> ProcessSafetyIssues(SafetyResult? safety, string projectDirectory)
    {
        if (safety == null) return [];

        var items = new List<DebtItem>();

        // Null safety issues
        foreach (var n in safety.NullIssues)
        {
            var timeToFix = 15;
            var interest = n.Severity == "High" ? 8 : 3;
            var impact = n.Severity == "High" ? 55 : 35;
            var effort = CalculateEffort(timeToFix);

            items.Add(new DebtItem
            {
                Id = $"NULL-{n.Type}-{n.Line}",
                Category = DebtCategory.Maintainability,
                Type = n.Type,
                Severity = n.Severity,
                Description = n.Description,
                FilePath = n.FilePath,
                Line = n.Line,
                TimeToFixMinutes = timeToFix,
                InterestPerWeek = interest,
                ImpactScore = impact,
                EffortScore = effort,
                PayoffScore = CalculatePayoff(impact, 1, effort),
                Priority = ClassifyPriority(impact, effort, n.Severity),
                Source = "CodeSafetyAnalyzer"
            });
        }

        // Immutability issues
        foreach (var i in safety.ImmutabilityIssues)
        {
            items.Add(new DebtItem
            {
                Id = $"IMM-{i.MemberName}-{i.Line}",
                Category = DebtCategory.Maintainability,
                Type = i.Type,
                Severity = "Low",
                Description = $"Immutability opportunity: {i.MemberName}",
                FilePath = i.FilePath,
                Line = i.Line,
                TimeToFixMinutes = 10,
                InterestPerWeek = 1,
                ImpactScore = 25,
                EffortScore = 15,
                PayoffScore = CalculatePayoff(25, 1, 15),
                Priority = DebtPriority.LowPriority,
                Suggestion = i.Suggestion,
                Source = "CodeSafetyAnalyzer"
            });
        }

        // Logging gaps
        foreach (var l in safety.LoggingGaps)
        {
            items.Add(new DebtItem
            {
                Id = $"LOG-{l.ClassName}-{l.MethodName}",
                Category = DebtCategory.Documentation,
                Type = l.GapType,
                Severity = "Low",
                Description = l.Description,
                FilePath = l.FilePath,
                Line = l.Line,
                TimeToFixMinutes = DebtCost.MissingDocs,
                InterestPerWeek = DebtInterest.MissingDocs,
                ImpactScore = 20,
                EffortScore = 15,
                PayoffScore = CalculatePayoff(20, 1, 15),
                Priority = DebtPriority.LowPriority,
                Source = "CodeSafetyAnalyzer"
            });
        }

        return items;
    }

    private List<DebtItem> ProcessOptimizationIssues(OptimizationResult? optimizations, string projectDirectory)
    {
        if (optimizations == null) return [];

        return optimizations.Opportunities.Select(o =>
        {
            var impact = o.Impact switch
            {
                "Critical" => 90,
                "High" => 70,
                "Medium" => 50,
                _ => 30
            };
            var effort = o.Confidence switch
            {
                "High" => 20,  // Easy if high confidence
                "Medium" => 40,
                _ => 60
            };
            var timeToFix = GetOptimizationCost(o.Type);

            return new DebtItem
            {
                Id = $"OPT-{o.Type}-{o.StartLine}",
                Category = DebtCategory.Performance,
                Type = o.Type,
                Severity = o.Impact,
                Description = o.Description,
                FilePath = o.FilePath,
                Line = o.StartLine,
                EndLine = o.EndLine,
                TimeToFixMinutes = timeToFix,
                InterestPerWeek = impact > 50 ? 5 : 2,
                ImpactScore = impact,
                EffortScore = effort,
                PayoffScore = CalculatePayoff(impact, 1, effort),
                Priority = ClassifyPriority(impact, effort, o.Impact),
                Suggestion = $"Replace with: {TruncateCode(o.SuggestedCode, 100)}",
                Source = "OptimizationAnalyzer",
                Context = o.CurrentCode
            };
        }).ToList();
    }

    private List<DebtItem> ProcessArchitectureIssues(ArchitectureResult? architecture, string projectDirectory)
    {
        if (architecture == null) return [];

        var items = new List<DebtItem>();

        // Deep inheritance
        foreach (var i in architecture.DeepInheritance)
        {
            items.Add(new DebtItem
            {
                Id = $"ARCH-DI-{i.TypeName}",
                Category = DebtCategory.Architecture,
                Type = DebtType.DeepInheritance,
                Severity = i.Depth > 5 ? "Medium" : "Low",
                Description = $"Type '{i.TypeName}' has inheritance depth of {i.Depth}",
                FilePath = "",
                Line = 0,
                TimeToFixMinutes = DebtCost.DeepInheritance,
                InterestPerWeek = 5,
                ImpactScore = 40,
                EffortScore = 60,
                PayoffScore = CalculatePayoff(40, 1, 60),
                Priority = DebtPriority.LowPriority,
                Suggestion = "Consider using composition over inheritance",
                Source = "ArchitectureAnalyzer",
                Context = string.Join(" -> ", i.Chain)
            });
        }

        // Interface issues (ISP violations)
        foreach (var i in architecture.InterfaceIssues)
        {
            items.Add(new DebtItem
            {
                Id = $"ARCH-IF-{i.InterfaceName}",
                Category = DebtCategory.Architecture,
                Type = "FatInterface",
                Severity = i.MemberCount > 15 ? "Medium" : "Low",
                Description = $"Interface '{i.InterfaceName}' has {i.MemberCount} members (ISP violation)",
                FilePath = i.FilePath,
                Line = i.Line,
                TimeToFixMinutes = 45,
                InterestPerWeek = 3,
                ImpactScore = 35,
                EffortScore = 50,
                PayoffScore = CalculatePayoff(35, 1, 50),
                Priority = DebtPriority.LowPriority,
                Suggestion = i.SuggestedSplits.Count > 0
                    ? $"Split into: {string.Join(", ", i.SuggestedSplits)}"
                    : "Consider splitting into smaller, focused interfaces",
                Source = "ArchitectureAnalyzer"
            });
        }

        // Composition candidates
        foreach (var c in architecture.CompositionCandidates)
        {
            items.Add(new DebtItem
            {
                Id = $"ARCH-CC-{c.TypeName}",
                Category = DebtCategory.Architecture,
                Type = "InheritanceOveruse",
                Severity = "Low",
                Description = $"Type '{c.TypeName}' could benefit from composition",
                FilePath = c.FilePath,
                Line = c.Line,
                TimeToFixMinutes = 60,
                InterestPerWeek = 2,
                ImpactScore = 30,
                EffortScore = 55,
                PayoffScore = CalculatePayoff(30, 1, 55),
                Priority = DebtPriority.LowPriority,
                Suggestion = c.Suggestion,
                Source = "ArchitectureAnalyzer"
            });
        }

        return items;
    }

    private List<DebtItem> ProcessDependencyIssues(DependencyResult? dependencies, string projectDirectory)
    {
        if (dependencies == null) return [];

        var items = new List<DebtItem>();

        // Circular dependencies
        foreach (var c in dependencies.CircularDependencies)
        {
            items.Add(new DebtItem
            {
                Id = $"DEP-CD-{c.Type}",
                Category = DebtCategory.Architecture,
                Type = DebtType.CircularDependency,
                Severity = "High",
                Description = $"Circular dependency detected: {string.Join(" -> ", c.Cycle.Take(4))}",
                FilePath = "",
                Line = 0,
                TimeToFixMinutes = DebtCost.CircularDependency,
                InterestPerWeek = 15,
                ImpactScore = 70,
                EffortScore = 70,
                PayoffScore = CalculatePayoff(70, 1, 70),
                Priority = DebtPriority.MajorProject,
                Suggestion = "Break the cycle by introducing an abstraction or restructuring",
                Source = "DependencyAnalyzer",
                Context = string.Join(" -> ", c.Cycle)
            });
        }

        // High coupling
        foreach (var h in dependencies.HighCouplingTypes)
        {
            items.Add(new DebtItem
            {
                Id = $"DEP-HC-{h.TypeName}",
                Category = DebtCategory.Architecture,
                Type = DebtType.HighCoupling,
                Severity = h.EfferentCoupling > 20 ? "Medium" : "Low",
                Description = $"Type '{h.TypeName}' has high coupling (Ce: {h.EfferentCoupling}, Ca: {h.AfferentCoupling})",
                FilePath = h.FilePath,
                Line = 0,
                TimeToFixMinutes = DebtCost.HighCoupling,
                InterestPerWeek = 5,
                ImpactScore = 45,
                EffortScore = 50,
                PayoffScore = CalculatePayoff(45, 1, 50),
                Priority = DebtPriority.LowPriority,
                Suggestion = "Reduce dependencies by introducing abstractions",
                Source = "DependencyAnalyzer",
                Context = $"Instability: {h.Instability:F2}"
            });
        }

        return items;
    }

    private List<DebtItem> ProcessMagicValues(List<MagicValueItem>? magicValues, string projectDirectory)
    {
        if (magicValues == null) return [];

        return magicValues.Select(m =>
        {
            var frequency = m.Occurrences;
            var impact = frequency > 5 ? 35 : 20;
            var effort = 15;

            return new DebtItem
            {
                Id = $"MAG-{m.Type}-{m.Value.GetHashCode():X8}",
                Category = DebtCategory.CodeSmells,
                Type = DebtType.MagicNumber,
                Severity = frequency > 5 ? "Low" : "Low",
                Description = $"Magic {m.Type.ToLower()} '{TruncateCode(m.Value, 30)}' used {frequency} times",
                FilePath = m.Locations.FirstOrDefault()?.FilePath ?? "",
                Line = m.Locations.FirstOrDefault()?.Line ?? 0,
                TimeToFixMinutes = DebtCost.MagicNumber,
                InterestPerWeek = DebtInterest.MagicNumber * frequency,
                ImpactScore = impact,
                EffortScore = effort,
                Frequency = frequency,
                PayoffScore = CalculatePayoff(impact, frequency, effort),
                Priority = frequency > 10 ? DebtPriority.QuickWin : DebtPriority.LowPriority,
                Suggestion = "Extract to a named constant",
                Source = "MagicValueAnalyzer"
            };
        }).ToList();
    }

    // Helper methods

    private static double CalculateSecurityImpact(string severity) => severity switch
    {
        "Critical" => 100,
        "High" => 80,
        "Medium" => 50,
        "Low" => 25,
        _ => 50
    };

    private static double CalculatePerformanceImpact(string severity) => severity switch
    {
        "High" => 70,
        "Medium" => 50,
        "Low" => 30,
        _ => 40
    };

    private static double CalculateComplexityImpact(int complexity, int lineCount)
    {
        var complexityScore = Math.Min(complexity / 25.0 * 100, 100);
        var sizeScore = Math.Min(lineCount / 100.0 * 100, 100);
        return (complexityScore * 0.7 + sizeScore * 0.3);
    }

    private static double CalculateGodClassImpact(int methodCount, double lcom)
    {
        var methodScore = Math.Min(methodCount / 30.0 * 100, 100);
        var cohesionScore = lcom * 100;
        return (methodScore * 0.5 + cohesionScore * 0.5);
    }

    private static double CalculateEffort(int timeToFixMinutes)
    {
        // Normalize to 0-100 scale where 480 min (8 hours) = 100
        return Math.Min(timeToFixMinutes / 480.0 * 100, 100);
    }

    private static double CalculatePayoff(double impact, int frequency, double effort)
    {
        // Payoff = (Impact * Frequency) / Effort
        // Higher is better - more bang for the buck
        if (effort <= 0) effort = 1;
        return (impact * frequency) / effort;
    }

    private static DebtPriority ClassifyPriority(double impact, double effort, string severity)
    {
        // Critical security issues are always critical priority
        if (severity == "Critical")
            return DebtPriority.Critical;

        // Quick wins: high impact, low effort
        if (impact >= 50 && effort <= 30)
            return DebtPriority.QuickWin;

        // Major projects: high impact, high effort
        if (impact >= 60 && effort > 50)
            return DebtPriority.MajorProject;

        // Low priority: low impact
        return DebtPriority.LowPriority;
    }

    private static int CalculateLongMethodCost(int lineCount, int complexity)
    {
        // Base cost + additional for size and complexity
        var baseCost = DebtCost.LongMethod;
        var sizeFactor = Math.Max(0, (lineCount - 30) / 10) * 10;
        var complexityFactor = Math.Max(0, (complexity - 10)) * 5;
        return baseCost + sizeFactor + complexityFactor;
    }

    private static int CalculateGodClassCost(int methodCount, int fieldCount, double lcom)
    {
        var baseCost = DebtCost.GodClass;
        var sizeFactor = (methodCount - 15) * 5 + (fieldCount - 10) * 3;
        return Math.Max(baseCost, baseCost + sizeFactor);
    }

    private static int GetPerformanceCost(string type) => type switch
    {
        "AsyncVoid" => DebtCost.AsyncIssue,
        "BlockingAsync" => DebtCost.AsyncIssue,
        _ => DebtCost.InefficientPattern
    };

    private static int GetPerformanceInterest(string severity) => severity switch
    {
        "High" => DebtInterest.PerformanceHigh,
        "Medium" => DebtInterest.PerformanceMedium,
        _ => DebtInterest.PerformanceLow
    };

    private static int GetOptimizationCost(string type) => type switch
    {
        "LinqAny" or "LinqCount" => 5,
        "AsyncVoid" => 20,
        "StringConcat" => 10,
        "ListToHashSet" => 10,
        _ => 15
    };

    private static string TruncateCode(string code, int maxLength)
    {
        if (string.IsNullOrEmpty(code)) return "";
        code = code.Replace("\n", " ").Replace("\r", "").Trim();
        return code.Length <= maxLength ? code : code[..maxLength] + "...";
    }
}
