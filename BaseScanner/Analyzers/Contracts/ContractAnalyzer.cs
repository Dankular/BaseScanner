using Microsoft.CodeAnalysis;
using System.Collections.Concurrent;
using BaseScanner.Analyzers.Contracts.Models;

namespace BaseScanner.Analyzers.Contracts;

/// <summary>
/// Main coordinator for contract and invariant analysis.
/// Orchestrates precondition, postcondition, invariant, and side effect detection.
/// </summary>
public class ContractAnalyzer
{
    private readonly PreconditionDetector _preconditionDetector;
    private readonly PostconditionDetector _postconditionDetector;
    private readonly InvariantDetector _invariantDetector;
    private readonly SideEffectAnalyzer _sideEffectAnalyzer;

    public ContractAnalyzer()
    {
        _preconditionDetector = new PreconditionDetector();
        _postconditionDetector = new PostconditionDetector();
        _invariantDetector = new InvariantDetector();
        _sideEffectAnalyzer = new SideEffectAnalyzer();
    }

    /// <summary>
    /// Analyze a project for contract violations and implicit contracts.
    /// </summary>
    public async Task<ContractAnalysisResult> AnalyzeAsync(Project project)
    {
        var preconditions = new ConcurrentBag<PreconditionIssue>();
        var postconditions = new ConcurrentBag<PostconditionIssue>();
        var invariants = new ConcurrentBag<InvariantIssue>();
        var sideEffects = new ConcurrentBag<SideEffectIssue>();
        var purityAnalysis = new ConcurrentBag<MethodPurityInfo>();

        await Parallel.ForEachAsync(
            project.Documents,
            new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount },
            async (document, ct) =>
            {
                if (document.FilePath == null)
                    return;

                if (IsGeneratedFile(document.FilePath))
                    return;

                var semanticModel = await document.GetSemanticModelAsync(ct);
                var syntaxRoot = await document.GetSyntaxRootAsync(ct);

                if (semanticModel == null || syntaxRoot == null)
                    return;

                try
                {
                    // Detect preconditions
                    var preconditionIssues = _preconditionDetector.Detect(
                        syntaxRoot, semanticModel, document.FilePath);
                    foreach (var issue in preconditionIssues)
                    {
                        preconditions.Add(issue);
                    }

                    // Detect postconditions
                    var postconditionIssues = _postconditionDetector.Detect(
                        syntaxRoot, semanticModel, document.FilePath);
                    foreach (var issue in postconditionIssues)
                    {
                        postconditions.Add(issue);
                    }

                    // Detect invariants
                    var invariantIssues = _invariantDetector.Detect(
                        syntaxRoot, semanticModel, document.FilePath);
                    foreach (var issue in invariantIssues)
                    {
                        invariants.Add(issue);
                    }

                    // Analyze side effects
                    var (sideEffectIssues, purity) = _sideEffectAnalyzer.Analyze(
                        syntaxRoot, semanticModel, document.FilePath);
                    foreach (var issue in sideEffectIssues)
                    {
                        sideEffects.Add(issue);
                    }
                    foreach (var info in purity)
                    {
                        purityAnalysis.Add(info);
                    }
                }
                catch (Exception)
                {
                    // Log but continue with other documents
                }
            });

        var preconditionList = preconditions
            .OrderByDescending(p => GetSeverityOrder(p.Severity))
            .ThenBy(p => p.FilePath)
            .ThenBy(p => p.Line)
            .ToList();

        var postconditionList = postconditions
            .OrderByDescending(p => GetSeverityOrder(p.Severity))
            .ThenBy(p => p.FilePath)
            .ThenBy(p => p.Line)
            .ToList();

        var invariantList = invariants
            .OrderByDescending(i => GetSeverityOrder(i.Severity))
            .ThenBy(i => i.FilePath)
            .ThenBy(i => i.Line)
            .ToList();

        var sideEffectList = sideEffects
            .OrderByDescending(s => GetSeverityOrder(s.Severity))
            .ThenBy(s => s.FilePath)
            .ThenBy(s => s.Line)
            .ToList();

        var purityList = purityAnalysis
            .OrderBy(p => p.Purity)
            .ThenBy(p => p.ClassName)
            .ThenBy(p => p.MethodName)
            .ToList();

        return new ContractAnalysisResult
        {
            Preconditions = preconditionList,
            Postconditions = postconditionList,
            Invariants = invariantList,
            SideEffects = sideEffectList,
            PurityAnalysis = purityList,
            Summary = BuildSummary(preconditionList, postconditionList, invariantList, sideEffectList)
        };
    }

    /// <summary>
    /// Analyze a single document for contracts.
    /// </summary>
    public async Task<ContractAnalysisResult> AnalyzeDocumentAsync(Document document)
    {
        if (document.FilePath == null)
            return new ContractAnalysisResult();

        var semanticModel = await document.GetSemanticModelAsync();
        var syntaxRoot = await document.GetSyntaxRootAsync();

        if (semanticModel == null || syntaxRoot == null)
            return new ContractAnalysisResult();

        var preconditions = _preconditionDetector.Detect(syntaxRoot, semanticModel, document.FilePath);
        var postconditions = _postconditionDetector.Detect(syntaxRoot, semanticModel, document.FilePath);
        var invariants = _invariantDetector.Detect(syntaxRoot, semanticModel, document.FilePath);
        var (sideEffects, purityAnalysis) = _sideEffectAnalyzer.Analyze(syntaxRoot, semanticModel, document.FilePath);

        return new ContractAnalysisResult
        {
            Preconditions = preconditions,
            Postconditions = postconditions,
            Invariants = invariants,
            SideEffects = sideEffects,
            PurityAnalysis = purityAnalysis,
            Summary = BuildSummary(preconditions, postconditions, invariants, sideEffects)
        };
    }

    /// <summary>
    /// Generate guard clause suggestions for a method.
    /// </summary>
    public List<string> GenerateGuardClauses(ContractAnalysisResult result, string className, string methodName)
    {
        var guards = new List<string>();

        // Get preconditions for this method
        var methodPreconditions = result.Preconditions
            .Where(p => p.ClassName == className && p.MethodName == methodName)
            .ToList();

        foreach (var precondition in methodPreconditions)
        {
            guards.Add(precondition.SuggestedFix);
        }

        return guards;
    }

    /// <summary>
    /// Get methods that might be pure based on naming but have side effects.
    /// </summary>
    public List<SideEffectIssue> GetSuspiciousSideEffects(ContractAnalysisResult result)
    {
        return result.SideEffects
            .Where(s => s.ExpectedPurity == MethodPurity.Pure || s.ExpectedPurity == MethodPurity.ReadsState)
            .OrderByDescending(s => s.Confidence)
            .ToList();
    }

    /// <summary>
    /// Get methods categorized by purity level.
    /// </summary>
    public Dictionary<MethodPurity, List<MethodPurityInfo>> GetMethodsByPurity(ContractAnalysisResult result)
    {
        return result.PurityAnalysis
            .GroupBy(p => p.Purity)
            .ToDictionary(g => g.Key, g => g.ToList());
    }

    /// <summary>
    /// Get all issues for a specific file.
    /// </summary>
    public List<ContractIssue> GetIssuesForFile(ContractAnalysisResult result, string filePath)
    {
        var issues = new List<ContractIssue>();

        issues.AddRange(result.Preconditions.Where(p => p.FilePath == filePath));
        issues.AddRange(result.Postconditions.Where(p => p.FilePath == filePath));
        issues.AddRange(result.Invariants.Where(i => i.FilePath == filePath));
        issues.AddRange(result.SideEffects.Where(s => s.FilePath == filePath));

        return issues.OrderBy(i => i.Line).ToList();
    }

    /// <summary>
    /// Get all issues for a specific class.
    /// </summary>
    public List<ContractIssue> GetIssuesForClass(ContractAnalysisResult result, string className)
    {
        var issues = new List<ContractIssue>();

        issues.AddRange(result.Preconditions.Where(p => p.ClassName == className));
        issues.AddRange(result.Postconditions.Where(p => p.ClassName == className));
        issues.AddRange(result.Invariants.Where(i => i.ClassName == className));
        issues.AddRange(result.SideEffects.Where(s => s.ClassName == className));

        return issues.OrderBy(i => i.Line).ToList();
    }

    /// <summary>
    /// Get a formatted report of all issues.
    /// </summary>
    public string GenerateReport(ContractAnalysisResult result)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("# Contract Analysis Report");
        sb.AppendLine();
        sb.AppendLine("## Summary");
        sb.AppendLine($"- Total Issues: {result.Summary.TotalIssues}");
        sb.AppendLine($"- Critical: {result.Summary.CriticalCount}");
        sb.AppendLine($"- Errors: {result.Summary.ErrorCount}");
        sb.AppendLine($"- Warnings: {result.Summary.WarningCount}");
        sb.AppendLine($"- Info: {result.Summary.InfoCount}");
        sb.AppendLine();

        if (result.Preconditions.Any())
        {
            sb.AppendLine("## Precondition Issues");
            sb.AppendLine();
            foreach (var issue in result.Preconditions)
            {
                sb.AppendLine($"### [{issue.Severity}] {issue.ClassName}.{issue.MethodName}");
                sb.AppendLine($"- **File**: {issue.FilePath}:{issue.Line}");
                sb.AppendLine($"- **Type**: {issue.Type}");
                sb.AppendLine($"- **Description**: {issue.Description}");
                sb.AppendLine($"- **Target**: {issue.TargetExpression}");
                sb.AppendLine($"- **Expected**: {issue.ExpectedCondition}");
                sb.AppendLine($"- **Fix**: `{issue.SuggestedFix}`");
                sb.AppendLine();
            }
        }

        if (result.SideEffects.Any())
        {
            sb.AppendLine("## Side Effect Issues");
            sb.AppendLine();
            foreach (var issue in result.SideEffects)
            {
                sb.AppendLine($"### [{issue.Severity}] {issue.ClassName}.{issue.MethodName}");
                sb.AppendLine($"- **File**: {issue.FilePath}:{issue.Line}");
                sb.AppendLine($"- **Expected Purity**: {issue.ExpectedPurity}");
                sb.AppendLine($"- **Actual Purity**: {issue.Purity}");
                sb.AppendLine($"- **Description**: {issue.Description}");
                if (issue.ModifiedFields.Any())
                    sb.AppendLine($"- **Modified Fields**: {string.Join(", ", issue.ModifiedFields)}");
                if (issue.SideEffectCalls.Any())
                    sb.AppendLine($"- **I/O Calls**: {string.Join(", ", issue.SideEffectCalls)}");
                sb.AppendLine();
            }
        }

        if (result.Invariants.Any(i => i.Severity >= ContractSeverity.Warning))
        {
            sb.AppendLine("## Invariant Issues");
            sb.AppendLine();
            foreach (var issue in result.Invariants.Where(i => i.Severity >= ContractSeverity.Warning))
            {
                sb.AppendLine($"### [{issue.Severity}] {issue.ClassName}");
                sb.AppendLine($"- **File**: {issue.FilePath}:{issue.Line}");
                sb.AppendLine($"- **Invariant**: {issue.InvariantCondition}");
                sb.AppendLine($"- **Description**: {issue.Description}");
                sb.AppendLine($"- **Members**: {string.Join(", ", issue.InvolvedMembers)}");
                if (issue.PotentiallyViolatingMethods.Any())
                    sb.AppendLine($"- **Violating Methods**: {string.Join(", ", issue.PotentiallyViolatingMethods)}");
                sb.AppendLine();
            }
        }

        return sb.ToString();
    }

    private bool IsGeneratedFile(string filePath)
    {
        var fileName = Path.GetFileName(filePath);
        return fileName.EndsWith(".g.cs") ||
               fileName.EndsWith(".Designer.cs") ||
               fileName.EndsWith(".generated.cs") ||
               filePath.Contains("obj" + Path.DirectorySeparatorChar);
    }

    private int GetSeverityOrder(ContractSeverity severity) => severity switch
    {
        ContractSeverity.Critical => 4,
        ContractSeverity.Error => 3,
        ContractSeverity.Warning => 2,
        ContractSeverity.Info => 1,
        _ => 0
    };

    private ContractSummary BuildSummary(
        List<PreconditionIssue> preconditions,
        List<PostconditionIssue> postconditions,
        List<InvariantIssue> invariants,
        List<SideEffectIssue> sideEffects)
    {
        var allIssues = preconditions.Cast<ContractIssue>()
            .Concat(postconditions)
            .Concat(invariants)
            .Concat(sideEffects)
            .ToList();

        return new ContractSummary
        {
            TotalIssues = allIssues.Count,
            NullPreconditions = preconditions.Count(p => p.Type == ContractType.NullPrecondition),
            RangePreconditions = preconditions.Count(p => p.Type == ContractType.RangePrecondition),
            StatePreconditions = preconditions.Count(p => p.Type == ContractType.StatePrecondition),
            Postconditions = postconditions.Count,
            Invariants = invariants.Count,
            SideEffects = sideEffects.Count,
            CriticalCount = allIssues.Count(i => i.Severity == ContractSeverity.Critical),
            ErrorCount = allIssues.Count(i => i.Severity == ContractSeverity.Error),
            WarningCount = allIssues.Count(i => i.Severity == ContractSeverity.Warning),
            InfoCount = allIssues.Count(i => i.Severity == ContractSeverity.Info),
            IssuesByFile = allIssues
                .GroupBy(i => i.FilePath)
                .ToDictionary(g => g.Key, g => g.Count()),
            IssuesByClass = allIssues
                .GroupBy(i => i.ClassName)
                .ToDictionary(g => g.Key, g => g.Count())
        };
    }
}
