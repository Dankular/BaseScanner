using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Concurrency.Models;
using BaseScanner.Analyzers.Concurrency.Detectors;
using System.Diagnostics;

namespace BaseScanner.Analyzers.Concurrency;

/// <summary>
/// Main coordinator for thread safety analysis.
/// Orchestrates multiple detectors to identify thread safety issues in C# code.
/// </summary>
public class ThreadSafetyAnalyzer
{
    private readonly List<IThreadSafetyDetector> _detectors;
    private readonly ThreadSafetyAnalysisContext _context;

    /// <summary>
    /// Creates a new ThreadSafetyAnalyzer with all default detectors.
    /// </summary>
    public ThreadSafetyAnalyzer()
    {
        _context = new ThreadSafetyAnalysisContext();
        _detectors =
        [
            new SharedStateDetector(),
            new Detectors.RaceConditionDetector(),
            new AtomicityDetector(),
            new AsyncReentrancyDetector(),
            new LockAnalyzer()
        ];
    }

    /// <summary>
    /// Creates a new ThreadSafetyAnalyzer with specified detectors.
    /// </summary>
    /// <param name="detectors">Custom set of detectors to use.</param>
    public ThreadSafetyAnalyzer(IEnumerable<IThreadSafetyDetector> detectors)
    {
        _context = new ThreadSafetyAnalysisContext();
        _detectors = detectors.ToList();
    }

    /// <summary>
    /// Gets the list of active detectors.
    /// </summary>
    public IReadOnlyList<IThreadSafetyDetector> Detectors => _detectors;

    /// <summary>
    /// Gets the analysis context containing shared state.
    /// </summary>
    public ThreadSafetyAnalysisContext Context => _context;

    /// <summary>
    /// Analyzes a single document for thread safety issues.
    /// </summary>
    /// <param name="document">The Roslyn document to analyze.</param>
    /// <param name="semanticModel">The semantic model for type resolution.</param>
    /// <param name="root">The syntax tree root node.</param>
    /// <returns>Analysis result containing all detected issues.</returns>
    public async Task<ThreadSafetyAnalysisResult> AnalyzeAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root)
    {
        var stopwatch = Stopwatch.StartNew();
        var allIssues = new List<ThreadSafetyIssue>();

        foreach (var detector in _detectors)
        {
            try
            {
                var issues = await detector.DetectAsync(document, semanticModel, root, _context);
                allIssues.AddRange(issues);
            }
            catch (Exception ex)
            {
                // Log error but continue with other detectors
                allIssues.Add(new ThreadSafetyIssue
                {
                    IssueType = "AnalyzerError",
                    RuleId = "TS000",
                    Severity = "Info",
                    Message = $"Detector '{detector.Name}' threw exception: {ex.Message}",
                    FilePath = document.FilePath ?? "",
                    Line = 1,
                    EndLine = 1,
                    CodeSnippet = ex.GetType().Name
                });
            }
        }

        stopwatch.Stop();

        return BuildResult(allIssues, 1, stopwatch.ElapsedMilliseconds);
    }

    /// <summary>
    /// Analyzes an entire project for thread safety issues.
    /// </summary>
    /// <param name="project">The Roslyn project to analyze.</param>
    /// <param name="progressCallback">Optional callback for progress updates.</param>
    /// <returns>Analysis result containing all detected issues across the project.</returns>
    public async Task<ThreadSafetyAnalysisResult> AnalyzeProjectAsync(
        Project project,
        Action<string, int, int>? progressCallback = null)
    {
        var stopwatch = Stopwatch.StartNew();
        var allIssues = new List<ThreadSafetyIssue>();
        var documents = project.Documents.ToList();
        var filesAnalyzed = 0;

        // First pass: collect shared state information across all files
        foreach (var document in documents)
        {
            if (ShouldSkipDocument(document)) continue;

            var root = await document.GetSyntaxRootAsync();
            var semanticModel = await document.GetSemanticModelAsync();

            if (root == null || semanticModel == null) continue;

            // Pre-analyze to collect field information
            CollectSharedStateInfo(document, semanticModel, root);
        }

        // Second pass: run all detectors with full context
        for (int i = 0; i < documents.Count; i++)
        {
            var document = documents[i];
            if (ShouldSkipDocument(document)) continue;

            progressCallback?.Invoke(document.FilePath ?? document.Name, i + 1, documents.Count);

            var root = await document.GetSyntaxRootAsync();
            var semanticModel = await document.GetSemanticModelAsync();

            if (root == null || semanticModel == null) continue;

            var result = await AnalyzeAsync(document, semanticModel, root);
            allIssues.AddRange(result.Issues);
            filesAnalyzed++;
        }

        stopwatch.Stop();

        // Deduplicate issues (some detectors may report similar issues)
        var deduplicatedIssues = DeduplicateIssues(allIssues);

        return BuildResult(deduplicatedIssues, filesAnalyzed, stopwatch.ElapsedMilliseconds);
    }

    /// <summary>
    /// Analyzes specific files in a project.
    /// </summary>
    /// <param name="project">The Roslyn project containing the files.</param>
    /// <param name="filePaths">Paths to the files to analyze.</param>
    /// <returns>Analysis result for the specified files.</returns>
    public async Task<ThreadSafetyAnalysisResult> AnalyzeFilesAsync(
        Project project,
        IEnumerable<string> filePaths)
    {
        var stopwatch = Stopwatch.StartNew();
        var allIssues = new List<ThreadSafetyIssue>();
        var filePathSet = filePaths.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var filesAnalyzed = 0;

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null) continue;
            if (!filePathSet.Contains(document.FilePath)) continue;

            var root = await document.GetSyntaxRootAsync();
            var semanticModel = await document.GetSemanticModelAsync();

            if (root == null || semanticModel == null) continue;

            var result = await AnalyzeAsync(document, semanticModel, root);
            allIssues.AddRange(result.Issues);
            filesAnalyzed++;
        }

        stopwatch.Stop();

        return BuildResult(allIssues, filesAnalyzed, stopwatch.ElapsedMilliseconds);
    }

    /// <summary>
    /// Gets a summary of supported rules across all detectors.
    /// </summary>
    public IReadOnlyDictionary<string, string> GetSupportedRules()
    {
        var rules = new Dictionary<string, string>();

        foreach (var detector in _detectors)
        {
            foreach (var ruleId in detector.SupportedRules)
            {
                if (!rules.ContainsKey(ruleId))
                {
                    rules[ruleId] = ThreadSafetyRules.GetRuleDescription(ruleId);
                }
            }
        }

        return rules;
    }

    /// <summary>
    /// Filters issues by severity.
    /// </summary>
    public static List<ThreadSafetyIssue> FilterBySeverity(
        IEnumerable<ThreadSafetyIssue> issues,
        params string[] severities)
    {
        var severitySet = severities.ToHashSet(StringComparer.OrdinalIgnoreCase);
        return issues.Where(i => severitySet.Contains(i.Severity)).ToList();
    }

    /// <summary>
    /// Groups issues by file.
    /// </summary>
    public static Dictionary<string, List<ThreadSafetyIssue>> GroupByFile(
        IEnumerable<ThreadSafetyIssue> issues)
    {
        return issues
            .GroupBy(i => i.FilePath)
            .ToDictionary(g => g.Key, g => g.OrderBy(i => i.Line).ToList());
    }

    /// <summary>
    /// Groups issues by rule.
    /// </summary>
    public static Dictionary<string, List<ThreadSafetyIssue>> GroupByRule(
        IEnumerable<ThreadSafetyIssue> issues)
    {
        return issues
            .GroupBy(i => i.RuleId)
            .ToDictionary(g => g.Key, g => g.ToList());
    }

    private bool ShouldSkipDocument(Document document)
    {
        if (document.FilePath == null) return true;
        if (document.FilePath.Contains(".Designer.cs")) return true;
        if (document.FilePath.Contains(".g.cs")) return true;
        if (document.FilePath.Contains(".generated.cs")) return true;
        if (document.FilePath.Contains("\\obj\\")) return true;
        if (document.FilePath.Contains("/obj/")) return true;
        return false;
    }

    private void CollectSharedStateInfo(Document document, SemanticModel semanticModel, SyntaxNode root)
    {
        // Collect static fields
        foreach (var classDecl in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
        {
            var className = classDecl.Identifier.Text;
            _context.AnalyzedClasses.Add(className);

            foreach (var field in classDecl.Members.OfType<FieldDeclarationSyntax>())
            {
                foreach (var variable in field.Declaration.Variables)
                {
                    var fieldSymbol = semanticModel.GetDeclaredSymbol(variable) as IFieldSymbol;
                    if (fieldSymbol == null) continue;

                    var fieldInfo = new SharedFieldInfo
                    {
                        FieldName = variable.Identifier.Text,
                        FieldType = field.Declaration.Type.ToString(),
                        ClassName = className,
                        IsStatic = fieldSymbol.IsStatic,
                        IsVolatile = fieldSymbol.IsVolatile,
                        IsReadOnly = fieldSymbol.IsReadOnly,
                        FilePath = document.FilePath ?? "",
                        DeclarationLine = field.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        Symbol = fieldSymbol
                    };

                    _context.RegisterSharedField(fieldInfo);
                }
            }
        }
    }

    private List<ThreadSafetyIssue> DeduplicateIssues(List<ThreadSafetyIssue> issues)
    {
        // Group by location and rule, keep the one with highest severity
        var grouped = issues.GroupBy(i => (i.FilePath, i.Line, i.RuleId));

        var severityOrder = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["Critical"] = 4,
            ["High"] = 3,
            ["Medium"] = 2,
            ["Low"] = 1,
            ["Info"] = 0
        };

        return grouped
            .Select(g => g.OrderByDescending(i => severityOrder.GetValueOrDefault(i.Severity, 0)).First())
            .OrderBy(i => i.FilePath)
            .ThenBy(i => i.Line)
            .ToList();
    }

    private ThreadSafetyAnalysisResult BuildResult(
        List<ThreadSafetyIssue> issues,
        int filesAnalyzed,
        long durationMs)
    {
        return new ThreadSafetyAnalysisResult
        {
            TotalIssues = issues.Count,
            CriticalCount = issues.Count(i => i.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase)),
            HighCount = issues.Count(i => i.Severity.Equals("High", StringComparison.OrdinalIgnoreCase)),
            MediumCount = issues.Count(i => i.Severity.Equals("Medium", StringComparison.OrdinalIgnoreCase)),
            LowCount = issues.Count(i => i.Severity.Equals("Low", StringComparison.OrdinalIgnoreCase)),
            InfoCount = issues.Count(i => i.Severity.Equals("Info", StringComparison.OrdinalIgnoreCase)),
            Issues = issues,
            IssuesByType = issues.GroupBy(i => i.IssueType).ToDictionary(g => g.Key, g => g.ToList()),
            IssueCountByRule = issues.GroupBy(i => i.RuleId).ToDictionary(g => g.Key, g => g.Count()),
            SharedFields = _context.SharedFields.Values.ToList(),
            LockPatterns = _context.LockPatterns,
            FilesAnalyzed = filesAnalyzed,
            AnalysisDurationMs = durationMs
        };
    }
}

/// <summary>
/// Extension methods for ThreadSafetyAnalysisResult.
/// </summary>
public static class ThreadSafetyAnalysisResultExtensions
{
    /// <summary>
    /// Generates a summary report of the analysis.
    /// </summary>
    public static string GenerateSummary(this ThreadSafetyAnalysisResult result)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("=== Thread Safety Analysis Summary ===");
        sb.AppendLine();
        sb.AppendLine($"Files Analyzed: {result.FilesAnalyzed}");
        sb.AppendLine($"Analysis Time: {result.AnalysisDurationMs}ms");
        sb.AppendLine();
        sb.AppendLine($"Total Issues: {result.TotalIssues}");
        sb.AppendLine($"  Critical: {result.CriticalCount}");
        sb.AppendLine($"  High: {result.HighCount}");
        sb.AppendLine($"  Medium: {result.MediumCount}");
        sb.AppendLine($"  Low: {result.LowCount}");
        sb.AppendLine($"  Info: {result.InfoCount}");
        sb.AppendLine();

        if (result.IssueCountByRule.Count > 0)
        {
            sb.AppendLine("Issues by Rule:");
            foreach (var (ruleId, count) in result.IssueCountByRule.OrderByDescending(kv => kv.Value))
            {
                var description = ThreadSafetyRules.GetRuleDescription(ruleId);
                sb.AppendLine($"  {ruleId}: {count} - {description}");
            }
            sb.AppendLine();
        }

        if (result.SharedFields.Count > 0)
        {
            sb.AppendLine($"Shared Fields Detected: {result.SharedFields.Count}");
            var potentiallyUnsafe = result.SharedFields.Count(f => !f.IsReadOnly && !f.IsVolatile && f.WritingMethods.Count > 0);
            sb.AppendLine($"  Potentially Unsafe: {potentiallyUnsafe}");
            sb.AppendLine();
        }

        if (result.LockPatterns.Count > 0)
        {
            sb.AppendLine($"Lock Patterns Detected: {result.LockPatterns.Count}");
            var nestedLockCount = result.LockPatterns.Count(l => l.NestedLocks.Count > 0);
            if (nestedLockCount > 0)
            {
                sb.AppendLine($"  With Nested Locks: {nestedLockCount}");
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Generates a detailed report of all issues.
    /// </summary>
    public static string GenerateDetailedReport(this ThreadSafetyAnalysisResult result)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine(result.GenerateSummary());
        sb.AppendLine("=== Detailed Issues ===");
        sb.AppendLine();

        var groupedByFile = ThreadSafetyAnalyzer.GroupByFile(result.Issues);

        foreach (var (filePath, issues) in groupedByFile.OrderBy(kv => kv.Key))
        {
            sb.AppendLine($"File: {filePath}");
            sb.AppendLine(new string('-', 80));

            foreach (var issue in issues)
            {
                sb.AppendLine($"  Line {issue.Line}: [{issue.Severity}] {issue.RuleId} - {issue.IssueType}");
                sb.AppendLine($"    {issue.Message}");
                if (!string.IsNullOrEmpty(issue.CodeSnippet))
                {
                    sb.AppendLine($"    Code: {issue.CodeSnippet}");
                }
                if (!string.IsNullOrEmpty(issue.SuggestedFix))
                {
                    sb.AppendLine($"    Fix: {issue.SuggestedFix}");
                }
                sb.AppendLine();
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Returns true if there are any critical or high severity issues.
    /// </summary>
    public static bool HasSevereIssues(this ThreadSafetyAnalysisResult result)
    {
        return result.CriticalCount > 0 || result.HighCount > 0;
    }

    /// <summary>
    /// Gets issues that should block CI/CD.
    /// </summary>
    public static List<ThreadSafetyIssue> GetBlockingIssues(this ThreadSafetyAnalysisResult result)
    {
        return result.Issues
            .Where(i => i.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase))
            .ToList();
    }
}
