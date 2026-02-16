using Microsoft.CodeAnalysis;
using BaseScanner.Context;
using BaseScanner.Analyzers.Documentation.Models;
using BaseScanner.Analyzers.Documentation.Detectors;

namespace BaseScanner.Analyzers.Documentation;

/// <summary>
/// Main coordinator for documentation quality analysis.
/// Orchestrates multiple detectors to analyze code documentation.
/// </summary>
public class DocumentationAnalyzer
{
    private readonly List<IDocDetector> _detectors;
    private readonly NamingQualityDetector _namingDetector;
    private readonly CompletenessDetector _completenessDetector;

    /// <summary>
    /// Initializes a new instance of the DocumentationAnalyzer with default detectors.
    /// </summary>
    public DocumentationAnalyzer()
    {
        _namingDetector = new NamingQualityDetector();
        _completenessDetector = new CompletenessDetector();

        _detectors =
        [
            new MissingDocDetector(),
            new StaleDocDetector(),
            _namingDetector,
            _completenessDetector
        ];
    }

    /// <summary>
    /// Initializes a new instance of the DocumentationAnalyzer with custom detectors.
    /// </summary>
    /// <param name="detectors">The detectors to use for analysis.</param>
    public DocumentationAnalyzer(IEnumerable<IDocDetector> detectors)
    {
        _detectors = [.. detectors];
        _namingDetector = _detectors.OfType<NamingQualityDetector>().FirstOrDefault() ?? new NamingQualityDetector();
        _completenessDetector = _detectors.OfType<CompletenessDetector>().FirstOrDefault() ?? new CompletenessDetector();
    }

    /// <summary>
    /// Analyzes documentation quality for an entire project.
    /// </summary>
    /// <param name="project">The Roslyn project to analyze.</param>
    /// <returns>Complete documentation analysis result.</returns>
    public async Task<DocumentationResult> AnalyzeAsync(Project project)
    {
        var allIssues = new List<DocumentationIssue>();
        var fileSummaries = new List<FileDocumentationSummary>();
        var allNameSuggestions = new List<NameSuggestion>();
        var allCoverage = new List<DocumentationCoverage>();

        foreach (var document in project.Documents)
        {
            if (document.FilePath?.Contains("obj") == true ||
                document.FilePath?.Contains("bin") == true)
            {
                continue;
            }

            var (issues, coverage) = await AnalyzeDocumentAsync(document);

            if (issues.Any() || coverage.Any())
            {
                var fileSummary = CreateFileSummary(document.FilePath ?? "", issues, coverage);
                fileSummaries.Add(fileSummary);
                allIssues.AddRange(issues);
                allCoverage.AddRange(coverage);
            }
        }

        // Collect name suggestions
        allNameSuggestions.AddRange(_namingDetector.GetNameSuggestions());

        var summary = CreateSummary(allIssues, allCoverage);

        return new DocumentationResult
        {
            Issues = allIssues,
            FileSummaries = fileSummaries,
            Summary = summary,
            NameSuggestions = allNameSuggestions,
            AnalyzedAt = DateTime.UtcNow
        };
    }

    /// <summary>
    /// Analyzes documentation quality for a single document.
    /// </summary>
    /// <param name="document">The Roslyn document to analyze.</param>
    /// <param name="context">Optional code context for enhanced analysis.</param>
    /// <returns>List of documentation issues found.</returns>
    public async Task<(List<DocumentationIssue> Issues, List<DocumentationCoverage> Coverage)> AnalyzeDocumentAsync(
        Document document,
        CodeContext? context = null)
    {
        var semanticModel = await document.GetSemanticModelAsync();
        var root = await document.GetSyntaxRootAsync();

        if (semanticModel == null || root == null)
        {
            return ([], []);
        }

        var allIssues = new List<DocumentationIssue>();

        foreach (var detector in _detectors)
        {
            try
            {
                var issues = await detector.DetectAsync(document, semanticModel, root, context);
                allIssues.AddRange(issues);
            }
            catch (Exception ex)
            {
                // Log error but continue with other detectors
                Console.Error.WriteLine($"Error in detector {detector.Name}: {ex.Message}");
            }
        }

        var coverage = _completenessDetector.GetCoverageDetails();

        return (allIssues, coverage);
    }

    /// <summary>
    /// Analyzes documentation quality for specific syntax node.
    /// </summary>
    /// <param name="document">The document containing the node.</param>
    /// <param name="node">The syntax node to analyze.</param>
    /// <returns>List of documentation issues for the node.</returns>
    public async Task<List<DocumentationIssue>> AnalyzeNodeAsync(Document document, SyntaxNode node)
    {
        var semanticModel = await document.GetSemanticModelAsync();
        if (semanticModel == null) return [];

        var allIssues = new List<DocumentationIssue>();

        foreach (var detector in _detectors)
        {
            try
            {
                var issues = await detector.DetectAsync(document, semanticModel, node, null);
                allIssues.AddRange(issues);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error in detector {detector.Name}: {ex.Message}");
            }
        }

        return allIssues;
    }

    /// <summary>
    /// Gets only missing documentation issues.
    /// </summary>
    public async Task<List<DocumentationIssue>> GetMissingDocumentationAsync(Project project)
    {
        var result = await AnalyzeAsync(project);
        return result.Issues
            .Where(i => i.Category == DocIssueCategory.MissingDocumentation)
            .ToList();
    }

    /// <summary>
    /// Gets only stale documentation issues.
    /// </summary>
    public async Task<List<DocumentationIssue>> GetStaleDocumentationAsync(Project project)
    {
        var result = await AnalyzeAsync(project);
        return result.Issues
            .Where(i => i.Category == DocIssueCategory.StaleDocumentation)
            .ToList();
    }

    /// <summary>
    /// Gets only naming quality issues.
    /// </summary>
    public async Task<List<DocumentationIssue>> GetNamingIssuesAsync(Project project)
    {
        var result = await AnalyzeAsync(project);
        return result.Issues
            .Where(i => i.Category == DocIssueCategory.NamingQuality)
            .ToList();
    }

    /// <summary>
    /// Gets all TODO/FIXME/HACK comments.
    /// </summary>
    public async Task<List<DocumentationIssue>> GetActionItemsAsync(Project project)
    {
        var result = await AnalyzeAsync(project);
        return result.Issues
            .Where(i => i.IssueType is DocumentationIssueType.TodoComment
                                    or DocumentationIssueType.FixmeComment
                                    or DocumentationIssueType.HackComment)
            .ToList();
    }

    /// <summary>
    /// Gets documentation coverage report.
    /// </summary>
    public async Task<(double OverallCoverage, Dictionary<string, double> FilesCoverage)> GetCoverageReportAsync(Project project)
    {
        var result = await AnalyzeAsync(project);

        var filesCoverage = result.FileSummaries
            .Where(f => f.TotalPublicSymbols > 0)
            .ToDictionary(f => f.FilePath, f => f.CoveragePercentage);

        return (result.Summary.OverallCoveragePercentage, filesCoverage);
    }

    /// <summary>
    /// Calculates documentation quality score (0-100).
    /// </summary>
    public async Task<double> CalculateQualityScoreAsync(Project project)
    {
        var result = await AnalyzeAsync(project);
        return result.Summary.QualityScore;
    }

    /// <summary>
    /// Generates a formatted report of documentation issues.
    /// </summary>
    public async Task<string> GenerateReportAsync(Project project)
    {
        var result = await AnalyzeAsync(project);

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("===========================================");
        sb.AppendLine("       DOCUMENTATION QUALITY REPORT        ");
        sb.AppendLine("===========================================");
        sb.AppendLine();

        // Summary
        sb.AppendLine("SUMMARY");
        sb.AppendLine("-------");
        sb.AppendLine($"Quality Score: {result.Summary.QualityScore:F1}/100");
        sb.AppendLine($"Naming Quality: {result.Summary.NamingQualityScore:F1}/100");
        sb.AppendLine($"Coverage: {result.Summary.OverallCoveragePercentage:F1}%");
        sb.AppendLine($"Total Issues: {result.Summary.TotalIssues}");
        sb.AppendLine($"  Critical: {result.Summary.IssuesBySeverity.GetValueOrDefault(DocIssueSeverity.Critical)}");
        sb.AppendLine($"  Major: {result.Summary.IssuesBySeverity.GetValueOrDefault(DocIssueSeverity.Major)}");
        sb.AppendLine($"  Minor: {result.Summary.IssuesBySeverity.GetValueOrDefault(DocIssueSeverity.Minor)}");
        sb.AppendLine($"  Warning: {result.Summary.IssuesBySeverity.GetValueOrDefault(DocIssueSeverity.Warning)}");
        sb.AppendLine($"  Info: {result.Summary.IssuesBySeverity.GetValueOrDefault(DocIssueSeverity.Info)}");
        sb.AppendLine();

        // Action items
        if (result.Summary.TodoCount > 0 || result.Summary.FixmeCount > 0 || result.Summary.HackCount > 0)
        {
            sb.AppendLine("ACTION ITEMS");
            sb.AppendLine("------------");
            sb.AppendLine($"  TODOs: {result.Summary.TodoCount}");
            sb.AppendLine($"  FIXMEs: {result.Summary.FixmeCount}");
            sb.AppendLine($"  HACKs: {result.Summary.HackCount}");
            sb.AppendLine();
        }

        // Issues by category
        sb.AppendLine("ISSUES BY CATEGORY");
        sb.AppendLine("------------------");
        foreach (var (category, count) in result.Summary.IssuesByCategory.OrderByDescending(x => x.Value))
        {
            sb.AppendLine($"  {category}: {count}");
        }
        sb.AppendLine();

        // Files with worst coverage
        var worstFiles = result.FileSummaries
            .Where(f => f.TotalPublicSymbols > 0)
            .OrderBy(f => f.CoveragePercentage)
            .Take(10)
            .ToList();

        if (worstFiles.Any())
        {
            sb.AppendLine("FILES WITH LOWEST COVERAGE");
            sb.AppendLine("--------------------------");
            foreach (var file in worstFiles)
            {
                var fileName = Path.GetFileName(file.FilePath);
                sb.AppendLine($"  {fileName}: {file.CoveragePercentage:F1}% ({file.DocumentedPublicSymbols}/{file.TotalPublicSymbols} documented)");
            }
            sb.AppendLine();
        }

        // Name suggestions
        if (result.NameSuggestions.Any())
        {
            sb.AppendLine("NAME IMPROVEMENT SUGGESTIONS");
            sb.AppendLine("----------------------------");
            foreach (var suggestion in result.NameSuggestions.Take(20))
            {
                sb.AppendLine($"  {suggestion.OriginalName} -> {suggestion.SuggestedName}");
                sb.AppendLine($"    Reason: {suggestion.Reason}");
            }
            sb.AppendLine();
        }

        // Critical/Major issues
        var criticalIssues = result.Issues
            .Where(i => i.Severity >= DocIssueSeverity.Major)
            .OrderByDescending(i => i.Severity)
            .Take(20)
            .ToList();

        if (criticalIssues.Any())
        {
            sb.AppendLine("TOP ISSUES TO ADDRESS");
            sb.AppendLine("---------------------");
            foreach (var issue in criticalIssues)
            {
                var fileName = Path.GetFileName(issue.FilePath);
                sb.AppendLine($"  [{issue.Severity}] {fileName}:{issue.StartLine}");
                sb.AppendLine($"    {issue.Description}");
                if (!string.IsNullOrEmpty(issue.Suggestion))
                {
                    sb.AppendLine($"    Suggestion: {issue.Suggestion}");
                }
                sb.AppendLine();
            }
        }

        return sb.ToString();
    }

    // Private helper methods

    private static FileDocumentationSummary CreateFileSummary(
        string filePath,
        List<DocumentationIssue> issues,
        List<DocumentationCoverage> coverage)
    {
        var publicSymbols = coverage.Count;
        var documentedSymbols = coverage.Count(c => c.HasSummary);
        var coveragePercentage = publicSymbols > 0
            ? (documentedSymbols * 100.0 / publicSymbols)
            : 100.0;

        return new FileDocumentationSummary
        {
            FilePath = filePath,
            TotalPublicSymbols = publicSymbols,
            DocumentedPublicSymbols = documentedSymbols,
            CoveragePercentage = coveragePercentage,
            Issues = issues,
            SymbolCoverage = coverage
        };
    }

    private static DocumentationSummary CreateSummary(
        List<DocumentationIssue> issues,
        List<DocumentationCoverage> coverage)
    {
        var issuesBySeverity = issues
            .GroupBy(i => i.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        var issuesByCategory = issues
            .GroupBy(i => i.Category)
            .ToDictionary(g => g.Key, g => g.Count());

        var issuesByType = issues
            .GroupBy(i => i.IssueType)
            .ToDictionary(g => g.Key, g => g.Count());

        var totalPublic = coverage.Count;
        var documented = coverage.Count(c => c.HasSummary);
        var overallCoverage = totalPublic > 0 ? (documented * 100.0 / totalPublic) : 100.0;

        var todoCount = issues.Count(i => i.IssueType == DocumentationIssueType.TodoComment);
        var fixmeCount = issues.Count(i => i.IssueType == DocumentationIssueType.FixmeComment);
        var hackCount = issues.Count(i => i.IssueType == DocumentationIssueType.HackComment);

        // Calculate quality score
        var qualityScore = CalculateQualityScore(issues, coverage, overallCoverage);
        var namingScore = CalculateNamingScore(issues);

        return new DocumentationSummary
        {
            TotalIssues = issues.Count,
            IssuesBySeverity = issuesBySeverity,
            IssuesByCategory = issuesByCategory,
            IssuesByType = issuesByType,
            TotalPublicSymbols = totalPublic,
            DocumentedPublicSymbols = documented,
            OverallCoveragePercentage = overallCoverage,
            TodoCount = todoCount,
            FixmeCount = fixmeCount,
            HackCount = hackCount,
            QualityScore = qualityScore,
            NamingQualityScore = namingScore
        };
    }

    private static double CalculateQualityScore(
        List<DocumentationIssue> issues,
        List<DocumentationCoverage> coverage,
        double overallCoverage)
    {
        // Start with base score of 100
        var score = 100.0;

        // Deduct for coverage
        score -= (100 - overallCoverage) * 0.3; // Coverage counts for 30%

        // Deduct for issues by severity
        foreach (var issue in issues)
        {
            score -= issue.Severity switch
            {
                DocIssueSeverity.Critical => 5.0,
                DocIssueSeverity.Major => 2.0,
                DocIssueSeverity.Minor => 1.0,
                DocIssueSeverity.Warning => 0.5,
                DocIssueSeverity.Info => 0.1,
                _ => 0
            };
        }

        // Bonus for having examples and remarks
        var withExamples = coverage.Count(c => c.HasExample);
        var withRemarks = coverage.Count(c => c.HasRemarks);
        if (coverage.Count > 0)
        {
            score += (withExamples * 100.0 / coverage.Count) * 0.05; // 5% bonus for examples
            score += (withRemarks * 100.0 / coverage.Count) * 0.02; // 2% bonus for remarks
        }

        return Math.Max(0, Math.Min(100, score));
    }

    private static double CalculateNamingScore(List<DocumentationIssue> issues)
    {
        var score = 100.0;

        var namingIssues = issues.Where(i => i.Category == DocIssueCategory.NamingQuality).ToList();

        foreach (var issue in namingIssues)
        {
            score -= issue.Severity switch
            {
                DocIssueSeverity.Major => 5.0,
                DocIssueSeverity.Minor => 2.0,
                DocIssueSeverity.Warning => 1.0,
                DocIssueSeverity.Info => 0.5,
                _ => 0
            };
        }

        return Math.Max(0, Math.Min(100, score));
    }
}
