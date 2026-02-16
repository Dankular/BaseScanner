using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Logging.Models;
using System.Collections.Concurrent;

namespace BaseScanner.Analyzers.Logging;

/// <summary>
/// Main orchestrator for logging quality analysis.
/// Coordinates multiple specialized detectors to identify logging issues across a project.
/// </summary>
public class LoggingQualityAnalyzer
{
    private readonly List<ILoggingDetector> _detectors;

    /// <summary>
    /// Creates a new logging quality analyzer with all detectors enabled.
    /// </summary>
    public LoggingQualityAnalyzer()
    {
        _detectors = new List<ILoggingDetector>
        {
            new LogLevelAnalyzer(),
            new SensitiveDataDetector(),
            new StructuredLoggingAnalyzer(),
            new CorrelationAnalyzer()
        };
    }

    /// <summary>
    /// Creates a logging quality analyzer with specific detectors.
    /// </summary>
    public LoggingQualityAnalyzer(IEnumerable<ILoggingDetector> detectors)
    {
        _detectors = detectors.ToList();
    }

    /// <summary>
    /// Analyze a project for logging quality issues.
    /// </summary>
    public async Task<LoggingAnalysisResult> AnalyzeAsync(Project project)
    {
        var issues = new ConcurrentBag<LoggingIssue>();
        var detectedFrameworks = new ConcurrentBag<string>();

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

                // Detect logging frameworks used in this file
                var frameworks = DetectLoggingFrameworks(syntaxRoot, semanticModel);
                foreach (var fw in frameworks)
                {
                    detectedFrameworks.Add(fw);
                }

                // Check for exception blocks without logging
                CheckExceptionBlocksWithoutLogging(document, semanticModel, syntaxRoot, issues);

                // Run all detectors
                foreach (var detector in _detectors)
                {
                    try
                    {
                        var detected = await detector.DetectAsync(document, semanticModel, syntaxRoot);
                        foreach (var issue in detected)
                        {
                            issues.Add(issue);
                        }
                    }
                    catch (Exception)
                    {
                        // Log but continue with other detectors
                    }
                }
            });

        var issueList = issues
            .OrderByDescending(i => GetSeverityOrder(i.Severity))
            .ThenBy(i => i.FilePath)
            .ThenBy(i => i.StartLine)
            .ToList();

        return new LoggingAnalysisResult
        {
            Issues = issueList,
            Summary = BuildSummary(issueList, detectedFrameworks.Distinct().ToHashSet()),
            AnalyzedAt = DateTime.UtcNow,
            ProjectPath = project.FilePath
        };
    }

    /// <summary>
    /// Analyze a single document for logging quality issues.
    /// </summary>
    public async Task<List<LoggingIssue>> AnalyzeDocumentAsync(Document document)
    {
        var issues = new List<LoggingIssue>();

        if (document.FilePath == null || IsGeneratedFile(document.FilePath))
            return issues;

        var semanticModel = await document.GetSemanticModelAsync();
        var syntaxRoot = await document.GetSyntaxRootAsync();

        if (semanticModel == null || syntaxRoot == null)
            return issues;

        // Check for exception blocks without logging
        var exceptionIssues = new ConcurrentBag<LoggingIssue>();
        CheckExceptionBlocksWithoutLogging(document, semanticModel, syntaxRoot, exceptionIssues);
        issues.AddRange(exceptionIssues);

        // Run all detectors
        foreach (var detector in _detectors)
        {
            try
            {
                var detected = await detector.DetectAsync(document, semanticModel, syntaxRoot);
                issues.AddRange(detected);
            }
            catch (Exception)
            {
                // Continue with other detectors
            }
        }

        return issues
            .OrderByDescending(i => GetSeverityOrder(i.Severity))
            .ThenBy(i => i.StartLine)
            .ToList();
    }

    /// <summary>
    /// Analyze code from a syntax tree directly.
    /// </summary>
    public async Task<List<LoggingIssue>> AnalyzeCodeAsync(string code, string filePath = "analysis.cs")
    {
        var issues = new List<LoggingIssue>();

        var tree = CSharpSyntaxTree.ParseText(code, path: filePath);
        var compilation = CSharpCompilation.Create("Analysis")
            .AddReferences(MetadataReference.CreateFromFile(typeof(object).Assembly.Location))
            .AddSyntaxTrees(tree);

        var semanticModel = compilation.GetSemanticModel(tree);
        var root = await tree.GetRootAsync();

        // Create a minimal document-like context
        foreach (var detector in _detectors)
        {
            try
            {
                // For direct code analysis, we pass null for document
                // Detectors should handle this gracefully
                var detected = await DetectWithRootAsync(detector, semanticModel, root, filePath);
                issues.AddRange(detected);
            }
            catch (Exception)
            {
                // Continue with other detectors
            }
        }

        return issues;
    }

    private async Task<List<LoggingIssue>> DetectWithRootAsync(
        ILoggingDetector detector,
        SemanticModel semanticModel,
        SyntaxNode root,
        string filePath)
    {
        // Create a temporary workspace and document for analysis
        var workspace = new AdhocWorkspace();
        var projectId = ProjectId.CreateNewId();
        var documentId = DocumentId.CreateNewId(projectId);

        var solution = workspace.CurrentSolution
            .AddProject(projectId, "TempProject", "TempProject", LanguageNames.CSharp)
            .AddDocument(documentId, Path.GetFileName(filePath), root.GetText());

        var document = solution.GetDocument(documentId);
        if (document == null)
            return new List<LoggingIssue>();

        return await detector.DetectAsync(document, semanticModel, root);
    }

    private bool IsGeneratedFile(string filePath)
    {
        var fileName = Path.GetFileName(filePath);
        return fileName.EndsWith(".g.cs") ||
               fileName.EndsWith(".Designer.cs") ||
               fileName.EndsWith(".generated.cs") ||
               filePath.Contains("obj" + Path.DirectorySeparatorChar);
    }

    private HashSet<string> DetectLoggingFrameworks(SyntaxNode root, SemanticModel semanticModel)
    {
        var frameworks = new HashSet<string>();

        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var receiverType = semanticModel.GetTypeInfo(memberAccess.Expression).Type;
                if (receiverType != null)
                {
                    var typeName = receiverType.ToDisplayString();

                    if (typeName.Contains("Microsoft.Extensions.Logging") || typeName.Contains("ILogger"))
                        frameworks.Add("ILogger");
                    else if (typeName.Contains("Serilog"))
                        frameworks.Add("Serilog");
                    else if (typeName.Contains("NLog"))
                        frameworks.Add("NLog");
                    else if (typeName.Contains("log4net"))
                        frameworks.Add("log4net");
                }
            }
        }

        // Also check using directives
        foreach (var usingDirective in root.DescendantNodes().OfType<UsingDirectiveSyntax>())
        {
            var ns = usingDirective.Name?.ToString() ?? "";
            if (ns.Contains("Microsoft.Extensions.Logging"))
                frameworks.Add("ILogger");
            else if (ns.Contains("Serilog"))
                frameworks.Add("Serilog");
            else if (ns.Contains("NLog"))
                frameworks.Add("NLog");
            else if (ns.Contains("log4net"))
                frameworks.Add("log4net");
        }

        return frameworks;
    }

    private void CheckExceptionBlocksWithoutLogging(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        ConcurrentBag<LoggingIssue> issues)
    {
        var filePath = document.FilePath ?? "";

        foreach (var catchClause in root.DescendantNodes().OfType<CatchClauseSyntax>())
        {
            // Skip empty catch blocks (handled by other analyzers)
            if (catchClause.Block.Statements.Count == 0)
                continue;

            // Check if there's any logging in the catch block
            var hasLogging = HasLoggingInvocation(catchClause.Block, semanticModel);

            // Check if exception is rethrown
            var hasRethrow = catchClause.Block.DescendantNodes()
                .OfType<ThrowStatementSyntax>()
                .Any();

            // Check if exception is returned (for Result pattern)
            var hasErrorReturn = catchClause.Block.DescendantNodes()
                .OfType<ReturnStatementSyntax>()
                .Any(r =>
                {
                    var returnText = r.ToString().ToLowerInvariant();
                    return returnText.Contains("error") ||
                           returnText.Contains("failure") ||
                           returnText.Contains("fail");
                });

            if (!hasLogging && !hasRethrow && !hasErrorReturn)
            {
                var lineSpan = catchClause.GetLocation().GetLineSpan();
                var exceptionType = catchClause.Declaration?.Type.ToString() ?? "Exception";

                issues.Add(new LoggingIssue
                {
                    IssueType = LoggingIssueType.ExceptionNotLogged,
                    Severity = LoggingSeverity.High,
                    Description = $"Catch block for {exceptionType} has no logging",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    ProblematicCode = TruncateCode(catchClause.ToString(), 200),
                    Suggestion = "Log the exception or rethrow it to avoid silent failures",
                    RecommendedCode = GenerateLoggingRecommendation(catchClause),
                    Confidence = "High",
                    Metadata = new Dictionary<string, string>
                    {
                        ["ExceptionType"] = exceptionType,
                        ["StatementCount"] = catchClause.Block.Statements.Count.ToString()
                    }
                });
            }
        }
    }

    private bool HasLoggingInvocation(SyntaxNode node, SemanticModel semanticModel)
    {
        var loggingMethods = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Log", "LogTrace", "LogDebug", "LogInformation", "LogWarning", "LogError", "LogCritical",
            "Trace", "Debug", "Information", "Info", "Warning", "Warn", "Error", "Fatal", "Critical",
            "Write", "Verbose"
        };

        foreach (var invocation in node.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var methodName = memberAccess.Name.Identifier.Text;
                if (loggingMethods.Contains(methodName))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private string TruncateCode(string code, int maxLength)
    {
        if (code.Length <= maxLength)
            return code;

        return code.Substring(0, maxLength) + "...";
    }

    private string GenerateLoggingRecommendation(CatchClauseSyntax catchClause)
    {
        var exceptionVar = catchClause.Declaration?.Identifier.Text ?? "ex";
        var exceptionType = catchClause.Declaration?.Type.ToString() ?? "Exception";

        return $@"catch ({exceptionType} {exceptionVar})
{{
    _logger.LogError({exceptionVar}, ""Error occurred while processing"");
    // Optionally rethrow or return error
    throw;
}}";
    }

    private int GetSeverityOrder(LoggingSeverity severity) => severity switch
    {
        LoggingSeverity.Critical => 4,
        LoggingSeverity.High => 3,
        LoggingSeverity.Medium => 2,
        LoggingSeverity.Low => 1,
        _ => 0
    };

    private LoggingAnalysisSummary BuildSummary(List<LoggingIssue> issues, HashSet<string> frameworks)
    {
        var summary = new LoggingAnalysisSummary
        {
            TotalIssues = issues.Count,
            CriticalCount = issues.Count(i => i.Severity == LoggingSeverity.Critical),
            HighCount = issues.Count(i => i.Severity == LoggingSeverity.High),
            MediumCount = issues.Count(i => i.Severity == LoggingSeverity.Medium),
            LowCount = issues.Count(i => i.Severity == LoggingSeverity.Low),
            IssuesByType = issues
                .GroupBy(i => i.IssueType)
                .ToDictionary(g => g.Key, g => g.Count()),
            IssuesByFile = issues
                .GroupBy(i => i.FilePath)
                .ToDictionary(g => g.Key, g => g.Count()),
            DetectedFrameworks = frameworks,
            QualityScore = CalculateQualityScore(issues),
            Recommendations = GenerateRecommendations(issues, frameworks)
        };

        return summary;
    }

    private double CalculateQualityScore(List<LoggingIssue> issues)
    {
        if (issues.Count == 0)
            return 100.0;

        // Start with 100 and deduct based on issues
        var score = 100.0;

        foreach (var issue in issues)
        {
            var deduction = issue.Severity switch
            {
                LoggingSeverity.Critical => 10.0,
                LoggingSeverity.High => 5.0,
                LoggingSeverity.Medium => 2.0,
                LoggingSeverity.Low => 0.5,
                _ => 0.0
            };
            score -= deduction;
        }

        return Math.Max(0, Math.Min(100, score));
    }

    private List<string> GenerateRecommendations(List<LoggingIssue> issues, HashSet<string> frameworks)
    {
        var recommendations = new List<string>();

        // Check for sensitive data issues
        var sensitiveDataCount = issues.Count(i => i.IssueType == LoggingIssueType.SensitiveDataLogged);
        if (sensitiveDataCount > 0)
        {
            recommendations.Add($"CRITICAL: Found {sensitiveDataCount} instances of sensitive data in logs. " +
                              "Implement data masking or filtering before logging.");
        }

        // Check for exception handling
        var exceptionNotLoggedCount = issues.Count(i => i.IssueType == LoggingIssueType.ExceptionNotLogged);
        if (exceptionNotLoggedCount > 0)
        {
            recommendations.Add($"Found {exceptionNotLoggedCount} catch blocks without logging. " +
                              "Add exception logging to prevent silent failures.");
        }

        // Check for string concatenation
        var stringConcatCount = issues.Count(i => i.IssueType == LoggingIssueType.StringConcatInLog);
        if (stringConcatCount > 5)
        {
            recommendations.Add($"Found {stringConcatCount} log statements using string interpolation/concatenation. " +
                              "Convert to structured logging for better searchability and performance.");
        }

        // Check for missing correlation
        var missingCorrelationCount = issues.Count(i => i.IssueType == LoggingIssueType.MissingCorrelation);
        if (missingCorrelationCount > 0)
        {
            recommendations.Add($"Found {missingCorrelationCount} request handlers without correlation IDs. " +
                              "Add correlation ID middleware for distributed tracing.");
        }

        // Check for verbose logging
        var verboseCount = issues.Count(i => i.IssueType == LoggingIssueType.VerboseInProduction);
        if (verboseCount > 0)
        {
            recommendations.Add($"Found {verboseCount} verbose (Debug/Trace) log statements in production code paths. " +
                              "Guard with IsEnabled checks or adjust log levels.");
        }

        // Framework-specific recommendations
        if (!frameworks.Any())
        {
            recommendations.Add("No logging framework detected. Consider using Microsoft.Extensions.Logging " +
                              "or Serilog for structured logging.");
        }
        else if (frameworks.Count > 1)
        {
            recommendations.Add($"Multiple logging frameworks detected ({string.Join(", ", frameworks)}). " +
                              "Consider consolidating to a single framework for consistency.");
        }

        if (recommendations.Count == 0)
        {
            recommendations.Add("Logging quality looks good! Continue following best practices.");
        }

        return recommendations;
    }
}
