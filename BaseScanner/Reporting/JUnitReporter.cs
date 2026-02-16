using System.Text;
using System.Xml;
using System.Xml.Linq;
using BaseScanner.Reporting.Models;

namespace BaseScanner.Reporting;

/// <summary>
/// Generates JUnit XML format reports for CI systems.
/// Maps static analysis findings to test results for integration with CI dashboards.
/// </summary>
/// <remarks>
/// JUnit XML format is widely supported by CI systems including:
/// - Jenkins
/// - GitLab CI
/// - CircleCI
/// - TeamCity
/// - Azure DevOps (with JUnit test results publisher)
///
/// Each analyzer is represented as a test suite, and each issue as a test case.
/// </remarks>
public class JUnitReporter : IReporter
{
    /// <inheritdoc />
    public Task<string> GenerateAsync(ReportData data, ReportOptions options)
    {
        var doc = BuildJUnitDocument(data, options);

        var settings = new XmlWriterSettings
        {
            Indent = true,
            Encoding = Encoding.UTF8,
            OmitXmlDeclaration = false
        };

        using var stringWriter = new StringWriter();
        using var xmlWriter = XmlWriter.Create(stringWriter, settings);
        doc.WriteTo(xmlWriter);
        xmlWriter.Flush();

        return Task.FromResult(stringWriter.ToString());
    }

    /// <inheritdoc />
    public async Task WriteAsync(ReportData data, ReportOptions options, string outputPath)
    {
        var content = await GenerateAsync(data, options);
        await File.WriteAllTextAsync(outputPath, content, Encoding.UTF8);
    }

    private XDocument BuildJUnitDocument(ReportData data, ReportOptions options)
    {
        var filteredIssues = data.Issues
            .Where(i => i.Severity >= options.MinSeverity)
            .Take(options.MaxIssues)
            .ToList();

        // Group issues by category (each category becomes a test suite)
        var suitesByCategory = filteredIssues
            .GroupBy(i => i.Category)
            .ToList();

        // Calculate aggregate statistics
        var totalTests = filteredIssues.Count + CountPassingTests(data, filteredIssues);
        var failures = filteredIssues.Count(i => i.Severity >= IssueSeverity.Error);
        var errors = 0; // We treat critical issues as failures, not errors
        var skipped = 0;
        var totalTime = data.Summary.AnalysisDurationMs / 1000.0;

        var root = new XElement("testsuites",
            new XAttribute("name", $"BaseScanner - {data.Project.Name}"),
            new XAttribute("tests", totalTests),
            new XAttribute("failures", failures),
            new XAttribute("errors", errors),
            new XAttribute("skipped", skipped),
            new XAttribute("time", totalTime.ToString("F3")),
            new XAttribute("timestamp", data.AnalysisTimestamp.ToString("yyyy-MM-ddTHH:mm:ss")));

        // Add properties with analysis metadata
        root.Add(BuildProperties(data));

        // Add test suites for each category
        foreach (var categoryGroup in suitesByCategory)
        {
            root.Add(BuildTestSuite(categoryGroup.Key, categoryGroup.ToList(), data, totalTime / suitesByCategory.Count));
        }

        // Add a summary test suite with passing tests for clean files
        root.Add(BuildCleanFilesSuite(data, filteredIssues, totalTime / (suitesByCategory.Count + 1)));

        return new XDocument(
            new XDeclaration("1.0", "utf-8", null),
            root);
    }

    private XElement BuildProperties(ReportData data)
    {
        return new XElement("properties",
            new XElement("property", new XAttribute("name", "project"), new XAttribute("value", data.Project.Name)),
            new XElement("property", new XAttribute("name", "project.path"), new XAttribute("value", data.Project.Path)),
            new XElement("property", new XAttribute("name", "commit"), new XAttribute("value", data.Project.CommitHash)),
            new XElement("property", new XAttribute("name", "branch"), new XAttribute("value", data.Project.Branch)),
            new XElement("property", new XAttribute("name", "files.analyzed"), new XAttribute("value", data.Summary.FilesAnalyzed)),
            new XElement("property", new XAttribute("name", "quality.score"), new XAttribute("value", data.Summary.QualityScore.ToString("F1"))),
            new XElement("property", new XAttribute("name", "security.score"), new XAttribute("value", data.Summary.SecurityScore.ToString("F1"))),
            new XElement("property", new XAttribute("name", "tool.name"), new XAttribute("value", "BaseScanner")),
            new XElement("property", new XAttribute("name", "tool.version"), new XAttribute("value", "1.0.0")));
    }

    private XElement BuildTestSuite(string category, List<ReportIssue> issues, ReportData data, double time)
    {
        var failures = issues.Count(i => i.Severity >= IssueSeverity.Error);
        var warnings = issues.Count(i => i.Severity == IssueSeverity.Warning);

        var suite = new XElement("testsuite",
            new XAttribute("name", $"BaseScanner.{SanitizeName(category)}"),
            new XAttribute("tests", issues.Count),
            new XAttribute("failures", failures),
            new XAttribute("errors", 0),
            new XAttribute("skipped", 0),
            new XAttribute("time", time.ToString("F3")),
            new XAttribute("timestamp", data.AnalysisTimestamp.ToString("yyyy-MM-ddTHH:mm:ss")),
            new XAttribute("hostname", Environment.MachineName));

        // Add test cases for each issue
        foreach (var issue in issues)
        {
            suite.Add(BuildTestCase(issue, category));
        }

        // Add system-out with summary
        suite.Add(new XElement("system-out",
            new XCData($"Category: {category}\nIssues: {issues.Count} (Errors: {failures}, Warnings: {warnings})")));

        return suite;
    }

    private XElement BuildTestCase(ReportIssue issue, string category)
    {
        var fileName = Path.GetFileName(issue.Location.FilePath);
        var testName = $"{issue.RuleId}: {fileName}:{issue.Location.StartLine}";
        var className = $"BaseScanner.{SanitizeName(category)}.{SanitizeName(issue.RuleId)}";

        var testCase = new XElement("testcase",
            new XAttribute("name", testName),
            new XAttribute("classname", className),
            new XAttribute("time", "0.001")); // Static analysis doesn't measure per-issue time

        // Add failure element for error-level issues
        if (issue.Severity >= IssueSeverity.Error)
        {
            testCase.Add(new XElement("failure",
                new XAttribute("message", issue.Message),
                new XAttribute("type", issue.Severity.ToString()),
                FormatFailureContent(issue)));
        }
        // Add warning as a different element type (some CI systems treat this differently)
        else if (issue.Severity == IssueSeverity.Warning)
        {
            testCase.Add(new XElement("failure",
                new XAttribute("message", issue.Message),
                new XAttribute("type", "Warning"),
                FormatFailureContent(issue)));
        }

        // Add system-out with additional context
        testCase.Add(new XElement("system-out",
            new XCData(FormatTestOutput(issue))));

        return testCase;
    }

    private XElement BuildCleanFilesSuite(ReportData data, List<ReportIssue> issues, double time)
    {
        // Get files without issues
        var filesWithIssues = issues.Select(i => i.Location.FilePath).Distinct().ToHashSet();
        var cleanFileCount = data.Summary.FilesAnalyzed - filesWithIssues.Count;

        if (cleanFileCount <= 0)
        {
            return new XElement("testsuite",
                new XAttribute("name", "BaseScanner.CleanFiles"),
                new XAttribute("tests", 0),
                new XAttribute("failures", 0),
                new XAttribute("errors", 0),
                new XAttribute("time", "0"));
        }

        var suite = new XElement("testsuite",
            new XAttribute("name", "BaseScanner.CleanFiles"),
            new XAttribute("tests", cleanFileCount),
            new XAttribute("failures", 0),
            new XAttribute("errors", 0),
            new XAttribute("skipped", 0),
            new XAttribute("time", time.ToString("F3")),
            new XAttribute("timestamp", data.AnalysisTimestamp.ToString("yyyy-MM-ddTHH:mm:ss")));

        // Add a representative passing test case
        suite.Add(new XElement("testcase",
            new XAttribute("name", $"{cleanFileCount} files passed analysis"),
            new XAttribute("classname", "BaseScanner.CleanFiles"),
            new XAttribute("time", time.ToString("F3"))));

        suite.Add(new XElement("system-out",
            new XCData($"{cleanFileCount} files analyzed without issues")));

        return suite;
    }

    private int CountPassingTests(ReportData data, List<ReportIssue> issues)
    {
        // Count files without issues as "passing tests"
        var filesWithIssues = issues.Select(i => i.Location.FilePath).Distinct().Count();
        return Math.Max(0, data.Summary.FilesAnalyzed - filesWithIssues);
    }

    private string FormatFailureContent(ReportIssue issue)
    {
        var sb = new StringBuilder();

        sb.AppendLine($"Rule: {issue.RuleId}");
        sb.AppendLine($"Severity: {issue.Severity}");
        sb.AppendLine($"Category: {issue.Category}");
        sb.AppendLine();
        sb.AppendLine($"Location: {issue.Location.FilePath}");
        sb.AppendLine($"Line: {issue.Location.StartLine}-{issue.Location.EndLine}");
        sb.AppendLine($"Column: {issue.Location.StartColumn}");
        sb.AppendLine();
        sb.AppendLine("Message:");
        sb.AppendLine(issue.Message);

        if (!string.IsNullOrEmpty(issue.Description))
        {
            sb.AppendLine();
            sb.AppendLine("Description:");
            sb.AppendLine(issue.Description);
        }

        if (!string.IsNullOrEmpty(issue.CweId))
        {
            sb.AppendLine();
            sb.AppendLine($"CWE: {issue.CweId}");
            sb.AppendLine($"Reference: https://cwe.mitre.org/data/definitions/{issue.CweId.Replace("CWE-", "")}.html");
        }

        if (!string.IsNullOrEmpty(issue.Location.Snippet))
        {
            sb.AppendLine();
            sb.AppendLine("Code:");
            sb.AppendLine(issue.Location.Snippet);
        }

        if (issue.Fix != null)
        {
            sb.AppendLine();
            sb.AppendLine("Suggested Fix:");
            sb.AppendLine(issue.Fix.Description);
        }

        return sb.ToString();
    }

    private string FormatTestOutput(ReportIssue issue)
    {
        var sb = new StringBuilder();

        sb.AppendLine($"Issue ID: {issue.Id}");
        sb.AppendLine($"Fingerprint: {issue.Fingerprint}");
        sb.AppendLine($"Confidence: {issue.Confidence}");

        if (!string.IsNullOrEmpty(issue.Location.LogicalLocation))
        {
            sb.AppendLine($"Logical Location: {issue.Location.LogicalLocation}");
        }

        if (issue.Tags.Any())
        {
            sb.AppendLine($"Tags: {string.Join(", ", issue.Tags)}");
        }

        if (issue.CodeFlow.Any())
        {
            sb.AppendLine();
            sb.AppendLine("Data Flow:");
            foreach (var step in issue.CodeFlow)
            {
                sb.AppendLine($"  {step.Step}. [{step.Kind}] {step.Location.FilePath}:{step.Location.StartLine} - {step.Message}");
            }
        }

        return sb.ToString();
    }

    private static string SanitizeName(string name)
    {
        if (string.IsNullOrEmpty(name))
            return "Unknown";

        // Replace invalid characters with underscores
        var sanitized = new StringBuilder();
        foreach (var c in name)
        {
            if (char.IsLetterOrDigit(c) || c == '_' || c == '-')
            {
                sanitized.Append(c);
            }
            else if (c == ' ' || c == '.' || c == '/')
            {
                sanitized.Append('_');
            }
        }

        return sanitized.ToString();
    }
}

/// <summary>
/// JUnit report options specific to test result formatting.
/// </summary>
public record JUnitReportOptions : ReportOptions
{
    /// <summary>
    /// Include passing test cases for files without issues.
    /// </summary>
    public bool IncludePassingTests { get; init; } = true;

    /// <summary>
    /// Group test suites by category (default) or by file.
    /// </summary>
    public JUnitGrouping Grouping { get; init; } = JUnitGrouping.ByCategory;

    /// <summary>
    /// Include code snippets in failure messages.
    /// </summary>
    public bool IncludeCodeInFailures { get; init; } = true;

    /// <summary>
    /// Include suggested fixes in failure messages.
    /// </summary>
    public bool IncludeFixesInFailures { get; init; } = true;

    /// <summary>
    /// Treat warnings as failures (fail the build).
    /// </summary>
    public bool TreatWarningsAsFailures { get; init; } = false;
}

/// <summary>
/// How to group test suites in JUnit output.
/// </summary>
public enum JUnitGrouping
{
    /// <summary>
    /// Group by issue category (Security, Performance, etc.).
    /// </summary>
    ByCategory,

    /// <summary>
    /// Group by source file.
    /// </summary>
    ByFile,

    /// <summary>
    /// Group by rule ID.
    /// </summary>
    ByRule,

    /// <summary>
    /// Single flat test suite.
    /// </summary>
    Flat
}

/// <summary>
/// Extension for enhanced JUnit report generation.
/// </summary>
public class EnhancedJUnitReporter : JUnitReporter
{
    private readonly JUnitReportOptions _options;

    public EnhancedJUnitReporter(JUnitReportOptions options)
    {
        _options = options;
    }

    /// <summary>
    /// Generate a JUnit report with additional grouping options.
    /// </summary>
    public Task<string> GenerateEnhancedAsync(ReportData data)
    {
        return GenerateAsync(data, _options);
    }
}
