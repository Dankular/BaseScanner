using System.Text;
using BaseScanner.Reporting.Models;

namespace BaseScanner.Reporting;

/// <summary>
/// Generates GitHub Actions workflow annotations for inline display of issues.
/// Uses GitHub's workflow command syntax for annotations.
/// </summary>
/// <remarks>
/// GitHub Actions annotation format:
/// ::error file={file},line={line},col={col},endColumn={endColumn},title={title}::{message}
/// ::warning file={file},line={line},col={col},endColumn={endColumn},title={title}::{message}
/// ::notice file={file},line={line},col={col},endColumn={endColumn},title={title}::{message}
/// </remarks>
public class GithubAnnotationReporter : IReporter
{
    /// <inheritdoc />
    public Task<string> GenerateAsync(ReportData data, ReportOptions options)
    {
        var sb = new StringBuilder();

        // Output summary as a group
        sb.AppendLine("::group::BaseScanner Analysis Summary");
        AppendSummary(sb, data);
        sb.AppendLine("::endgroup::");
        sb.AppendLine();

        // Output annotations for each issue
        var filteredIssues = data.Issues
            .Where(i => i.Severity >= options.MinSeverity)
            .OrderByDescending(i => i.Severity)
            .ThenBy(i => i.Location.FilePath)
            .ThenBy(i => i.Location.StartLine)
            .Take(options.MaxIssues);

        foreach (var issue in filteredIssues)
        {
            sb.AppendLine(FormatAnnotation(issue, data.Project.Path));
        }

        // Add step summary using GitHub's special file
        sb.AppendLine();
        sb.AppendLine("::group::Markdown Summary");
        AppendMarkdownSummary(sb, data);
        sb.AppendLine("::endgroup::");

        return Task.FromResult(sb.ToString());
    }

    /// <inheritdoc />
    public async Task WriteAsync(ReportData data, ReportOptions options, string outputPath)
    {
        var content = await GenerateAsync(data, options);
        await File.WriteAllTextAsync(outputPath, content, Encoding.UTF8);

        // Also write to GITHUB_STEP_SUMMARY if available
        var summaryPath = Environment.GetEnvironmentVariable("GITHUB_STEP_SUMMARY");
        if (!string.IsNullOrEmpty(summaryPath))
        {
            var markdownSummary = GenerateMarkdownSummary(data);
            await File.AppendAllTextAsync(summaryPath, markdownSummary, Encoding.UTF8);
        }

        // Write annotations to stdout for GitHub Actions to pick up
        Console.Write(content);
    }

    private string FormatAnnotation(ReportIssue issue, string projectPath)
    {
        var level = MapSeverityToLevel(issue.Severity);
        var file = GetRelativePath(issue.Location.FilePath, projectPath);
        var line = issue.Location.StartLine;
        var col = issue.Location.StartColumn;
        var endColumn = issue.Location.EndColumn > 0 ? issue.Location.EndColumn : col + 1;
        var endLine = issue.Location.EndLine > 0 ? issue.Location.EndLine : line;
        var title = EscapeAnnotationValue($"{issue.RuleId}: {issue.Category}");
        var message = EscapeAnnotationValue(FormatMessage(issue));

        // Build the annotation string
        var annotation = new StringBuilder();
        annotation.Append($"::{level} ");
        annotation.Append($"file={EscapeAnnotationValue(file)}");
        annotation.Append($",line={line}");
        annotation.Append($",endLine={endLine}");
        annotation.Append($",col={col}");
        annotation.Append($",endColumn={endColumn}");
        annotation.Append($",title={title}");
        annotation.Append($"::{message}");

        return annotation.ToString();
    }

    private string FormatMessage(ReportIssue issue)
    {
        var sb = new StringBuilder();
        sb.Append(issue.Message);

        if (!string.IsNullOrEmpty(issue.CweId))
        {
            sb.Append($" [{issue.CweId}]");
        }

        if (issue.Confidence != ConfidenceLevel.High)
        {
            sb.Append($" (Confidence: {issue.Confidence})");
        }

        return sb.ToString();
    }

    private void AppendSummary(StringBuilder sb, ReportData data)
    {
        sb.AppendLine($"Project: {data.Project.Name}");
        sb.AppendLine($"Analysis Time: {data.AnalysisTimestamp:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"Files Analyzed: {data.Summary.FilesAnalyzed}");
        sb.AppendLine($"Duration: {data.Summary.AnalysisDurationMs}ms");
        sb.AppendLine();
        sb.AppendLine($"Total Issues: {data.Summary.TotalIssues}");
        sb.AppendLine($"  Errors: {data.Summary.ErrorCount}");
        sb.AppendLine($"  Warnings: {data.Summary.WarningCount}");
        sb.AppendLine($"  Notes: {data.Summary.InfoCount}");
        sb.AppendLine();
        sb.AppendLine($"Quality Score: {data.Summary.QualityScore:F1}/100");
        sb.AppendLine($"Security Score: {data.Summary.SecurityScore:F1}/100");
    }

    private void AppendMarkdownSummary(StringBuilder sb, ReportData data)
    {
        sb.AppendLine(GenerateMarkdownSummary(data));
    }

    private string GenerateMarkdownSummary(ReportData data)
    {
        var sb = new StringBuilder();

        // Header
        sb.AppendLine("## BaseScanner Analysis Results");
        sb.AppendLine();

        // Badges/Metrics
        var errorBadge = data.Summary.ErrorCount > 0 ? "red" : "green";
        var warningBadge = data.Summary.WarningCount > 0 ? "yellow" : "green";

        sb.AppendLine("| Metric | Value |");
        sb.AppendLine("|--------|-------|");
        sb.AppendLine($"| **Total Issues** | {data.Summary.TotalIssues} |");
        sb.AppendLine($"| Errors | {data.Summary.ErrorCount} |");
        sb.AppendLine($"| Warnings | {data.Summary.WarningCount} |");
        sb.AppendLine($"| Notes | {data.Summary.InfoCount} |");
        sb.AppendLine($"| **Quality Score** | {data.Summary.QualityScore:F1}/100 |");
        sb.AppendLine($"| **Security Score** | {data.Summary.SecurityScore:F1}/100 |");
        sb.AppendLine($"| Files Analyzed | {data.Summary.FilesAnalyzed} |");
        sb.AppendLine($"| Files with Issues | {data.Summary.FilesWithIssues} |");
        sb.AppendLine();

        // Issues by category
        if (data.Summary.IssuesByCategory.Any())
        {
            sb.AppendLine("### Issues by Category");
            sb.AppendLine();
            sb.AppendLine("| Category | Count |");
            sb.AppendLine("|----------|-------|");
            foreach (var category in data.Summary.IssuesByCategory.OrderByDescending(c => c.Value))
            {
                sb.AppendLine($"| {category.Key} | {category.Value} |");
            }
            sb.AppendLine();
        }

        // Top issues
        var topIssues = data.Issues
            .OrderByDescending(i => i.Severity)
            .Take(10)
            .ToList();

        if (topIssues.Any())
        {
            sb.AppendLine("### Top Issues");
            sb.AppendLine();
            sb.AppendLine("| Severity | Rule | File | Line | Message |");
            sb.AppendLine("|----------|------|------|------|---------|");
            foreach (var issue in topIssues)
            {
                var severity = GetSeverityEmoji(issue.Severity);
                var file = Path.GetFileName(issue.Location.FilePath);
                var message = TruncateMessage(issue.Message, 60);
                sb.AppendLine($"| {severity} | `{issue.RuleId}` | `{file}` | {issue.Location.StartLine} | {message} |");
            }
            sb.AppendLine();
        }

        // Footer
        sb.AppendLine("---");
        sb.AppendLine($"*Generated by BaseScanner at {data.AnalysisTimestamp:yyyy-MM-dd HH:mm:ss} UTC*");

        return sb.ToString();
    }

    private static string GetSeverityEmoji(IssueSeverity severity) => severity switch
    {
        IssueSeverity.Critical => ":rotating_light: Critical",
        IssueSeverity.Error => ":x: Error",
        IssueSeverity.Warning => ":warning: Warning",
        IssueSeverity.Note => ":information_source: Note",
        _ => ":grey_question: Unknown"
    };

    private static string MapSeverityToLevel(IssueSeverity severity) => severity switch
    {
        IssueSeverity.Critical or IssueSeverity.Error => "error",
        IssueSeverity.Warning => "warning",
        _ => "notice"
    };

    private static string GetRelativePath(string fullPath, string projectPath)
    {
        if (string.IsNullOrEmpty(fullPath))
            return "";

        try
        {
            var projectDir = Path.GetDirectoryName(projectPath) ?? projectPath;
            return Path.GetRelativePath(projectDir, fullPath).Replace('\\', '/');
        }
        catch
        {
            return Path.GetFileName(fullPath);
        }
    }

    private static string EscapeAnnotationValue(string value)
    {
        if (string.IsNullOrEmpty(value))
            return "";

        // GitHub Actions requires certain characters to be escaped in annotations
        return value
            .Replace("%", "%25")
            .Replace("\r", "%0D")
            .Replace("\n", "%0A")
            .Replace(":", "%3A")
            .Replace(",", "%2C");
    }

    private static string TruncateMessage(string message, int maxLength)
    {
        if (string.IsNullOrEmpty(message))
            return "";

        if (message.Length <= maxLength)
            return message;

        return message[..(maxLength - 3)] + "...";
    }
}

/// <summary>
/// Helper class for GitHub Actions outputs.
/// </summary>
public static class GitHubActionsHelper
{
    /// <summary>
    /// Set an output variable for the current step.
    /// </summary>
    public static async Task SetOutputAsync(string name, string value)
    {
        var outputFile = Environment.GetEnvironmentVariable("GITHUB_OUTPUT");
        if (!string.IsNullOrEmpty(outputFile))
        {
            // Use heredoc syntax for multiline values
            if (value.Contains('\n'))
            {
                var delimiter = $"ghadelimiter_{Guid.NewGuid():N}";
                await File.AppendAllTextAsync(outputFile, $"{name}<<{delimiter}\n{value}\n{delimiter}\n");
            }
            else
            {
                await File.AppendAllTextAsync(outputFile, $"{name}={value}\n");
            }
        }
        else
        {
            // Legacy format (deprecated but still works)
            Console.WriteLine($"::set-output name={name}::{value}");
        }
    }

    /// <summary>
    /// Add a path to the system PATH for subsequent steps.
    /// </summary>
    public static async Task AddPathAsync(string path)
    {
        var pathFile = Environment.GetEnvironmentVariable("GITHUB_PATH");
        if (!string.IsNullOrEmpty(pathFile))
        {
            await File.AppendAllTextAsync(pathFile, $"{path}\n");
        }
        else
        {
            Console.WriteLine($"::add-path::{path}");
        }
    }

    /// <summary>
    /// Set an environment variable for subsequent steps.
    /// </summary>
    public static async Task SetEnvAsync(string name, string value)
    {
        var envFile = Environment.GetEnvironmentVariable("GITHUB_ENV");
        if (!string.IsNullOrEmpty(envFile))
        {
            if (value.Contains('\n'))
            {
                var delimiter = $"ghadelimiter_{Guid.NewGuid():N}";
                await File.AppendAllTextAsync(envFile, $"{name}<<{delimiter}\n{value}\n{delimiter}\n");
            }
            else
            {
                await File.AppendAllTextAsync(envFile, $"{name}={value}\n");
            }
        }
    }

    /// <summary>
    /// Mask a value in logs.
    /// </summary>
    public static void MaskValue(string value)
    {
        Console.WriteLine($"::add-mask::{value}");
    }

    /// <summary>
    /// Start a log group.
    /// </summary>
    public static void StartGroup(string title)
    {
        Console.WriteLine($"::group::{title}");
    }

    /// <summary>
    /// End the current log group.
    /// </summary>
    public static void EndGroup()
    {
        Console.WriteLine("::endgroup::");
    }

    /// <summary>
    /// Write a debug message.
    /// </summary>
    public static void Debug(string message)
    {
        Console.WriteLine($"::debug::{message}");
    }

    /// <summary>
    /// Check if running in GitHub Actions.
    /// </summary>
    public static bool IsGitHubActions => !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GITHUB_ACTIONS"));

    /// <summary>
    /// Get the current workflow run URL.
    /// </summary>
    public static string? GetRunUrl()
    {
        var serverUrl = Environment.GetEnvironmentVariable("GITHUB_SERVER_URL");
        var repository = Environment.GetEnvironmentVariable("GITHUB_REPOSITORY");
        var runId = Environment.GetEnvironmentVariable("GITHUB_RUN_ID");

        if (!string.IsNullOrEmpty(serverUrl) && !string.IsNullOrEmpty(repository) && !string.IsNullOrEmpty(runId))
        {
            return $"{serverUrl}/{repository}/actions/runs/{runId}";
        }

        return null;
    }
}
