using System.Text;
using BaseScanner.Reporting.Models;

namespace BaseScanner.Reporting;

/// <summary>
/// Generates Azure DevOps pipeline logging commands for inline display of issues.
/// Uses Azure DevOps logging command syntax for task results, issues, and artifacts.
/// </summary>
/// <remarks>
/// Azure DevOps logging command format:
/// ##vso[task.logissue type=error;sourcepath={file};linenumber={line};columnnumber={col};code={code}]{message}
/// ##vso[task.logissue type=warning;sourcepath={file};linenumber={line};columnnumber={col};code={code}]{message}
/// ##vso[task.complete result=Succeeded|SucceededWithIssues|Failed]
/// ##vso[build.addbuildtag]{tag}
/// ##vso[task.uploadsummary]{path}
/// </remarks>
public class AzureDevOpsReporter : IReporter
{
    /// <inheritdoc />
    public Task<string> GenerateAsync(ReportData data, ReportOptions options)
    {
        var sb = new StringBuilder();

        // Set build variables with analysis results
        AppendBuildVariables(sb, data);

        // Add build tags based on severity
        AppendBuildTags(sb, data);

        // Output logging issues for each finding
        var filteredIssues = data.Issues
            .Where(i => i.Severity >= options.MinSeverity)
            .OrderByDescending(i => i.Severity)
            .ThenBy(i => i.Location.FilePath)
            .ThenBy(i => i.Location.StartLine)
            .Take(options.MaxIssues);

        // Group issues by file for better organization
        var groupedIssues = filteredIssues.GroupBy(i => i.Location.FilePath);

        foreach (var fileGroup in groupedIssues)
        {
            sb.AppendLine($"##[section]Issues in {Path.GetFileName(fileGroup.Key)}");

            foreach (var issue in fileGroup)
            {
                sb.AppendLine(FormatLogIssue(issue, data.Project.Path));
            }
        }

        // Set task result based on findings
        AppendTaskResult(sb, data);

        return Task.FromResult(sb.ToString());
    }

    /// <inheritdoc />
    public async Task WriteAsync(ReportData data, ReportOptions options, string outputPath)
    {
        var content = await GenerateAsync(data, options);
        await File.WriteAllTextAsync(outputPath, content, Encoding.UTF8);

        // Generate and upload summary markdown
        var summaryPath = Path.ChangeExtension(outputPath, ".md");
        var summary = GenerateMarkdownSummary(data);
        await File.WriteAllTextAsync(summaryPath, summary, Encoding.UTF8);

        // Upload summary to Azure DevOps
        Console.WriteLine($"##vso[task.uploadsummary]{summaryPath}");

        // Upload SARIF for Code Analysis Results tab
        var sarifPath = Path.ChangeExtension(outputPath, ".sarif");
        var sarifReporter = new SarifReporter();
        await sarifReporter.WriteAsync(data, options, sarifPath);
        Console.WriteLine($"##vso[artifact.upload artifactname=CodeAnalysisResults]{sarifPath}");

        // Write logging commands to stdout for Azure DevOps to pick up
        Console.Write(content);
    }

    private void AppendBuildVariables(StringBuilder sb, ReportData data)
    {
        // Set build variables for use in subsequent tasks/stages
        sb.AppendLine($"##vso[task.setvariable variable=BaseScanner.TotalIssues]{data.Summary.TotalIssues}");
        sb.AppendLine($"##vso[task.setvariable variable=BaseScanner.ErrorCount]{data.Summary.ErrorCount}");
        sb.AppendLine($"##vso[task.setvariable variable=BaseScanner.WarningCount]{data.Summary.WarningCount}");
        sb.AppendLine($"##vso[task.setvariable variable=BaseScanner.QualityScore]{data.Summary.QualityScore:F1}");
        sb.AppendLine($"##vso[task.setvariable variable=BaseScanner.SecurityScore]{data.Summary.SecurityScore:F1}");

        // Set output variables (available to dependent jobs)
        sb.AppendLine($"##vso[task.setvariable variable=BaseScanner.TotalIssues;isOutput=true]{data.Summary.TotalIssues}");
        sb.AppendLine($"##vso[task.setvariable variable=BaseScanner.HasErrors;isOutput=true]{(data.Summary.ErrorCount > 0).ToString().ToLower()}");
    }

    private void AppendBuildTags(StringBuilder sb, ReportData data)
    {
        // Add tags based on analysis results
        if (data.Summary.TotalIssues == 0)
        {
            sb.AppendLine("##vso[build.addbuildtag]code-analysis-clean");
        }
        else
        {
            sb.AppendLine($"##vso[build.addbuildtag]code-analysis-issues-{data.Summary.TotalIssues}");
        }

        if (data.Summary.ErrorCount > 0)
        {
            sb.AppendLine("##vso[build.addbuildtag]code-analysis-errors");
        }

        // Add security-related tags
        var securityIssues = data.Issues.Count(i => i.CweId != null);
        if (securityIssues > 0)
        {
            sb.AppendLine($"##vso[build.addbuildtag]security-issues-{securityIssues}");
        }

        // Quality gate tags
        if (data.Summary.QualityScore >= 80)
        {
            sb.AppendLine("##vso[build.addbuildtag]quality-gate-passed");
        }
        else
        {
            sb.AppendLine("##vso[build.addbuildtag]quality-gate-failed");
        }
    }

    private string FormatLogIssue(ReportIssue issue, string projectPath)
    {
        var type = MapSeverityToType(issue.Severity);
        var sourcePath = GetRelativePath(issue.Location.FilePath, projectPath);
        var lineNumber = issue.Location.StartLine;
        var columnNumber = issue.Location.StartColumn;
        var code = issue.RuleId;
        var message = FormatMessage(issue);

        // Build the logging command
        var command = new StringBuilder();
        command.Append($"##vso[task.logissue type={type}");
        command.Append($";sourcepath={sourcePath}");
        command.Append($";linenumber={lineNumber}");
        command.Append($";columnnumber={columnNumber}");
        command.Append($";code={code}");
        command.Append($"]{message}");

        return command.ToString();
    }

    private string FormatMessage(ReportIssue issue)
    {
        var sb = new StringBuilder();
        sb.Append($"[{issue.Category}] ");
        sb.Append(issue.Message);

        if (!string.IsNullOrEmpty(issue.CweId))
        {
            sb.Append($" ({issue.CweId})");
        }

        // Escape special characters that could break the logging command
        return EscapeMessage(sb.ToString());
    }

    private void AppendTaskResult(StringBuilder sb, ReportData data)
    {
        sb.AppendLine();

        // Determine task result based on findings
        string result;
        if (data.Summary.ErrorCount > 0)
        {
            result = "Failed";
            sb.AppendLine("##[error]Code analysis found critical issues");
        }
        else if (data.Summary.WarningCount > 0)
        {
            result = "SucceededWithIssues";
            sb.AppendLine("##[warning]Code analysis found issues that should be reviewed");
        }
        else
        {
            result = "Succeeded";
            sb.AppendLine("##[section]Code analysis completed with no issues");
        }

        sb.AppendLine($"##vso[task.complete result={result}]BaseScanner analysis complete");
    }

    private string GenerateMarkdownSummary(ReportData data)
    {
        var sb = new StringBuilder();

        // Header with status badge
        sb.AppendLine("# BaseScanner Analysis Results");
        sb.AppendLine();

        // Summary metrics
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine($"| Metric | Value |");
        sb.AppendLine($"|--------|-------|");
        sb.AppendLine($"| **Project** | {data.Project.Name} |");
        sb.AppendLine($"| **Total Issues** | {data.Summary.TotalIssues} |");
        sb.AppendLine($"| Errors | {data.Summary.ErrorCount} |");
        sb.AppendLine($"| Warnings | {data.Summary.WarningCount} |");
        sb.AppendLine($"| Notes | {data.Summary.InfoCount} |");
        sb.AppendLine($"| **Quality Score** | {data.Summary.QualityScore:F1}/100 |");
        sb.AppendLine($"| **Security Score** | {data.Summary.SecurityScore:F1}/100 |");
        sb.AppendLine($"| Files Analyzed | {data.Summary.FilesAnalyzed} |");
        sb.AppendLine($"| Analysis Duration | {data.Summary.AnalysisDurationMs}ms |");
        sb.AppendLine();

        // Issues by category (as a chart-friendly format)
        if (data.Summary.IssuesByCategory.Any())
        {
            sb.AppendLine("## Issues by Category");
            sb.AppendLine();

            // Bar chart visualization using ASCII
            var maxCount = data.Summary.IssuesByCategory.Values.Max();
            foreach (var category in data.Summary.IssuesByCategory.OrderByDescending(c => c.Value))
            {
                var barLength = maxCount > 0 ? (int)(30.0 * category.Value / maxCount) : 0;
                var bar = new string('█', barLength);
                sb.AppendLine($"| {category.Key,-25} | {bar} {category.Value} |");
            }
            sb.AppendLine();
        }

        // Top files with issues
        var topFiles = data.Summary.IssuesByFile
            .OrderByDescending(f => f.Value)
            .Take(10)
            .ToList();

        if (topFiles.Any())
        {
            sb.AppendLine("## Files with Most Issues");
            sb.AppendLine();
            sb.AppendLine("| File | Issue Count |");
            sb.AppendLine("|------|-------------|");
            foreach (var file in topFiles)
            {
                sb.AppendLine($"| `{file.Key}` | {file.Value} |");
            }
            sb.AppendLine();
        }

        // Critical issues detail
        var criticalIssues = data.Issues
            .Where(i => i.Severity >= IssueSeverity.Error)
            .Take(20)
            .ToList();

        if (criticalIssues.Any())
        {
            sb.AppendLine("## Critical Issues");
            sb.AppendLine();
            sb.AppendLine("| Severity | Rule | Location | Message |");
            sb.AppendLine("|----------|------|----------|---------|");
            foreach (var issue in criticalIssues)
            {
                var severity = issue.Severity == IssueSeverity.Critical ? "🔴 Critical" : "🟠 Error";
                var location = $"{Path.GetFileName(issue.Location.FilePath)}:{issue.Location.StartLine}";
                var message = TruncateMessage(issue.Message, 50);
                sb.AppendLine($"| {severity} | `{issue.RuleId}` | `{location}` | {message} |");
            }
            sb.AppendLine();
        }

        // Security issues
        var securityIssues = data.Issues
            .Where(i => i.CweId != null)
            .Take(10)
            .ToList();

        if (securityIssues.Any())
        {
            sb.AppendLine("## Security Findings");
            sb.AppendLine();
            sb.AppendLine("| CWE | Severity | Location | Description |");
            sb.AppendLine("|-----|----------|----------|-------------|");
            foreach (var issue in securityIssues)
            {
                var location = $"{Path.GetFileName(issue.Location.FilePath)}:{issue.Location.StartLine}";
                var message = TruncateMessage(issue.Message, 40);
                sb.AppendLine($"| [{issue.CweId}](https://cwe.mitre.org/data/definitions/{issue.CweId?.Replace("CWE-", "")}.html) | {issue.Severity} | `{location}` | {message} |");
            }
            sb.AppendLine();
        }

        // Footer
        sb.AppendLine("---");
        sb.AppendLine($"*Generated by BaseScanner v1.0.0 at {data.AnalysisTimestamp:yyyy-MM-dd HH:mm:ss} UTC*");

        return sb.ToString();
    }

    private static string MapSeverityToType(IssueSeverity severity) => severity switch
    {
        IssueSeverity.Critical or IssueSeverity.Error => "error",
        IssueSeverity.Warning => "warning",
        _ => "warning" // Azure DevOps only supports error/warning
    };

    private static string GetRelativePath(string fullPath, string projectPath)
    {
        if (string.IsNullOrEmpty(fullPath))
            return "";

        try
        {
            var projectDir = Path.GetDirectoryName(projectPath) ?? projectPath;
            return Path.GetRelativePath(projectDir, fullPath);
        }
        catch
        {
            return Path.GetFileName(fullPath);
        }
    }

    private static string EscapeMessage(string message)
    {
        if (string.IsNullOrEmpty(message))
            return "";

        // Azure DevOps logging commands need semicolons escaped
        return message
            .Replace(";", "%3B")
            .Replace("\r", "")
            .Replace("\n", " ");
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
/// Helper class for Azure DevOps pipeline operations.
/// </summary>
public static class AzureDevOpsHelper
{
    /// <summary>
    /// Check if running in Azure DevOps.
    /// </summary>
    public static bool IsAzureDevOps =>
        !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("TF_BUILD"));

    /// <summary>
    /// Get the current build ID.
    /// </summary>
    public static string? BuildId =>
        Environment.GetEnvironmentVariable("BUILD_BUILDID");

    /// <summary>
    /// Get the current build number.
    /// </summary>
    public static string? BuildNumber =>
        Environment.GetEnvironmentVariable("BUILD_BUILDNUMBER");

    /// <summary>
    /// Get the source branch.
    /// </summary>
    public static string? SourceBranch =>
        Environment.GetEnvironmentVariable("BUILD_SOURCEBRANCH");

    /// <summary>
    /// Get the source commit ID.
    /// </summary>
    public static string? SourceVersion =>
        Environment.GetEnvironmentVariable("BUILD_SOURCEVERSION");

    /// <summary>
    /// Get the repository name.
    /// </summary>
    public static string? RepositoryName =>
        Environment.GetEnvironmentVariable("BUILD_REPOSITORY_NAME");

    /// <summary>
    /// Log a debug message.
    /// </summary>
    public static void Debug(string message)
    {
        Console.WriteLine($"##[debug]{message}");
    }

    /// <summary>
    /// Log a warning message.
    /// </summary>
    public static void Warning(string message)
    {
        Console.WriteLine($"##[warning]{message}");
    }

    /// <summary>
    /// Log an error message.
    /// </summary>
    public static void Error(string message)
    {
        Console.WriteLine($"##[error]{message}");
    }

    /// <summary>
    /// Start a collapsible section.
    /// </summary>
    public static void StartSection(string name)
    {
        Console.WriteLine($"##[section]{name}");
    }

    /// <summary>
    /// Start a group (collapsible region).
    /// </summary>
    public static void StartGroup(string name)
    {
        Console.WriteLine($"##[group]{name}");
    }

    /// <summary>
    /// End a group.
    /// </summary>
    public static void EndGroup()
    {
        Console.WriteLine("##[endgroup]");
    }

    /// <summary>
    /// Set a variable for use in subsequent tasks.
    /// </summary>
    public static void SetVariable(string name, string value, bool isOutput = false, bool isSecret = false)
    {
        var command = $"##vso[task.setvariable variable={name}";
        if (isOutput) command += ";isOutput=true";
        if (isSecret) command += ";isSecret=true";
        command += $"]{value}";
        Console.WriteLine(command);
    }

    /// <summary>
    /// Add a build tag.
    /// </summary>
    public static void AddBuildTag(string tag)
    {
        Console.WriteLine($"##vso[build.addbuildtag]{tag}");
    }

    /// <summary>
    /// Update the build number.
    /// </summary>
    public static void UpdateBuildNumber(string buildNumber)
    {
        Console.WriteLine($"##vso[build.updatebuildnumber]{buildNumber}");
    }

    /// <summary>
    /// Upload an artifact.
    /// </summary>
    public static void UploadArtifact(string containerFolder, string artifactName, string filePath)
    {
        Console.WriteLine($"##vso[artifact.upload containerfolder={containerFolder};artifactname={artifactName}]{filePath}");
    }

    /// <summary>
    /// Upload a summary markdown file.
    /// </summary>
    public static void UploadSummary(string filePath)
    {
        Console.WriteLine($"##vso[task.uploadsummary]{filePath}");
    }

    /// <summary>
    /// Set the task result.
    /// </summary>
    public static void SetTaskResult(TaskResult result, string message = "")
    {
        Console.WriteLine($"##vso[task.complete result={result}]{message}");
    }

    /// <summary>
    /// Publish test results.
    /// </summary>
    public static void PublishTestResults(string type, string resultFiles, string? runTitle = null)
    {
        var command = $"##vso[results.publish type={type};resultFiles={resultFiles}";
        if (!string.IsNullOrEmpty(runTitle))
        {
            command += $";runTitle={runTitle}";
        }
        command += "]";
        Console.WriteLine(command);
    }
}

/// <summary>
/// Azure DevOps task result values.
/// </summary>
public enum TaskResult
{
    Succeeded,
    SucceededWithIssues,
    Failed,
    Cancelled,
    Skipped
}
