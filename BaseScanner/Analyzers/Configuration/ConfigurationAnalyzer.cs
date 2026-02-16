using Microsoft.CodeAnalysis;
using BaseScanner.Analyzers.Configuration.Models;
using System.Collections.Concurrent;

namespace BaseScanner.Analyzers.Configuration;

/// <summary>
/// Main orchestrator for configuration analysis.
/// Coordinates detection of:
/// - Hardcoded configuration values (connection strings, URLs, paths, credentials)
/// - Environment-specific code patterns
/// - Configuration schema validation
/// - Configuration usage patterns
/// </summary>
public class ConfigurationAnalyzer
{
    private readonly HardcodedValueDetector _hardcodedValueDetector;
    private readonly EnvironmentCodeDetector _environmentCodeDetector;
    private readonly ConfigSchemaValidator _configSchemaValidator;
    private readonly ConfigUsageAnalyzer _configUsageAnalyzer;

    public ConfigurationAnalyzer()
    {
        _hardcodedValueDetector = new HardcodedValueDetector();
        _environmentCodeDetector = new EnvironmentCodeDetector();
        _configSchemaValidator = new ConfigSchemaValidator();
        _configUsageAnalyzer = new ConfigUsageAnalyzer();
    }

    /// <summary>
    /// Analyze a project for configuration issues.
    /// </summary>
    public async Task<ConfigurationResult> AnalyzeAsync(Project project)
    {
        var allIssues = new ConcurrentBag<ConfigurationIssue>();
        var allConfigAccesses = new ConcurrentBag<ConfigurationAccess>();
        var allEnvironmentPatterns = new ConcurrentBag<EnvironmentCodePattern>();

        // Get project directory for config file scanning
        var projectDirectory = Path.GetDirectoryName(project.FilePath) ?? "";

        // Parse configuration files
        var configDefinitions = await _configSchemaValidator.ParseConfigurationFilesAsync(projectDirectory);

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

                try
                {
                    // Detect hardcoded values
                    var hardcodedIssues = await _hardcodedValueDetector.DetectAsync(document, semanticModel, syntaxRoot);
                    foreach (var issue in hardcodedIssues)
                    {
                        allIssues.Add(issue);
                    }

                    // Detect environment-specific code
                    var envPatterns = await _environmentCodeDetector.DetectAsync(document, semanticModel, syntaxRoot);
                    foreach (var pattern in envPatterns)
                    {
                        allEnvironmentPatterns.Add(pattern);
                    }

                    // Analyze configuration usage
                    var configAccesses = await _configUsageAnalyzer.AnalyzeAsync(document, semanticModel, syntaxRoot);
                    foreach (var access in configAccesses)
                    {
                        allConfigAccesses.Add(access);
                    }
                }
                catch (Exception)
                {
                    // Log but continue with other documents
                }
            });

        // Convert environment patterns to issues
        var environmentIssues = _environmentCodeDetector.CreateIssuesFromPatterns(allEnvironmentPatterns.ToList());
        foreach (var issue in environmentIssues)
        {
            allIssues.Add(issue);
        }

        // Validate configuration (missing/unused keys)
        var configAccessList = allConfigAccesses.ToList();
        var validationIssues = _configSchemaValidator.ValidateConfiguration(configAccessList, configDefinitions);
        foreach (var issue in validationIssues)
        {
            allIssues.Add(issue);
        }

        // Build result
        var issueList = allIssues
            .OrderByDescending(i => GetSeverityOrder(i.Severity))
            .ThenBy(i => i.FilePath)
            .ThenBy(i => i.StartLine)
            .ToList();

        var environmentPatternList = allEnvironmentPatterns.ToList();

        return new ConfigurationResult
        {
            Issues = issueList,
            ConfigAccesses = configAccessList,
            ConfigDefinitions = configDefinitions,
            EnvironmentPatterns = environmentPatternList,
            Summary = BuildSummary(issueList, configAccessList, configDefinitions, environmentPatternList)
        };
    }

    /// <summary>
    /// Analyze a single file for configuration issues.
    /// Useful for incremental analysis or IDE integration.
    /// </summary>
    public async Task<List<ConfigurationIssue>> AnalyzeDocumentAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root)
    {
        var issues = new List<ConfigurationIssue>();

        try
        {
            // Detect hardcoded values
            var hardcodedIssues = await _hardcodedValueDetector.DetectAsync(document, semanticModel, root);
            issues.AddRange(hardcodedIssues);

            // Detect environment-specific code
            var envPatterns = await _environmentCodeDetector.DetectAsync(document, semanticModel, root);
            var environmentIssues = _environmentCodeDetector.CreateIssuesFromPatterns(envPatterns);
            issues.AddRange(environmentIssues);
        }
        catch (Exception)
        {
            // Return partial results on error
        }

        return issues;
    }

    /// <summary>
    /// Get configuration access patterns from a document.
    /// </summary>
    public async Task<List<ConfigurationAccess>> GetConfigurationAccessesAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root)
    {
        return await _configUsageAnalyzer.AnalyzeAsync(document, semanticModel, root);
    }

    /// <summary>
    /// Parse configuration files in a directory.
    /// </summary>
    public async Task<List<ConfigurationDefinition>> ParseConfigurationFilesAsync(string projectPath)
    {
        return await _configSchemaValidator.ParseConfigurationFilesAsync(projectPath);
    }

    /// <summary>
    /// Validate configuration accesses against definitions.
    /// </summary>
    public List<ConfigurationIssue> ValidateConfiguration(
        List<ConfigurationAccess> accesses,
        List<ConfigurationDefinition> definitions)
    {
        return _configSchemaValidator.ValidateConfiguration(accesses, definitions);
    }

    private bool IsGeneratedFile(string filePath)
    {
        var fileName = Path.GetFileName(filePath);
        return fileName.EndsWith(".g.cs") ||
               fileName.EndsWith(".Designer.cs") ||
               fileName.EndsWith(".generated.cs") ||
               filePath.Contains("obj" + Path.DirectorySeparatorChar) ||
               filePath.Contains("bin" + Path.DirectorySeparatorChar);
    }

    private int GetSeverityOrder(ConfigurationSeverity severity) => severity switch
    {
        ConfigurationSeverity.Critical => 5,
        ConfigurationSeverity.High => 4,
        ConfigurationSeverity.Medium => 3,
        ConfigurationSeverity.Low => 2,
        ConfigurationSeverity.Info => 1,
        _ => 0
    };

    private ConfigurationSummary BuildSummary(
        List<ConfigurationIssue> issues,
        List<ConfigurationAccess> accesses,
        List<ConfigurationDefinition> definitions,
        List<EnvironmentCodePattern> environmentPatterns)
    {
        var issuesByType = issues
            .GroupBy(i => i.IssueType)
            .ToDictionary(g => g.Key, g => g.Count());

        var unusedConfigKeys = issues
            .Where(i => i.IssueType == ConfigurationIssueType.UnusedConfig)
            .Select(i => i.ConfigKey ?? "")
            .Where(k => !string.IsNullOrEmpty(k))
            .ToList();

        var missingConfigKeys = issues
            .Where(i => i.IssueType == ConfigurationIssueType.MissingConfig)
            .Select(i => i.ConfigKey ?? "")
            .Where(k => !string.IsNullOrEmpty(k))
            .ToList();

        return new ConfigurationSummary
        {
            TotalIssues = issues.Count,
            CriticalCount = issues.Count(i => i.Severity == ConfigurationSeverity.Critical),
            HighCount = issues.Count(i => i.Severity == ConfigurationSeverity.High),
            MediumCount = issues.Count(i => i.Severity == ConfigurationSeverity.Medium),
            LowCount = issues.Count(i => i.Severity == ConfigurationSeverity.Low),
            IssuesByType = issuesByType,
            TotalConfigAccesses = accesses.Count,
            UnusedConfigKeys = unusedConfigKeys,
            MissingConfigKeys = missingConfigKeys,
            EnvironmentPatternCount = environmentPatterns.Count
        };
    }
}

/// <summary>
/// Extension methods for configuration analysis results.
/// </summary>
public static class ConfigurationResultExtensions
{
    /// <summary>
    /// Get issues filtered by type.
    /// </summary>
    public static IEnumerable<ConfigurationIssue> GetIssuesByType(
        this ConfigurationResult result,
        ConfigurationIssueType type)
    {
        return result.Issues.Where(i => i.IssueType == type);
    }

    /// <summary>
    /// Get issues filtered by severity.
    /// </summary>
    public static IEnumerable<ConfigurationIssue> GetIssuesBySeverity(
        this ConfigurationResult result,
        ConfigurationSeverity severity)
    {
        return result.Issues.Where(i => i.Severity == severity);
    }

    /// <summary>
    /// Get issues for a specific file.
    /// </summary>
    public static IEnumerable<ConfigurationIssue> GetIssuesForFile(
        this ConfigurationResult result,
        string filePath)
    {
        return result.Issues.Where(i =>
            i.FilePath.Equals(filePath, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Get critical and high severity issues.
    /// </summary>
    public static IEnumerable<ConfigurationIssue> GetHighPriorityIssues(
        this ConfigurationResult result)
    {
        return result.Issues.Where(i =>
            i.Severity == ConfigurationSeverity.Critical ||
            i.Severity == ConfigurationSeverity.High);
    }

    /// <summary>
    /// Get all hardcoded value issues.
    /// </summary>
    public static IEnumerable<ConfigurationIssue> GetHardcodedValueIssues(
        this ConfigurationResult result)
    {
        return result.Issues.Where(i =>
            i.IssueType == ConfigurationIssueType.HardcodedConnection ||
            i.IssueType == ConfigurationIssueType.HardcodedUrl ||
            i.IssueType == ConfigurationIssueType.HardcodedPath ||
            i.IssueType == ConfigurationIssueType.HardcodedCredential);
    }

    /// <summary>
    /// Check if there are any critical issues.
    /// </summary>
    public static bool HasCriticalIssues(this ConfigurationResult result)
    {
        return result.Issues.Any(i => i.Severity == ConfigurationSeverity.Critical);
    }

    /// <summary>
    /// Get configuration accesses grouped by key.
    /// </summary>
    public static Dictionary<string, List<ConfigurationAccess>> GetAccessesByKey(
        this ConfigurationResult result)
    {
        return result.ConfigAccesses
            .GroupBy(a => a.Key)
            .ToDictionary(g => g.Key, g => g.ToList());
    }

    /// <summary>
    /// Get the most frequently accessed configuration keys.
    /// </summary>
    public static IEnumerable<(string Key, int Count)> GetMostAccessedKeys(
        this ConfigurationResult result,
        int top = 10)
    {
        return result.ConfigAccesses
            .GroupBy(a => a.Key)
            .OrderByDescending(g => g.Count())
            .Take(top)
            .Select(g => (g.Key, g.Count()));
    }

    /// <summary>
    /// Generate a report string of the analysis.
    /// </summary>
    public static string GenerateReport(this ConfigurationResult result)
    {
        var report = new System.Text.StringBuilder();

        report.AppendLine("=== Configuration Analysis Report ===");
        report.AppendLine();

        // Summary
        report.AppendLine("## Summary");
        report.AppendLine($"Total Issues: {result.Summary.TotalIssues}");
        report.AppendLine($"  - Critical: {result.Summary.CriticalCount}");
        report.AppendLine($"  - High: {result.Summary.HighCount}");
        report.AppendLine($"  - Medium: {result.Summary.MediumCount}");
        report.AppendLine($"  - Low: {result.Summary.LowCount}");
        report.AppendLine();
        report.AppendLine($"Configuration Accesses: {result.Summary.TotalConfigAccesses}");
        report.AppendLine($"Environment Patterns: {result.Summary.EnvironmentPatternCount}");
        report.AppendLine();

        // Issues by type
        if (result.Summary.IssuesByType.Count > 0)
        {
            report.AppendLine("## Issues by Type");
            foreach (var (type, count) in result.Summary.IssuesByType.OrderByDescending(x => x.Value))
            {
                report.AppendLine($"  - {type}: {count}");
            }
            report.AppendLine();
        }

        // Missing config keys
        if (result.Summary.MissingConfigKeys.Count > 0)
        {
            report.AppendLine("## Missing Configuration Keys");
            foreach (var key in result.Summary.MissingConfigKeys.Take(10))
            {
                report.AppendLine($"  - {key}");
            }
            if (result.Summary.MissingConfigKeys.Count > 10)
            {
                report.AppendLine($"  ... and {result.Summary.MissingConfigKeys.Count - 10} more");
            }
            report.AppendLine();
        }

        // Unused config keys
        if (result.Summary.UnusedConfigKeys.Count > 0)
        {
            report.AppendLine("## Unused Configuration Keys");
            foreach (var key in result.Summary.UnusedConfigKeys.Take(10))
            {
                report.AppendLine($"  - {key}");
            }
            if (result.Summary.UnusedConfigKeys.Count > 10)
            {
                report.AppendLine($"  ... and {result.Summary.UnusedConfigKeys.Count - 10} more");
            }
            report.AppendLine();
        }

        // Critical issues details
        var criticalIssues = result.GetIssuesBySeverity(ConfigurationSeverity.Critical).ToList();
        if (criticalIssues.Count > 0)
        {
            report.AppendLine("## Critical Issues (Require Immediate Attention)");
            foreach (var issue in criticalIssues)
            {
                report.AppendLine($"  [{issue.IssueType}] {issue.FilePath}:{issue.StartLine}");
                report.AppendLine($"    {issue.Description}");
                report.AppendLine($"    Recommendation: {issue.Recommendation}");
                report.AppendLine();
            }
        }

        return report.ToString();
    }
}
