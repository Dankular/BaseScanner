using System.Text.RegularExpressions;
using BaseScanner.Hooks.Models;

namespace BaseScanner.Hooks;

/// <summary>
/// Loads hook configuration from YAML files.
/// </summary>
public class HookConfigLoader
{
    /// <summary>
    /// Default configuration file name.
    /// </summary>
    public const string DefaultConfigFileName = "hooks.yaml";

    /// <summary>
    /// Default configuration directory name.
    /// </summary>
    public const string DefaultConfigDirectory = ".basescanner";

    /// <summary>
    /// Loads hook configuration from the default location.
    /// </summary>
    /// <param name="projectPath">Path to the project directory.</param>
    /// <returns>The loaded configuration or default configuration if file doesn't exist.</returns>
    public HooksConfiguration Load(string projectPath)
    {
        var configPath = GetConfigPath(projectPath);

        if (!File.Exists(configPath))
        {
            return GetDefaultConfiguration();
        }

        var yaml = File.ReadAllText(configPath);
        return ParseYaml(yaml);
    }

    /// <summary>
    /// Loads hook configuration from a specific file.
    /// </summary>
    /// <param name="configPath">Path to the configuration file.</param>
    /// <returns>The loaded configuration.</returns>
    public HooksConfiguration LoadFromFile(string configPath)
    {
        if (!File.Exists(configPath))
        {
            throw new FileNotFoundException($"Configuration file not found: {configPath}");
        }

        var yaml = File.ReadAllText(configPath);
        return ParseYaml(yaml);
    }

    /// <summary>
    /// Saves hook configuration to the default location.
    /// </summary>
    /// <param name="projectPath">Path to the project directory.</param>
    /// <param name="config">The configuration to save.</param>
    public void Save(string projectPath, HooksConfiguration config)
    {
        var configDir = Path.Combine(projectPath, DefaultConfigDirectory);
        Directory.CreateDirectory(configDir);

        var configPath = Path.Combine(configDir, DefaultConfigFileName);
        var yaml = GenerateYaml(config);
        File.WriteAllText(configPath, yaml);
    }

    /// <summary>
    /// Gets the default configuration path for a project.
    /// </summary>
    public static string GetConfigPath(string projectPath)
    {
        return Path.Combine(projectPath, DefaultConfigDirectory, DefaultConfigFileName);
    }

    /// <summary>
    /// Creates a default configuration with sensible defaults.
    /// </summary>
    public static HooksConfiguration GetDefaultConfiguration()
    {
        return new HooksConfiguration
        {
            PreCommit = new HookConfiguration
            {
                Type = HookType.PreCommit,
                Enabled = true,
                Analyses = HookAnalysisType.Security | HookAnalysisType.Performance,
                FailOn = [HookSeverity.Critical],
                Incremental = true,
                Quick = true,
                TimeoutSeconds = 60
            },
            PrePush = new HookConfiguration
            {
                Type = HookType.PrePush,
                Enabled = true,
                Analyses = HookAnalysisType.All,
                FailOn = [HookSeverity.Critical, HookSeverity.High],
                Incremental = true,
                Quick = false,
                TimeoutSeconds = 300
            }
        };
    }

    /// <summary>
    /// Parses YAML configuration into a HooksConfiguration object.
    /// Simple YAML parser for hook configuration (no external dependencies).
    /// </summary>
    private HooksConfiguration ParseYaml(string yaml)
    {
        var config = new HooksConfiguration();
        var lines = yaml.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

        HookConfiguration? currentHook = null;
        var currentSection = "";

        foreach (var line in lines)
        {
            // Skip comments
            if (line.StartsWith('#')) continue;

            // Check for section headers (no indentation)
            if (!line.StartsWith(' ') && !line.StartsWith('\t') && line.EndsWith(':'))
            {
                currentSection = line.TrimEnd(':').ToLowerInvariant();
                currentHook = currentSection switch
                {
                    "pre-commit" => config.PreCommit = new HookConfiguration { Type = HookType.PreCommit },
                    "pre-push" => config.PrePush = new HookConfiguration { Type = HookType.PrePush },
                    "commit-msg" => config.CommitMsg = new HookConfiguration { Type = HookType.CommitMsg },
                    "post-commit" => config.PostCommit = new HookConfiguration { Type = HookType.PostCommit },
                    _ => null
                };
                continue;
            }

            if (currentHook == null) continue;

            // Parse key-value pairs
            var kvMatch = Regex.Match(line, @"^\s*(\w+[\w-]*):\s*(.*)$");
            if (!kvMatch.Success) continue;

            var key = kvMatch.Groups[1].Value.ToLowerInvariant();
            var value = kvMatch.Groups[2].Value.Trim();

            switch (key)
            {
                case "enabled":
                    currentHook.Enabled = ParseBool(value);
                    break;

                case "analyses":
                    currentHook.Analyses = ParseAnalyses(value);
                    break;

                case "fail-on":
                    currentHook.FailOn = ParseSeverities(value);
                    break;

                case "incremental":
                    currentHook.Incremental = ParseBool(value);
                    break;

                case "quick":
                    currentHook.Quick = ParseBool(value);
                    break;

                case "timeout":
                case "timeout-seconds":
                    if (int.TryParse(value, out var timeout))
                        currentHook.TimeoutSeconds = timeout;
                    break;

                case "custom-args":
                    currentHook.CustomArgs = value.Trim('"', '\'');
                    break;

                case "include":
                case "include-patterns":
                    currentHook.IncludePatterns = ParseList(value);
                    break;

                case "exclude":
                case "exclude-patterns":
                    currentHook.ExcludePatterns = ParseList(value);
                    break;
            }
        }

        return config;
    }

    /// <summary>
    /// Parses a boolean value from YAML.
    /// </summary>
    private static bool ParseBool(string value)
    {
        return value.ToLowerInvariant() switch
        {
            "true" or "yes" or "on" or "1" => true,
            _ => false
        };
    }

    /// <summary>
    /// Parses analysis types from YAML.
    /// </summary>
    private static HookAnalysisType ParseAnalyses(string value)
    {
        // Handle "all" keyword
        if (value.Equals("all", StringComparison.OrdinalIgnoreCase))
            return HookAnalysisType.All;

        // Parse list format: [security, perf] or security,perf
        var items = ParseList(value);
        var result = HookAnalysisType.None;

        foreach (var item in items)
        {
            result |= item.ToLowerInvariant() switch
            {
                "security" => HookAnalysisType.Security,
                "perf" or "performance" => HookAnalysisType.Performance,
                "exceptions" => HookAnalysisType.Exceptions,
                "resources" => HookAnalysisType.Resources,
                "deps" or "dependencies" => HookAnalysisType.Dependencies,
                "magic" => HookAnalysisType.Magic,
                "refactor" or "refactoring" => HookAnalysisType.Refactoring,
                "arch" or "architecture" => HookAnalysisType.Architecture,
                "safety" => HookAnalysisType.Safety,
                "all" => HookAnalysisType.All,
                _ => HookAnalysisType.None
            };
        }

        return result;
    }

    /// <summary>
    /// Parses severity levels from YAML.
    /// </summary>
    private static List<HookSeverity> ParseSeverities(string value)
    {
        var items = ParseList(value);
        var result = new List<HookSeverity>();

        foreach (var item in items)
        {
            if (Enum.TryParse<HookSeverity>(item, true, out var severity))
            {
                result.Add(severity);
            }
        }

        return result.Count > 0 ? result : [HookSeverity.Critical];
    }

    /// <summary>
    /// Parses a YAML list (either inline [a, b] or as string a,b).
    /// </summary>
    private static List<string> ParseList(string value)
    {
        // Remove brackets if present
        value = value.Trim('[', ']', ' ');

        // Split by comma
        return value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim('"', '\''))
            .ToList();
    }

    /// <summary>
    /// Generates YAML content from a configuration object.
    /// </summary>
    private static string GenerateYaml(HooksConfiguration config)
    {
        var lines = new List<string>
        {
            "# BaseScanner Git Hooks Configuration",
            "# See https://github.com/your-org/basescanner for documentation",
            ""
        };

        if (config.PreCommit != null)
        {
            lines.AddRange(GenerateHookYaml("pre-commit", config.PreCommit));
            lines.Add("");
        }

        if (config.PrePush != null)
        {
            lines.AddRange(GenerateHookYaml("pre-push", config.PrePush));
            lines.Add("");
        }

        if (config.CommitMsg != null)
        {
            lines.AddRange(GenerateHookYaml("commit-msg", config.CommitMsg));
            lines.Add("");
        }

        if (config.PostCommit != null)
        {
            lines.AddRange(GenerateHookYaml("post-commit", config.PostCommit));
        }

        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// Generates YAML for a single hook configuration.
    /// </summary>
    private static IEnumerable<string> GenerateHookYaml(string name, HookConfiguration hook)
    {
        yield return $"{name}:";
        yield return $"  enabled: {hook.Enabled.ToString().ToLowerInvariant()}";
        yield return $"  analyses: {FormatAnalyses(hook.Analyses)}";
        yield return $"  fail-on: {string.Join(",", hook.FailOn.Select(s => s.ToString().ToLowerInvariant()))}";
        yield return $"  incremental: {hook.Incremental.ToString().ToLowerInvariant()}";
        yield return $"  quick: {hook.Quick.ToString().ToLowerInvariant()}";
        yield return $"  timeout: {hook.TimeoutSeconds}";

        if (!string.IsNullOrEmpty(hook.CustomArgs))
        {
            yield return $"  custom-args: \"{hook.CustomArgs}\"";
        }

        if (hook.IncludePatterns.Count > 0)
        {
            yield return $"  include: [{string.Join(", ", hook.IncludePatterns.Select(p => $"\"{p}\""))}]";
        }

        if (hook.ExcludePatterns.Count > 0)
        {
            yield return $"  exclude: [{string.Join(", ", hook.ExcludePatterns.Select(p => $"\"{p}\""))}]";
        }
    }

    /// <summary>
    /// Formats analysis types for YAML output.
    /// </summary>
    private static string FormatAnalyses(HookAnalysisType analyses)
    {
        if (analyses == HookAnalysisType.All)
            return "all";

        var items = new List<string>();

        if (analyses.HasFlag(HookAnalysisType.Security)) items.Add("security");
        if (analyses.HasFlag(HookAnalysisType.Performance)) items.Add("perf");
        if (analyses.HasFlag(HookAnalysisType.Exceptions)) items.Add("exceptions");
        if (analyses.HasFlag(HookAnalysisType.Resources)) items.Add("resources");
        if (analyses.HasFlag(HookAnalysisType.Dependencies)) items.Add("deps");
        if (analyses.HasFlag(HookAnalysisType.Magic)) items.Add("magic");
        if (analyses.HasFlag(HookAnalysisType.Refactoring)) items.Add("refactor");
        if (analyses.HasFlag(HookAnalysisType.Architecture)) items.Add("arch");
        if (analyses.HasFlag(HookAnalysisType.Safety)) items.Add("safety");

        return $"[{string.Join(", ", items)}]";
    }

    /// <summary>
    /// Validates a configuration and returns any errors.
    /// </summary>
    public static List<string> Validate(HooksConfiguration config)
    {
        var errors = new List<string>();

        ValidateHook(config.PreCommit, "pre-commit", errors);
        ValidateHook(config.PrePush, "pre-push", errors);
        ValidateHook(config.CommitMsg, "commit-msg", errors);
        ValidateHook(config.PostCommit, "post-commit", errors);

        return errors;
    }

    /// <summary>
    /// Validates a single hook configuration.
    /// </summary>
    private static void ValidateHook(HookConfiguration? hook, string name, List<string> errors)
    {
        if (hook == null) return;

        if (hook.TimeoutSeconds < 1)
        {
            errors.Add($"{name}: timeout must be at least 1 second");
        }

        if (hook.TimeoutSeconds > 3600)
        {
            errors.Add($"{name}: timeout should not exceed 3600 seconds (1 hour)");
        }

        if (hook.FailOn.Count == 0)
        {
            errors.Add($"{name}: at least one severity level must be specified in fail-on");
        }

        if (hook.Analyses == HookAnalysisType.None)
        {
            errors.Add($"{name}: at least one analysis type must be enabled");
        }
    }
}
