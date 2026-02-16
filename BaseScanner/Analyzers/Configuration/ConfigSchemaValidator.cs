using Microsoft.CodeAnalysis;
using BaseScanner.Analyzers.Configuration.Models;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace BaseScanner.Analyzers.Configuration;

/// <summary>
/// Validates configuration schema and detects configuration issues:
/// - Missing configuration keys (used in code but not defined)
/// - Unused configuration keys (defined but never read)
/// - Configuration type mismatches
/// - Sensitive values in config files
/// </summary>
public class ConfigSchemaValidator
{
    // Patterns for detecting sensitive configuration values
    private static readonly Regex PasswordPattern = new(
        @"(password|pwd|passwd|secret|apikey|api_key|api-key|token|auth|credential|key)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ConnectionStringValuePattern = new(
        @"Server\s*=|Data Source\s*=|Password\s*=|User Id\s*=",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex PlaceholderPattern = new(
        @"\$\{[^}]+\}|\%[^%]+\%|\{\{[^}]+\}\}",
        RegexOptions.Compiled);

    /// <summary>
    /// Parse configuration files and extract definitions.
    /// </summary>
    public async Task<List<ConfigurationDefinition>> ParseConfigurationFilesAsync(string projectPath)
    {
        var definitions = new List<ConfigurationDefinition>();

        // Find all configuration files
        var configFiles = FindConfigurationFiles(projectPath);

        foreach (var configFile in configFiles)
        {
            try
            {
                var fileDefinitions = await ParseConfigFileAsync(configFile);
                definitions.AddRange(fileDefinitions);
            }
            catch (Exception)
            {
                // Skip files that can't be parsed
            }
        }

        return definitions;
    }

    /// <summary>
    /// Validate configuration by comparing accesses with definitions.
    /// </summary>
    public List<ConfigurationIssue> ValidateConfiguration(
        List<ConfigurationAccess> accesses,
        List<ConfigurationDefinition> definitions)
    {
        var issues = new List<ConfigurationIssue>();

        // Build sets for comparison
        var definedKeys = definitions.Select(d => NormalizeKey(d.Key)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var accessedKeys = accesses.Select(a => NormalizeKey(a.Key)).ToHashSet(StringComparer.OrdinalIgnoreCase);

        // Find missing configurations (used but not defined)
        var missingKeys = new Dictionary<string, List<ConfigurationAccess>>();
        foreach (var access in accesses)
        {
            var normalizedKey = NormalizeKey(access.Key);
            if (!definedKeys.Contains(normalizedKey) && !IsWellKnownKey(normalizedKey))
            {
                if (!missingKeys.ContainsKey(normalizedKey))
                    missingKeys[normalizedKey] = new List<ConfigurationAccess>();
                missingKeys[normalizedKey].Add(access);
            }
        }

        foreach (var (key, accessList) in missingKeys)
        {
            var firstAccess = accessList.First();
            issues.Add(new ConfigurationIssue
            {
                IssueType = ConfigurationIssueType.MissingConfig,
                Severity = firstAccess.HasDefaultValue ? ConfigurationSeverity.Low : ConfigurationSeverity.Medium,
                FilePath = firstAccess.FilePath,
                StartLine = firstAccess.Line,
                EndLine = firstAccess.Line,
                CodeSnippet = $"Accessed key: {firstAccess.Key}",
                Description = firstAccess.HasDefaultValue
                    ? $"Configuration key '{key}' is used but not defined. A default value of '{firstAccess.DefaultValue}' is provided."
                    : $"Configuration key '{key}' is used but not defined in any configuration file. This may cause runtime failures.",
                Recommendation = $"Add '{key}' to appsettings.json or provide a default value in code.",
                ConfigKey = key,
                SuggestedFix = GenerateSuggestedConfig(key, firstAccess.ExpectedType),
                Confidence = "High"
            });
        }

        // Find unused configurations (defined but never used)
        foreach (var definition in definitions)
        {
            var normalizedKey = NormalizeKey(definition.Key);

            // Skip common framework keys
            if (IsFrameworkKey(normalizedKey))
                continue;

            if (!accessedKeys.Contains(normalizedKey))
            {
                issues.Add(new ConfigurationIssue
                {
                    IssueType = ConfigurationIssueType.UnusedConfig,
                    Severity = ConfigurationSeverity.Info,
                    FilePath = definition.SourceFile,
                    StartLine = definition.Line,
                    EndLine = definition.Line,
                    CodeSnippet = $"{definition.Key}: {(definition.IsSensitive ? "[SENSITIVE]" : definition.Value)}",
                    Description = $"Configuration key '{definition.Key}' is defined but never accessed in code. It may be dead configuration or accessed dynamically.",
                    Recommendation = "Review if this configuration is still needed. Remove unused configuration to reduce maintenance burden.",
                    ConfigKey = definition.Key,
                    Confidence = "Medium"
                });
            }
        }

        // Check for sensitive values in config files
        foreach (var definition in definitions.Where(d => d.IsSensitive && !d.IsPlaceholder))
        {
            issues.Add(new ConfigurationIssue
            {
                IssueType = ConfigurationIssueType.HardcodedCredential,
                Severity = ConfigurationSeverity.High,
                FilePath = definition.SourceFile,
                StartLine = definition.Line,
                EndLine = definition.Line,
                CodeSnippet = $"{definition.Key}: [SENSITIVE VALUE]",
                Description = $"Configuration key '{definition.Key}' appears to contain a sensitive value. Secrets should not be stored in configuration files.",
                Recommendation = "Use Azure Key Vault, AWS Secrets Manager, or environment variables for sensitive configuration. Use User Secrets for local development.",
                ConfigKey = definition.Key,
                SuggestedFix = $"// Use User Secrets:\ndotnet user-secrets set \"{definition.Key}\" \"your-secret\"",
                Confidence = "High"
            });
        }

        return issues;
    }

    private List<string> FindConfigurationFiles(string projectPath)
    {
        var files = new List<string>();

        try
        {
            // JSON configuration files
            files.AddRange(Directory.GetFiles(projectPath, "appsettings*.json", SearchOption.AllDirectories)
                .Where(f => !f.Contains("bin") && !f.Contains("obj")));

            // XML configuration files
            files.AddRange(Directory.GetFiles(projectPath, "*.config", SearchOption.AllDirectories)
                .Where(f => !f.Contains("bin") && !f.Contains("obj") &&
                           (f.EndsWith("App.config", StringComparison.OrdinalIgnoreCase) ||
                            f.EndsWith("Web.config", StringComparison.OrdinalIgnoreCase))));

            // Environment files
            files.AddRange(Directory.GetFiles(projectPath, ".env*", SearchOption.TopDirectoryOnly));
        }
        catch (Exception)
        {
            // Handle access issues
        }

        return files;
    }

    private async Task<List<ConfigurationDefinition>> ParseConfigFileAsync(string filePath)
    {
        var definitions = new List<ConfigurationDefinition>();
        var extension = Path.GetExtension(filePath).ToLowerInvariant();

        if (extension == ".json")
        {
            definitions.AddRange(await ParseJsonConfigAsync(filePath));
        }
        else if (extension == ".config")
        {
            definitions.AddRange(ParseXmlConfig(filePath));
        }
        else if (Path.GetFileName(filePath).StartsWith(".env", StringComparison.OrdinalIgnoreCase))
        {
            definitions.AddRange(ParseEnvFile(filePath));
        }

        return definitions;
    }

    private async Task<List<ConfigurationDefinition>> ParseJsonConfigAsync(string filePath)
    {
        var definitions = new List<ConfigurationDefinition>();

        try
        {
            var json = await File.ReadAllTextAsync(filePath);
            using var doc = JsonDocument.Parse(json);

            ExtractJsonProperties(doc.RootElement, "", filePath, definitions, 1);
        }
        catch (Exception)
        {
            // Skip malformed JSON
        }

        return definitions;
    }

    private void ExtractJsonProperties(JsonElement element, string prefix, string filePath,
        List<ConfigurationDefinition> definitions, int lineEstimate)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    var key = string.IsNullOrEmpty(prefix) ? property.Name : $"{prefix}:{property.Name}";
                    ExtractJsonProperties(property.Value, key, filePath, definitions, lineEstimate++);
                }
                break;

            case JsonValueKind.Array:
                int index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    var key = $"{prefix}:{index}";
                    ExtractJsonProperties(item, key, filePath, definitions, lineEstimate++);
                    index++;
                }
                break;

            case JsonValueKind.String:
                var stringValue = element.GetString() ?? "";
                definitions.Add(new ConfigurationDefinition
                {
                    Key = prefix,
                    Value = stringValue,
                    SourceFile = filePath,
                    Line = lineEstimate,
                    IsSensitive = IsSensitiveKey(prefix) && !string.IsNullOrEmpty(stringValue) && stringValue.Length > 3,
                    IsPlaceholder = PlaceholderPattern.IsMatch(stringValue)
                });
                break;

            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
                definitions.Add(new ConfigurationDefinition
                {
                    Key = prefix,
                    Value = element.ToString(),
                    SourceFile = filePath,
                    Line = lineEstimate,
                    IsSensitive = false,
                    IsPlaceholder = false
                });
                break;
        }
    }

    private List<ConfigurationDefinition> ParseXmlConfig(string filePath)
    {
        var definitions = new List<ConfigurationDefinition>();

        try
        {
            var doc = XDocument.Load(filePath);
            var lineNumber = 1;

            // Parse appSettings
            var appSettings = doc.Descendants("appSettings").FirstOrDefault();
            if (appSettings != null)
            {
                foreach (var add in appSettings.Descendants("add"))
                {
                    var key = add.Attribute("key")?.Value;
                    var value = add.Attribute("value")?.Value;

                    if (!string.IsNullOrEmpty(key))
                    {
                        definitions.Add(new ConfigurationDefinition
                        {
                            Key = key,
                            Value = value,
                            SourceFile = filePath,
                            Line = lineNumber++,
                            IsSensitive = IsSensitiveKey(key) && !string.IsNullOrEmpty(value),
                            IsPlaceholder = value != null && PlaceholderPattern.IsMatch(value)
                        });
                    }
                }
            }

            // Parse connectionStrings
            var connectionStrings = doc.Descendants("connectionStrings").FirstOrDefault();
            if (connectionStrings != null)
            {
                foreach (var add in connectionStrings.Descendants("add"))
                {
                    var name = add.Attribute("name")?.Value;
                    var connectionString = add.Attribute("connectionString")?.Value;

                    if (!string.IsNullOrEmpty(name))
                    {
                        definitions.Add(new ConfigurationDefinition
                        {
                            Key = $"ConnectionStrings:{name}",
                            Value = connectionString,
                            SourceFile = filePath,
                            Line = lineNumber++,
                            IsSensitive = connectionString != null && ConnectionStringValuePattern.IsMatch(connectionString),
                            IsPlaceholder = connectionString != null && PlaceholderPattern.IsMatch(connectionString)
                        });
                    }
                }
            }
        }
        catch (Exception)
        {
            // Skip malformed XML
        }

        return definitions;
    }

    private List<ConfigurationDefinition> ParseEnvFile(string filePath)
    {
        var definitions = new List<ConfigurationDefinition>();

        try
        {
            var lines = File.ReadAllLines(filePath);
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i].Trim();

                // Skip comments and empty lines
                if (string.IsNullOrEmpty(line) || line.StartsWith('#'))
                    continue;

                var equalsIndex = line.IndexOf('=');
                if (equalsIndex > 0)
                {
                    var key = line[..equalsIndex].Trim();
                    var value = line[(equalsIndex + 1)..].Trim().Trim('"', '\'');

                    definitions.Add(new ConfigurationDefinition
                    {
                        Key = key,
                        Value = value,
                        SourceFile = filePath,
                        Line = i + 1,
                        IsSensitive = IsSensitiveKey(key),
                        IsPlaceholder = PlaceholderPattern.IsMatch(value)
                    });
                }
            }
        }
        catch (Exception)
        {
            // Skip unreadable files
        }

        return definitions;
    }

    private static string NormalizeKey(string key)
    {
        // Normalize different key formats (colon vs double underscore)
        return key.Replace("__", ":").Trim();
    }

    private static bool IsSensitiveKey(string key)
    {
        return PasswordPattern.IsMatch(key);
    }

    private static bool IsWellKnownKey(string key)
    {
        // Framework keys that are commonly used but not always explicitly defined
        var wellKnownPrefixes = new[]
        {
            "ASPNETCORE_",
            "DOTNET_",
            "Logging:",
            "AllowedHosts",
            "Urls",
            "ContentRoot",
            "WebRoot"
        };

        return wellKnownPrefixes.Any(p => key.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsFrameworkKey(string key)
    {
        // Keys that are part of the framework and commonly unused explicitly
        var frameworkPrefixes = new[]
        {
            "Logging:",
            "Microsoft:",
            "System:",
            "AllowedHosts",
            "$schema"
        };

        return frameworkPrefixes.Any(p => key.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }

    private static string GenerateSuggestedConfig(string key, string? expectedType)
    {
        var type = expectedType ?? "string";
        var sampleValue = type.ToLowerInvariant() switch
        {
            "int" or "int32" or "integer" => "0",
            "bool" or "boolean" => "false",
            "double" or "float" or "decimal" => "0.0",
            _ => "\"value\""
        };

        // Generate JSON path
        var parts = key.Split(':');
        if (parts.Length == 1)
        {
            return $"// Add to appsettings.json:\n\"{key}\": {sampleValue}";
        }

        // Build nested JSON structure
        var indent = "  ";
        var result = "// Add to appsettings.json:\n";

        for (int i = 0; i < parts.Length; i++)
        {
            var currentIndent = new string(' ', i * 2);
            if (i == parts.Length - 1)
            {
                result += $"{currentIndent}\"{parts[i]}\": {sampleValue}";
            }
            else
            {
                result += $"{currentIndent}\"{parts[i]}\": {{\n";
            }
        }

        // Close brackets
        for (int i = parts.Length - 2; i >= 0; i--)
        {
            var currentIndent = new string(' ', i * 2);
            result += $"\n{currentIndent}}}";
        }

        return result;
    }
}
