using BaseScanner.Rules.Models;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace BaseScanner.Rules;

/// <summary>
/// Parses YAML rule definitions into strongly-typed rule objects.
/// </summary>
public class RuleParser
{
    private readonly IDeserializer _deserializer;
    private readonly string _rulesDirectory;

    public RuleParser(string? rulesDirectory = null)
    {
        _rulesDirectory = rulesDirectory ?? Path.Combine(".basescanner", "rules");

        _deserializer = new DeserializerBuilder()
            .WithNamingConvention(CamelCaseNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();
    }

    /// <summary>
    /// Loads all rules from the rules directory.
    /// </summary>
    public async Task<List<CustomRule>> LoadAllRulesAsync()
    {
        var rules = new List<CustomRule>();

        if (!Directory.Exists(_rulesDirectory))
        {
            return rules;
        }

        var yamlFiles = Directory.GetFiles(_rulesDirectory, "*.yaml", SearchOption.AllDirectories)
            .Concat(Directory.GetFiles(_rulesDirectory, "*.yml", SearchOption.AllDirectories));

        foreach (var file in yamlFiles)
        {
            try
            {
                var fileRules = await ParseFileAsync(file);
                rules.AddRange(fileRules);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error parsing rule file '{file}': {ex.Message}");
            }
        }

        return rules.Where(r => r.Enabled).ToList();
    }

    /// <summary>
    /// Parses a single YAML rule file.
    /// </summary>
    public async Task<List<CustomRule>> ParseFileAsync(string filePath)
    {
        var content = await File.ReadAllTextAsync(filePath);
        return ParseYaml(content, filePath);
    }

    /// <summary>
    /// Parses YAML content into rules.
    /// </summary>
    public List<CustomRule> ParseYaml(string yamlContent, string? sourceFile = null)
    {
        var ruleFile = _deserializer.Deserialize<RuleFileYaml>(yamlContent);

        if (ruleFile?.Rules == null)
        {
            return new List<CustomRule>();
        }

        var rules = new List<CustomRule>();

        foreach (var yamlRule in ruleFile.Rules)
        {
            try
            {
                var rule = ConvertToCustomRule(yamlRule);
                if (rule != null)
                {
                    rules.Add(rule);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error parsing rule '{yamlRule.Name}' in '{sourceFile}': {ex.Message}");
            }
        }

        return rules;
    }

    /// <summary>
    /// Validates a rule definition.
    /// </summary>
    public (bool IsValid, List<string> Errors) ValidateRule(CustomRule rule)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(rule.Name))
        {
            errors.Add("Rule name is required");
        }

        if (rule.Pattern == null)
        {
            errors.Add("Rule pattern is required");
        }
        else
        {
            if (string.IsNullOrWhiteSpace(rule.Pattern.Match) &&
                string.IsNullOrWhiteSpace(rule.Pattern.NamePattern) &&
                rule.Pattern.MinValue == null &&
                rule.Pattern.MaxValue == null)
            {
                errors.Add("Pattern must have at least one matching criteria (match, namePattern, minValue, maxValue)");
            }
        }

        if (string.IsNullOrWhiteSpace(rule.Message))
        {
            errors.Add("Rule message is required");
        }

        return (errors.Count == 0, errors);
    }

    private CustomRule? ConvertToCustomRule(RuleYaml yamlRule)
    {
        if (yamlRule == null) return null;

        var pattern = new RulePattern
        {
            Type = ParsePatternType(yamlRule.Pattern?.Type),
            Match = yamlRule.Pattern?.Match,
            Returns = yamlRule.Pattern?.Returns,
            NamePattern = yamlRule.Pattern?.NamePattern,
            NotIn = yamlRule.Pattern?.NotIn ?? new List<string>(),
            In = yamlRule.Pattern?.In ?? new List<string>(),
            MinValue = yamlRule.Pattern?.MinValue,
            MaxValue = yamlRule.Pattern?.MaxValue,
            UseRegex = yamlRule.Pattern?.UseRegex ?? false,
            RequiredArguments = yamlRule.Pattern?.RequiredArguments ?? new List<string>(),
            MinParameters = yamlRule.Pattern?.MinParameters,
            MaxParameters = yamlRule.Pattern?.MaxParameters,
            Conditions = yamlRule.Pattern?.Conditions ?? new List<string>()
        };

        return new CustomRule
        {
            Name = yamlRule.Name ?? "UnnamedRule",
            Description = yamlRule.Description ?? "",
            Severity = ParseSeverity(yamlRule.Severity),
            Pattern = pattern,
            Message = yamlRule.Message ?? "Rule violation",
            Suggestion = yamlRule.Suggestion,
            HelpUrl = yamlRule.HelpUrl,
            Enabled = yamlRule.Enabled ?? true,
            Tags = yamlRule.Tags ?? new List<string>()
        };
    }

    private PatternType ParsePatternType(string? type)
    {
        return type?.ToLowerInvariant() switch
        {
            "methodinvocation" => PatternType.MethodInvocation,
            "methoddeclaration" => PatternType.MethodDeclaration,
            "typeusage" => PatternType.TypeUsage,
            "numericliteral" => PatternType.NumericLiteral,
            "stringliteral" => PatternType.StringLiteral,
            "attribute" => PatternType.Attribute,
            _ => PatternType.MethodInvocation
        };
    }

    private RuleSeverity ParseSeverity(string? severity)
    {
        return severity?.ToLowerInvariant() switch
        {
            "info" => RuleSeverity.Info,
            "warning" => RuleSeverity.Warning,
            "error" => RuleSeverity.Error,
            _ => RuleSeverity.Warning
        };
    }

    #region YAML Deserialization Classes

    private class RuleFileYaml
    {
        public string? Version { get; set; }
        public List<RuleYaml>? Rules { get; set; }
        public RuleFileSettingsYaml? Settings { get; set; }
    }

    private class RuleYaml
    {
        public string? Name { get; set; }
        public string? Description { get; set; }
        public string? Severity { get; set; }
        public PatternYaml? Pattern { get; set; }
        public string? Message { get; set; }
        public string? Suggestion { get; set; }
        public string? HelpUrl { get; set; }
        public bool? Enabled { get; set; }
        public List<string>? Tags { get; set; }
    }

    private class PatternYaml
    {
        public string? Type { get; set; }
        public string? Match { get; set; }
        public string? Returns { get; set; }
        public string? NamePattern { get; set; }
        public List<string>? NotIn { get; set; }
        public List<string>? In { get; set; }
        public double? MinValue { get; set; }
        public double? MaxValue { get; set; }
        public bool? UseRegex { get; set; }
        public List<string>? RequiredArguments { get; set; }
        public int? MinParameters { get; set; }
        public int? MaxParameters { get; set; }
        public List<string>? Conditions { get; set; }
    }

    private class RuleFileSettingsYaml
    {
        public bool? ContinueOnViolation { get; set; }
        public List<string>? ExcludeFiles { get; set; }
        public List<string>? ExcludeDirectories { get; set; }
    }

    #endregion
}
