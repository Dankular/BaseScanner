using System.Text.RegularExpressions;
using BaseScanner.Analyzers.Naming.Models;

namespace BaseScanner.Analyzers.Naming;

/// <summary>
/// Configurable naming convention rules for C# code analysis.
/// Validates identifiers against defined patterns and conventions.
/// </summary>
public class ConventionRules
{
    private readonly NamingConfiguration _configuration;
    private readonly Dictionary<SymbolCategory, NamingRule> _rules;

    // Common regex patterns for naming conventions
    private static readonly Regex PascalCasePattern = new(@"^[A-Z][a-zA-Z0-9]*$", RegexOptions.Compiled);
    private static readonly Regex CamelCasePattern = new(@"^[a-z][a-zA-Z0-9]*$", RegexOptions.Compiled);
    private static readonly Regex UpperSnakeCasePattern = new(@"^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$", RegexOptions.Compiled);
    private static readonly Regex LowerSnakeCasePattern = new(@"^[a-z][a-z0-9]*(_[a-z0-9]+)*$", RegexOptions.Compiled);
    private static readonly Regex InterfacePrefixPattern = new(@"^I[A-Z][a-zA-Z0-9]*$", RegexOptions.Compiled);
    private static readonly Regex PrivateFieldPattern = new(@"^_[a-z][a-zA-Z0-9]*$", RegexOptions.Compiled);
    private static readonly Regex TypeParameterPattern = new(@"^T([A-Z][a-zA-Z0-9]*)?$", RegexOptions.Compiled);

    public ConventionRules() : this(CreateDefaultConfiguration())
    {
    }

    public ConventionRules(NamingConfiguration configuration)
    {
        _configuration = configuration;
        _rules = configuration.Rules.Any()
            ? configuration.Rules
            : CreateDefaultRules();
    }

    /// <summary>
    /// Creates the default naming configuration for C#.
    /// </summary>
    public static NamingConfiguration CreateDefaultConfiguration()
    {
        return new NamingConfiguration
        {
            Rules = CreateDefaultRules(),
            AllowedAbbreviations = new List<string>
            {
                "Id", "Db", "Io", "Ui", "Xml", "Json", "Html", "Css", "Sql",
                "Api", "Url", "Uri", "Http", "Https", "Ftp", "Tcp", "Udp",
                "Guid", "Dto", "Poco", "Crud", "Orm", "Sdk", "Cli", "Mvc"
            },
            AllowedPrefixes = new List<string> { "I", "_", "s_", "t_" },
            AllowedSuffixes = new List<string> { "Async", "Handler", "Factory", "Service", "Manager", "Helper", "Builder" },
            TermEquivalences = new List<TermEquivalence>
            {
                new() { PreferredTerm = "User", AlternativeTerms = ["Customer", "Client", "Member", "Account"] },
                new() { PreferredTerm = "Delete", AlternativeTerms = ["Remove", "Erase", "Destroy"] },
                new() { PreferredTerm = "Create", AlternativeTerms = ["Add", "Insert", "New", "Make", "Build"] },
                new() { PreferredTerm = "Update", AlternativeTerms = ["Modify", "Change", "Edit", "Alter"] },
                new() { PreferredTerm = "Get", AlternativeTerms = ["Fetch", "Retrieve", "Read", "Load", "Find"] },
                new() { PreferredTerm = "Config", AlternativeTerms = ["Configuration", "Settings", "Options", "Preferences"] },
                new() { PreferredTerm = "Message", AlternativeTerms = ["Notification", "Alert", "Notice"] }
            },
            EnforceSemanticNaming = true,
            CheckTerminologyConsistency = true,
            MinNameLength = 2,
            MaxNameLength = 50
        };
    }

    /// <summary>
    /// Creates the default set of naming rules.
    /// </summary>
    private static Dictionary<SymbolCategory, NamingRule> CreateDefaultRules()
    {
        return new Dictionary<SymbolCategory, NamingRule>
        {
            [SymbolCategory.Class] = new NamingRule
            {
                RuleId = "NC001",
                RuleName = "ClassNaming",
                AppliesTo = SymbolCategory.Class,
                Convention = NamingConvention.PascalCase,
                Severity = NamingViolationSeverity.Warning,
                Description = "Classes should use PascalCase"
            },
            [SymbolCategory.Interface] = new NamingRule
            {
                RuleId = "NC002",
                RuleName = "InterfaceNaming",
                AppliesTo = SymbolCategory.Interface,
                Convention = NamingConvention.IPrefixed,
                RequiredPrefix = "I",
                Severity = NamingViolationSeverity.Warning,
                Description = "Interfaces should start with 'I' followed by PascalCase"
            },
            [SymbolCategory.Method] = new NamingRule
            {
                RuleId = "NC003",
                RuleName = "MethodNaming",
                AppliesTo = SymbolCategory.Method,
                Convention = NamingConvention.PascalCase,
                Severity = NamingViolationSeverity.Warning,
                Description = "Methods should use PascalCase"
            },
            [SymbolCategory.Property] = new NamingRule
            {
                RuleId = "NC004",
                RuleName = "PropertyNaming",
                AppliesTo = SymbolCategory.Property,
                Convention = NamingConvention.PascalCase,
                Severity = NamingViolationSeverity.Warning,
                Description = "Properties should use PascalCase"
            },
            [SymbolCategory.PrivateField] = new NamingRule
            {
                RuleId = "NC005",
                RuleName = "PrivateFieldNaming",
                AppliesTo = SymbolCategory.PrivateField,
                Convention = NamingConvention.UnderscorePrefixed,
                RequiredPrefix = "_",
                Severity = NamingViolationSeverity.Warning,
                Description = "Private fields should use _camelCase"
            },
            [SymbolCategory.PublicField] = new NamingRule
            {
                RuleId = "NC006",
                RuleName = "PublicFieldNaming",
                AppliesTo = SymbolCategory.PublicField,
                Convention = NamingConvention.PascalCase,
                Severity = NamingViolationSeverity.Warning,
                Description = "Public fields should use PascalCase"
            },
            [SymbolCategory.ProtectedField] = new NamingRule
            {
                RuleId = "NC007",
                RuleName = "ProtectedFieldNaming",
                AppliesTo = SymbolCategory.ProtectedField,
                Convention = NamingConvention.UnderscorePrefixed,
                RequiredPrefix = "_",
                Severity = NamingViolationSeverity.Suggestion,
                Description = "Protected fields should use _camelCase"
            },
            [SymbolCategory.InternalField] = new NamingRule
            {
                RuleId = "NC008",
                RuleName = "InternalFieldNaming",
                AppliesTo = SymbolCategory.InternalField,
                Convention = NamingConvention.UnderscorePrefixed,
                RequiredPrefix = "_",
                Severity = NamingViolationSeverity.Suggestion,
                Description = "Internal fields should use _camelCase"
            },
            [SymbolCategory.Parameter] = new NamingRule
            {
                RuleId = "NC009",
                RuleName = "ParameterNaming",
                AppliesTo = SymbolCategory.Parameter,
                Convention = NamingConvention.CamelCase,
                Severity = NamingViolationSeverity.Warning,
                Description = "Parameters should use camelCase"
            },
            [SymbolCategory.LocalVariable] = new NamingRule
            {
                RuleId = "NC010",
                RuleName = "LocalVariableNaming",
                AppliesTo = SymbolCategory.LocalVariable,
                Convention = NamingConvention.CamelCase,
                Severity = NamingViolationSeverity.Suggestion,
                Description = "Local variables should use camelCase"
            },
            [SymbolCategory.Constant] = new NamingRule
            {
                RuleId = "NC011",
                RuleName = "ConstantNaming",
                AppliesTo = SymbolCategory.Constant,
                Convention = NamingConvention.PascalCase, // or UPPER_CASE
                Severity = NamingViolationSeverity.Suggestion,
                Description = "Constants should use PascalCase or UPPER_CASE"
            },
            [SymbolCategory.Enum] = new NamingRule
            {
                RuleId = "NC012",
                RuleName = "EnumNaming",
                AppliesTo = SymbolCategory.Enum,
                Convention = NamingConvention.PascalCase,
                Severity = NamingViolationSeverity.Warning,
                Description = "Enums should use PascalCase"
            },
            [SymbolCategory.EnumMember] = new NamingRule
            {
                RuleId = "NC013",
                RuleName = "EnumMemberNaming",
                AppliesTo = SymbolCategory.EnumMember,
                Convention = NamingConvention.PascalCase,
                Severity = NamingViolationSeverity.Warning,
                Description = "Enum members should use PascalCase"
            },
            [SymbolCategory.Struct] = new NamingRule
            {
                RuleId = "NC014",
                RuleName = "StructNaming",
                AppliesTo = SymbolCategory.Struct,
                Convention = NamingConvention.PascalCase,
                Severity = NamingViolationSeverity.Warning,
                Description = "Structs should use PascalCase"
            },
            [SymbolCategory.Record] = new NamingRule
            {
                RuleId = "NC015",
                RuleName = "RecordNaming",
                AppliesTo = SymbolCategory.Record,
                Convention = NamingConvention.PascalCase,
                Severity = NamingViolationSeverity.Warning,
                Description = "Records should use PascalCase"
            },
            [SymbolCategory.Delegate] = new NamingRule
            {
                RuleId = "NC016",
                RuleName = "DelegateNaming",
                AppliesTo = SymbolCategory.Delegate,
                Convention = NamingConvention.PascalCase,
                Severity = NamingViolationSeverity.Warning,
                Description = "Delegates should use PascalCase"
            },
            [SymbolCategory.Event] = new NamingRule
            {
                RuleId = "NC017",
                RuleName = "EventNaming",
                AppliesTo = SymbolCategory.Event,
                Convention = NamingConvention.PascalCase,
                Severity = NamingViolationSeverity.Warning,
                Description = "Events should use PascalCase"
            },
            [SymbolCategory.TypeParameter] = new NamingRule
            {
                RuleId = "NC018",
                RuleName = "TypeParameterNaming",
                AppliesTo = SymbolCategory.TypeParameter,
                Convention = NamingConvention.PascalCase,
                RequiredPrefix = "T",
                Severity = NamingViolationSeverity.Suggestion,
                Description = "Type parameters should be 'T' or start with 'T'"
            },
            [SymbolCategory.Namespace] = new NamingRule
            {
                RuleId = "NC019",
                RuleName = "NamespaceNaming",
                AppliesTo = SymbolCategory.Namespace,
                Convention = NamingConvention.PascalCase,
                Severity = NamingViolationSeverity.Warning,
                Description = "Namespaces should use PascalCase"
            }
        };
    }

    /// <summary>
    /// Gets the rule for a specific symbol category.
    /// </summary>
    public NamingRule? GetRule(SymbolCategory category)
    {
        return _rules.TryGetValue(category, out var rule) ? rule : null;
    }

    /// <summary>
    /// Gets all configured rules.
    /// </summary>
    public IReadOnlyDictionary<SymbolCategory, NamingRule> GetAllRules() => _rules;

    /// <summary>
    /// Gets the naming configuration.
    /// </summary>
    public NamingConfiguration GetConfiguration() => _configuration;

    /// <summary>
    /// Validates a name against the rule for its category.
    /// </summary>
    public NamingViolation? ValidateName(string name, SymbolCategory category, string filePath, int line, int column, string? containingType = null)
    {
        var rule = GetRule(category);
        if (rule == null || !rule.IsEnabled)
            return null;

        var actualConvention = DetectNamingConvention(name);
        var isValid = IsValidForConvention(name, rule.Convention, rule.RequiredPrefix, rule.RequiredSuffix);

        if (isValid)
            return null;

        return new NamingViolation
        {
            SymbolName = name,
            SymbolCategory = category,
            FilePath = filePath,
            Line = line,
            Column = column,
            RuleId = rule.RuleId,
            RuleName = rule.RuleName,
            Message = BuildViolationMessage(name, rule),
            Severity = rule.Severity,
            ExpectedConvention = rule.Convention,
            ActualConvention = actualConvention,
            SuggestedName = SuggestCorrectName(name, category, rule),
            ContainingTypeName = containingType,
            Explanation = rule.Description
        };
    }

    /// <summary>
    /// Validates a constant name (allows PascalCase or UPPER_CASE).
    /// </summary>
    public NamingViolation? ValidateConstantName(string name, string filePath, int line, int column, string? containingType = null)
    {
        var rule = GetRule(SymbolCategory.Constant);
        if (rule == null || !rule.IsEnabled)
            return null;

        // Constants can be either PascalCase or UPPER_CASE
        var isPascalCase = PascalCasePattern.IsMatch(name);
        var isUpperCase = UpperSnakeCasePattern.IsMatch(name);

        if (isPascalCase || isUpperCase)
            return null;

        var actualConvention = DetectNamingConvention(name);

        return new NamingViolation
        {
            SymbolName = name,
            SymbolCategory = SymbolCategory.Constant,
            FilePath = filePath,
            Line = line,
            Column = column,
            RuleId = rule.RuleId,
            RuleName = rule.RuleName,
            Message = $"Constant '{name}' should use PascalCase or UPPER_CASE",
            Severity = rule.Severity,
            ExpectedConvention = NamingConvention.PascalCase,
            ActualConvention = actualConvention,
            SuggestedName = SuggestConstantName(name),
            ContainingTypeName = containingType,
            Explanation = rule.Description
        };
    }

    /// <summary>
    /// Detects the naming convention used by a given name.
    /// </summary>
    public NamingConvention DetectNamingConvention(string name)
    {
        if (string.IsNullOrEmpty(name))
            return NamingConvention.Unknown;

        if (InterfacePrefixPattern.IsMatch(name))
            return NamingConvention.IPrefixed;

        if (PrivateFieldPattern.IsMatch(name))
            return NamingConvention.UnderscorePrefixed;

        if (UpperSnakeCasePattern.IsMatch(name))
            return NamingConvention.UpperSnakeCase;

        if (LowerSnakeCasePattern.IsMatch(name))
            return NamingConvention.LowerSnakeCase;

        if (PascalCasePattern.IsMatch(name))
            return NamingConvention.PascalCase;

        if (CamelCasePattern.IsMatch(name))
            return NamingConvention.CamelCase;

        // Check for Hungarian notation (common prefixes)
        if (Regex.IsMatch(name, @"^(str|int|bln|dbl|obj|arr|lst|dic)[A-Z]"))
            return NamingConvention.HungarianNotation;

        return NamingConvention.Unknown;
    }

    /// <summary>
    /// Checks if a name is valid for the specified convention.
    /// </summary>
    public bool IsValidForConvention(string name, NamingConvention convention, string? requiredPrefix = null, string? requiredSuffix = null)
    {
        if (string.IsNullOrEmpty(name))
            return false;

        // Check required prefix
        if (!string.IsNullOrEmpty(requiredPrefix) && !name.StartsWith(requiredPrefix))
            return false;

        // Check required suffix
        if (!string.IsNullOrEmpty(requiredSuffix) && !name.EndsWith(requiredSuffix))
            return false;

        // For prefix checks, validate the remaining part
        var nameToCheck = name;
        if (!string.IsNullOrEmpty(requiredPrefix))
            nameToCheck = name.Substring(requiredPrefix.Length);

        return convention switch
        {
            NamingConvention.PascalCase => PascalCasePattern.IsMatch(nameToCheck),
            NamingConvention.CamelCase => CamelCasePattern.IsMatch(name),
            NamingConvention.UpperSnakeCase => UpperSnakeCasePattern.IsMatch(name),
            NamingConvention.LowerSnakeCase => LowerSnakeCasePattern.IsMatch(name),
            NamingConvention.IPrefixed => InterfacePrefixPattern.IsMatch(name),
            NamingConvention.UnderscorePrefixed => PrivateFieldPattern.IsMatch(name),
            _ => true
        };
    }

    /// <summary>
    /// Suggests a corrected name based on the target convention.
    /// </summary>
    public string SuggestCorrectName(string name, SymbolCategory category, NamingRule rule)
    {
        if (string.IsNullOrEmpty(name))
            return name;

        var words = SplitIntoWords(name);
        if (words.Count == 0)
            return name;

        return rule.Convention switch
        {
            NamingConvention.PascalCase => string.Concat(words.Select(w => char.ToUpperInvariant(w[0]) + w.Substring(1).ToLowerInvariant())),
            NamingConvention.CamelCase => ToCamelCase(words),
            NamingConvention.UpperSnakeCase => string.Join("_", words.Select(w => w.ToUpperInvariant())),
            NamingConvention.LowerSnakeCase => string.Join("_", words.Select(w => w.ToLowerInvariant())),
            NamingConvention.IPrefixed => "I" + string.Concat(words.Select(w => char.ToUpperInvariant(w[0]) + w.Substring(1).ToLowerInvariant())),
            NamingConvention.UnderscorePrefixed => "_" + ToCamelCase(words),
            _ => name
        };
    }

    /// <summary>
    /// Suggests a corrected constant name.
    /// </summary>
    private string SuggestConstantName(string name)
    {
        var words = SplitIntoWords(name);
        if (words.Count == 0)
            return name;

        // Prefer PascalCase for constants
        return string.Concat(words.Select(w => char.ToUpperInvariant(w[0]) + w.Substring(1).ToLowerInvariant()));
    }

    /// <summary>
    /// Splits a name into constituent words.
    /// </summary>
    public List<string> SplitIntoWords(string name)
    {
        if (string.IsNullOrEmpty(name))
            return new List<string>();

        // Remove common prefixes
        var cleanName = name;
        if (cleanName.StartsWith("_"))
            cleanName = cleanName.Substring(1);
        if (cleanName.StartsWith("I") && cleanName.Length > 1 && char.IsUpper(cleanName[1]))
            cleanName = cleanName.Substring(1);

        // Handle snake_case
        if (cleanName.Contains('_'))
        {
            return cleanName.Split('_', StringSplitOptions.RemoveEmptyEntries)
                .Select(w => w.ToLowerInvariant())
                .Where(w => w.Length > 0)
                .ToList();
        }

        // Handle PascalCase/camelCase
        var words = new List<string>();
        var currentWord = new System.Text.StringBuilder();

        foreach (var c in cleanName)
        {
            if (char.IsUpper(c) && currentWord.Length > 0)
            {
                // Check if we're in an acronym (all caps)
                if (currentWord.ToString().All(char.IsUpper))
                {
                    // Peek ahead - if next is lowercase, end the acronym
                    if (currentWord.Length > 1)
                    {
                        words.Add(currentWord.ToString().ToLowerInvariant());
                        currentWord.Clear();
                    }
                }
                else
                {
                    words.Add(currentWord.ToString().ToLowerInvariant());
                    currentWord.Clear();
                }
            }
            currentWord.Append(c);
        }

        if (currentWord.Length > 0)
            words.Add(currentWord.ToString().ToLowerInvariant());

        return words;
    }

    /// <summary>
    /// Checks if a name contains known abbreviations.
    /// </summary>
    public bool ContainsAbbreviation(string name, out List<string> foundAbbreviations)
    {
        foundAbbreviations = new List<string>();
        var upperName = name.ToUpperInvariant();

        foreach (var abbr in _configuration.AllowedAbbreviations)
        {
            if (upperName.Contains(abbr.ToUpperInvariant()))
            {
                foundAbbreviations.Add(abbr);
            }
        }

        return foundAbbreviations.Count > 0;
    }

    /// <summary>
    /// Validates the length of a name.
    /// </summary>
    public (bool isValid, string? issue) ValidateNameLength(string name, SymbolCategory category)
    {
        if (name.Length < _configuration.MinNameLength)
        {
            // Allow single-letter names for specific cases
            if (category == SymbolCategory.TypeParameter ||
                (category == SymbolCategory.LocalVariable && name.Length == 1 && char.IsLetter(name[0])))
            {
                return (true, null);
            }
            return (false, $"Name '{name}' is too short (minimum {_configuration.MinNameLength} characters)");
        }

        if (name.Length > _configuration.MaxNameLength)
        {
            return (false, $"Name '{name}' is too long (maximum {_configuration.MaxNameLength} characters)");
        }

        return (true, null);
    }

    private static string ToCamelCase(List<string> words)
    {
        if (words.Count == 0)
            return "";

        var result = words[0].ToLowerInvariant();
        for (var i = 1; i < words.Count; i++)
        {
            var word = words[i];
            result += char.ToUpperInvariant(word[0]) + word.Substring(1).ToLowerInvariant();
        }
        return result;
    }

    private static string BuildViolationMessage(string name, NamingRule rule)
    {
        var message = $"{rule.AppliesTo} '{name}' should use {FormatConventionName(rule.Convention)}";

        if (!string.IsNullOrEmpty(rule.RequiredPrefix))
            message += $" with prefix '{rule.RequiredPrefix}'";

        if (!string.IsNullOrEmpty(rule.RequiredSuffix))
            message += $" with suffix '{rule.RequiredSuffix}'";

        return message;
    }

    private static string FormatConventionName(NamingConvention convention) => convention switch
    {
        NamingConvention.PascalCase => "PascalCase",
        NamingConvention.CamelCase => "camelCase",
        NamingConvention.UpperSnakeCase => "UPPER_SNAKE_CASE",
        NamingConvention.LowerSnakeCase => "lower_snake_case",
        NamingConvention.IPrefixed => "IPascalCase (interface prefix)",
        NamingConvention.UnderscorePrefixed => "_camelCase (underscore prefix)",
        _ => convention.ToString()
    };
}
