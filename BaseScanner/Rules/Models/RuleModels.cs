using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace BaseScanner.Rules.Models;

/// <summary>
/// Represents the severity level of a rule violation.
/// </summary>
public enum RuleSeverity
{
    Info,
    Warning,
    Error
}

/// <summary>
/// Represents the type of pattern to match in the code.
/// </summary>
public enum PatternType
{
    MethodInvocation,
    MethodDeclaration,
    TypeUsage,
    NumericLiteral,
    StringLiteral,
    Attribute
}

/// <summary>
/// Represents a pattern definition for matching code elements.
/// </summary>
public class RulePattern
{
    /// <summary>
    /// The type of code element to match.
    /// </summary>
    public PatternType Type { get; set; }

    /// <summary>
    /// The pattern to match (supports wildcards).
    /// For MethodInvocation: "ClassName.MethodName" or "*.MethodName"
    /// For MethodDeclaration: method name pattern
    /// For TypeUsage: type name pattern
    /// For NumericLiteral/StringLiteral: value pattern
    /// For Attribute: attribute name pattern
    /// </summary>
    public string? Match { get; set; }

    /// <summary>
    /// For MethodDeclaration: pattern for return type.
    /// </summary>
    public string? Returns { get; set; }

    /// <summary>
    /// For MethodDeclaration: regex pattern for method name.
    /// </summary>
    public string? NamePattern { get; set; }

    /// <summary>
    /// Locations where the pattern should NOT match (exclusions).
    /// </summary>
    public List<string> NotIn { get; set; } = new();

    /// <summary>
    /// Locations where the pattern MUST be in (inclusions).
    /// </summary>
    public List<string> In { get; set; } = new();

    /// <summary>
    /// For NumericLiteral: minimum value.
    /// </summary>
    public double? MinValue { get; set; }

    /// <summary>
    /// For NumericLiteral: maximum value.
    /// </summary>
    public double? MaxValue { get; set; }

    /// <summary>
    /// For StringLiteral: whether to use regex matching.
    /// </summary>
    public bool UseRegex { get; set; }

    /// <summary>
    /// For Attribute: required arguments.
    /// </summary>
    public List<string> RequiredArguments { get; set; } = new();

    /// <summary>
    /// For MethodDeclaration: minimum parameter count.
    /// </summary>
    public int? MinParameters { get; set; }

    /// <summary>
    /// For MethodDeclaration: maximum parameter count.
    /// </summary>
    public int? MaxParameters { get; set; }

    /// <summary>
    /// Additional conditions using built-in functions.
    /// </summary>
    public List<string> Conditions { get; set; } = new();
}

/// <summary>
/// Represents a custom rule definition.
/// </summary>
public class CustomRule
{
    /// <summary>
    /// Unique identifier for the rule.
    /// </summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable description of what the rule checks.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// The severity level of violations.
    /// </summary>
    public RuleSeverity Severity { get; set; } = RuleSeverity.Warning;

    /// <summary>
    /// The pattern to match.
    /// </summary>
    public RulePattern Pattern { get; set; } = new();

    /// <summary>
    /// The message to display when a violation is found.
    /// Supports interpolation: {method}, {class}, {file}, {line}, {value}
    /// </summary>
    public string Message { get; set; } = string.Empty;

    /// <summary>
    /// Optional suggested fix or action.
    /// </summary>
    public string? Suggestion { get; set; }

    /// <summary>
    /// Optional URL for more information.
    /// </summary>
    public string? HelpUrl { get; set; }

    /// <summary>
    /// Whether the rule is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Tags for categorizing rules.
    /// </summary>
    public List<string> Tags { get; set; } = new();
}

/// <summary>
/// Represents a collection of rules from a YAML file.
/// </summary>
public class RuleFile
{
    /// <summary>
    /// Version of the rule schema.
    /// </summary>
    public string Version { get; set; } = "1.0";

    /// <summary>
    /// The list of rules defined in the file.
    /// </summary>
    public List<CustomRule> Rules { get; set; } = new();

    /// <summary>
    /// Global settings for all rules in this file.
    /// </summary>
    public RuleFileSettings Settings { get; set; } = new();
}

/// <summary>
/// Global settings for a rule file.
/// </summary>
public class RuleFileSettings
{
    /// <summary>
    /// Whether to continue checking after the first violation.
    /// </summary>
    public bool ContinueOnViolation { get; set; } = true;

    /// <summary>
    /// Files to exclude from rule checking.
    /// </summary>
    public List<string> ExcludeFiles { get; set; } = new();

    /// <summary>
    /// Directories to exclude from rule checking.
    /// </summary>
    public List<string> ExcludeDirectories { get; set; } = new();
}

/// <summary>
/// Represents a violation of a custom rule.
/// </summary>
public class RuleViolation
{
    /// <summary>
    /// The rule that was violated.
    /// </summary>
    public required CustomRule Rule { get; init; }

    /// <summary>
    /// The file where the violation occurred.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// The line number of the violation.
    /// </summary>
    public required int Line { get; init; }

    /// <summary>
    /// The column number of the violation.
    /// </summary>
    public int Column { get; init; }

    /// <summary>
    /// The interpolated message for this specific violation.
    /// </summary>
    public required string Message { get; init; }

    /// <summary>
    /// The code snippet where the violation occurred.
    /// </summary>
    public string? CodeSnippet { get; init; }

    /// <summary>
    /// Additional context about the violation.
    /// </summary>
    public Dictionary<string, string> Context { get; init; } = new();

    /// <summary>
    /// The syntax node that triggered the violation.
    /// </summary>
    public SyntaxNode? Node { get; init; }
}

/// <summary>
/// Represents a compiled rule pattern that can be executed against code.
/// </summary>
public class CompiledRule
{
    /// <summary>
    /// The original rule definition.
    /// </summary>
    public required CustomRule Rule { get; init; }

    /// <summary>
    /// The compiled matcher function.
    /// </summary>
    public required Func<SyntaxNode, SemanticModel?, MatchResult?> Matcher { get; init; }

    /// <summary>
    /// Additional validators to run after the initial match.
    /// </summary>
    public List<Func<SyntaxNode, SemanticModel?, bool>> Validators { get; init; } = new();
}

/// <summary>
/// Result of a pattern match.
/// </summary>
public class MatchResult
{
    /// <summary>
    /// Whether the pattern matched.
    /// </summary>
    public bool IsMatch { get; set; }

    /// <summary>
    /// The matched syntax node.
    /// </summary>
    public SyntaxNode? Node { get; set; }

    /// <summary>
    /// Captured values from the match for message interpolation.
    /// </summary>
    public Dictionary<string, string> Captures { get; set; } = new();
}

/// <summary>
/// Result of rule execution.
/// </summary>
public class RuleExecutionResult
{
    /// <summary>
    /// Whether the execution was successful.
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// All violations found during execution.
    /// </summary>
    public List<RuleViolation> Violations { get; set; } = new();

    /// <summary>
    /// Number of rules that were executed.
    /// </summary>
    public int RulesExecuted { get; set; }

    /// <summary>
    /// Number of files that were analyzed.
    /// </summary>
    public int FilesAnalyzed { get; set; }

    /// <summary>
    /// Time taken to execute the rules.
    /// </summary>
    public TimeSpan ExecutionTime { get; set; }

    /// <summary>
    /// Any errors that occurred during execution.
    /// </summary>
    public List<string> Errors { get; set; } = new();
}
