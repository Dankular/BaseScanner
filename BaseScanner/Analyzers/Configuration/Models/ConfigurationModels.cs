namespace BaseScanner.Analyzers.Configuration.Models;

/// <summary>
/// Types of configuration issues detected.
/// </summary>
public enum ConfigurationIssueType
{
    /// <summary>Connection strings hardcoded in source code.</summary>
    HardcodedConnection,

    /// <summary>URLs and endpoints hardcoded in source code.</summary>
    HardcodedUrl,

    /// <summary>File paths hardcoded in source code (C:\, /usr/, etc.).</summary>
    HardcodedPath,

    /// <summary>Usernames, passwords, or other credentials in source code.</summary>
    HardcodedCredential,

    /// <summary>Environment-specific branching (if env == "Production").</summary>
    EnvironmentBranch,

    /// <summary>Configuration key used in code but not defined in config files.</summary>
    MissingConfig,

    /// <summary>Configuration key defined in config files but never read in code.</summary>
    UnusedConfig
}

/// <summary>
/// Severity levels for configuration issues.
/// </summary>
public enum ConfigurationSeverity
{
    /// <summary>Critical security or deployment risk.</summary>
    Critical,

    /// <summary>High-priority issue affecting maintainability.</summary>
    High,

    /// <summary>Moderate issue that should be addressed.</summary>
    Medium,

    /// <summary>Minor issue or potential improvement.</summary>
    Low,

    /// <summary>Informational finding.</summary>
    Info
}

/// <summary>
/// Represents a detected configuration issue.
/// </summary>
public record ConfigurationIssue
{
    /// <summary>
    /// Type of configuration issue detected.
    /// </summary>
    public required ConfigurationIssueType IssueType { get; init; }

    /// <summary>
    /// Severity of the issue.
    /// </summary>
    public required ConfigurationSeverity Severity { get; init; }

    /// <summary>
    /// Path to the file containing the issue.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Starting line number (1-based).
    /// </summary>
    public required int StartLine { get; init; }

    /// <summary>
    /// Ending line number (1-based).
    /// </summary>
    public required int EndLine { get; init; }

    /// <summary>
    /// The problematic code or configuration snippet.
    /// </summary>
    public required string CodeSnippet { get; init; }

    /// <summary>
    /// Human-readable description of the issue.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Recommendation for fixing the issue.
    /// </summary>
    public required string Recommendation { get; init; }

    /// <summary>
    /// The hardcoded value detected (if applicable).
    /// </summary>
    public string? DetectedValue { get; init; }

    /// <summary>
    /// Configuration key name (if applicable).
    /// </summary>
    public string? ConfigKey { get; init; }

    /// <summary>
    /// Suggested secure code replacement.
    /// </summary>
    public string? SuggestedFix { get; init; }

    /// <summary>
    /// Confidence level of the detection: High, Medium, Low.
    /// </summary>
    public string Confidence { get; init; } = "Medium";
}

/// <summary>
/// Represents a configuration access pattern in code.
/// </summary>
public record ConfigurationAccess
{
    /// <summary>
    /// Configuration key being accessed.
    /// </summary>
    public required string Key { get; init; }

    /// <summary>
    /// Type of configuration access pattern.
    /// </summary>
    public required ConfigurationAccessType AccessType { get; init; }

    /// <summary>
    /// File where the access occurs.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Line number of the access.
    /// </summary>
    public required int Line { get; init; }

    /// <summary>
    /// Method containing the access.
    /// </summary>
    public string? ContainingMethod { get; init; }

    /// <summary>
    /// Type containing the access.
    /// </summary>
    public string? ContainingType { get; init; }

    /// <summary>
    /// Whether a default value is provided.
    /// </summary>
    public bool HasDefaultValue { get; init; }

    /// <summary>
    /// The default value if provided.
    /// </summary>
    public string? DefaultValue { get; init; }

    /// <summary>
    /// Expected type of the configuration value.
    /// </summary>
    public string? ExpectedType { get; init; }
}

/// <summary>
/// Types of configuration access patterns.
/// </summary>
public enum ConfigurationAccessType
{
    /// <summary>IConfiguration indexer access (config["key"]).</summary>
    IConfigurationIndexer,

    /// <summary>IConfiguration.GetValue method.</summary>
    IConfigurationGetValue,

    /// <summary>IConfiguration.GetSection method.</summary>
    IConfigurationGetSection,

    /// <summary>IConfiguration.GetConnectionString method.</summary>
    IConfigurationGetConnectionString,

    /// <summary>ConfigurationManager.AppSettings.</summary>
    ConfigurationManagerAppSettings,

    /// <summary>ConfigurationManager.ConnectionStrings.</summary>
    ConfigurationManagerConnectionStrings,

    /// <summary>Environment.GetEnvironmentVariable.</summary>
    EnvironmentVariable,

    /// <summary>Options pattern (IOptions&lt;T&gt;).</summary>
    OptionsPattern,

    /// <summary>Unknown or unrecognized pattern.</summary>
    Unknown
}

/// <summary>
/// Represents a configuration definition in a config file.
/// </summary>
public record ConfigurationDefinition
{
    /// <summary>
    /// Configuration key path (e.g., "ConnectionStrings:DefaultConnection").
    /// </summary>
    public required string Key { get; init; }

    /// <summary>
    /// Value of the configuration (may be redacted for secrets).
    /// </summary>
    public string? Value { get; init; }

    /// <summary>
    /// Source file of the configuration.
    /// </summary>
    public required string SourceFile { get; init; }

    /// <summary>
    /// Line number in the source file.
    /// </summary>
    public int Line { get; init; }

    /// <summary>
    /// Whether this appears to be a sensitive value.
    /// </summary>
    public bool IsSensitive { get; init; }

    /// <summary>
    /// Whether the value is a placeholder (e.g., "${ENV_VAR}").
    /// </summary>
    public bool IsPlaceholder { get; init; }
}

/// <summary>
/// Detected environment-specific code pattern.
/// </summary>
public record EnvironmentCodePattern
{
    /// <summary>
    /// The environment name detected (e.g., "Production", "Development").
    /// </summary>
    public required string EnvironmentName { get; init; }

    /// <summary>
    /// Type of pattern detected.
    /// </summary>
    public required EnvironmentPatternType PatternType { get; init; }

    /// <summary>
    /// File containing the pattern.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Line number of the pattern.
    /// </summary>
    public required int Line { get; init; }

    /// <summary>
    /// The code containing the environment check.
    /// </summary>
    public required string CodeSnippet { get; init; }

    /// <summary>
    /// Description of the issue.
    /// </summary>
    public required string Description { get; init; }
}

/// <summary>
/// Types of environment-specific code patterns.
/// </summary>
public enum EnvironmentPatternType
{
    /// <summary>String comparison with environment name.</summary>
    StringComparison,

    /// <summary>IHostEnvironment.IsProduction() or similar.</summary>
    HostEnvironmentCheck,

    /// <summary>Preprocessor directive (#if DEBUG).</summary>
    PreprocessorDirective,

    /// <summary>Environment variable check.</summary>
    EnvironmentVariableCheck,

    /// <summary>Configuration-based environment check.</summary>
    ConfigurationCheck
}

/// <summary>
/// Summary of configuration analysis results.
/// </summary>
public record ConfigurationSummary
{
    /// <summary>
    /// Total number of issues detected.
    /// </summary>
    public int TotalIssues { get; init; }

    /// <summary>
    /// Number of critical issues.
    /// </summary>
    public int CriticalCount { get; init; }

    /// <summary>
    /// Number of high-severity issues.
    /// </summary>
    public int HighCount { get; init; }

    /// <summary>
    /// Number of medium-severity issues.
    /// </summary>
    public int MediumCount { get; init; }

    /// <summary>
    /// Number of low-severity issues.
    /// </summary>
    public int LowCount { get; init; }

    /// <summary>
    /// Issues grouped by type.
    /// </summary>
    public Dictionary<ConfigurationIssueType, int> IssuesByType { get; init; } = [];

    /// <summary>
    /// Total configuration keys accessed in code.
    /// </summary>
    public int TotalConfigAccesses { get; init; }

    /// <summary>
    /// Configuration keys that are defined but unused.
    /// </summary>
    public List<string> UnusedConfigKeys { get; init; } = [];

    /// <summary>
    /// Configuration keys that are used but not defined.
    /// </summary>
    public List<string> MissingConfigKeys { get; init; } = [];

    /// <summary>
    /// Environment-specific code patterns found.
    /// </summary>
    public int EnvironmentPatternCount { get; init; }
}

/// <summary>
/// Complete result of configuration analysis.
/// </summary>
public record ConfigurationResult
{
    /// <summary>
    /// All detected configuration issues.
    /// </summary>
    public List<ConfigurationIssue> Issues { get; init; } = [];

    /// <summary>
    /// All configuration access patterns found in code.
    /// </summary>
    public List<ConfigurationAccess> ConfigAccesses { get; init; } = [];

    /// <summary>
    /// All configuration definitions found in config files.
    /// </summary>
    public List<ConfigurationDefinition> ConfigDefinitions { get; init; } = [];

    /// <summary>
    /// Environment-specific code patterns detected.
    /// </summary>
    public List<EnvironmentCodePattern> EnvironmentPatterns { get; init; } = [];

    /// <summary>
    /// Summary of the analysis results.
    /// </summary>
    public ConfigurationSummary Summary { get; init; } = new();
}
