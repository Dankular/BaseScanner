namespace BaseScanner.Hooks.Models;

/// <summary>
/// Represents the type of Git hook.
/// </summary>
public enum HookType
{
    PreCommit,
    PrePush,
    CommitMsg,
    PrepareCommitMsg,
    PostCommit,
    PostCheckout,
    PostMerge
}

/// <summary>
/// Represents the shell type for hook scripts.
/// </summary>
public enum ShellType
{
    Bash,
    PowerShell,
    Cmd
}

/// <summary>
/// Severity levels for hook failure conditions.
/// </summary>
public enum HookSeverity
{
    Critical,
    High,
    Medium,
    Low,
    Info
}

/// <summary>
/// Analysis types that can be run in hooks.
/// </summary>
[Flags]
public enum HookAnalysisType
{
    None = 0,
    Security = 1,
    Performance = 2,
    Exceptions = 4,
    Resources = 8,
    Dependencies = 16,
    Magic = 32,
    Refactoring = 64,
    Architecture = 128,
    Safety = 256,
    All = Security | Performance | Exceptions | Resources | Dependencies | Magic | Refactoring | Architecture | Safety
}

/// <summary>
/// Configuration for a single hook.
/// </summary>
public class HookConfiguration
{
    /// <summary>
    /// Type of the hook (e.g., pre-commit, pre-push).
    /// </summary>
    public HookType Type { get; set; }

    /// <summary>
    /// Whether this hook is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Analysis types to run.
    /// </summary>
    public HookAnalysisType Analyses { get; set; } = HookAnalysisType.All;

    /// <summary>
    /// Severities that will cause the hook to fail.
    /// </summary>
    public List<HookSeverity> FailOn { get; set; } = [HookSeverity.Critical, HookSeverity.High];

    /// <summary>
    /// Whether to run in incremental mode (only changed files).
    /// </summary>
    public bool Incremental { get; set; } = true;

    /// <summary>
    /// Whether to run in quick mode (faster, less thorough analysis).
    /// </summary>
    public bool Quick { get; set; } = true;

    /// <summary>
    /// Custom arguments to pass to the scanner.
    /// </summary>
    public string? CustomArgs { get; set; }

    /// <summary>
    /// Timeout in seconds for the hook execution.
    /// </summary>
    public int TimeoutSeconds { get; set; } = 120;

    /// <summary>
    /// File patterns to include (glob patterns).
    /// </summary>
    public List<string> IncludePatterns { get; set; } = ["*.cs"];

    /// <summary>
    /// File patterns to exclude (glob patterns).
    /// </summary>
    public List<string> ExcludePatterns { get; set; } = ["*.Designer.cs", "*.Generated.cs", "**/obj/**", "**/bin/**"];
}

/// <summary>
/// Complete hooks configuration for a project.
/// </summary>
public class HooksConfiguration
{
    /// <summary>
    /// Pre-commit hook configuration.
    /// </summary>
    public HookConfiguration? PreCommit { get; set; }

    /// <summary>
    /// Pre-push hook configuration.
    /// </summary>
    public HookConfiguration? PrePush { get; set; }

    /// <summary>
    /// Commit message hook configuration.
    /// </summary>
    public HookConfiguration? CommitMsg { get; set; }

    /// <summary>
    /// Post-commit hook configuration.
    /// </summary>
    public HookConfiguration? PostCommit { get; set; }

    /// <summary>
    /// Gets all enabled hook configurations.
    /// </summary>
    public IEnumerable<HookConfiguration> GetEnabledHooks()
    {
        if (PreCommit?.Enabled == true) yield return PreCommit;
        if (PrePush?.Enabled == true) yield return PrePush;
        if (CommitMsg?.Enabled == true) yield return CommitMsg;
        if (PostCommit?.Enabled == true) yield return PostCommit;
    }

    /// <summary>
    /// Gets a hook configuration by type.
    /// </summary>
    public HookConfiguration? GetHook(HookType type) => type switch
    {
        HookType.PreCommit => PreCommit,
        HookType.PrePush => PrePush,
        HookType.CommitMsg => CommitMsg,
        HookType.PostCommit => PostCommit,
        _ => null
    };
}

/// <summary>
/// Result of a hook installation operation.
/// </summary>
public class HookInstallResult
{
    /// <summary>
    /// Whether the installation was successful.
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Type of hook that was installed.
    /// </summary>
    public HookType HookType { get; set; }

    /// <summary>
    /// Path to the installed hook script.
    /// </summary>
    public string? HookPath { get; set; }

    /// <summary>
    /// Path to the backup of the original hook (if any).
    /// </summary>
    public string? BackupPath { get; set; }

    /// <summary>
    /// Error message if installation failed.
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Shell type of the generated script.
    /// </summary>
    public ShellType ShellType { get; set; }
}

/// <summary>
/// Result of a hook uninstallation operation.
/// </summary>
public class HookUninstallResult
{
    /// <summary>
    /// Whether the uninstallation was successful.
    /// </summary>
    public bool Success { get; set; }

    /// <summary>
    /// Type of hook that was uninstalled.
    /// </summary>
    public HookType HookType { get; set; }

    /// <summary>
    /// Whether a backup was restored.
    /// </summary>
    public bool BackupRestored { get; set; }

    /// <summary>
    /// Error message if uninstallation failed.
    /// </summary>
    public string? ErrorMessage { get; set; }
}

/// <summary>
/// Represents a generated hook script.
/// </summary>
public class GeneratedHookScript
{
    /// <summary>
    /// Type of hook.
    /// </summary>
    public HookType HookType { get; set; }

    /// <summary>
    /// Shell type of the script.
    /// </summary>
    public ShellType ShellType { get; set; }

    /// <summary>
    /// The generated script content.
    /// </summary>
    public required string Content { get; set; }

    /// <summary>
    /// File extension for the script.
    /// </summary>
    public string FileExtension => ShellType switch
    {
        ShellType.PowerShell => ".ps1",
        ShellType.Cmd => ".cmd",
        _ => ""
    };

    /// <summary>
    /// Name of the hook file.
    /// </summary>
    public string FileName => HookType switch
    {
        HookType.PreCommit => "pre-commit",
        HookType.PrePush => "pre-push",
        HookType.CommitMsg => "commit-msg",
        HookType.PrepareCommitMsg => "prepare-commit-msg",
        HookType.PostCommit => "post-commit",
        HookType.PostCheckout => "post-checkout",
        HookType.PostMerge => "post-merge",
        _ => "unknown-hook"
    };
}

/// <summary>
/// Status of hook installation for a repository.
/// </summary>
public class HookStatus
{
    /// <summary>
    /// Path to the Git repository.
    /// </summary>
    public required string RepositoryPath { get; set; }

    /// <summary>
    /// Path to the .git/hooks directory.
    /// </summary>
    public string? HooksDirectory { get; set; }

    /// <summary>
    /// Whether the .git directory exists.
    /// </summary>
    public bool IsGitRepository { get; set; }

    /// <summary>
    /// Status of each hook type.
    /// </summary>
    public Dictionary<HookType, HookTypeStatus> Hooks { get; set; } = [];
}

/// <summary>
/// Status of a specific hook type.
/// </summary>
public class HookTypeStatus
{
    /// <summary>
    /// Whether a hook script exists.
    /// </summary>
    public bool Exists { get; set; }

    /// <summary>
    /// Whether the existing hook was installed by BaseScanner.
    /// </summary>
    public bool IsBaScannerHook { get; set; }

    /// <summary>
    /// Whether a backup exists for this hook.
    /// </summary>
    public bool HasBackup { get; set; }

    /// <summary>
    /// Path to the hook script.
    /// </summary>
    public string? Path { get; set; }

    /// <summary>
    /// Path to the backup file.
    /// </summary>
    public string? BackupPath { get; set; }
}
