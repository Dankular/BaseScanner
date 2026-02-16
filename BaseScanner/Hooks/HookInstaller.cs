using System.Runtime.InteropServices;
using BaseScanner.Hooks.Models;

namespace BaseScanner.Hooks;

/// <summary>
/// Installs and uninstalls Git hooks for a repository.
/// </summary>
public class HookInstaller
{
    private readonly HookGenerator _generator;
    private readonly HookConfigLoader _configLoader;

    /// <summary>
    /// Backup directory name within .git/hooks.
    /// </summary>
    private const string BackupDirectoryName = ".basescanner-backup";

    public HookInstaller()
    {
        _generator = new HookGenerator();
        _configLoader = new HookConfigLoader();
    }

    public HookInstaller(HookGenerator generator, HookConfigLoader configLoader)
    {
        _generator = generator;
        _configLoader = configLoader;
    }

    /// <summary>
    /// Installs all enabled hooks for a repository.
    /// </summary>
    /// <param name="repositoryPath">Path to the Git repository.</param>
    /// <param name="shellType">Shell type for scripts. If null, auto-detects.</param>
    /// <returns>Results of the installation.</returns>
    public List<HookInstallResult> InstallAll(string repositoryPath, ShellType? shellType = null)
    {
        var results = new List<HookInstallResult>();
        var hooksDir = GetHooksDirectory(repositoryPath);

        if (hooksDir == null)
        {
            return
            [
                new HookInstallResult
                {
                    Success = false,
                    ErrorMessage = "Not a Git repository or .git directory not found."
                }
            ];
        }

        var config = _configLoader.Load(repositoryPath);
        var scripts = _generator.GenerateAll(config, shellType);

        foreach (var script in scripts)
        {
            var result = InstallScript(hooksDir, script);
            results.Add(result);
        }

        return results;
    }

    /// <summary>
    /// Installs a specific hook type.
    /// </summary>
    /// <param name="repositoryPath">Path to the Git repository.</param>
    /// <param name="hookType">Type of hook to install.</param>
    /// <param name="shellType">Shell type for the script. If null, auto-detects.</param>
    /// <returns>Result of the installation.</returns>
    public HookInstallResult Install(string repositoryPath, HookType hookType, ShellType? shellType = null)
    {
        var hooksDir = GetHooksDirectory(repositoryPath);

        if (hooksDir == null)
        {
            return new HookInstallResult
            {
                Success = false,
                HookType = hookType,
                ErrorMessage = "Not a Git repository or .git directory not found."
            };
        }

        var script = _generator.GenerateDefault(hookType, shellType);
        return InstallScript(hooksDir, script);
    }

    /// <summary>
    /// Installs a hook from a custom configuration.
    /// </summary>
    /// <param name="repositoryPath">Path to the Git repository.</param>
    /// <param name="hookConfig">Custom hook configuration.</param>
    /// <param name="shellType">Shell type for the script. If null, auto-detects.</param>
    /// <returns>Result of the installation.</returns>
    public HookInstallResult InstallWithConfig(string repositoryPath, HookConfiguration hookConfig, ShellType? shellType = null)
    {
        var hooksDir = GetHooksDirectory(repositoryPath);

        if (hooksDir == null)
        {
            return new HookInstallResult
            {
                Success = false,
                HookType = hookConfig.Type,
                ErrorMessage = "Not a Git repository or .git directory not found."
            };
        }

        var shell = shellType ?? HookGenerator.DetectShellType();
        var script = _generator.Generate(hookConfig, shell);
        var result = InstallScript(hooksDir, script);

        // For PowerShell, also install the wrapper
        if (shell == ShellType.PowerShell)
        {
            var wrapper = _generator.GeneratePowerShellWrapper(hookConfig.Type);
            InstallScript(hooksDir, wrapper);
        }

        return result;
    }

    /// <summary>
    /// Uninstalls a specific hook type.
    /// </summary>
    /// <param name="repositoryPath">Path to the Git repository.</param>
    /// <param name="hookType">Type of hook to uninstall.</param>
    /// <param name="restoreBackup">Whether to restore the original hook from backup.</param>
    /// <returns>Result of the uninstallation.</returns>
    public HookUninstallResult Uninstall(string repositoryPath, HookType hookType, bool restoreBackup = true)
    {
        var hooksDir = GetHooksDirectory(repositoryPath);

        if (hooksDir == null)
        {
            return new HookUninstallResult
            {
                Success = false,
                HookType = hookType,
                ErrorMessage = "Not a Git repository or .git directory not found."
            };
        }

        var hookName = GetHookFileName(hookType);
        var hookPath = Path.Combine(hooksDir, hookName);
        var psHookPath = Path.Combine(hooksDir, $"{hookName}.ps1");

        try
        {
            var backupRestored = false;

            // Check if it's a BaseScanner hook before removing
            if (File.Exists(hookPath))
            {
                var content = File.ReadAllText(hookPath);
                if (content.Contains(HookTemplates.BaseScannerMarker))
                {
                    File.Delete(hookPath);

                    // Also remove PowerShell script if exists
                    if (File.Exists(psHookPath))
                    {
                        File.Delete(psHookPath);
                    }

                    // Restore backup if requested
                    if (restoreBackup)
                    {
                        backupRestored = RestoreBackup(hooksDir, hookType);
                    }
                }
                else
                {
                    return new HookUninstallResult
                    {
                        Success = false,
                        HookType = hookType,
                        ErrorMessage = "Hook was not installed by BaseScanner. Use --force to remove."
                    };
                }
            }

            return new HookUninstallResult
            {
                Success = true,
                HookType = hookType,
                BackupRestored = backupRestored
            };
        }
        catch (Exception ex)
        {
            return new HookUninstallResult
            {
                Success = false,
                HookType = hookType,
                ErrorMessage = ex.Message
            };
        }
    }

    /// <summary>
    /// Uninstalls all BaseScanner hooks from a repository.
    /// </summary>
    /// <param name="repositoryPath">Path to the Git repository.</param>
    /// <param name="restoreBackups">Whether to restore original hooks from backups.</param>
    /// <returns>Results of the uninstallation.</returns>
    public List<HookUninstallResult> UninstallAll(string repositoryPath, bool restoreBackups = true)
    {
        var results = new List<HookUninstallResult>();

        foreach (HookType hookType in Enum.GetValues<HookType>())
        {
            var result = Uninstall(repositoryPath, hookType, restoreBackups);
            if (result.ErrorMessage != "Hook was not installed by BaseScanner. Use --force to remove.")
            {
                results.Add(result);
            }
        }

        return results;
    }

    /// <summary>
    /// Gets the status of hooks for a repository.
    /// </summary>
    /// <param name="repositoryPath">Path to the Git repository.</param>
    /// <returns>Status of all hooks.</returns>
    public HookStatus GetStatus(string repositoryPath)
    {
        var status = new HookStatus
        {
            RepositoryPath = repositoryPath
        };

        var gitDir = FindGitDirectory(repositoryPath);
        if (gitDir == null)
        {
            status.IsGitRepository = false;
            return status;
        }

        status.IsGitRepository = true;
        status.HooksDirectory = Path.Combine(gitDir, "hooks");

        foreach (HookType hookType in Enum.GetValues<HookType>())
        {
            var hookName = GetHookFileName(hookType);
            var hookPath = Path.Combine(status.HooksDirectory, hookName);
            var backupPath = GetBackupPath(status.HooksDirectory, hookType);

            var hookStatus = new HookTypeStatus
            {
                Path = hookPath,
                BackupPath = backupPath,
                Exists = File.Exists(hookPath),
                HasBackup = File.Exists(backupPath)
            };

            if (hookStatus.Exists)
            {
                var content = File.ReadAllText(hookPath);
                hookStatus.IsBaScannerHook = content.Contains(HookTemplates.BaseScannerMarker);
            }

            status.Hooks[hookType] = hookStatus;
        }

        return status;
    }

    /// <summary>
    /// Installs a generated script to the hooks directory.
    /// </summary>
    private HookInstallResult InstallScript(string hooksDir, GeneratedHookScript script)
    {
        var result = new HookInstallResult
        {
            HookType = script.HookType,
            ShellType = script.ShellType
        };

        try
        {
            // Determine the file name
            var fileName = script.ShellType == ShellType.PowerShell
                ? $"{script.FileName}.ps1"
                : script.FileName;

            var hookPath = Path.Combine(hooksDir, fileName);
            result.HookPath = hookPath;

            // Backup existing hook if it exists and wasn't installed by us
            if (File.Exists(hookPath))
            {
                var existingContent = File.ReadAllText(hookPath);
                if (!existingContent.Contains(HookTemplates.BaseScannerMarker))
                {
                    var backupPath = CreateBackup(hooksDir, script.HookType, existingContent);
                    result.BackupPath = backupPath;
                }
            }

            // Ensure hooks directory exists
            Directory.CreateDirectory(hooksDir);

            // Write the hook script
            File.WriteAllText(hookPath, script.Content);

            // Make executable on Unix-like systems
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                MakeExecutable(hookPath);
            }

            result.Success = true;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.ErrorMessage = ex.Message;
        }

        return result;
    }

    /// <summary>
    /// Creates a backup of an existing hook.
    /// </summary>
    private string CreateBackup(string hooksDir, HookType hookType, string content)
    {
        var backupDir = Path.Combine(hooksDir, BackupDirectoryName);
        Directory.CreateDirectory(backupDir);

        var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
        var backupPath = Path.Combine(backupDir, $"{GetHookFileName(hookType)}.{timestamp}.bak");

        File.WriteAllText(backupPath, content);
        return backupPath;
    }

    /// <summary>
    /// Restores a hook from backup.
    /// </summary>
    private bool RestoreBackup(string hooksDir, HookType hookType)
    {
        var backupDir = Path.Combine(hooksDir, BackupDirectoryName);
        if (!Directory.Exists(backupDir))
            return false;

        var hookName = GetHookFileName(hookType);
        var backups = Directory.GetFiles(backupDir, $"{hookName}.*.bak")
            .OrderByDescending(f => f)
            .ToList();

        if (backups.Count == 0)
            return false;

        var latestBackup = backups[0];
        var hookPath = Path.Combine(hooksDir, hookName);

        var content = File.ReadAllText(latestBackup);
        File.WriteAllText(hookPath, content);

        // Make executable on Unix-like systems
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            MakeExecutable(hookPath);
        }

        // Remove the restored backup
        File.Delete(latestBackup);

        return true;
    }

    /// <summary>
    /// Gets the backup path for a hook type.
    /// </summary>
    private static string GetBackupPath(string hooksDir, HookType hookType)
    {
        var backupDir = Path.Combine(hooksDir, BackupDirectoryName);
        var hookName = GetHookFileName(hookType);

        if (Directory.Exists(backupDir))
        {
            var backups = Directory.GetFiles(backupDir, $"{hookName}.*.bak");
            if (backups.Length > 0)
            {
                return backups.OrderByDescending(f => f).First();
            }
        }

        return Path.Combine(backupDir, $"{hookName}.bak");
    }

    /// <summary>
    /// Gets the hooks directory for a repository.
    /// </summary>
    private static string? GetHooksDirectory(string repositoryPath)
    {
        var gitDir = FindGitDirectory(repositoryPath);
        if (gitDir == null)
            return null;

        var hooksDir = Path.Combine(gitDir, "hooks");

        // Create hooks directory if it doesn't exist
        if (!Directory.Exists(hooksDir))
        {
            Directory.CreateDirectory(hooksDir);
        }

        return hooksDir;
    }

    /// <summary>
    /// Finds the .git directory for a repository.
    /// </summary>
    private static string? FindGitDirectory(string path)
    {
        var currentPath = Path.GetFullPath(path);

        while (!string.IsNullOrEmpty(currentPath))
        {
            var gitDir = Path.Combine(currentPath, ".git");

            // Check for regular .git directory
            if (Directory.Exists(gitDir))
            {
                return gitDir;
            }

            // Check for .git file (worktrees/submodules)
            if (File.Exists(gitDir))
            {
                var gitFileContent = File.ReadAllText(gitDir).Trim();
                if (gitFileContent.StartsWith("gitdir:"))
                {
                    var linkedGitDir = gitFileContent.Substring(7).Trim();
                    if (!Path.IsPathRooted(linkedGitDir))
                    {
                        linkedGitDir = Path.Combine(currentPath, linkedGitDir);
                    }
                    return Path.GetFullPath(linkedGitDir);
                }
            }

            var parentPath = Path.GetDirectoryName(currentPath);
            if (parentPath == currentPath)
                break;

            currentPath = parentPath;
        }

        return null;
    }

    /// <summary>
    /// Gets the standard file name for a hook type.
    /// </summary>
    private static string GetHookFileName(HookType hookType)
    {
        return hookType switch
        {
            HookType.PreCommit => "pre-commit",
            HookType.PrePush => "pre-push",
            HookType.CommitMsg => "commit-msg",
            HookType.PrepareCommitMsg => "prepare-commit-msg",
            HookType.PostCommit => "post-commit",
            HookType.PostCheckout => "post-checkout",
            HookType.PostMerge => "post-merge",
            _ => throw new ArgumentOutOfRangeException(nameof(hookType))
        };
    }

    /// <summary>
    /// Makes a file executable on Unix-like systems.
    /// </summary>
    private static void MakeExecutable(string filePath)
    {
        try
        {
            // Use chmod to make the file executable
            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "chmod",
                    Arguments = $"+x \"{filePath}\"",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                }
            };

            process.Start();
            process.WaitForExit();
        }
        catch
        {
            // Ignore errors - chmod may not be available on all systems
        }
    }

    /// <summary>
    /// Lists all available backups for a repository.
    /// </summary>
    /// <param name="repositoryPath">Path to the Git repository.</param>
    /// <returns>Dictionary of hook types to their backup files.</returns>
    public Dictionary<HookType, List<string>> ListBackups(string repositoryPath)
    {
        var result = new Dictionary<HookType, List<string>>();
        var hooksDir = GetHooksDirectory(repositoryPath);

        if (hooksDir == null)
            return result;

        var backupDir = Path.Combine(hooksDir, BackupDirectoryName);
        if (!Directory.Exists(backupDir))
            return result;

        foreach (HookType hookType in Enum.GetValues<HookType>())
        {
            var hookName = GetHookFileName(hookType);
            var backups = Directory.GetFiles(backupDir, $"{hookName}.*.bak")
                .OrderByDescending(f => f)
                .ToList();

            if (backups.Count > 0)
            {
                result[hookType] = backups;
            }
        }

        return result;
    }

    /// <summary>
    /// Cleans up old backups, keeping only the most recent N backups per hook type.
    /// </summary>
    /// <param name="repositoryPath">Path to the Git repository.</param>
    /// <param name="keepCount">Number of backups to keep per hook type.</param>
    /// <returns>Number of backups deleted.</returns>
    public int CleanupBackups(string repositoryPath, int keepCount = 3)
    {
        var deleted = 0;
        var hooksDir = GetHooksDirectory(repositoryPath);

        if (hooksDir == null)
            return 0;

        var backupDir = Path.Combine(hooksDir, BackupDirectoryName);
        if (!Directory.Exists(backupDir))
            return 0;

        foreach (HookType hookType in Enum.GetValues<HookType>())
        {
            var hookName = GetHookFileName(hookType);
            var backups = Directory.GetFiles(backupDir, $"{hookName}.*.bak")
                .OrderByDescending(f => f)
                .Skip(keepCount)
                .ToList();

            foreach (var backup in backups)
            {
                File.Delete(backup);
                deleted++;
            }
        }

        return deleted;
    }

    /// <summary>
    /// Initializes hook configuration for a repository.
    /// Creates the default configuration file and optionally installs hooks.
    /// </summary>
    /// <param name="repositoryPath">Path to the Git repository.</param>
    /// <param name="install">Whether to also install the hooks.</param>
    /// <returns>Path to the created configuration file.</returns>
    public string Initialize(string repositoryPath, bool install = true)
    {
        // Create default configuration
        var config = HookConfigLoader.GetDefaultConfiguration();
        _configLoader.Save(repositoryPath, config);

        var configPath = HookConfigLoader.GetConfigPath(repositoryPath);

        // Install hooks if requested
        if (install)
        {
            InstallAll(repositoryPath);
        }

        return configPath;
    }
}
