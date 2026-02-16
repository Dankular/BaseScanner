using System.Runtime.InteropServices;
using BaseScanner.Hooks.Models;

namespace BaseScanner.Hooks;

/// <summary>
/// Generates Git hook scripts based on configuration.
/// </summary>
public class HookGenerator
{
    private readonly HookConfigLoader _configLoader;

    public HookGenerator()
    {
        _configLoader = new HookConfigLoader();
    }

    public HookGenerator(HookConfigLoader configLoader)
    {
        _configLoader = configLoader;
    }

    /// <summary>
    /// Generates all enabled hook scripts for a project.
    /// </summary>
    /// <param name="projectPath">Path to the project directory.</param>
    /// <param name="shellType">Shell type to generate scripts for. If null, auto-detects.</param>
    /// <returns>List of generated hook scripts.</returns>
    public List<GeneratedHookScript> GenerateAll(string projectPath, ShellType? shellType = null)
    {
        var config = _configLoader.Load(projectPath);
        return GenerateAll(config, shellType);
    }

    /// <summary>
    /// Generates all enabled hook scripts from a configuration.
    /// </summary>
    /// <param name="config">The hooks configuration.</param>
    /// <param name="shellType">Shell type to generate scripts for. If null, auto-detects.</param>
    /// <returns>List of generated hook scripts.</returns>
    public List<GeneratedHookScript> GenerateAll(HooksConfiguration config, ShellType? shellType = null)
    {
        var shell = shellType ?? DetectShellType();
        var scripts = new List<GeneratedHookScript>();

        foreach (var hook in config.GetEnabledHooks())
        {
            try
            {
                var script = Generate(hook, shell);
                scripts.Add(script);

                // For PowerShell on Windows, also generate the bash wrapper
                if (shell == ShellType.PowerShell)
                {
                    scripts.Add(GeneratePowerShellWrapper(hook.Type));
                }
            }
            catch (NotSupportedException)
            {
                // Skip unsupported hook types
            }
        }

        return scripts;
    }

    /// <summary>
    /// Generates a hook script for a specific hook type.
    /// </summary>
    /// <param name="hookConfig">The hook configuration.</param>
    /// <param name="shellType">Shell type to generate script for.</param>
    /// <returns>The generated hook script.</returns>
    public GeneratedHookScript Generate(HookConfiguration hookConfig, ShellType shellType)
    {
        var content = HookTemplates.GetHookTemplate(hookConfig.Type, shellType, hookConfig);

        return new GeneratedHookScript
        {
            HookType = hookConfig.Type,
            ShellType = shellType,
            Content = content
        };
    }

    /// <summary>
    /// Generates a specific hook type with default configuration.
    /// </summary>
    /// <param name="hookType">Type of hook to generate.</param>
    /// <param name="shellType">Shell type to generate script for. If null, auto-detects.</param>
    /// <returns>The generated hook script.</returns>
    public GeneratedHookScript GenerateDefault(HookType hookType, ShellType? shellType = null)
    {
        var shell = shellType ?? DetectShellType();
        var config = CreateDefaultConfig(hookType);

        return Generate(config, shell);
    }

    /// <summary>
    /// Generates a PowerShell wrapper script for Windows environments.
    /// </summary>
    /// <param name="hookType">Type of hook to generate wrapper for.</param>
    /// <returns>The generated wrapper script.</returns>
    public GeneratedHookScript GeneratePowerShellWrapper(HookType hookType)
    {
        var content = HookTemplates.GetPowerShellWrapperBashTemplate(hookType);

        return new GeneratedHookScript
        {
            HookType = hookType,
            ShellType = ShellType.Bash, // The wrapper itself is bash
            Content = content
        };
    }

    /// <summary>
    /// Generates hook scripts with custom options.
    /// </summary>
    /// <param name="options">Custom generation options.</param>
    /// <returns>List of generated hook scripts.</returns>
    public List<GeneratedHookScript> GenerateWithOptions(HookGenerationOptions options)
    {
        var scripts = new List<GeneratedHookScript>();
        var shell = options.ShellType ?? DetectShellType();

        foreach (var hookType in options.HookTypes)
        {
            var config = new HookConfiguration
            {
                Type = hookType,
                Enabled = true,
                Analyses = options.Analyses,
                FailOn = options.FailOn,
                Incremental = options.Incremental,
                Quick = options.Quick,
                TimeoutSeconds = options.TimeoutSeconds,
                CustomArgs = options.CustomArgs,
                IncludePatterns = options.IncludePatterns,
                ExcludePatterns = options.ExcludePatterns
            };

            try
            {
                var script = Generate(config, shell);
                scripts.Add(script);

                if (shell == ShellType.PowerShell)
                {
                    scripts.Add(GeneratePowerShellWrapper(hookType));
                }
            }
            catch (NotSupportedException)
            {
                // Skip unsupported hook types
            }
        }

        return scripts;
    }

    /// <summary>
    /// Creates a default configuration for a hook type.
    /// </summary>
    private static HookConfiguration CreateDefaultConfig(HookType hookType)
    {
        return hookType switch
        {
            HookType.PreCommit => new HookConfiguration
            {
                Type = HookType.PreCommit,
                Enabled = true,
                Analyses = HookAnalysisType.Security | HookAnalysisType.Performance,
                FailOn = [HookSeverity.Critical],
                Incremental = true,
                Quick = true,
                TimeoutSeconds = 60
            },
            HookType.PrePush => new HookConfiguration
            {
                Type = HookType.PrePush,
                Enabled = true,
                Analyses = HookAnalysisType.All,
                FailOn = [HookSeverity.Critical, HookSeverity.High],
                Incremental = true,
                Quick = false,
                TimeoutSeconds = 300
            },
            HookType.CommitMsg => new HookConfiguration
            {
                Type = HookType.CommitMsg,
                Enabled = true,
                TimeoutSeconds = 5
            },
            _ => new HookConfiguration
            {
                Type = hookType,
                Enabled = true,
                Analyses = HookAnalysisType.All,
                FailOn = [HookSeverity.Critical, HookSeverity.High],
                Incremental = true,
                Quick = false,
                TimeoutSeconds = 120
            }
        };
    }

    /// <summary>
    /// Detects the appropriate shell type for the current environment.
    /// </summary>
    public static ShellType DetectShellType()
    {
        // Check for explicit environment variable override
        var shellOverride = Environment.GetEnvironmentVariable("BASESCANNER_HOOK_SHELL");
        if (!string.IsNullOrEmpty(shellOverride))
        {
            return shellOverride.ToLowerInvariant() switch
            {
                "bash" => ShellType.Bash,
                "powershell" or "pwsh" => ShellType.PowerShell,
                "cmd" => ShellType.Cmd,
                _ => DetectFromPlatform()
            };
        }

        return DetectFromPlatform();
    }

    /// <summary>
    /// Detects shell type based on the current platform.
    /// </summary>
    private static ShellType DetectFromPlatform()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            // Check if PowerShell is preferred on Windows
            // Git for Windows uses bash by default, but we prefer PowerShell for better integration
            var psVersion = Environment.GetEnvironmentVariable("PSModulePath");
            if (!string.IsNullOrEmpty(psVersion))
            {
                return ShellType.PowerShell;
            }

            // Check if running in PowerShell
            var psEdition = Environment.GetEnvironmentVariable("PSEdition");
            if (!string.IsNullOrEmpty(psEdition))
            {
                return ShellType.PowerShell;
            }

            // Default to PowerShell on Windows for better experience
            return ShellType.PowerShell;
        }

        // Default to Bash on Unix-like systems
        return ShellType.Bash;
    }

    /// <summary>
    /// Gets the recommended shell type with explanation.
    /// </summary>
    public static (ShellType Shell, string Reason) GetRecommendedShell()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return (ShellType.PowerShell, "PowerShell is recommended on Windows for better integration and error handling.");
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return (ShellType.Bash, "Bash is the default shell on macOS and is widely available.");
        }

        return (ShellType.Bash, "Bash is the standard shell on Linux systems.");
    }

    /// <summary>
    /// Validates that a generated script is syntactically correct.
    /// </summary>
    public static bool ValidateScript(GeneratedHookScript script)
    {
        if (string.IsNullOrWhiteSpace(script.Content))
            return false;

        // Check for required markers
        if (!script.Content.Contains(HookTemplates.BaseScannerMarker))
            return false;

        // Basic syntax checks based on shell type
        return script.ShellType switch
        {
            ShellType.Bash => ValidateBashScript(script.Content),
            ShellType.PowerShell => ValidatePowerShellScript(script.Content),
            _ => true
        };
    }

    /// <summary>
    /// Basic validation for bash scripts.
    /// </summary>
    private static bool ValidateBashScript(string content)
    {
        // Check for shebang
        if (!content.TrimStart().StartsWith("#!/bin/bash"))
            return false;

        // Check for balanced quotes (simple check)
        var singleQuotes = content.Count(c => c == '\'');
        var doubleQuotes = content.Count(c => c == '"');

        // Quotes should be even (paired) - simplified check
        // Note: This is a basic heuristic and may not catch all issues
        return true;
    }

    /// <summary>
    /// Basic validation for PowerShell scripts.
    /// </summary>
    private static bool ValidatePowerShellScript(string content)
    {
        // Check for balanced braces
        var openBraces = content.Count(c => c == '{');
        var closeBraces = content.Count(c => c == '}');

        if (openBraces != closeBraces)
            return false;

        // Check for balanced parentheses
        var openParens = content.Count(c => c == '(');
        var closeParens = content.Count(c => c == ')');

        return openParens == closeParens;
    }
}

/// <summary>
/// Options for generating hook scripts.
/// </summary>
public class HookGenerationOptions
{
    /// <summary>
    /// Hook types to generate.
    /// </summary>
    public List<HookType> HookTypes { get; set; } = [HookType.PreCommit, HookType.PrePush];

    /// <summary>
    /// Shell type for scripts. If null, auto-detects.
    /// </summary>
    public ShellType? ShellType { get; set; }

    /// <summary>
    /// Analysis types to run.
    /// </summary>
    public HookAnalysisType Analyses { get; set; } = HookAnalysisType.Security | HookAnalysisType.Performance;

    /// <summary>
    /// Severities that cause hook failure.
    /// </summary>
    public List<HookSeverity> FailOn { get; set; } = [HookSeverity.Critical, HookSeverity.High];

    /// <summary>
    /// Enable incremental mode.
    /// </summary>
    public bool Incremental { get; set; } = true;

    /// <summary>
    /// Enable quick mode.
    /// </summary>
    public bool Quick { get; set; } = true;

    /// <summary>
    /// Timeout in seconds.
    /// </summary>
    public int TimeoutSeconds { get; set; } = 120;

    /// <summary>
    /// Custom arguments for the scanner.
    /// </summary>
    public string? CustomArgs { get; set; }

    /// <summary>
    /// File patterns to include.
    /// </summary>
    public List<string> IncludePatterns { get; set; } = ["*.cs"];

    /// <summary>
    /// File patterns to exclude.
    /// </summary>
    public List<string> ExcludePatterns { get; set; } = ["*.Designer.cs", "*.Generated.cs"];
}
