using Microsoft.CodeAnalysis;
using BaseScanner.Analyzers.Migration.Models;
using BaseScanner.Analyzers.Migration.Detectors;
using System.Xml.Linq;

namespace BaseScanner.Analyzers.Migration;

/// <summary>
/// Checks compatibility of a project with target .NET frameworks.
/// Analyzes APIs, packages, and project configuration for migration readiness.
/// </summary>
public class CompatibilityChecker
{
    private readonly ApiMappingDatabase _mappingDatabase;
    private readonly DeprecatedApiDetector _deprecatedApiDetector;
    private readonly PlatformSpecificDetector _platformDetector;

    // Known package mappings for .NET Core/.NET 5+
    private static readonly Dictionary<string, PackageMigrationInfo> PackageMappings = new(StringComparer.OrdinalIgnoreCase)
    {
        // Entity Framework
        ["EntityFramework"] = new("Microsoft.EntityFrameworkCore", "8.0.0", false, "EF Core has different API surface. Review migrations and DbContext configuration."),
        ["EntityFramework6"] = new("Microsoft.EntityFrameworkCore", "8.0.0", false, "Migrate from EF6 to EF Core. Use ef6 scaffolding tools if needed."),

        // ASP.NET
        ["Microsoft.AspNet.Mvc"] = new("Microsoft.AspNetCore.Mvc", "8.0.0", false, "ASP.NET MVC to ASP.NET Core requires significant changes."),
        ["Microsoft.AspNet.WebApi"] = new("Microsoft.AspNetCore.Mvc", "8.0.0", false, "Web API is merged into ASP.NET Core MVC."),
        ["Microsoft.AspNet.WebApi.Core"] = new("Microsoft.AspNetCore.Mvc.Core", "8.0.0", false, "Web API Core is merged into ASP.NET Core MVC."),
        ["Microsoft.AspNet.WebPages"] = new("Microsoft.AspNetCore.Mvc.Razor", "8.0.0", false, "Web Pages replaced by Razor Pages in ASP.NET Core."),
        ["Microsoft.AspNet.SignalR"] = new("Microsoft.AspNetCore.SignalR", "8.0.0", false, "SignalR has been rewritten for ASP.NET Core."),
        ["Microsoft.Owin"] = new(null, null, false, "OWIN is replaced by ASP.NET Core middleware."),
        ["Owin"] = new(null, null, false, "OWIN is replaced by ASP.NET Core middleware."),

        // Configuration
        ["System.Configuration.ConfigurationManager"] = new("Microsoft.Extensions.Configuration", "8.0.0", true, "Consider migrating to appsettings.json with IConfiguration."),

        // Logging
        ["log4net"] = new("Microsoft.Extensions.Logging", "8.0.0", true, "Consider migrating to Microsoft.Extensions.Logging with log4net provider."),
        ["NLog"] = new("NLog.Extensions.Logging", "5.3.0", true, "NLog works with .NET Core. Update to NLog.Extensions.Logging."),
        ["Serilog"] = new("Serilog.AspNetCore", "8.0.0", true, "Serilog works with .NET Core. Use Serilog.AspNetCore for ASP.NET Core."),

        // JSON
        ["Newtonsoft.Json"] = new("System.Text.Json", null, true, "Consider migrating to System.Text.Json for better performance, or continue using Newtonsoft.Json."),

        // HTTP
        ["Microsoft.Net.Http"] = new("System.Net.Http", null, true, "System.Net.Http is included in .NET Core."),
        ["System.Net.Http"] = new("System.Net.Http", null, true, "Already compatible."),

        // AutoMapper
        ["AutoMapper"] = new("AutoMapper", "12.0.0", true, "Update to latest version. Some API changes in v12+."),

        // Dependency Injection
        ["Unity"] = new("Microsoft.Extensions.DependencyInjection", "8.0.0", true, "Consider migrating to built-in DI. Unity also has .NET Core support."),
        ["Autofac"] = new("Autofac.Extensions.DependencyInjection", "8.0.0", true, "Autofac supports .NET Core. Use Autofac.Extensions.DependencyInjection."),
        ["Ninject"] = new("Microsoft.Extensions.DependencyInjection", "8.0.0", true, "Ninject has limited .NET Core support. Consider migrating to built-in DI."),
        ["StructureMap"] = new("Lamar", "12.0.0", true, "StructureMap is replaced by Lamar for .NET Core."),
        ["SimpleInjector"] = new("SimpleInjector", "5.4.0", true, "SimpleInjector supports .NET Core."),

        // Testing
        ["MSTest.TestFramework"] = new("MSTest.TestFramework", "3.1.0", true, "Update to latest version."),
        ["NUnit"] = new("NUnit", "4.0.0", true, "NUnit supports .NET Core."),
        ["xunit"] = new("xunit", "2.6.0", true, "xUnit supports .NET Core."),
        ["Moq"] = new("Moq", "4.20.0", true, "Moq supports .NET Core."),
        ["FluentAssertions"] = new("FluentAssertions", "6.12.0", true, "FluentAssertions supports .NET Core."),

        // ORM
        ["Dapper"] = new("Dapper", "2.1.0", true, "Dapper supports .NET Core."),
        ["NHibernate"] = new("NHibernate", "5.4.0", true, "NHibernate supports .NET Core 3.1+."),

        // Validation
        ["FluentValidation"] = new("FluentValidation", "11.8.0", true, "FluentValidation supports .NET Core."),

        // Caching
        ["System.Runtime.Caching"] = new("Microsoft.Extensions.Caching.Memory", "8.0.0", true, "Use IMemoryCache from Microsoft.Extensions.Caching.Memory."),
        ["StackExchange.Redis"] = new("StackExchange.Redis", "2.7.0", true, "StackExchange.Redis supports .NET Core."),

        // Messaging
        ["RabbitMQ.Client"] = new("RabbitMQ.Client", "6.8.0", true, "RabbitMQ.Client supports .NET Core."),
        ["MassTransit"] = new("MassTransit", "8.1.0", true, "MassTransit supports .NET Core."),

        // Obsolete/Unsupported
        ["System.Web"] = new(null, null, false, "System.Web is not available in .NET Core. Migrate to ASP.NET Core."),
        ["System.Web.Mvc"] = new("Microsoft.AspNetCore.Mvc", "8.0.0", false, "Migrate to ASP.NET Core MVC."),
        ["System.Web.Http"] = new("Microsoft.AspNetCore.Mvc", "8.0.0", false, "Migrate to ASP.NET Core."),

        // WCF
        ["System.ServiceModel"] = new("CoreWCF.Primitives", "1.5.0", false, "WCF client supported via System.ServiceModel.* packages. Server requires CoreWCF or migration to gRPC."),
    };

    // APIs not available in .NET Core
    private static readonly Dictionary<string, UnavailableApiInfo> UnavailableApis = new(StringComparer.OrdinalIgnoreCase)
    {
        ["System.Web.HttpContext.Current"] = new("Static HttpContext.Current is not available", "Inject IHttpContextAccessor"),
        ["System.Web.HttpRuntime"] = new("HttpRuntime is not available in .NET Core", "Use IWebHostEnvironment for path information"),
        ["System.Web.HttpServerUtility"] = new("Server utility methods moved to different classes", "Use WebUtility, HtmlEncoder, etc."),
        ["System.Web.Security.FormsAuthentication"] = new("Forms authentication replaced by cookie authentication", "Use AddAuthentication().AddCookie()"),
        ["System.Web.Caching.Cache"] = new("Cache is not available", "Use IMemoryCache or IDistributedCache"),
        ["System.Runtime.Remoting"] = new(".NET Remoting is not supported in .NET Core", "Use gRPC, Web API, or named pipes"),
        ["System.AppDomain.CreateDomain"] = new("Multiple AppDomains not supported", "Use AssemblyLoadContext for isolation"),
        ["System.Threading.Thread.Abort"] = new("Thread.Abort throws PlatformNotSupportedException", "Use CancellationToken for cancellation"),
        ["System.Runtime.Serialization.Formatters.Binary.BinaryFormatter"] = new("BinaryFormatter is disabled by default (security risk)", "Use System.Text.Json or other serializers"),
        ["System.Data.Entity"] = new("Entity Framework 6 not in .NET Core", "Migrate to Entity Framework Core"),
        ["System.Data.Linq"] = new("LINQ to SQL not in .NET Core", "Migrate to Entity Framework Core"),
        ["System.EnterpriseServices"] = new("COM+ not available in .NET Core", "Use modern alternatives for transactions and services"),
    };

    public CompatibilityChecker(ApiMappingDatabase? mappingDatabase = null)
    {
        _mappingDatabase = mappingDatabase ?? new ApiMappingDatabase();
        _deprecatedApiDetector = new DeprecatedApiDetector(_mappingDatabase);
        _platformDetector = new PlatformSpecificDetector();
    }

    /// <summary>
    /// Checks compatibility of a project with a target framework.
    /// </summary>
    public async Task<CompatibilityResult> CheckCompatibilityAsync(
        Project project,
        string targetFramework = "net8.0")
    {
        var result = new CompatibilityResult
        {
            TargetFramework = targetFramework,
            Level = CompatibilityLevel.Compatible
        };

        var unavailableApis = new List<UnavailableApi>();
        var packageIssues = new List<PackageCompatibility>();
        var requiredChanges = new List<ProjectChange>();

        // Check deprecated APIs
        var deprecatedUsages = await _deprecatedApiDetector.DetectInProjectAsync(project);
        var blockingApis = _deprecatedApiDetector.GetBlockingIssues(deprecatedUsages);

        // Group by API and create unavailable API entries
        var groupedByApi = DeprecatedApiDetector.GroupByApi(deprecatedUsages);
        foreach (var (api, usages) in groupedByApi)
        {
            if (usages.Any(u => u.Mapping?.IsBlockingIssue == true) ||
                UnavailableApis.ContainsKey(api))
            {
                var info = UnavailableApis.GetValueOrDefault(api);
                var mapping = usages.First().Mapping;

                unavailableApis.Add(new UnavailableApi
                {
                    Api = api,
                    Reason = info?.Reason ?? mapping?.Reason ?? "API not available in target framework",
                    Alternative = info?.Alternative ?? mapping?.NewApi,
                    UsageCount = usages.Count,
                    Files = usages.Select(u => u.FilePath).Distinct().ToList()
                });
            }
        }

        // Check platform-specific code
        var platformIssues = await _platformDetector.DetectInProjectAsync(project);
        var blockingPlatformIssues = PlatformSpecificDetector.GetBlockingIssues(platformIssues);

        // Check project file for packages and properties
        var projectFilePath = project.FilePath;
        if (!string.IsNullOrEmpty(projectFilePath) && File.Exists(projectFilePath))
        {
            var (packages, properties) = await AnalyzeProjectFileAsync(projectFilePath);

            // Check package compatibility
            foreach (var (packageName, version) in packages)
            {
                var packageCompatibility = CheckPackageCompatibility(packageName, version, targetFramework);
                if (packageCompatibility != null)
                {
                    packageIssues.Add(packageCompatibility);
                }
            }

            // Check for required project property changes
            requiredChanges.AddRange(GetRequiredProjectChanges(properties, targetFramework));
        }

        // Determine overall compatibility level
        var hasBlockingApis = blockingApis.Any() || blockingPlatformIssues.Any();
        var hasPackageIssues = packageIssues.Any(p => !p.IsCompatible);
        var hasWarnings = deprecatedUsages.Any() || platformIssues.Any() || packageIssues.Any();

        result = result with
        {
            Level = hasBlockingApis ? CompatibilityLevel.NotCompatible
                  : hasPackageIssues ? CompatibilityLevel.PartiallyCompatible
                  : hasWarnings ? CompatibilityLevel.PartiallyCompatible
                  : CompatibilityLevel.Compatible,
            UnavailableApis = unavailableApis,
            PackageIssues = packageIssues,
            RequiredChanges = requiredChanges,
            Summary = new CompatibilitySummary
            {
                TotalIssues = unavailableApis.Count + packageIssues.Count + requiredChanges.Count,
                BlockingIssues = blockingApis.Count + blockingPlatformIssues.Count,
                UnavailableApiCount = unavailableApis.Count,
                PackageIssueCount = packageIssues.Count,
                ProjectChangeCount = requiredChanges.Count,
                CompatibilityScore = CalculateCompatibilityScore(unavailableApis, packageIssues, blockingPlatformIssues)
            }
        };

        return result;
    }

    /// <summary>
    /// Checks if a specific API is available in the target framework.
    /// </summary>
    public (bool IsAvailable, string? Reason, string? Alternative) CheckApiAvailability(
        string api,
        string targetFramework = "net8.0")
    {
        // Check known unavailable APIs
        if (UnavailableApis.TryGetValue(api, out var info))
        {
            return (false, info.Reason, info.Alternative);
        }

        // Check mapping database for blocking issues
        if (_mappingDatabase.TryGetMapping(api, out var mapping) && mapping?.IsBlockingIssue == true)
        {
            return (false, mapping.Reason, mapping.NewApi);
        }

        return (true, null, null);
    }

    /// <summary>
    /// Gets recommended package version for target framework.
    /// </summary>
    public PackageCompatibility? CheckPackageCompatibility(
        string packageName,
        string currentVersion,
        string targetFramework = "net8.0")
    {
        if (PackageMappings.TryGetValue(packageName, out var info))
        {
            return new PackageCompatibility
            {
                PackageName = packageName,
                CurrentVersion = currentVersion,
                IsCompatible = info.IsCompatible,
                MinimumCompatibleVersion = info.NewVersion,
                ReplacementPackage = info.NewPackage != packageName ? info.NewPackage : null,
                Notes = info.Notes
            };
        }

        // For unknown packages, assume compatible but may need version update
        return null;
    }

    private async Task<(List<(string Name, string Version)> Packages, Dictionary<string, string> Properties)> AnalyzeProjectFileAsync(string projectFilePath)
    {
        var packages = new List<(string Name, string Version)>();
        var properties = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var content = await File.ReadAllTextAsync(projectFilePath);
            var doc = XDocument.Parse(content);
            var ns = doc.Root?.Name.Namespace ?? XNamespace.None;

            // Extract packages
            var packageRefs = doc.Descendants().Where(e =>
                e.Name.LocalName == "PackageReference" ||
                e.Name.LocalName == "Reference");

            foreach (var pkgRef in packageRefs)
            {
                var name = pkgRef.Attribute("Include")?.Value;
                var version = pkgRef.Attribute("Version")?.Value ??
                              pkgRef.Elements().FirstOrDefault(e => e.Name.LocalName == "Version")?.Value ??
                              "";

                if (!string.IsNullOrEmpty(name))
                {
                    packages.Add((name, version));
                }
            }

            // Extract properties
            var propertyGroups = doc.Descendants().Where(e => e.Name.LocalName == "PropertyGroup");
            foreach (var pg in propertyGroups)
            {
                foreach (var prop in pg.Elements())
                {
                    properties[prop.Name.LocalName] = prop.Value;
                }
            }
        }
        catch
        {
            // Project file parsing failed, return empty results
        }

        return (packages, properties);
    }

    private List<ProjectChange> GetRequiredProjectChanges(
        Dictionary<string, string> currentProperties,
        string targetFramework)
    {
        var changes = new List<ProjectChange>();

        // Check TargetFramework
        if (currentProperties.TryGetValue("TargetFramework", out var tf) ||
            currentProperties.TryGetValue("TargetFrameworkVersion", out tf))
        {
            if (!tf.StartsWith("net") || tf.StartsWith("net4"))
            {
                changes.Add(new ProjectChange
                {
                    ChangeType = "UpdateProperty",
                    Target = "TargetFramework",
                    CurrentValue = tf,
                    NewValue = targetFramework,
                    Reason = "Update to modern .NET target framework",
                    IsRequired = true
                });
            }
        }
        else
        {
            changes.Add(new ProjectChange
            {
                ChangeType = "AddProperty",
                Target = "TargetFramework",
                NewValue = targetFramework,
                Reason = "Specify target framework",
                IsRequired = true
            });
        }

        // Check for SDK-style project
        if (currentProperties.TryGetValue("ProjectGuid", out _))
        {
            changes.Add(new ProjectChange
            {
                ChangeType = "ConvertProject",
                Target = "ProjectFormat",
                CurrentValue = "Legacy (non-SDK)",
                NewValue = "SDK-style",
                Reason = "Convert to SDK-style project format for .NET Core/5+ support",
                IsRequired = true
            });
        }

        // Check for web project properties
        if (currentProperties.TryGetValue("ProjectTypeGuids", out var guids) &&
            guids.Contains("349c5851-65df-11da-9384-00065b846f21", StringComparison.OrdinalIgnoreCase)) // ASP.NET
        {
            changes.Add(new ProjectChange
            {
                ChangeType = "RemoveProperty",
                Target = "ProjectTypeGuids",
                CurrentValue = guids,
                Reason = "Project type GUIDs are not used in SDK-style projects",
                IsRequired = true
            });
        }

        // Recommend enabling nullable reference types
        if (!currentProperties.ContainsKey("Nullable"))
        {
            changes.Add(new ProjectChange
            {
                ChangeType = "AddProperty",
                Target = "Nullable",
                NewValue = "enable",
                Reason = "Enable nullable reference types for better null safety",
                IsRequired = false
            });
        }

        // Recommend enabling implicit usings
        if (!currentProperties.ContainsKey("ImplicitUsings"))
        {
            changes.Add(new ProjectChange
            {
                ChangeType = "AddProperty",
                Target = "ImplicitUsings",
                NewValue = "enable",
                Reason = "Enable implicit usings to reduce boilerplate",
                IsRequired = false
            });
        }

        return changes;
    }

    private double CalculateCompatibilityScore(
        List<UnavailableApi> unavailableApis,
        List<PackageCompatibility> packageIssues,
        List<PlatformSpecificCode> blockingPlatformIssues)
    {
        // Start with perfect score
        double score = 1.0;

        // Deduct for unavailable APIs (more usage = more deduction)
        foreach (var api in unavailableApis)
        {
            score -= Math.Min(0.1, api.UsageCount * 0.01);
        }

        // Deduct for incompatible packages
        var incompatiblePackages = packageIssues.Count(p => !p.IsCompatible);
        score -= incompatiblePackages * 0.05;

        // Deduct for blocking platform issues
        score -= blockingPlatformIssues.Count * 0.1;

        return Math.Max(0, Math.Min(1, score));
    }

    /// <summary>
    /// Gets a human-readable compatibility summary.
    /// </summary>
    public string GetCompatibilitySummary(CompatibilityResult result)
    {
        var summary = new System.Text.StringBuilder();

        summary.AppendLine($"Compatibility Check for {result.TargetFramework}");
        summary.AppendLine(new string('=', 50));
        summary.AppendLine();

        summary.AppendLine($"Overall Compatibility: {result.Level}");
        summary.AppendLine($"Compatibility Score: {result.Summary.CompatibilityScore:P0}");
        summary.AppendLine();

        if (result.Summary.BlockingIssues > 0)
        {
            summary.AppendLine($"BLOCKING ISSUES: {result.Summary.BlockingIssues}");
            summary.AppendLine("These must be resolved before migration:");
            foreach (var api in result.UnavailableApis.Take(5))
            {
                summary.AppendLine($"  - {api.Api}: {api.Reason}");
                if (!string.IsNullOrEmpty(api.Alternative))
                {
                    summary.AppendLine($"    Alternative: {api.Alternative}");
                }
            }
            summary.AppendLine();
        }

        if (result.PackageIssues.Any(p => !p.IsCompatible))
        {
            summary.AppendLine("Package Migration Required:");
            foreach (var pkg in result.PackageIssues.Where(p => !p.IsCompatible).Take(5))
            {
                summary.AppendLine($"  - {pkg.PackageName} ({pkg.CurrentVersion})");
                if (!string.IsNullOrEmpty(pkg.ReplacementPackage))
                {
                    summary.AppendLine($"    Replace with: {pkg.ReplacementPackage} {pkg.MinimumCompatibleVersion}");
                }
                if (!string.IsNullOrEmpty(pkg.Notes))
                {
                    summary.AppendLine($"    Note: {pkg.Notes}");
                }
            }
            summary.AppendLine();
        }

        if (result.RequiredChanges.Any(c => c.IsRequired))
        {
            summary.AppendLine("Required Project Changes:");
            foreach (var change in result.RequiredChanges.Where(c => c.IsRequired))
            {
                summary.AppendLine($"  - {change.ChangeType}: {change.Target}");
                summary.AppendLine($"    {change.Reason}");
            }
            summary.AppendLine();
        }

        return summary.ToString();
    }
}

/// <summary>
/// Package migration information.
/// </summary>
internal record PackageMigrationInfo(
    string? NewPackage,
    string? NewVersion,
    bool IsCompatible,
    string Notes);

/// <summary>
/// Information about unavailable API.
/// </summary>
internal record UnavailableApiInfo(
    string Reason,
    string Alternative);
