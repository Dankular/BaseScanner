using System.Xml.Linq;
using BaseScanner.Analyzers.Dependencies.Models;

namespace BaseScanner.Analyzers.Dependencies;

/// <summary>
/// Analyzes package references from .csproj files and packages.config.
/// Supports both SDK-style and legacy project formats.
/// </summary>
public class PackageAnalyzer
{
    private readonly TransitiveDependencyResolver _transitiveResolver;

    public PackageAnalyzer()
    {
        _transitiveResolver = new TransitiveDependencyResolver();
    }

    /// <summary>
    /// Analyzes all projects in a solution/directory for package references.
    /// </summary>
    /// <param name="solutionOrProjectPath">Path to solution, project, or directory</param>
    /// <returns>All package references with their metadata</returns>
    public async Task<PackageAnalysisResult> AnalyzePackagesAsync(string solutionOrProjectPath)
    {
        var projectPaths = FindProjectFiles(solutionOrProjectPath);
        var allPackages = new Dictionary<string, PackageReference>(StringComparer.OrdinalIgnoreCase);
        var transitiveTree = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var projectPackages = new Dictionary<string, List<PackageReference>>();

        foreach (var projectPath in projectPaths)
        {
            try
            {
                var packages = await ParseProjectPackagesAsync(projectPath);
                projectPackages[projectPath] = packages;

                // Add to global package list
                foreach (var package in packages)
                {
                    var key = $"{package.PackageId}@{package.Version}";
                    if (!allPackages.ContainsKey(key))
                    {
                        allPackages[key] = package;
                    }
                }

                // Resolve transitive dependencies
                var transitive = await _transitiveResolver.ResolveTransitiveDependenciesAsync(projectPath, packages);
                foreach (var (packageId, deps) in transitive)
                {
                    if (!transitiveTree.ContainsKey(packageId))
                    {
                        transitiveTree[packageId] = deps;
                    }
                    else
                    {
                        // Merge dependencies
                        foreach (var dep in deps)
                        {
                            if (!transitiveTree[packageId].Contains(dep, StringComparer.OrdinalIgnoreCase))
                            {
                                transitiveTree[packageId].Add(dep);
                            }
                        }
                    }
                }
            }
            catch
            {
                // Continue with other projects if one fails
            }
        }

        // Get all packages including transitive
        var packageVersions = _transitiveResolver.GetPackageVersions();

        // Add versions from direct packages
        foreach (var package in allPackages.Values)
        {
            if (!packageVersions.ContainsKey(package.PackageId))
            {
                packageVersions[package.PackageId] = package.Version;
            }
        }

        var directPackages = allPackages.Values.ToList();
        var allPackagesIncludingTransitive = _transitiveResolver.GetAllPackages(
            directPackages,
            transitiveTree,
            packageVersions);

        return new PackageAnalysisResult
        {
            DirectPackages = directPackages,
            AllPackages = allPackagesIncludingTransitive,
            TransitiveDependencyTree = transitiveTree,
            ProjectPackages = projectPackages,
            PackageVersions = packageVersions
        };
    }

    /// <summary>
    /// Parses package references from a single project file.
    /// </summary>
    public async Task<List<PackageReference>> ParseProjectPackagesAsync(string projectPath)
    {
        var packages = new List<PackageReference>();

        if (!File.Exists(projectPath))
            return packages;

        var extension = Path.GetExtension(projectPath).ToLowerInvariant();

        if (extension == ".csproj" || extension == ".vbproj" || extension == ".fsproj")
        {
            packages.AddRange(await ParseSdkStyleProjectAsync(projectPath));

            // Also check for packages.config in legacy projects
            var projectDir = Path.GetDirectoryName(projectPath);
            if (projectDir != null)
            {
                var packagesConfigPath = Path.Combine(projectDir, "packages.config");
                if (File.Exists(packagesConfigPath))
                {
                    packages.AddRange(await ParsePackagesConfigAsync(packagesConfigPath, projectPath));
                }
            }
        }

        return packages;
    }

    /// <summary>
    /// Parses SDK-style project files (PackageReference).
    /// </summary>
    private async Task<List<PackageReference>> ParseSdkStyleProjectAsync(string projectPath)
    {
        var packages = new List<PackageReference>();

        try
        {
            var content = await File.ReadAllTextAsync(projectPath);
            var doc = XDocument.Parse(content);

            // Find all PackageReference elements
            var packageReferences = doc.Descendants()
                .Where(e => e.Name.LocalName == "PackageReference");

            foreach (var reference in packageReferences)
            {
                var packageId = reference.Attribute("Include")?.Value ??
                               reference.Attribute("Update")?.Value;

                if (string.IsNullOrEmpty(packageId))
                    continue;

                // Get version from attribute or child element
                var version = reference.Attribute("Version")?.Value ??
                             reference.Elements().FirstOrDefault(e => e.Name.LocalName == "Version")?.Value ??
                             "*"; // Floating version

                packages.Add(new PackageReference
                {
                    PackageId = packageId,
                    Version = version,
                    IsDirectReference = true,
                    ProjectPath = projectPath
                });
            }

            // Also check for Central Package Management (Directory.Packages.props)
            var projectDir = Path.GetDirectoryName(projectPath);
            if (projectDir != null)
            {
                var centralPackages = await FindCentralPackageVersionsAsync(projectDir);

                // Update versions from central package management
                foreach (var package in packages)
                {
                    if (package.Version == "*" && centralPackages.TryGetValue(package.PackageId, out var centralVersion))
                    {
                        // Can't modify record, but PackageReference doesn't need update for this case
                        // Version is resolved during build
                    }
                }
            }
        }
        catch
        {
            // Return empty list on parse failure
        }

        return packages;
    }

    /// <summary>
    /// Parses legacy packages.config files.
    /// </summary>
    private async Task<List<PackageReference>> ParsePackagesConfigAsync(string packagesConfigPath, string projectPath)
    {
        var packages = new List<PackageReference>();

        try
        {
            var content = await File.ReadAllTextAsync(packagesConfigPath);
            var doc = XDocument.Parse(content);

            var packageElements = doc.Descendants()
                .Where(e => e.Name.LocalName == "package");

            foreach (var element in packageElements)
            {
                var packageId = element.Attribute("id")?.Value;
                var version = element.Attribute("version")?.Value;

                if (string.IsNullOrEmpty(packageId) || string.IsNullOrEmpty(version))
                    continue;

                packages.Add(new PackageReference
                {
                    PackageId = packageId,
                    Version = version,
                    IsDirectReference = true,
                    ProjectPath = projectPath
                });
            }
        }
        catch
        {
            // Return empty list on parse failure
        }

        return packages;
    }

    /// <summary>
    /// Finds central package versions from Directory.Packages.props.
    /// </summary>
    private async Task<Dictionary<string, string>> FindCentralPackageVersionsAsync(string startDir)
    {
        var versions = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var currentDir = startDir;
        while (currentDir != null)
        {
            var propsPath = Path.Combine(currentDir, "Directory.Packages.props");
            if (File.Exists(propsPath))
            {
                try
                {
                    var content = await File.ReadAllTextAsync(propsPath);
                    var doc = XDocument.Parse(content);

                    var packageVersions = doc.Descendants()
                        .Where(e => e.Name.LocalName == "PackageVersion");

                    foreach (var pv in packageVersions)
                    {
                        var packageId = pv.Attribute("Include")?.Value;
                        var version = pv.Attribute("Version")?.Value;

                        if (!string.IsNullOrEmpty(packageId) && !string.IsNullOrEmpty(version))
                        {
                            versions[packageId] = version;
                        }
                    }

                    break; // Found the central package management file
                }
                catch
                {
                    // Continue searching parent directories
                }
            }

            var parent = Directory.GetParent(currentDir);
            currentDir = parent?.FullName;
        }

        return versions;
    }

    /// <summary>
    /// Finds all project files in a solution or directory.
    /// </summary>
    private List<string> FindProjectFiles(string path)
    {
        var projects = new List<string>();

        if (File.Exists(path))
        {
            var extension = Path.GetExtension(path).ToLowerInvariant();

            if (extension == ".sln")
            {
                projects.AddRange(ParseSolutionForProjects(path));
            }
            else if (extension is ".csproj" or ".vbproj" or ".fsproj")
            {
                projects.Add(path);
            }
        }
        else if (Directory.Exists(path))
        {
            // Find all project files in directory
            projects.AddRange(Directory.GetFiles(path, "*.csproj", SearchOption.AllDirectories));
            projects.AddRange(Directory.GetFiles(path, "*.vbproj", SearchOption.AllDirectories));
            projects.AddRange(Directory.GetFiles(path, "*.fsproj", SearchOption.AllDirectories));
        }

        return projects.Distinct().ToList();
    }

    /// <summary>
    /// Parses a solution file to find project paths.
    /// </summary>
    private List<string> ParseSolutionForProjects(string solutionPath)
    {
        var projects = new List<string>();
        var solutionDir = Path.GetDirectoryName(solutionPath);

        if (solutionDir == null)
            return projects;

        try
        {
            var lines = File.ReadAllLines(solutionPath);

            foreach (var line in lines)
            {
                if (line.StartsWith("Project("))
                {
                    // Format: Project("{GUID}") = "Name", "Path", "{GUID}"
                    var parts = line.Split('"');
                    if (parts.Length >= 6)
                    {
                        var relativePath = parts[5];
                        if (relativePath.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase) ||
                            relativePath.EndsWith(".vbproj", StringComparison.OrdinalIgnoreCase) ||
                            relativePath.EndsWith(".fsproj", StringComparison.OrdinalIgnoreCase))
                        {
                            var fullPath = Path.Combine(solutionDir, relativePath);
                            if (File.Exists(fullPath))
                            {
                                projects.Add(Path.GetFullPath(fullPath));
                            }
                        }
                    }
                }
            }
        }
        catch
        {
            // Return empty list on parse failure
        }

        return projects;
    }
}

/// <summary>
/// Result of package analysis.
/// </summary>
public record PackageAnalysisResult
{
    /// <summary>
    /// Directly referenced packages from project files.
    /// </summary>
    public required List<PackageReference> DirectPackages { get; init; }

    /// <summary>
    /// All packages including transitive dependencies.
    /// </summary>
    public required List<PackageReference> AllPackages { get; init; }

    /// <summary>
    /// Tree of transitive dependencies (package ID -> list of transitive deps).
    /// </summary>
    public required Dictionary<string, List<string>> TransitiveDependencyTree { get; init; }

    /// <summary>
    /// Packages by project path.
    /// </summary>
    public required Dictionary<string, List<PackageReference>> ProjectPackages { get; init; }

    /// <summary>
    /// Package versions from lock/assets files.
    /// </summary>
    public required Dictionary<string, string> PackageVersions { get; init; }
}
