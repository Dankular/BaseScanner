using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Api.Models;

namespace BaseScanner.Analyzers.Api;

/// <summary>
/// Analyzes API versioning patterns including version attributes,
/// deprecation handling, and version consistency.
/// </summary>
public class VersioningAnalyzer
{
    // Known versioning attribute names
    private static readonly string[] VersionAttributes =
    [
        "ApiVersion", "ApiVersionAttribute",
        "MapToApiVersion", "MapToApiVersionAttribute"
    ];

    // Known deprecation attributes
    private static readonly string[] DeprecationAttributes =
    [
        "Obsolete", "ObsoleteAttribute",
        "Deprecated", "DeprecatedAttribute"
    ];

    // Version format patterns
    private static readonly System.Text.RegularExpressions.Regex SemanticVersionPattern =
        new(@"^v?\d+(\.\d+){0,2}(-[\w\.]+)?$", System.Text.RegularExpressions.RegexOptions.Compiled);

    private static readonly System.Text.RegularExpressions.Regex DateVersionPattern =
        new(@"^\d{4}-\d{2}-\d{2}$", System.Text.RegularExpressions.RegexOptions.Compiled);

    public async Task<List<VersioningIssue>> AnalyzeAsync(Project project)
    {
        var issues = new List<VersioningIssue>();
        var versionedElements = new List<VersionedElement>();

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null) continue;
            if (IsGeneratedFile(document.FilePath)) continue;

            var root = await document.GetSyntaxRootAsync();
            var semanticModel = await document.GetSemanticModelAsync();
            if (root == null || semanticModel == null) continue;

            // Find versioned elements
            versionedElements.AddRange(FindVersionedElements(root, semanticModel, document.FilePath));
        }

        // Analyze versioning patterns
        issues.AddRange(AnalyzeVersionConsistency(versionedElements));
        issues.AddRange(AnalyzeDeprecationPatterns(versionedElements));
        issues.AddRange(AnalyzeVersionFormat(versionedElements));
        issues.AddRange(AnalyzeVersionStrategy(versionedElements));

        return issues
            .OrderByDescending(i => GetSeverityOrder(i.Severity))
            .ThenBy(i => i.FilePath)
            .ThenBy(i => i.Line)
            .ToList();
    }

    private List<VersionedElement> FindVersionedElements(SyntaxNode root, SemanticModel model, string filePath)
    {
        var elements = new List<VersionedElement>();

        // Find controllers with version attributes
        foreach (var classDecl in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
        {
            if (!IsController(classDecl)) continue;

            var versionInfo = ExtractVersionInfo(classDecl.AttributeLists);
            var deprecationInfo = ExtractDeprecationInfo(classDecl.AttributeLists);

            var element = new VersionedElement
            {
                Name = classDecl.Identifier.Text,
                ElementKind = "Controller",
                FilePath = filePath,
                Line = classDecl.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                Versions = versionInfo.Versions,
                VersioningStrategy = versionInfo.Strategy,
                IsDeprecated = deprecationInfo.IsDeprecated,
                DeprecationMessage = deprecationInfo.Message,
                ReplacementVersion = deprecationInfo.Replacement
            };

            elements.Add(element);

            // Find versioned actions within the controller
            foreach (var method in classDecl.Members.OfType<MethodDeclarationSyntax>())
            {
                if (!method.Modifiers.Any(SyntaxKind.PublicKeyword)) continue;

                var actionVersionInfo = ExtractVersionInfo(method.AttributeLists);
                var actionDeprecationInfo = ExtractDeprecationInfo(method.AttributeLists);

                // Only add if action has its own versioning
                if (actionVersionInfo.Versions.Any() || actionDeprecationInfo.IsDeprecated)
                {
                    elements.Add(new VersionedElement
                    {
                        Name = $"{classDecl.Identifier.Text}.{method.Identifier.Text}",
                        ElementKind = "Action",
                        FilePath = filePath,
                        Line = method.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        Versions = actionVersionInfo.Versions.Any()
                            ? actionVersionInfo.Versions
                            : versionInfo.Versions, // Inherit from controller
                        VersioningStrategy = actionVersionInfo.Strategy ?? versionInfo.Strategy,
                        IsDeprecated = actionDeprecationInfo.IsDeprecated,
                        DeprecationMessage = actionDeprecationInfo.Message,
                        ReplacementVersion = actionDeprecationInfo.Replacement,
                        ParentController = classDecl.Identifier.Text
                    });
                }
            }
        }

        // Find versioned interfaces/services
        foreach (var typeDecl in root.DescendantNodes().OfType<TypeDeclarationSyntax>())
        {
            if (typeDecl is ClassDeclarationSyntax c && IsController(c)) continue;

            var versionInfo = ExtractVersionInfo(typeDecl.AttributeLists);
            var deprecationInfo = ExtractDeprecationInfo(typeDecl.AttributeLists);

            // Check if type name contains version info
            var nameVersionInfo = ExtractVersionFromName(typeDecl.Identifier.Text);

            if (versionInfo.Versions.Any() || deprecationInfo.IsDeprecated || nameVersionInfo != null)
            {
                elements.Add(new VersionedElement
                {
                    Name = typeDecl.Identifier.Text,
                    ElementKind = typeDecl switch
                    {
                        InterfaceDeclarationSyntax => "Interface",
                        ClassDeclarationSyntax => "Class",
                        RecordDeclarationSyntax => "Record",
                        _ => "Type"
                    },
                    FilePath = filePath,
                    Line = typeDecl.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                    Versions = versionInfo.Versions.Any()
                        ? versionInfo.Versions
                        : nameVersionInfo != null ? [nameVersionInfo] : [],
                    VersioningStrategy = versionInfo.Strategy ?? (nameVersionInfo != null ? "NameBased" : null),
                    IsDeprecated = deprecationInfo.IsDeprecated,
                    DeprecationMessage = deprecationInfo.Message,
                    ReplacementVersion = deprecationInfo.Replacement
                });
            }
        }

        return elements;
    }

    private List<VersioningIssue> AnalyzeVersionConsistency(List<VersionedElement> elements)
    {
        var issues = new List<VersioningIssue>();

        // Group controllers by their versioning strategy
        var controllers = elements.Where(e => e.ElementKind == "Controller").ToList();

        if (!controllers.Any()) return issues;

        var strategies = controllers
            .Where(c => c.VersioningStrategy != null)
            .GroupBy(c => c.VersioningStrategy)
            .ToList();

        // Check for mixed strategies
        if (strategies.Count > 1)
        {
            var first = controllers.First();
            issues.Add(new VersioningIssue
            {
                IssueType = VersioningIssueType.InconsistentVersioning,
                Severity = "Medium",
                Message = $"Mixed versioning strategies detected: {string.Join(", ", strategies.Select(s => s.Key))}",
                FilePath = first.FilePath,
                Line = first.Line,
                AffectedElement = "Multiple Controllers",
                Recommendation = "Use a single versioning strategy across all controllers",
                SuggestedPattern = strategies.OrderByDescending(s => s.Count()).First().Key
            });
        }

        // Check for unversioned controllers when others are versioned
        var versionedControllers = controllers.Where(c => c.Versions.Any()).ToList();
        var unversionedControllers = controllers.Where(c => !c.Versions.Any()).ToList();

        if (versionedControllers.Any() && unversionedControllers.Any())
        {
            foreach (var controller in unversionedControllers)
            {
                issues.Add(new VersioningIssue
                {
                    IssueType = VersioningIssueType.MissingVersioning,
                    Severity = "Medium",
                    Message = $"Controller '{controller.Name}' is not versioned while other controllers are",
                    FilePath = controller.FilePath,
                    Line = controller.Line,
                    AffectedElement = controller.Name,
                    Recommendation = "Add [ApiVersion] attribute for consistency",
                    SuggestedPattern = versionedControllers.FirstOrDefault()?.Versions.FirstOrDefault()
                });
            }
        }

        // Check for version gaps
        var allVersions = controllers
            .SelectMany(c => c.Versions)
            .Where(v => v != null)
            .Distinct()
            .OrderBy(v => v)
            .ToList();

        if (allVersions.Count >= 2)
        {
            var numericVersions = allVersions
                .Select(v => TryParseVersion(v ?? ""))
                .Where(v => v.HasValue)
                .Select(v => v!.Value)
                .OrderBy(v => v)
                .ToList();

            for (int i = 1; i < numericVersions.Count; i++)
            {
                var gap = numericVersions[i] - numericVersions[i - 1];
                if (gap > 1)
                {
                    var first = controllers.First();
                    issues.Add(new VersioningIssue
                    {
                        IssueType = VersioningIssueType.InconsistentVersioning,
                        Severity = "Low",
                        Message = $"Version gap detected: v{numericVersions[i - 1]} to v{numericVersions[i]}",
                        FilePath = first.FilePath,
                        Line = first.Line,
                        AffectedElement = "API Versions",
                        Recommendation = "Consider if intermediate versions were intentionally skipped",
                        CurrentVersion = $"v{numericVersions[i - 1]}, v{numericVersions[i]}"
                    });
                }
            }
        }

        return issues;
    }

    private List<VersioningIssue> AnalyzeDeprecationPatterns(List<VersionedElement> elements)
    {
        var issues = new List<VersioningIssue>();

        // Find deprecated elements
        var deprecated = elements.Where(e => e.IsDeprecated).ToList();

        foreach (var element in deprecated)
        {
            // Check for deprecated without replacement guidance
            if (string.IsNullOrEmpty(element.ReplacementVersion) &&
                (string.IsNullOrEmpty(element.DeprecationMessage) ||
                 !element.DeprecationMessage!.Contains("use", StringComparison.OrdinalIgnoreCase)))
            {
                issues.Add(new VersioningIssue
                {
                    IssueType = VersioningIssueType.DeprecatedWithoutReplacement,
                    Severity = "Medium",
                    Message = $"Deprecated {element.ElementKind.ToLower()} '{element.Name}' doesn't indicate replacement",
                    FilePath = element.FilePath,
                    Line = element.Line,
                    AffectedElement = element.Name,
                    Recommendation = "Update deprecation message to indicate the replacement API",
                    CurrentVersion = element.Versions.FirstOrDefault()
                });
            }
        }

        // Find old versions that should be deprecated
        var byNameGroup = elements
            .Where(e => e.Versions.Any())
            .GroupBy(e => GetBaseName(e.Name))
            .Where(g => g.Count() > 1);

        foreach (var group in byNameGroup)
        {
            var sorted = group
                .OrderBy(e => TryParseVersion(e.Versions.FirstOrDefault() ?? "") ?? 0)
                .ToList();

            // Check if older versions are marked deprecated
            foreach (var oldVersion in sorted.Take(sorted.Count - 1))
            {
                if (!oldVersion.IsDeprecated)
                {
                    var newestVersion = sorted.Last().Versions.FirstOrDefault();
                    issues.Add(new VersioningIssue
                    {
                        IssueType = VersioningIssueType.MissingDeprecation,
                        Severity = "Low",
                        Message = $"{oldVersion.ElementKind} '{oldVersion.Name}' is an older version but not marked deprecated",
                        FilePath = oldVersion.FilePath,
                        Line = oldVersion.Line,
                        AffectedElement = oldVersion.Name,
                        Recommendation = $"Mark as deprecated and point to version {newestVersion}",
                        CurrentVersion = oldVersion.Versions.FirstOrDefault(),
                        SuggestedPattern = newestVersion
                    });
                }
            }
        }

        return issues;
    }

    private List<VersioningIssue> AnalyzeVersionFormat(List<VersionedElement> elements)
    {
        var issues = new List<VersioningIssue>();

        // Group by version format
        var versionFormats = new Dictionary<string, List<(VersionedElement Element, string Version)>>();

        foreach (var element in elements)
        {
            foreach (var version in element.Versions.Where(v => v != null))
            {
                var format = DetermineVersionFormat(version!);
                if (!versionFormats.ContainsKey(format))
                {
                    versionFormats[format] = new List<(VersionedElement, string)>();
                }
                versionFormats[format].Add((element, version!));
            }
        }

        // Check for mixed formats
        if (versionFormats.Count > 1)
        {
            var dominantFormat = versionFormats.OrderByDescending(kv => kv.Value.Count).First();
            var minorityFormats = versionFormats.Where(kv => kv.Key != dominantFormat.Key);

            foreach (var (format, items) in minorityFormats)
            {
                foreach (var (element, version) in items)
                {
                    issues.Add(new VersioningIssue
                    {
                        IssueType = VersioningIssueType.InvalidVersionFormat,
                        Severity = "Low",
                        Message = $"Version '{version}' uses {format} format while most others use {dominantFormat.Key}",
                        FilePath = element.FilePath,
                        Line = element.Line,
                        AffectedElement = element.Name,
                        Recommendation = $"Use consistent version format ({dominantFormat.Key})",
                        CurrentVersion = version,
                        SuggestedPattern = dominantFormat.Key
                    });
                }
            }
        }

        return issues;
    }

    private List<VersioningIssue> AnalyzeVersionStrategy(List<VersionedElement> elements)
    {
        var issues = new List<VersioningIssue>();

        var controllers = elements.Where(e => e.ElementKind == "Controller").ToList();

        // Check for URL-based versioning
        var urlVersioned = controllers.Where(c =>
            c.Versions.Any(v => v != null && v.Contains("/")) ||
            c.VersioningStrategy == "URL").ToList();

        if (urlVersioned.Any())
        {
            // URL versioning is common but has trade-offs
            foreach (var controller in urlVersioned)
            {
                issues.Add(new VersioningIssue
                {
                    IssueType = VersioningIssueType.VersionInUrl,
                    Severity = "Low",
                    Message = $"Controller '{controller.Name}' uses URL-based versioning",
                    FilePath = controller.FilePath,
                    Line = controller.Line,
                    AffectedElement = controller.Name,
                    Recommendation = "URL versioning is valid but consider header-based for flexibility",
                    CurrentVersion = controller.Versions.FirstOrDefault()
                });
            }
        }

        // Check for multiple version attributes
        var multiVersioned = elements.Where(e => e.Versions.Count > 2).ToList();

        foreach (var element in multiVersioned)
        {
            issues.Add(new VersioningIssue
            {
                IssueType = VersioningIssueType.MultipleVersionAttributes,
                Severity = "Low",
                Message = $"{element.ElementKind} '{element.Name}' supports {element.Versions.Count} versions - consider consolidating",
                FilePath = element.FilePath,
                Line = element.Line,
                AffectedElement = element.Name,
                Recommendation = "Supporting many versions increases maintenance burden",
                CurrentVersion = string.Join(", ", element.Versions)
            });
        }

        return issues;
    }

    // Helper methods
    private (List<string?> Versions, string? Strategy) ExtractVersionInfo(SyntaxList<AttributeListSyntax> attributeLists)
    {
        var versions = new List<string?>();
        string? strategy = null;

        foreach (var attrList in attributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                var name = attr.Name.ToString();

                if (VersionAttributes.Any(va => name.Contains(va.Replace("Attribute", ""))))
                {
                    if (attr.ArgumentList?.Arguments.FirstOrDefault() is { } arg)
                    {
                        var version = arg.ToString().Trim('"');
                        versions.Add(version);

                        // Try to determine strategy
                        if (version.Contains("/"))
                            strategy = "URL";
                        else if (SemanticVersionPattern.IsMatch(version))
                            strategy = "Semantic";
                        else if (DateVersionPattern.IsMatch(version))
                            strategy = "Date";
                        else
                            strategy = "Simple";
                    }
                }
            }
        }

        return (versions, strategy);
    }

    private (bool IsDeprecated, string? Message, string? Replacement) ExtractDeprecationInfo(
        SyntaxList<AttributeListSyntax> attributeLists)
    {
        foreach (var attrList in attributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                var name = attr.Name.ToString();

                if (DeprecationAttributes.Any(da => name.Contains(da.Replace("Attribute", ""))))
                {
                    var message = attr.ArgumentList?.Arguments.FirstOrDefault()?.ToString().Trim('"');
                    var replacement = ExtractReplacementFromMessage(message);
                    return (true, message, replacement);
                }
            }
        }

        return (false, null, null);
    }

    private string? ExtractReplacementFromMessage(string? message)
    {
        if (string.IsNullOrEmpty(message)) return null;

        // Look for patterns like "use v2", "replaced by v2", "see Version 2"
        var patterns = new[]
        {
            @"use\s+v?(\d+(\.\d+)*)",
            @"replaced\s+by\s+v?(\d+(\.\d+)*)",
            @"see\s+v(ersion)?\s*(\d+(\.\d+)*)",
            @"migrate\s+to\s+v?(\d+(\.\d+)*)"
        };

        foreach (var pattern in patterns)
        {
            var match = System.Text.RegularExpressions.Regex.Match(
                message,
                pattern,
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            if (match.Success)
            {
                return match.Groups[1].Value;
            }
        }

        return null;
    }

    private string? ExtractVersionFromName(string name)
    {
        // Look for version patterns in type names like "UserServiceV2", "ProductApiV1"
        var match = System.Text.RegularExpressions.Regex.Match(name, @"[Vv](\d+)$");
        if (match.Success)
        {
            return match.Groups[1].Value;
        }

        // Also check for "Version2" pattern
        match = System.Text.RegularExpressions.Regex.Match(name, @"Version(\d+)$");
        if (match.Success)
        {
            return match.Groups[1].Value;
        }

        return null;
    }

    private string DetermineVersionFormat(string version)
    {
        if (SemanticVersionPattern.IsMatch(version)) return "SemanticVersion";
        if (DateVersionPattern.IsMatch(version)) return "DateVersion";
        if (System.Text.RegularExpressions.Regex.IsMatch(version, @"^\d+$")) return "SimpleInteger";
        if (version.StartsWith("v", StringComparison.OrdinalIgnoreCase)) return "PrefixedVersion";
        return "Other";
    }

    private decimal? TryParseVersion(string version)
    {
        // Remove 'v' prefix if present
        var cleaned = version.TrimStart('v', 'V');

        // Try to parse as decimal
        if (decimal.TryParse(cleaned.Split('.').FirstOrDefault(), out var result))
        {
            return result;
        }

        return null;
    }

    private string GetBaseName(string name)
    {
        // Remove version suffixes like V2, Version2
        return System.Text.RegularExpressions.Regex.Replace(name, @"([Vv]ersion?)?\d+$", "");
    }

    private bool IsController(ClassDeclarationSyntax classDecl)
    {
        // Check for Controller/ControllerBase inheritance
        if (classDecl.BaseList != null)
        {
            foreach (var baseType in classDecl.BaseList.Types)
            {
                var typeName = baseType.Type.ToString();
                if (typeName.Contains("Controller") || typeName.Contains("ControllerBase"))
                    return true;
            }
        }

        // Check for [ApiController] attribute
        return classDecl.AttributeLists
            .SelectMany(al => al.Attributes)
            .Any(a => a.Name.ToString().Contains("ApiController") ||
                      a.Name.ToString() == "Controller");
    }

    private int GetSeverityOrder(string severity) => severity switch
    {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0
    };

    private bool IsGeneratedFile(string filePath)
    {
        var fileName = Path.GetFileName(filePath);
        return fileName.EndsWith(".g.cs") ||
               fileName.EndsWith(".Designer.cs") ||
               fileName.EndsWith(".generated.cs") ||
               filePath.Contains("obj" + Path.DirectorySeparatorChar);
    }

    private record VersionedElement
    {
        public required string Name { get; init; }
        public required string ElementKind { get; init; }
        public required string FilePath { get; init; }
        public required int Line { get; init; }
        public List<string?> Versions { get; init; } = [];
        public string? VersioningStrategy { get; init; }
        public bool IsDeprecated { get; init; }
        public string? DeprecationMessage { get; init; }
        public string? ReplacementVersion { get; init; }
        public string? ParentController { get; init; }
    }
}
