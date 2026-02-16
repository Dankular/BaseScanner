using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Api.Models;

namespace BaseScanner.Analyzers.Api;

/// <summary>
/// Analyzes API consistency patterns including naming conventions,
/// return types, error handling, and async patterns.
/// </summary>
public class ConsistencyAnalyzer
{
    // Common naming patterns for similar operations
    private static readonly Dictionary<string, string[]> OperationSynonyms = new()
    {
        ["Get"] = ["Get", "Fetch", "Retrieve", "Load", "Read", "Find"],
        ["Create"] = ["Create", "Add", "Insert", "New", "Make"],
        ["Update"] = ["Update", "Modify", "Edit", "Change", "Set"],
        ["Delete"] = ["Delete", "Remove", "Erase", "Destroy"],
        ["Validate"] = ["Validate", "Check", "Verify", "Ensure"],
        ["Convert"] = ["Convert", "Transform", "Map", "Parse"],
        ["Send"] = ["Send", "Post", "Transmit", "Dispatch", "Emit"]
    };

    public async Task<List<ApiDesignIssue>> AnalyzeAsync(Project project)
    {
        var issues = new List<ApiDesignIssue>();
        var publicMethods = new List<ApiMethodInfo>();

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null) continue;
            if (IsGeneratedFile(document.FilePath)) continue;

            var root = await document.GetSyntaxRootAsync();
            var semanticModel = await document.GetSemanticModelAsync();
            if (root == null || semanticModel == null) continue;

            // Collect public methods from public types
            var methods = CollectPublicMethods(root, semanticModel, document.FilePath);
            publicMethods.AddRange(methods);
        }

        // Analyze for consistency issues
        issues.AddRange(AnalyzeNamingConsistency(publicMethods));
        issues.AddRange(AnalyzeReturnTypeConsistency(publicMethods));
        issues.AddRange(AnalyzeAsyncConsistency(publicMethods));
        issues.AddRange(AnalyzeOverloadAmbiguity(publicMethods));
        issues.AddRange(AnalyzeParameterConsistency(publicMethods));

        return issues;
    }

    private List<ApiMethodInfo> CollectPublicMethods(SyntaxNode root, SemanticModel model, string filePath)
    {
        var methods = new List<ApiMethodInfo>();

        // Find public types
        var publicTypes = root.DescendantNodes()
            .OfType<TypeDeclarationSyntax>()
            .Where(t => t.Modifiers.Any(SyntaxKind.PublicKeyword));

        foreach (var type in publicTypes)
        {
            var typeSymbol = model.GetDeclaredSymbol(type);
            if (typeSymbol == null) continue;

            // Find public methods
            foreach (var method in type.Members.OfType<MethodDeclarationSyntax>())
            {
                if (!method.Modifiers.Any(SyntaxKind.PublicKeyword)) continue;

                var methodSymbol = model.GetDeclaredSymbol(method);
                if (methodSymbol == null) continue;

                var parameters = method.ParameterList.Parameters
                    .Select(p => $"{p.Type?.ToString() ?? "?"} {p.Identifier.Text}")
                    .ToList();

                var methodInfo = new ApiMethodInfo
                {
                    TypeName = typeSymbol.Name,
                    MethodName = methodSymbol.Name,
                    FullSignature = methodSymbol.ToDisplayString(),
                    FilePath = filePath,
                    Line = method.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                    ReturnType = method.ReturnType.ToString(),
                    Parameters = parameters,
                    IsAsync = method.Modifiers.Any(SyntaxKind.AsyncKeyword) ||
                              method.ReturnType.ToString().Contains("Task"),
                    NamingPattern = ExtractNamingPattern(methodSymbol.Name),
                    HasAsyncCounterpart = false // Will be determined later
                };

                methods.Add(methodInfo);
            }
        }

        // Check for async counterparts
        var methodNames = methods.Select(m => m.MethodName).ToHashSet();
        for (int i = 0; i < methods.Count; i++)
        {
            var method = methods[i];
            var asyncName = method.MethodName + "Async";
            var syncName = method.MethodName.EndsWith("Async")
                ? method.MethodName[..^5]
                : null;

            methods[i] = method with
            {
                HasAsyncCounterpart = methodNames.Contains(asyncName) ||
                                      (syncName != null && methodNames.Contains(syncName))
            };
        }

        return methods;
    }

    private string? ExtractNamingPattern(string methodName)
    {
        foreach (var (operation, synonyms) in OperationSynonyms)
        {
            foreach (var synonym in synonyms)
            {
                if (methodName.StartsWith(synonym, StringComparison.Ordinal))
                {
                    return synonym;
                }
            }
        }
        return null;
    }

    private List<ApiDesignIssue> AnalyzeNamingConsistency(List<ApiMethodInfo> methods)
    {
        var issues = new List<ApiDesignIssue>();

        // Group methods by their type
        var methodsByType = methods.GroupBy(m => m.TypeName);

        foreach (var typeGroup in methodsByType)
        {
            var typeMethods = typeGroup.ToList();

            // Check for inconsistent naming patterns within the same operation category
            foreach (var (operation, synonyms) in OperationSynonyms)
            {
                var relatedMethods = typeMethods
                    .Where(m => synonyms.Any(s => m.MethodName.StartsWith(s, StringComparison.Ordinal)))
                    .ToList();

                if (relatedMethods.Count < 2) continue;

                var usedPatterns = relatedMethods
                    .Select(m => m.NamingPattern)
                    .Where(p => p != null)
                    .Distinct()
                    .ToList();

                if (usedPatterns.Count > 1)
                {
                    // Find the most common pattern
                    var patternCounts = relatedMethods
                        .GroupBy(m => m.NamingPattern)
                        .OrderByDescending(g => g.Count())
                        .ToList();

                    var dominantPattern = patternCounts.First().Key;
                    var inconsistentMethods = relatedMethods
                        .Where(m => m.NamingPattern != dominantPattern)
                        .ToList();

                    foreach (var method in inconsistentMethods)
                    {
                        issues.Add(new ApiDesignIssue
                        {
                            Category = "Consistency",
                            IssueType = "InconsistentNaming",
                            Severity = "Medium",
                            Message = $"Method '{method.MethodName}' uses '{method.NamingPattern}' pattern while other similar operations use '{dominantPattern}'",
                            FilePath = method.FilePath,
                            Line = method.Line,
                            AffectedElement = $"{method.TypeName}.{method.MethodName}",
                            Recommendation = $"Consider renaming to use '{dominantPattern}' prefix for consistency (e.g., '{dominantPattern}{method.MethodName[method.NamingPattern!.Length..]}')",
                            RelatedElements = relatedMethods
                                .Where(m => m.NamingPattern == dominantPattern)
                                .Select(m => $"{m.TypeName}.{m.MethodName}")
                                .Take(3)
                                .ToList(),
                            ImpactScore = 4
                        });
                    }
                }
            }
        }

        return issues;
    }

    private List<ApiDesignIssue> AnalyzeReturnTypeConsistency(List<ApiMethodInfo> methods)
    {
        var issues = new List<ApiDesignIssue>();

        // Group by type and analyze methods with similar purposes
        var methodsByType = methods.GroupBy(m => m.TypeName);

        foreach (var typeGroup in methodsByType)
        {
            var typeMethods = typeGroup.ToList();

            // Find methods that return collections
            var collectionMethods = typeMethods
                .Where(m => IsCollectionType(m.ReturnType))
                .GroupBy(m => GetCollectionPattern(m.ReturnType))
                .Where(g => g.Count() > 1)
                .ToList();

            // Check for inconsistent collection return types
            if (collectionMethods.Count > 1)
            {
                var allCollectionMethods = collectionMethods.SelectMany(g => g).ToList();
                var dominantPattern = collectionMethods
                    .OrderByDescending(g => g.Count())
                    .First().Key;

                foreach (var method in allCollectionMethods.Where(m => GetCollectionPattern(m.ReturnType) != dominantPattern))
                {
                    issues.Add(new ApiDesignIssue
                    {
                        Category = "Consistency",
                        IssueType = "InconsistentReturns",
                        Severity = "Medium",
                        Message = $"Method '{method.MethodName}' returns '{method.ReturnType}' while similar methods return '{dominantPattern}' types",
                        FilePath = method.FilePath,
                        Line = method.Line,
                        AffectedElement = $"{method.TypeName}.{method.MethodName}",
                        Recommendation = $"Consider using consistent collection type (e.g., '{dominantPattern}') across similar methods",
                        RelatedElements = allCollectionMethods
                            .Where(m => GetCollectionPattern(m.ReturnType) == dominantPattern)
                            .Select(m => $"{m.TypeName}.{m.MethodName}")
                            .Take(3)
                            .ToList(),
                        ImpactScore = 5
                    });
                }
            }

            // Check for nullable vs. non-nullable inconsistencies in similar operations
            var nullablePatterns = typeMethods
                .Where(m => m.NamingPattern != null)
                .GroupBy(m => m.NamingPattern)
                .Where(g => g.Count() > 1);

            foreach (var group in nullablePatterns)
            {
                var groupMethods = group.ToList();
                var hasNullable = groupMethods.Any(m => m.ReturnType.EndsWith("?"));
                var hasNonNullable = groupMethods.Any(m => !m.ReturnType.EndsWith("?") && !m.ReturnType.Contains("IEnumerable"));

                if (hasNullable && hasNonNullable)
                {
                    var nullableMethods = groupMethods.Where(m => m.ReturnType.EndsWith("?")).ToList();
                    var nonNullableMethods = groupMethods.Where(m => !m.ReturnType.EndsWith("?") && !m.ReturnType.Contains("IEnumerable")).ToList();

                    if (nullableMethods.Count < nonNullableMethods.Count)
                    {
                        foreach (var method in nullableMethods)
                        {
                            issues.Add(new ApiDesignIssue
                            {
                                Category = "Consistency",
                                IssueType = "InconsistentReturns",
                                Severity = "Low",
                                Message = $"Method '{method.MethodName}' returns nullable while similar methods return non-nullable",
                                FilePath = method.FilePath,
                                Line = method.Line,
                                AffectedElement = $"{method.TypeName}.{method.MethodName}",
                                Recommendation = "Consider consistent null handling - either all nullable or all non-nullable with exception throwing",
                                RelatedElements = nonNullableMethods
                                    .Select(m => $"{m.TypeName}.{m.MethodName}")
                                    .Take(3)
                                    .ToList(),
                                ImpactScore = 3
                            });
                        }
                    }
                }
            }
        }

        return issues;
    }

    private List<ApiDesignIssue> AnalyzeAsyncConsistency(List<ApiMethodInfo> methods)
    {
        var issues = new List<ApiDesignIssue>();

        var methodsByType = methods.GroupBy(m => m.TypeName);

        foreach (var typeGroup in methodsByType)
        {
            var typeMethods = typeGroup.ToList();

            // Find async methods without sync counterparts (or vice versa)
            var asyncMethods = typeMethods.Where(m => m.IsAsync).ToList();
            var syncMethods = typeMethods.Where(m => !m.IsAsync).ToList();

            // Check for methods that should probably have both sync and async
            foreach (var asyncMethod in asyncMethods)
            {
                var baseName = asyncMethod.MethodName.EndsWith("Async")
                    ? asyncMethod.MethodName[..^5]
                    : asyncMethod.MethodName;

                var hasSyncVersion = syncMethods.Any(m =>
                    m.MethodName == baseName &&
                    ParametersMatch(m.Parameters, asyncMethod.Parameters));

                // Only flag if there are other methods in the type that have both versions
                var typeHasBothPatterns = asyncMethods.Any(a =>
                {
                    var aBaseName = a.MethodName.EndsWith("Async")
                        ? a.MethodName[..^5]
                        : a.MethodName;
                    return syncMethods.Any(s =>
                        s.MethodName == aBaseName &&
                        ParametersMatch(s.Parameters, a.Parameters));
                });

                if (typeHasBothPatterns && !hasSyncVersion)
                {
                    issues.Add(new ApiDesignIssue
                    {
                        Category = "Consistency",
                        IssueType = "MissingAsync",
                        Severity = "Low",
                        Message = $"Async method '{asyncMethod.MethodName}' has no synchronous counterpart, but other methods in this type provide both",
                        FilePath = asyncMethod.FilePath,
                        Line = asyncMethod.Line,
                        AffectedElement = $"{asyncMethod.TypeName}.{asyncMethod.MethodName}",
                        Recommendation = "Consider providing a synchronous version for consistency, or document why only async is available",
                        ImpactScore = 2
                    });
                }
            }

            // Check for async-like names on sync methods
            foreach (var method in syncMethods)
            {
                if (method.MethodName.EndsWith("Async") && !method.IsAsync)
                {
                    issues.Add(new ApiDesignIssue
                    {
                        Category = "Consistency",
                        IssueType = "InconsistentNaming",
                        Severity = "Medium",
                        Message = $"Method '{method.MethodName}' is named 'Async' but doesn't return Task/ValueTask",
                        FilePath = method.FilePath,
                        Line = method.Line,
                        AffectedElement = $"{method.TypeName}.{method.MethodName}",
                        Recommendation = "Either make the method async or remove 'Async' suffix",
                        ImpactScore = 5
                    });
                }
            }

            // Check for async methods without Async suffix
            foreach (var method in asyncMethods)
            {
                if (!method.MethodName.EndsWith("Async"))
                {
                    // Check if this type consistently omits Async suffix
                    var asyncMethodsWithSuffix = asyncMethods.Count(m => m.MethodName.EndsWith("Async"));
                    var asyncMethodsWithoutSuffix = asyncMethods.Count(m => !m.MethodName.EndsWith("Async"));

                    if (asyncMethodsWithSuffix > asyncMethodsWithoutSuffix)
                    {
                        issues.Add(new ApiDesignIssue
                        {
                            Category = "Consistency",
                            IssueType = "InconsistentNaming",
                            Severity = "Low",
                            Message = $"Async method '{method.MethodName}' doesn't follow the 'Async' suffix convention used by other methods",
                            FilePath = method.FilePath,
                            Line = method.Line,
                            AffectedElement = $"{method.TypeName}.{method.MethodName}",
                            Recommendation = $"Consider renaming to '{method.MethodName}Async' for consistency",
                            RelatedElements = asyncMethods
                                .Where(m => m.MethodName.EndsWith("Async"))
                                .Select(m => m.MethodName)
                                .Take(3)
                                .ToList(),
                            ImpactScore = 3
                        });
                    }
                }
            }
        }

        return issues;
    }

    private List<ApiDesignIssue> AnalyzeOverloadAmbiguity(List<ApiMethodInfo> methods)
    {
        var issues = new List<ApiDesignIssue>();

        var methodsByType = methods.GroupBy(m => m.TypeName);

        foreach (var typeGroup in methodsByType)
        {
            // Find overloaded methods
            var overloadGroups = typeGroup
                .GroupBy(m => m.MethodName)
                .Where(g => g.Count() > 1);

            foreach (var group in overloadGroups)
            {
                var overloads = group.ToList();

                // Check for ambiguous overloads
                for (int i = 0; i < overloads.Count; i++)
                {
                    for (int j = i + 1; j < overloads.Count; j++)
                    {
                        var ambiguity = DetectAmbiguity(overloads[i], overloads[j]);
                        if (ambiguity != null)
                        {
                            issues.Add(new ApiDesignIssue
                            {
                                Category = "Consistency",
                                IssueType = "OverloadAmbiguity",
                                Severity = "Medium",
                                Message = $"Overloaded methods may be ambiguous: {ambiguity}",
                                FilePath = overloads[i].FilePath,
                                Line = overloads[i].Line,
                                AffectedElement = $"{overloads[i].TypeName}.{overloads[i].MethodName}",
                                Recommendation = "Consider using different method names or more distinct parameter types",
                                RelatedElements = [overloads[j].FullSignature],
                                ImpactScore = 6
                            });
                        }
                    }
                }

                // Check for too many overloads
                if (overloads.Count > 5)
                {
                    issues.Add(new ApiDesignIssue
                    {
                        Category = "Consistency",
                        IssueType = "OverloadAmbiguity",
                        Severity = "Medium",
                        Message = $"Method '{group.Key}' has {overloads.Count} overloads, which may confuse API consumers",
                        FilePath = overloads[0].FilePath,
                        Line = overloads[0].Line,
                        AffectedElement = $"{overloads[0].TypeName}.{group.Key}",
                        Recommendation = "Consider using an options class or builder pattern instead of many overloads",
                        ImpactScore = 5
                    });
                }
            }
        }

        return issues;
    }

    private List<ApiDesignIssue> AnalyzeParameterConsistency(List<ApiMethodInfo> methods)
    {
        var issues = new List<ApiDesignIssue>();

        var methodsByType = methods.GroupBy(m => m.TypeName);

        foreach (var typeGroup in methodsByType)
        {
            var typeMethods = typeGroup.ToList();

            // Find common parameter patterns
            var parameterNames = typeMethods
                .SelectMany(m => m.Parameters)
                .Select(p => p.Split(' ').Last())
                .GroupBy(n => n.ToLowerInvariant())
                .Where(g => g.Count() > 1)
                .ToDictionary(g => g.Key, g => g.ToList());

            // Check for inconsistent parameter naming
            foreach (var (normalizedName, variants) in parameterNames)
            {
                var distinctVariants = variants.Distinct().ToList();
                if (distinctVariants.Count > 1)
                {
                    var dominantVariant = variants
                        .GroupBy(v => v)
                        .OrderByDescending(g => g.Count())
                        .First().Key;

                    var inconsistentMethods = typeMethods
                        .Where(m => m.Parameters.Any(p =>
                        {
                            var paramName = p.Split(' ').Last();
                            return paramName.ToLowerInvariant() == normalizedName &&
                                   paramName != dominantVariant;
                        }))
                        .ToList();

                    foreach (var method in inconsistentMethods)
                    {
                        var inconsistentParam = method.Parameters
                            .FirstOrDefault(p => p.Split(' ').Last().ToLowerInvariant() == normalizedName);

                        if (inconsistentParam != null)
                        {
                            issues.Add(new ApiDesignIssue
                            {
                                Category = "Consistency",
                                IssueType = "InconsistentNaming",
                                Severity = "Low",
                                Message = $"Parameter '{inconsistentParam.Split(' ').Last()}' uses different casing than '{dominantVariant}' in other methods",
                                FilePath = method.FilePath,
                                Line = method.Line,
                                AffectedElement = $"{method.TypeName}.{method.MethodName}",
                                Recommendation = $"Use consistent parameter naming: '{dominantVariant}'",
                                ImpactScore = 2
                            });
                        }
                    }
                }
            }
        }

        return issues;
    }

    private string? DetectAmbiguity(ApiMethodInfo m1, ApiMethodInfo m2)
    {
        var p1 = m1.Parameters;
        var p2 = m2.Parameters;

        // Same parameter count with implicitly convertible types
        if (p1.Count == p2.Count)
        {
            var allConvertible = true;
            for (int i = 0; i < p1.Count; i++)
            {
                var t1 = p1[i].Split(' ').First();
                var t2 = p2[i].Split(' ').First();

                if (!AreImplicitlyConvertible(t1, t2))
                {
                    allConvertible = false;
                    break;
                }
            }

            if (allConvertible)
            {
                return $"Parameters at same positions may be implicitly convertible";
            }
        }

        // Optional parameters that could match
        var hasOptional1 = p1.Any(p => p.Contains("="));
        var hasOptional2 = p2.Any(p => p.Contains("="));

        if (hasOptional1 || hasOptional2)
        {
            var required1 = p1.Count(p => !p.Contains("="));
            var required2 = p2.Count(p => !p.Contains("="));

            if (required1 == required2 || required1 == p2.Count || required2 == p1.Count)
            {
                return "Optional parameters may cause ambiguous overload resolution";
            }
        }

        return null;
    }

    private bool AreImplicitlyConvertible(string t1, string t2)
    {
        if (t1 == t2) return true;

        var numericTypes = new HashSet<string> { "int", "long", "float", "double", "decimal", "short", "byte" };
        if (numericTypes.Contains(t1) && numericTypes.Contains(t2)) return true;

        // object can accept anything
        if (t1 == "object" || t2 == "object") return true;

        return false;
    }

    private bool IsCollectionType(string typeName)
    {
        return typeName.Contains("List") ||
               typeName.Contains("IEnumerable") ||
               typeName.Contains("ICollection") ||
               typeName.Contains("[]") ||
               typeName.Contains("Array") ||
               typeName.Contains("IReadOnlyList") ||
               typeName.Contains("IReadOnlyCollection");
    }

    private string GetCollectionPattern(string typeName)
    {
        if (typeName.Contains("IReadOnlyList")) return "IReadOnlyList";
        if (typeName.Contains("IReadOnlyCollection")) return "IReadOnlyCollection";
        if (typeName.Contains("IEnumerable")) return "IEnumerable";
        if (typeName.Contains("ICollection")) return "ICollection";
        if (typeName.Contains("List")) return "List";
        if (typeName.Contains("[]")) return "Array";
        return "Collection";
    }

    private bool ParametersMatch(List<string> p1, List<string> p2)
    {
        if (p1.Count != p2.Count) return false;

        for (int i = 0; i < p1.Count; i++)
        {
            var t1 = p1[i].Split(' ').First();
            var t2 = p2[i].Split(' ').First();
            if (t1 != t2) return false;
        }

        return true;
    }

    private bool IsGeneratedFile(string filePath)
    {
        var fileName = Path.GetFileName(filePath);
        return fileName.EndsWith(".g.cs") ||
               fileName.EndsWith(".Designer.cs") ||
               fileName.EndsWith(".generated.cs") ||
               filePath.Contains("obj" + Path.DirectorySeparatorChar);
    }
}
