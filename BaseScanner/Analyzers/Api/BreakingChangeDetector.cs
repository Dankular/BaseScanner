using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Api.Models;

namespace BaseScanner.Analyzers.Api;

/// <summary>
/// Detects potential breaking changes in public API surface.
/// Analyzes code patterns that could break consumers if modified.
/// </summary>
public class BreakingChangeDetector
{
    public async Task<List<BreakingChange>> AnalyzeAsync(Project project)
    {
        var breakingChanges = new List<BreakingChange>();
        var publicApiSurface = new List<PublicApiSurface>();

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null) continue;
            if (IsGeneratedFile(document.FilePath)) continue;

            var root = await document.GetSyntaxRootAsync();
            var semanticModel = await document.GetSemanticModelAsync();
            if (root == null || semanticModel == null) continue;

            // Collect public API surface
            var apiElements = CollectPublicApiSurface(root, semanticModel, document.FilePath);
            publicApiSurface.AddRange(apiElements);

            // Analyze for breaking change risks
            breakingChanges.AddRange(AnalyzeBreakingChangeRisks(root, semanticModel, document.FilePath));
        }

        // Analyze cross-cutting concerns
        breakingChanges.AddRange(AnalyzeCrossFileConcerns(publicApiSurface));

        return breakingChanges
            .OrderByDescending(bc => GetSeverityOrder(bc.Severity))
            .ThenBy(bc => bc.FilePath)
            .ToList();
    }

    private List<PublicApiSurface> CollectPublicApiSurface(SyntaxNode root, SemanticModel model, string filePath)
    {
        var surface = new List<PublicApiSurface>();

        // Find public types
        var publicTypes = root.DescendantNodes()
            .OfType<TypeDeclarationSyntax>()
            .Where(t => t.Modifiers.Any(SyntaxKind.PublicKeyword));

        foreach (var type in publicTypes)
        {
            var typeSymbol = model.GetDeclaredSymbol(type);
            if (typeSymbol == null) continue;

            // Add the type itself
            surface.Add(new PublicApiSurface
            {
                TypeName = typeSymbol.Name,
                Namespace = typeSymbol.ContainingNamespace?.ToDisplayString() ?? "",
                FilePath = filePath,
                Line = type.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                ElementType = GetApiElementType(type),
                Signature = GetTypeSignature(type, typeSymbol),
                Accessibility = typeSymbol.DeclaredAccessibility,
                IsVirtual = false,
                IsSealed = type.Modifiers.Any(SyntaxKind.SealedKeyword),
                IsAbstract = type.Modifiers.Any(SyntaxKind.AbstractKeyword),
                IsObsolete = HasObsoleteAttribute(type),
                ObsoleteMessage = GetObsoleteMessage(type),
                Interfaces = typeSymbol.Interfaces.Select(i => i.ToDisplayString()).ToList(),
                BaseType = typeSymbol.BaseType?.ToDisplayString()
            });

            // Add public members
            foreach (var member in type.Members)
            {
                if (!IsPublicMember(member)) continue;

                var memberSurface = CreateMemberSurface(member, model, filePath, typeSymbol.Name);
                if (memberSurface != null)
                {
                    surface.Add(memberSurface);
                }
            }
        }

        return surface;
    }

    private PublicApiSurface? CreateMemberSurface(MemberDeclarationSyntax member, SemanticModel model,
        string filePath, string typeName)
    {
        var symbol = model.GetDeclaredSymbol(member);
        if (symbol == null) return null;

        return member switch
        {
            MethodDeclarationSyntax method => new PublicApiSurface
            {
                TypeName = typeName,
                Namespace = symbol.ContainingNamespace?.ToDisplayString() ?? "",
                FilePath = filePath,
                Line = method.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                ElementType = ApiElementType.Method,
                Signature = symbol.ToDisplayString(),
                Accessibility = symbol.DeclaredAccessibility,
                IsVirtual = method.Modifiers.Any(SyntaxKind.VirtualKeyword),
                IsSealed = method.Modifiers.Any(SyntaxKind.SealedKeyword),
                IsAbstract = method.Modifiers.Any(SyntaxKind.AbstractKeyword),
                IsObsolete = HasObsoleteAttribute(method),
                ObsoleteMessage = GetObsoleteMessage(method)
            },

            PropertyDeclarationSyntax prop => new PublicApiSurface
            {
                TypeName = typeName,
                Namespace = symbol.ContainingNamespace?.ToDisplayString() ?? "",
                FilePath = filePath,
                Line = prop.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                ElementType = ApiElementType.Property,
                Signature = symbol.ToDisplayString(),
                Accessibility = symbol.DeclaredAccessibility,
                IsVirtual = prop.Modifiers.Any(SyntaxKind.VirtualKeyword),
                IsSealed = prop.Modifiers.Any(SyntaxKind.SealedKeyword),
                IsAbstract = prop.Modifiers.Any(SyntaxKind.AbstractKeyword),
                IsObsolete = HasObsoleteAttribute(prop),
                ObsoleteMessage = GetObsoleteMessage(prop)
            },

            EventDeclarationSyntax evt => new PublicApiSurface
            {
                TypeName = typeName,
                Namespace = symbol.ContainingNamespace?.ToDisplayString() ?? "",
                FilePath = filePath,
                Line = evt.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                ElementType = ApiElementType.Event,
                Signature = symbol.ToDisplayString(),
                Accessibility = symbol.DeclaredAccessibility,
                IsObsolete = HasObsoleteAttribute(evt)
            },

            FieldDeclarationSyntax field => new PublicApiSurface
            {
                TypeName = typeName,
                Namespace = symbol.ContainingNamespace?.ToDisplayString() ?? "",
                FilePath = filePath,
                Line = field.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                ElementType = ApiElementType.Field,
                Signature = symbol.ToDisplayString(),
                Accessibility = symbol.DeclaredAccessibility,
                IsObsolete = HasObsoleteAttribute(field)
            },

            ConstructorDeclarationSyntax ctor => new PublicApiSurface
            {
                TypeName = typeName,
                Namespace = symbol.ContainingNamespace?.ToDisplayString() ?? "",
                FilePath = filePath,
                Line = ctor.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                ElementType = ApiElementType.Constructor,
                Signature = symbol.ToDisplayString(),
                Accessibility = symbol.DeclaredAccessibility,
                IsObsolete = HasObsoleteAttribute(ctor)
            },

            _ => null
        };
    }

    private List<BreakingChange> AnalyzeBreakingChangeRisks(SyntaxNode root, SemanticModel model, string filePath)
    {
        var risks = new List<BreakingChange>();

        // Find public types
        var publicTypes = root.DescendantNodes()
            .OfType<TypeDeclarationSyntax>()
            .Where(t => t.Modifiers.Any(SyntaxKind.PublicKeyword));

        foreach (var type in publicTypes)
        {
            var typeSymbol = model.GetDeclaredSymbol(type);
            if (typeSymbol == null) continue;

            // Check for sealed classes that implement interfaces (hard to extend)
            if (type.Modifiers.Any(SyntaxKind.SealedKeyword) && typeSymbol.Interfaces.Any())
            {
                risks.Add(new BreakingChange
                {
                    ChangeType = BreakingChangeType.SealedClass,
                    Severity = "Medium",
                    AffectedMember = typeSymbol.ToDisplayString(),
                    Description = $"Sealed class '{typeSymbol.Name}' with interfaces prevents consumers from providing alternative implementations",
                    FilePath = filePath,
                    Line = type.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                    CurrentState = "sealed " + typeSymbol.Name,
                    Mitigation = "Consider making the class unsealed or providing a factory/DI pattern"
                });
            }

            // Check methods for breaking change risks
            foreach (var method in type.Members.OfType<MethodDeclarationSyntax>())
            {
                if (!method.Modifiers.Any(SyntaxKind.PublicKeyword)) continue;

                var methodSymbol = model.GetDeclaredSymbol(method);
                if (methodSymbol == null) continue;

                risks.AddRange(AnalyzeMethodBreakingRisks(method, methodSymbol, filePath, typeSymbol.Name));
            }

            // Check properties
            foreach (var prop in type.Members.OfType<PropertyDeclarationSyntax>())
            {
                if (!prop.Modifiers.Any(SyntaxKind.PublicKeyword)) continue;

                var propSymbol = model.GetDeclaredSymbol(prop);
                if (propSymbol == null) continue;

                risks.AddRange(AnalyzePropertyBreakingRisks(prop, propSymbol, filePath, typeSymbol.Name));
            }

            // Check for obsolete without replacement
            if (HasObsoleteAttribute(type))
            {
                var obsoleteMsg = GetObsoleteMessage(type);
                if (string.IsNullOrEmpty(obsoleteMsg) || !obsoleteMsg.Contains("use", StringComparison.OrdinalIgnoreCase))
                {
                    risks.Add(new BreakingChange
                    {
                        ChangeType = BreakingChangeType.RemovedPublicMember,
                        Severity = "Medium",
                        AffectedMember = typeSymbol.ToDisplayString(),
                        Description = $"Type '{typeSymbol.Name}' is marked obsolete without indicating replacement",
                        FilePath = filePath,
                        Line = type.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        CurrentState = $"[Obsolete(\"{obsoleteMsg ?? ""}\")]",
                        Mitigation = "Add replacement guidance to the Obsolete message"
                    });
                }
            }
        }

        // Check for interfaces
        foreach (var iface in root.DescendantNodes().OfType<InterfaceDeclarationSyntax>())
        {
            if (!iface.Modifiers.Any(SyntaxKind.PublicKeyword)) continue;

            var ifaceSymbol = model.GetDeclaredSymbol(iface);
            if (ifaceSymbol == null) continue;

            risks.AddRange(AnalyzeInterfaceBreakingRisks(iface, ifaceSymbol, filePath));
        }

        return risks;
    }

    private List<BreakingChange> AnalyzeMethodBreakingRisks(MethodDeclarationSyntax method,
        IMethodSymbol methodSymbol, string filePath, string typeName)
    {
        var risks = new List<BreakingChange>();
        var line = method.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

        // Virtual method without sealed - high breaking change risk if removed
        if (method.Modifiers.Any(SyntaxKind.VirtualKeyword))
        {
            risks.Add(new BreakingChange
            {
                ChangeType = BreakingChangeType.RemovedVirtual,
                Severity = "High",
                AffectedMember = methodSymbol.ToDisplayString(),
                Description = $"Virtual method '{methodSymbol.Name}' - removing virtual modifier would break derived classes",
                FilePath = filePath,
                Line = line,
                CurrentState = "virtual",
                Mitigation = "Mark as obsolete before removing virtual, or keep virtual"
            });
        }

        // Check for exception documentation vs. implementation
        var throwStatements = method.DescendantNodes().OfType<ThrowStatementSyntax>().ToList();
        var throwExpressions = method.DescendantNodes().OfType<ThrowExpressionSyntax>().ToList();
        var hasThrows = throwStatements.Any() || throwExpressions.Any();
        var hasExceptionDoc = method.GetLeadingTrivia()
            .Any(t => t.ToString().Contains("<exception"));

        if (hasThrows && !hasExceptionDoc)
        {
            risks.Add(new BreakingChange
            {
                ChangeType = BreakingChangeType.ChangedException,
                Severity = "Low",
                AffectedMember = methodSymbol.ToDisplayString(),
                Description = $"Method '{methodSymbol.Name}' throws exceptions but lacks XML documentation for them",
                FilePath = filePath,
                Line = line,
                Mitigation = "Document thrown exceptions with <exception> tags"
            });
        }

        // Check for params array - removing would break callers
        if (methodSymbol.Parameters.Any(p => p.IsParams))
        {
            risks.Add(new BreakingChange
            {
                ChangeType = BreakingChangeType.RemovedOptionalParameter,
                Severity = "Medium",
                AffectedMember = methodSymbol.ToDisplayString(),
                Description = $"Method '{methodSymbol.Name}' uses params - removing it would break existing callers",
                FilePath = filePath,
                Line = line,
                CurrentState = "params array",
                Mitigation = "Keep params or add overload accepting array"
            });
        }

        // Check for optional parameters
        var optionalParams = methodSymbol.Parameters.Where(p => p.HasExplicitDefaultValue).ToList();
        if (optionalParams.Any())
        {
            risks.Add(new BreakingChange
            {
                ChangeType = BreakingChangeType.RemovedOptionalParameter,
                Severity = "Low",
                AffectedMember = methodSymbol.ToDisplayString(),
                Description = $"Method '{methodSymbol.Name}' has {optionalParams.Count} optional parameter(s) - removing or reordering would break callers",
                FilePath = filePath,
                Line = line,
                CurrentState = string.Join(", ", optionalParams.Select(p => $"{p.Name} = {p.ExplicitDefaultValue}")),
                Mitigation = "Keep optional parameters or add overloads"
            });
        }

        // Check for generic type parameters with constraints
        if (methodSymbol.TypeParameters.Any(tp => tp.ConstraintTypes.Any()))
        {
            risks.Add(new BreakingChange
            {
                ChangeType = BreakingChangeType.ChangedSignature,
                Severity = "Medium",
                AffectedMember = methodSymbol.ToDisplayString(),
                Description = $"Method '{methodSymbol.Name}' has generic constraints - changing them would break callers",
                FilePath = filePath,
                Line = line,
                CurrentState = string.Join(", ", methodSymbol.TypeParameters
                    .Where(tp => tp.ConstraintTypes.Any())
                    .Select(tp => $"where {tp.Name}: {string.Join(", ", tp.ConstraintTypes.Select(c => c.Name))}")),
                Mitigation = "Only loosen constraints, never tighten"
            });
        }

        return risks;
    }

    private List<BreakingChange> AnalyzePropertyBreakingRisks(PropertyDeclarationSyntax prop,
        IPropertySymbol propSymbol, string filePath, string typeName)
    {
        var risks = new List<BreakingChange>();
        var line = prop.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

        // Check for settable properties that might become read-only
        if (propSymbol.SetMethod != null && propSymbol.SetMethod.DeclaredAccessibility == Accessibility.Public)
        {
            risks.Add(new BreakingChange
            {
                ChangeType = BreakingChangeType.ChangedSignature,
                Severity = "Medium",
                AffectedMember = propSymbol.ToDisplayString(),
                Description = $"Public settable property '{propSymbol.Name}' - making it read-only would break consumers",
                FilePath = filePath,
                Line = line,
                CurrentState = "public setter",
                Mitigation = "Keep setter or mark as obsolete first"
            });
        }

        // Virtual property
        if (prop.Modifiers.Any(SyntaxKind.VirtualKeyword))
        {
            risks.Add(new BreakingChange
            {
                ChangeType = BreakingChangeType.RemovedVirtual,
                Severity = "Medium",
                AffectedMember = propSymbol.ToDisplayString(),
                Description = $"Virtual property '{propSymbol.Name}' - removing virtual would break derived classes",
                FilePath = filePath,
                Line = line,
                CurrentState = "virtual",
                Mitigation = "Keep virtual or mark obsolete first"
            });
        }

        return risks;
    }

    private List<BreakingChange> AnalyzeInterfaceBreakingRisks(InterfaceDeclarationSyntax iface,
        INamedTypeSymbol ifaceSymbol, string filePath)
    {
        var risks = new List<BreakingChange>();
        var line = iface.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

        // Any change to interface is potentially breaking
        var memberCount = iface.Members.Count;
        if (memberCount > 0)
        {
            risks.Add(new BreakingChange
            {
                ChangeType = BreakingChangeType.RemovedInterface,
                Severity = "Critical",
                AffectedMember = ifaceSymbol.ToDisplayString(),
                Description = $"Interface '{ifaceSymbol.Name}' has {memberCount} members - adding or removing any member is a breaking change",
                FilePath = filePath,
                Line = line,
                CurrentState = $"{memberCount} members",
                Mitigation = "Use default interface implementations (C# 8+) for additions, or create new interface version"
            });
        }

        // Check for default interface implementations
        var hasDefaultImpls = iface.Members
            .OfType<MethodDeclarationSyntax>()
            .Any(m => m.Body != null || m.ExpressionBody != null);

        if (!hasDefaultImpls && memberCount > 5)
        {
            risks.Add(new BreakingChange
            {
                ChangeType = BreakingChangeType.RemovedInterface,
                Severity = "Medium",
                AffectedMember = ifaceSymbol.ToDisplayString(),
                Description = $"Large interface '{ifaceSymbol.Name}' without default implementations - consider splitting",
                FilePath = filePath,
                Line = line,
                Mitigation = "Consider interface segregation principle - split into smaller interfaces"
            });
        }

        return risks;
    }

    private List<BreakingChange> AnalyzeCrossFileConcerns(List<PublicApiSurface> surface)
    {
        var risks = new List<BreakingChange>();

        // Group by namespace to find potential naming conflicts
        var byNamespace = surface.GroupBy(s => s.Namespace);

        foreach (var nsGroup in byNamespace)
        {
            // Find overloaded methods across different classes in same namespace
            var methods = nsGroup
                .Where(s => s.ElementType == ApiElementType.Method)
                .GroupBy(s => s.TypeName)
                .Where(g => g.Count() > 1);

            // Look for inconsistent patterns
            var classPatterns = nsGroup
                .Where(s => s.ElementType == ApiElementType.Class || s.ElementType == ApiElementType.Interface)
                .ToList();

            // Check for mix of sealed and unsealed similar classes
            var sealedClasses = classPatterns.Where(c => c.IsSealed).ToList();
            var unsealedClasses = classPatterns.Where(c => !c.IsSealed && c.ElementType == ApiElementType.Class).ToList();

            if (sealedClasses.Any() && unsealedClasses.Any())
            {
                // Check if they follow similar naming patterns
                var sealedNames = sealedClasses.Select(c => c.TypeName).ToList();
                var unsealedNames = unsealedClasses.Select(c => c.TypeName).ToList();

                // Simple heuristic: if similar suffixes, might be inconsistent
                var sealedSuffixes = sealedNames.Select(n => n.Length > 4 ? n[^4..] : n).Distinct().ToList();
                var unsealedSuffixes = unsealedNames.Select(n => n.Length > 4 ? n[^4..] : n).Distinct().ToList();

                var commonSuffixes = sealedSuffixes.Intersect(unsealedSuffixes).ToList();
                if (commonSuffixes.Any())
                {
                    risks.Add(new BreakingChange
                    {
                        ChangeType = BreakingChangeType.SealedClass,
                        Severity = "Low",
                        AffectedMember = nsGroup.Key ?? "Unknown",
                        Description = $"Namespace has inconsistent sealed/unsealed pattern for similar classes",
                        FilePath = sealedClasses.First().FilePath,
                        Line = sealedClasses.First().Line,
                        CurrentState = $"Sealed: {string.Join(", ", sealedNames.Take(3))}; Unsealed: {string.Join(", ", unsealedNames.Take(3))}",
                        Mitigation = "Consider consistent sealing strategy across similar types"
                    });
                }
            }
        }

        return risks;
    }

    private ApiElementType GetApiElementType(TypeDeclarationSyntax type) => type switch
    {
        ClassDeclarationSyntax => ApiElementType.Class,
        InterfaceDeclarationSyntax => ApiElementType.Interface,
        StructDeclarationSyntax => ApiElementType.Struct,
        RecordDeclarationSyntax => ApiElementType.Record,
        _ => ApiElementType.Class
    };

    private string GetTypeSignature(TypeDeclarationSyntax type, INamedTypeSymbol symbol)
    {
        var modifiers = string.Join(" ", type.Modifiers.Select(m => m.Text));
        var keyword = type switch
        {
            ClassDeclarationSyntax => "class",
            InterfaceDeclarationSyntax => "interface",
            StructDeclarationSyntax => "struct",
            RecordDeclarationSyntax => "record",
            _ => "type"
        };
        return $"{modifiers} {keyword} {symbol.ToDisplayString()}".Trim();
    }

    private bool IsPublicMember(MemberDeclarationSyntax member) => member switch
    {
        MethodDeclarationSyntax m => m.Modifiers.Any(SyntaxKind.PublicKeyword),
        PropertyDeclarationSyntax p => p.Modifiers.Any(SyntaxKind.PublicKeyword),
        FieldDeclarationSyntax f => f.Modifiers.Any(SyntaxKind.PublicKeyword),
        EventDeclarationSyntax e => e.Modifiers.Any(SyntaxKind.PublicKeyword),
        ConstructorDeclarationSyntax c => c.Modifiers.Any(SyntaxKind.PublicKeyword),
        _ => false
    };

    private bool HasObsoleteAttribute(SyntaxNode node)
    {
        if (node is MemberDeclarationSyntax member)
        {
            return member.AttributeLists
                .SelectMany(al => al.Attributes)
                .Any(a => a.Name.ToString().Contains("Obsolete"));
        }
        return false;
    }

    private string? GetObsoleteMessage(SyntaxNode node)
    {
        if (node is MemberDeclarationSyntax member)
        {
            var obsoleteAttr = member.AttributeLists
                .SelectMany(al => al.Attributes)
                .FirstOrDefault(a => a.Name.ToString().Contains("Obsolete"));

            if (obsoleteAttr?.ArgumentList?.Arguments.FirstOrDefault() is { } arg)
            {
                return arg.ToString().Trim('"');
            }
        }
        return null;
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
}
