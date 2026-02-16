using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Migration.Models;

namespace BaseScanner.Analyzers.Migration.Detectors;

/// <summary>
/// Detects usage of deprecated, obsolete, or migration-requiring APIs in C# code.
/// </summary>
public class DeprecatedApiDetector
{
    private readonly ApiMappingDatabase _mappingDatabase;

    public DeprecatedApiDetector(ApiMappingDatabase mappingDatabase)
    {
        _mappingDatabase = mappingDatabase;
    }

    /// <summary>
    /// Detects deprecated API usage in a document.
    /// </summary>
    public async Task<List<DeprecatedApiUsage>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root)
    {
        var usages = new List<DeprecatedApiUsage>();
        var filePath = document.FilePath ?? "";

        // Detect various forms of API usage
        usages.AddRange(DetectTypeReferences(root, semanticModel, filePath));
        usages.AddRange(DetectMethodInvocations(root, semanticModel, filePath));
        usages.AddRange(DetectPropertyAccess(root, semanticModel, filePath));
        usages.AddRange(DetectObjectCreations(root, semanticModel, filePath));
        usages.AddRange(DetectInheritance(root, semanticModel, filePath));
        usages.AddRange(DetectUsingDirectives(root, semanticModel, filePath));
        usages.AddRange(DetectAttributeUsage(root, semanticModel, filePath));

        return usages;
    }

    /// <summary>
    /// Detects deprecated API usage across a project.
    /// </summary>
    public async Task<List<DeprecatedApiUsage>> DetectInProjectAsync(Project project)
    {
        var allUsages = new List<DeprecatedApiUsage>();

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null) continue;
            if (document.FilePath.Contains(".Designer.cs")) continue;
            if (document.FilePath.Contains("\\obj\\")) continue;
            if (document.FilePath.Contains("/obj/")) continue;

            var syntaxRoot = await document.GetSyntaxRootAsync();
            var semanticModel = await document.GetSemanticModelAsync();
            if (syntaxRoot == null || semanticModel == null) continue;

            var usages = await DetectAsync(document, semanticModel, syntaxRoot);
            allUsages.AddRange(usages);
        }

        return allUsages;
    }

    private IEnumerable<DeprecatedApiUsage> DetectTypeReferences(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        // Find type references in variable declarations, parameters, return types
        var typeNodes = root.DescendantNodes()
            .OfType<TypeSyntax>()
            .Where(t => t is not PredefinedTypeSyntax); // Skip int, string, etc.

        foreach (var typeNode in typeNodes)
        {
            var typeInfo = semanticModel.GetTypeInfo(typeNode);
            var typeSymbol = typeInfo.Type;

            if (typeSymbol == null) continue;

            var fullTypeName = typeSymbol.ToDisplayString();
            var containingNamespace = typeSymbol.ContainingNamespace?.ToDisplayString() ?? "";

            // Check if this is a deprecated API
            if (_mappingDatabase.TryGetMapping(fullTypeName, out var mapping) ||
                _mappingDatabase.TryGetMapping(containingNamespace, out mapping))
            {
                var lineSpan = typeNode.GetLocation().GetLineSpan();
                var containingMember = GetContainingMember(typeNode);

                yield return new DeprecatedApiUsage
                {
                    Api = fullTypeName,
                    Mapping = mapping,
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = GetCodeSnippet(typeNode),
                    UsageType = "TypeReference",
                    ContainingType = GetContainingTypeName(typeNode, semanticModel),
                    ContainingMethod = containingMember
                };
            }
        }
    }

    private IEnumerable<DeprecatedApiUsage> DetectMethodInvocations(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in invocations)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(invocation);
            var methodSymbol = symbolInfo.Symbol as IMethodSymbol;

            if (methodSymbol == null) continue;

            var containingType = methodSymbol.ContainingType?.ToDisplayString() ?? "";
            var methodName = methodSymbol.Name;
            var fullMethodName = $"{containingType}.{methodName}";

            // Check for deprecated methods
            if (_mappingDatabase.TryGetMapping(fullMethodName, out var mapping) ||
                _mappingDatabase.TryGetMapping(containingType, out mapping))
            {
                var lineSpan = invocation.GetLocation().GetLineSpan();

                yield return new DeprecatedApiUsage
                {
                    Api = fullMethodName,
                    Mapping = mapping,
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = GetCodeSnippet(invocation),
                    UsageType = "MethodCall",
                    ContainingType = GetContainingTypeName(invocation, semanticModel),
                    ContainingMethod = GetContainingMember(invocation)
                };
            }

            // Also check for Obsolete attribute on the method itself
            if (HasObsoleteAttribute(methodSymbol))
            {
                var lineSpan = invocation.GetLocation().GetLineSpan();

                yield return new DeprecatedApiUsage
                {
                    Api = fullMethodName,
                    Mapping = null, // No mapping for custom obsolete methods
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = GetCodeSnippet(invocation),
                    UsageType = "ObsoleteMethodCall",
                    ContainingType = GetContainingTypeName(invocation, semanticModel),
                    ContainingMethod = GetContainingMember(invocation)
                };
            }
        }
    }

    private IEnumerable<DeprecatedApiUsage> DetectPropertyAccess(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var memberAccesses = root.DescendantNodes().OfType<MemberAccessExpressionSyntax>();

        foreach (var memberAccess in memberAccesses)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(memberAccess);
            var symbol = symbolInfo.Symbol;

            if (symbol == null) continue;

            var containingType = symbol.ContainingType?.ToDisplayString() ?? "";
            var memberName = symbol.Name;
            var fullMemberName = $"{containingType}.{memberName}";

            // Check for deprecated properties/fields
            if (symbol is IPropertySymbol or IFieldSymbol)
            {
                if (_mappingDatabase.TryGetMapping(fullMemberName, out var mapping) ||
                    _mappingDatabase.TryGetMapping(containingType, out mapping))
                {
                    var lineSpan = memberAccess.GetLocation().GetLineSpan();

                    yield return new DeprecatedApiUsage
                    {
                        Api = fullMemberName,
                        Mapping = mapping,
                        FilePath = filePath,
                        Line = lineSpan.StartLinePosition.Line + 1,
                        Column = lineSpan.StartLinePosition.Character + 1,
                        CodeSnippet = GetCodeSnippet(memberAccess),
                        UsageType = "PropertyAccess",
                        ContainingType = GetContainingTypeName(memberAccess, semanticModel),
                        ContainingMethod = GetContainingMember(memberAccess)
                    };
                }

                // Check for Obsolete attribute
                if (HasObsoleteAttribute(symbol))
                {
                    var lineSpan = memberAccess.GetLocation().GetLineSpan();

                    yield return new DeprecatedApiUsage
                    {
                        Api = fullMemberName,
                        Mapping = null,
                        FilePath = filePath,
                        Line = lineSpan.StartLinePosition.Line + 1,
                        Column = lineSpan.StartLinePosition.Character + 1,
                        CodeSnippet = GetCodeSnippet(memberAccess),
                        UsageType = "ObsoletePropertyAccess",
                        ContainingType = GetContainingTypeName(memberAccess, semanticModel),
                        ContainingMethod = GetContainingMember(memberAccess)
                    };
                }
            }
        }
    }

    private IEnumerable<DeprecatedApiUsage> DetectObjectCreations(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var creations = root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();

        foreach (var creation in creations)
        {
            var typeInfo = semanticModel.GetTypeInfo(creation);
            var typeSymbol = typeInfo.Type;

            if (typeSymbol == null) continue;

            var fullTypeName = typeSymbol.ToDisplayString();

            if (_mappingDatabase.TryGetMapping(fullTypeName, out var mapping))
            {
                var lineSpan = creation.GetLocation().GetLineSpan();

                yield return new DeprecatedApiUsage
                {
                    Api = fullTypeName,
                    Mapping = mapping,
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = GetCodeSnippet(creation),
                    UsageType = "ObjectCreation",
                    ContainingType = GetContainingTypeName(creation, semanticModel),
                    ContainingMethod = GetContainingMember(creation)
                };
            }

            // Check for Obsolete attribute on the type
            if (HasObsoleteAttribute(typeSymbol))
            {
                var lineSpan = creation.GetLocation().GetLineSpan();

                yield return new DeprecatedApiUsage
                {
                    Api = fullTypeName,
                    Mapping = null,
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = GetCodeSnippet(creation),
                    UsageType = "ObsoleteTypeCreation",
                    ContainingType = GetContainingTypeName(creation, semanticModel),
                    ContainingMethod = GetContainingMember(creation)
                };
            }
        }
    }

    private IEnumerable<DeprecatedApiUsage> DetectInheritance(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var typeDeclarations = root.DescendantNodes().OfType<TypeDeclarationSyntax>();

        foreach (var typeDecl in typeDeclarations)
        {
            if (typeDecl.BaseList == null) continue;

            foreach (var baseType in typeDecl.BaseList.Types)
            {
                var typeInfo = semanticModel.GetTypeInfo(baseType.Type);
                var typeSymbol = typeInfo.Type;

                if (typeSymbol == null) continue;

                var fullTypeName = typeSymbol.ToDisplayString();

                if (_mappingDatabase.TryGetMapping(fullTypeName, out var mapping))
                {
                    var lineSpan = baseType.GetLocation().GetLineSpan();

                    yield return new DeprecatedApiUsage
                    {
                        Api = fullTypeName,
                        Mapping = mapping,
                        FilePath = filePath,
                        Line = lineSpan.StartLinePosition.Line + 1,
                        Column = lineSpan.StartLinePosition.Character + 1,
                        CodeSnippet = GetCodeSnippet(typeDecl),
                        UsageType = "Inheritance",
                        ContainingType = GetContainingTypeName(typeDecl, semanticModel),
                        ContainingMethod = null
                    };
                }
            }
        }
    }

    private IEnumerable<DeprecatedApiUsage> DetectUsingDirectives(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var usingDirectives = root.DescendantNodes().OfType<UsingDirectiveSyntax>();

        foreach (var usingDirective in usingDirectives)
        {
            var namespaceName = usingDirective.Name?.ToString() ?? "";

            if (_mappingDatabase.TryGetMapping(namespaceName, out var mapping))
            {
                var lineSpan = usingDirective.GetLocation().GetLineSpan();

                yield return new DeprecatedApiUsage
                {
                    Api = namespaceName,
                    Mapping = mapping,
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = usingDirective.ToString().Trim(),
                    UsageType = "UsingDirective",
                    ContainingType = null,
                    ContainingMethod = null
                };
            }
        }
    }

    private IEnumerable<DeprecatedApiUsage> DetectAttributeUsage(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var attributes = root.DescendantNodes().OfType<AttributeSyntax>();

        foreach (var attribute in attributes)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(attribute);
            var attributeSymbol = symbolInfo.Symbol?.ContainingType;

            if (attributeSymbol == null) continue;

            var fullTypeName = attributeSymbol.ToDisplayString();

            if (_mappingDatabase.TryGetMapping(fullTypeName, out var mapping))
            {
                var lineSpan = attribute.GetLocation().GetLineSpan();

                yield return new DeprecatedApiUsage
                {
                    Api = fullTypeName,
                    Mapping = mapping,
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = GetCodeSnippet(attribute),
                    UsageType = "AttributeUsage",
                    ContainingType = GetContainingTypeName(attribute, semanticModel),
                    ContainingMethod = GetContainingMember(attribute)
                };
            }
        }
    }

    private static bool HasObsoleteAttribute(ISymbol symbol)
    {
        return symbol.GetAttributes().Any(attr =>
            attr.AttributeClass?.Name == "ObsoleteAttribute" ||
            attr.AttributeClass?.ToDisplayString() == "System.ObsoleteAttribute");
    }

    private static string GetCodeSnippet(SyntaxNode node)
    {
        // Get the containing statement or declaration for context
        var statement = node.AncestorsAndSelf()
            .FirstOrDefault(n => n is StatementSyntax or MemberDeclarationSyntax or UsingDirectiveSyntax);

        var text = (statement ?? node).ToString();

        // Limit length and clean up
        if (text.Length > 200)
        {
            text = text.Substring(0, 197) + "...";
        }

        return text.Replace("\r\n", " ").Replace("\n", " ").Trim();
    }

    private static string? GetContainingTypeName(SyntaxNode node, SemanticModel semanticModel)
    {
        var typeDecl = node.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault();
        if (typeDecl == null) return null;

        var symbol = semanticModel.GetDeclaredSymbol(typeDecl);
        return symbol?.ToDisplayString();
    }

    private static string? GetContainingMember(SyntaxNode node)
    {
        var member = node.Ancestors()
            .FirstOrDefault(n => n is MethodDeclarationSyntax or PropertyDeclarationSyntax or ConstructorDeclarationSyntax);

        return member switch
        {
            MethodDeclarationSyntax method => method.Identifier.Text,
            PropertyDeclarationSyntax prop => prop.Identifier.Text,
            ConstructorDeclarationSyntax ctor => ".ctor",
            _ => null
        };
    }

    /// <summary>
    /// Groups detected usages by API for summary reporting.
    /// </summary>
    public static Dictionary<string, List<DeprecatedApiUsage>> GroupByApi(List<DeprecatedApiUsage> usages)
    {
        return usages.GroupBy(u => u.Api)
            .ToDictionary(g => g.Key, g => g.ToList());
    }

    /// <summary>
    /// Groups detected usages by category.
    /// </summary>
    public static Dictionary<string, List<DeprecatedApiUsage>> GroupByCategory(List<DeprecatedApiUsage> usages)
    {
        return usages
            .Where(u => u.Mapping != null)
            .GroupBy(u => u.Mapping!.Category)
            .ToDictionary(g => g.Key, g => g.ToList());
    }

    /// <summary>
    /// Gets security risk usages.
    /// </summary>
    public List<DeprecatedApiUsage> GetSecurityRisks(List<DeprecatedApiUsage> usages)
    {
        return usages
            .Where(u => u.Mapping?.IsSecurityRisk == true || _mappingDatabase.IsSecurityRisk(u.Api))
            .ToList();
    }

    /// <summary>
    /// Gets blocking issues.
    /// </summary>
    public List<DeprecatedApiUsage> GetBlockingIssues(List<DeprecatedApiUsage> usages)
    {
        return usages
            .Where(u => u.Mapping?.IsBlockingIssue == true || _mappingDatabase.IsBlockingIssue(u.Api))
            .ToList();
    }
}
