using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;
using BaseScanner.Analyzers.Documentation.Models;
using System.Xml.Linq;

namespace BaseScanner.Analyzers.Documentation.Detectors;

/// <summary>
/// Detects missing XML documentation on public APIs.
/// Checks for missing summary, parameter, return, and exception documentation.
/// </summary>
public class MissingDocDetector : DocDetectorBase
{
    public override DocIssueCategory Category => DocIssueCategory.MissingDocumentation;
    public override string Name => "Missing Documentation Detector";
    public override string Description => "Detects missing XML documentation on public types, methods, properties, and parameters.";

    public override async Task<List<DocumentationIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext? context = null)
    {
        var issues = new List<DocumentationIssue>();
        var filePath = document.FilePath ?? "";

        // Check types (classes, interfaces, structs, records, enums)
        issues.AddRange(await CheckTypesAsync(root, semanticModel, filePath));

        // Check methods
        issues.AddRange(await CheckMethodsAsync(root, semanticModel, filePath));

        // Check properties
        issues.AddRange(await CheckPropertiesAsync(root, semanticModel, filePath));

        // Check events
        issues.AddRange(await CheckEventsAsync(root, semanticModel, filePath));

        // Check delegates
        issues.AddRange(await CheckDelegatesAsync(root, semanticModel, filePath));

        return issues;
    }

    private Task<List<DocumentationIssue>> CheckTypesAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        var typeDeclarations = root.DescendantNodes()
            .OfType<TypeDeclarationSyntax>()
            .Where(t => IsPublicDeclaration(t.Modifiers));

        foreach (var typeDecl in typeDeclarations)
        {
            var symbol = semanticModel.GetDeclaredSymbol(typeDecl);
            if (symbol == null || !IsPubliclyVisible(symbol)) continue;

            var (startLine, endLine) = GetLineSpan(typeDecl.Identifier);
            var typeName = typeDecl.Identifier.Text;
            var typeKind = GetTypeKindName(typeDecl);

            // Check for missing summary
            if (!HasXmlDocumentation(symbol))
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MissingPublicDoc,
                    DocIssueSeverity.Major,
                    filePath,
                    startLine,
                    endLine,
                    typeName,
                    typeKind,
                    $"Public {typeKind.ToLower()} '{typeName}' lacks XML documentation",
                    $"Add XML documentation with <summary> describing the purpose of {typeName}",
                    currentCode: typeDecl.ToFullString().Split('\n').FirstOrDefault()?.Trim() ?? "",
                    suggestedCode: GenerateSuggestedTypeDoc(typeName, typeKind)));
            }
            else
            {
                // Check type parameters
                issues.AddRange(CheckTypeParameters(typeDecl, symbol, filePath, startLine, typeName, typeKind));
            }
        }

        // Check enum declarations separately
        var enumDeclarations = root.DescendantNodes()
            .OfType<EnumDeclarationSyntax>()
            .Where(e => IsPublicDeclaration(e.Modifiers));

        foreach (var enumDecl in enumDeclarations)
        {
            var symbol = semanticModel.GetDeclaredSymbol(enumDecl);
            if (symbol == null || !IsPubliclyVisible(symbol)) continue;

            var (startLine, endLine) = GetLineSpan(enumDecl.Identifier);
            var enumName = enumDecl.Identifier.Text;

            if (!HasXmlDocumentation(symbol))
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MissingPublicDoc,
                    DocIssueSeverity.Major,
                    filePath,
                    startLine,
                    endLine,
                    enumName,
                    "Enum",
                    $"Public enum '{enumName}' lacks XML documentation",
                    $"Add XML documentation with <summary> describing the enum values",
                    suggestedCode: $"/// <summary>\n/// Defines the types of {enumName.ToLower()}.\n/// </summary>"));
            }
        }

        return Task.FromResult(issues);
    }

    private Task<List<DocumentationIssue>> CheckMethodsAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        var methods = root.DescendantNodes()
            .OfType<MethodDeclarationSyntax>()
            .Where(m => IsPublicDeclaration(m.Modifiers));

        foreach (var method in methods)
        {
            var symbol = semanticModel.GetDeclaredSymbol(method);
            if (symbol == null || !IsPubliclyVisible(symbol)) continue;

            var (startLine, endLine) = GetLineSpan(method.Identifier);
            var methodName = method.Identifier.Text;

            // Check for missing summary
            if (!HasXmlDocumentation(symbol))
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MissingPublicDoc,
                    DocIssueSeverity.Major,
                    filePath,
                    startLine,
                    endLine,
                    methodName,
                    "Method",
                    $"Public method '{methodName}' lacks XML documentation",
                    "Add XML documentation with <summary>, <param>, and <returns> tags",
                    suggestedCode: GenerateSuggestedMethodDoc(method, symbol)));
            }
            else
            {
                // Check for missing parameter documentation
                issues.AddRange(CheckParameterDocumentation(method, symbol, filePath, startLine));

                // Check for missing return documentation
                if (!symbol.ReturnsVoid && !method.ReturnType.ToString().Equals("void", StringComparison.OrdinalIgnoreCase))
                {
                    var xmlDoc = symbol.GetDocumentationCommentXml();
                    if (!string.IsNullOrEmpty(xmlDoc) && !xmlDoc.Contains("<returns>"))
                    {
                        issues.Add(CreateIssue(
                            DocumentationIssueType.MissingReturnDoc,
                            DocIssueSeverity.Minor,
                            filePath,
                            startLine,
                            endLine,
                            methodName,
                            "Method",
                            $"Method '{methodName}' returns '{method.ReturnType}' but has no <returns> documentation",
                            $"Add <returns> tag describing what the method returns",
                            suggestedCode: $"/// <returns>The {GetReturnDescription(method.ReturnType.ToString())}.</returns>"));
                    }
                }

                // Check type parameters
                issues.AddRange(CheckMethodTypeParameters(method, symbol, filePath, startLine, methodName));
            }
        }

        // Check constructors
        var constructors = root.DescendantNodes()
            .OfType<ConstructorDeclarationSyntax>()
            .Where(c => IsPublicDeclaration(c.Modifiers));

        foreach (var ctor in constructors)
        {
            var symbol = semanticModel.GetDeclaredSymbol(ctor);
            if (symbol == null || !IsPubliclyVisible(symbol)) continue;

            var (startLine, endLine) = GetLineSpan(ctor.Identifier);
            var ctorName = ctor.Identifier.Text;

            if (!HasXmlDocumentation(symbol))
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MissingPublicDoc,
                    DocIssueSeverity.Minor,
                    filePath,
                    startLine,
                    endLine,
                    ctorName,
                    "Constructor",
                    $"Public constructor '{ctorName}' lacks XML documentation",
                    "Add XML documentation describing the constructor and its parameters",
                    suggestedCode: GenerateSuggestedConstructorDoc(ctor)));
            }
            else
            {
                issues.AddRange(CheckConstructorParameterDocumentation(ctor, symbol, filePath, startLine));
            }
        }

        return Task.FromResult(issues);
    }

    private Task<List<DocumentationIssue>> CheckPropertiesAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        var properties = root.DescendantNodes()
            .OfType<PropertyDeclarationSyntax>()
            .Where(p => IsPublicDeclaration(p.Modifiers));

        foreach (var property in properties)
        {
            var symbol = semanticModel.GetDeclaredSymbol(property);
            if (symbol == null || !IsPubliclyVisible(symbol)) continue;

            var (startLine, endLine) = GetLineSpan(property.Identifier);
            var propName = property.Identifier.Text;

            if (!HasXmlDocumentation(symbol))
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MissingPublicDoc,
                    DocIssueSeverity.Minor,
                    filePath,
                    startLine,
                    endLine,
                    propName,
                    "Property",
                    $"Public property '{propName}' lacks XML documentation",
                    "Add XML documentation with <summary> describing the property",
                    suggestedCode: $"/// <summary>\n/// Gets or sets the {SplitCamelCase(propName).ToLower()}.\n/// </summary>"));
            }
        }

        // Check indexers
        var indexers = root.DescendantNodes()
            .OfType<IndexerDeclarationSyntax>()
            .Where(i => IsPublicDeclaration(i.Modifiers));

        foreach (var indexer in indexers)
        {
            var symbol = semanticModel.GetDeclaredSymbol(indexer);
            if (symbol == null || !IsPubliclyVisible(symbol)) continue;

            var (startLine, endLine) = GetLineSpan(indexer.ThisKeyword);

            if (!HasXmlDocumentation(symbol))
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MissingPublicDoc,
                    DocIssueSeverity.Minor,
                    filePath,
                    startLine,
                    endLine,
                    "this[]",
                    "Indexer",
                    "Public indexer lacks XML documentation",
                    "Add XML documentation with <summary>, <param>, and <returns> tags"));
            }
        }

        return Task.FromResult(issues);
    }

    private Task<List<DocumentationIssue>> CheckEventsAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        var events = root.DescendantNodes()
            .OfType<EventDeclarationSyntax>()
            .Where(e => IsPublicDeclaration(e.Modifiers));

        foreach (var evt in events)
        {
            var symbol = semanticModel.GetDeclaredSymbol(evt);
            if (symbol == null || !IsPubliclyVisible(symbol)) continue;

            var (startLine, endLine) = GetLineSpan(evt.Identifier);
            var eventName = evt.Identifier.Text;

            if (!HasXmlDocumentation(symbol))
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MissingPublicDoc,
                    DocIssueSeverity.Minor,
                    filePath,
                    startLine,
                    endLine,
                    eventName,
                    "Event",
                    $"Public event '{eventName}' lacks XML documentation",
                    "Add XML documentation describing when the event is raised"));
            }
        }

        // Check event field declarations
        var eventFields = root.DescendantNodes()
            .OfType<EventFieldDeclarationSyntax>()
            .Where(e => IsPublicDeclaration(e.Modifiers));

        foreach (var evtField in eventFields)
        {
            foreach (var variable in evtField.Declaration.Variables)
            {
                var symbol = semanticModel.GetDeclaredSymbol(variable);
                if (symbol == null || !IsPubliclyVisible(symbol)) continue;

                var (startLine, endLine) = GetLineSpan(variable.Identifier);
                var eventName = variable.Identifier.Text;

                if (!HasXmlDocumentation(symbol))
                {
                    issues.Add(CreateIssue(
                        DocumentationIssueType.MissingPublicDoc,
                        DocIssueSeverity.Minor,
                        filePath,
                        startLine,
                        endLine,
                        eventName,
                        "Event",
                        $"Public event '{eventName}' lacks XML documentation",
                        "Add XML documentation describing when the event is raised"));
                }
            }
        }

        return Task.FromResult(issues);
    }

    private Task<List<DocumentationIssue>> CheckDelegatesAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        var delegates = root.DescendantNodes()
            .OfType<DelegateDeclarationSyntax>()
            .Where(d => IsPublicDeclaration(d.Modifiers));

        foreach (var del in delegates)
        {
            var symbol = semanticModel.GetDeclaredSymbol(del);
            if (symbol == null || !IsPubliclyVisible(symbol)) continue;

            var (startLine, endLine) = GetLineSpan(del.Identifier);
            var delegateName = del.Identifier.Text;

            if (!HasXmlDocumentation(symbol))
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MissingPublicDoc,
                    DocIssueSeverity.Minor,
                    filePath,
                    startLine,
                    endLine,
                    delegateName,
                    "Delegate",
                    $"Public delegate '{delegateName}' lacks XML documentation",
                    "Add XML documentation with <summary> and <param> tags"));
            }
        }

        return Task.FromResult(issues);
    }

    private List<DocumentationIssue> CheckParameterDocumentation(
        MethodDeclarationSyntax method,
        IMethodSymbol symbol,
        string filePath,
        int line)
    {
        var issues = new List<DocumentationIssue>();
        var xmlDoc = symbol.GetDocumentationCommentXml();

        if (string.IsNullOrEmpty(xmlDoc)) return issues;

        foreach (var param in symbol.Parameters)
        {
            var paramName = param.Name;
            if (!xmlDoc.Contains($"<param name=\"{paramName}\""))
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MissingParamDoc,
                    DocIssueSeverity.Minor,
                    filePath,
                    line,
                    line,
                    $"{method.Identifier.Text}.{paramName}",
                    "Parameter",
                    $"Parameter '{paramName}' in method '{method.Identifier.Text}' is not documented",
                    $"Add <param name=\"{paramName}\"> tag describing the parameter",
                    suggestedCode: $"/// <param name=\"{paramName}\">The {SplitCamelCase(paramName).ToLower()}.</param>"));
            }
        }

        return issues;
    }

    private List<DocumentationIssue> CheckConstructorParameterDocumentation(
        ConstructorDeclarationSyntax ctor,
        IMethodSymbol symbol,
        string filePath,
        int line)
    {
        var issues = new List<DocumentationIssue>();
        var xmlDoc = symbol.GetDocumentationCommentXml();

        if (string.IsNullOrEmpty(xmlDoc)) return issues;

        foreach (var param in symbol.Parameters)
        {
            var paramName = param.Name;
            if (!xmlDoc.Contains($"<param name=\"{paramName}\""))
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MissingParamDoc,
                    DocIssueSeverity.Minor,
                    filePath,
                    line,
                    line,
                    $"{ctor.Identifier.Text}.{paramName}",
                    "Parameter",
                    $"Constructor parameter '{paramName}' is not documented",
                    $"Add <param name=\"{paramName}\"> tag describing the parameter",
                    suggestedCode: $"/// <param name=\"{paramName}\">The {SplitCamelCase(paramName).ToLower()}.</param>"));
            }
        }

        return issues;
    }

    private List<DocumentationIssue> CheckTypeParameters(
        TypeDeclarationSyntax typeDecl,
        INamedTypeSymbol symbol,
        string filePath,
        int line,
        string typeName,
        string typeKind)
    {
        var issues = new List<DocumentationIssue>();
        var xmlDoc = symbol.GetDocumentationCommentXml();

        if (string.IsNullOrEmpty(xmlDoc) || !symbol.TypeParameters.Any()) return issues;

        foreach (var typeParam in symbol.TypeParameters)
        {
            var typeParamName = typeParam.Name;
            if (!xmlDoc.Contains($"<typeparam name=\"{typeParamName}\""))
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MissingTypeParamDoc,
                    DocIssueSeverity.Minor,
                    filePath,
                    line,
                    line,
                    $"{typeName}.{typeParamName}",
                    "TypeParameter",
                    $"Type parameter '{typeParamName}' in {typeKind.ToLower()} '{typeName}' is not documented",
                    $"Add <typeparam name=\"{typeParamName}\"> tag describing the type parameter",
                    suggestedCode: $"/// <typeparam name=\"{typeParamName}\">The type of {SplitCamelCase(typeParamName).ToLower()}.</typeparam>"));
            }
        }

        return issues;
    }

    private List<DocumentationIssue> CheckMethodTypeParameters(
        MethodDeclarationSyntax method,
        IMethodSymbol symbol,
        string filePath,
        int line,
        string methodName)
    {
        var issues = new List<DocumentationIssue>();
        var xmlDoc = symbol.GetDocumentationCommentXml();

        if (string.IsNullOrEmpty(xmlDoc) || !symbol.TypeParameters.Any()) return issues;

        foreach (var typeParam in symbol.TypeParameters)
        {
            var typeParamName = typeParam.Name;
            if (!xmlDoc.Contains($"<typeparam name=\"{typeParamName}\""))
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MissingTypeParamDoc,
                    DocIssueSeverity.Minor,
                    filePath,
                    line,
                    line,
                    $"{methodName}.{typeParamName}",
                    "TypeParameter",
                    $"Type parameter '{typeParamName}' in method '{methodName}' is not documented",
                    $"Add <typeparam name=\"{typeParamName}\"> tag describing the type parameter",
                    suggestedCode: $"/// <typeparam name=\"{typeParamName}\">The type of {SplitCamelCase(typeParamName).ToLower()}.</typeparam>"));
            }
        }

        return issues;
    }

    // Helper methods
    private static bool IsPublicDeclaration(SyntaxTokenList modifiers)
    {
        return modifiers.Any(m =>
            m.IsKind(SyntaxKind.PublicKeyword) ||
            m.IsKind(SyntaxKind.ProtectedKeyword));
    }

    private static string GetTypeKindName(TypeDeclarationSyntax typeDecl)
    {
        return typeDecl switch
        {
            ClassDeclarationSyntax => "Class",
            InterfaceDeclarationSyntax => "Interface",
            StructDeclarationSyntax => "Struct",
            RecordDeclarationSyntax => "Record",
            _ => "Type"
        };
    }

    private static string SplitCamelCase(string name)
    {
        if (string.IsNullOrEmpty(name)) return name;

        var result = new System.Text.StringBuilder();
        for (int i = 0; i < name.Length; i++)
        {
            if (i > 0 && char.IsUpper(name[i]) && !char.IsUpper(name[i - 1]))
            {
                result.Append(' ');
            }
            result.Append(name[i]);
        }
        return result.ToString();
    }

    private static string GenerateSuggestedTypeDoc(string typeName, string typeKind)
    {
        var description = SplitCamelCase(typeName).ToLower();
        return $"/// <summary>\n/// Represents a {description}.\n/// </summary>";
    }

    private static string GenerateSuggestedMethodDoc(MethodDeclarationSyntax method, IMethodSymbol symbol)
    {
        var sb = new System.Text.StringBuilder();
        var methodName = method.Identifier.Text;
        var description = SplitCamelCase(methodName).ToLower();

        sb.AppendLine("/// <summary>");
        sb.AppendLine($"/// {char.ToUpper(description[0])}{description[1..]}.");
        sb.AppendLine("/// </summary>");

        foreach (var param in symbol.Parameters)
        {
            var paramDesc = SplitCamelCase(param.Name).ToLower();
            sb.AppendLine($"/// <param name=\"{param.Name}\">The {paramDesc}.</param>");
        }

        if (!symbol.ReturnsVoid)
        {
            var returnDesc = GetReturnDescription(symbol.ReturnType.ToString());
            sb.AppendLine($"/// <returns>{returnDesc}.</returns>");
        }

        return sb.ToString().TrimEnd();
    }

    private static string GenerateSuggestedConstructorDoc(ConstructorDeclarationSyntax ctor)
    {
        var sb = new System.Text.StringBuilder();
        var typeName = ctor.Identifier.Text;

        sb.AppendLine("/// <summary>");
        sb.AppendLine($"/// Initializes a new instance of the <see cref=\"{typeName}\"/> class.");
        sb.AppendLine("/// </summary>");

        foreach (var param in ctor.ParameterList.Parameters)
        {
            var paramName = param.Identifier.Text;
            var paramDesc = SplitCamelCase(paramName).ToLower();
            sb.AppendLine($"/// <param name=\"{paramName}\">The {paramDesc}.</param>");
        }

        return sb.ToString().TrimEnd();
    }

    private static string GetReturnDescription(string returnType)
    {
        return returnType switch
        {
            "bool" or "Boolean" => "True if successful; otherwise, false",
            "string" or "String" => "The result string",
            "int" or "Int32" => "The calculated value",
            "Task" => "A task representing the asynchronous operation",
            _ when returnType.StartsWith("Task<") => $"A task that returns {returnType[5..^1]}",
            _ when returnType.StartsWith("List<") => $"A list of {returnType[5..^1]} items",
            _ when returnType.StartsWith("IEnumerable<") => $"A collection of {returnType[12..^1]} items",
            _ => $"The {SplitCamelCase(returnType).ToLower()}"
        };
    }
}
