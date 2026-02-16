using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;
using BaseScanner.Analyzers.Documentation.Models;
using System.Xml.Linq;

namespace BaseScanner.Analyzers.Documentation.Detectors;

/// <summary>
/// Analyzes documentation completeness and calculates coverage scores.
/// Detects empty, generic, or overly brief documentation.
/// </summary>
public class CompletenessDetector : DocDetectorBase
{
    public override DocIssueCategory Category => DocIssueCategory.Completeness;
    public override string Name => "Documentation Completeness Detector";
    public override string Description => "Analyzes documentation coverage and detects empty or generic documentation.";

    // Minimum word counts for adequate documentation
    private const int MinSummaryWords = 3;
    private const int MinParamWords = 2;
    private const int MinReturnWords = 2;

    // Generic documentation patterns to flag
    private static readonly string[] GenericPhrases =
    [
        "gets or sets the",
        "the value",
        "the object",
        "this method",
        "this property",
        "this class",
        "does something",
        "handles",
        "processes",
        "not documented"
    ];

    // Coverage details accumulated during analysis
    private readonly List<DocumentationCoverage> _coverageDetails = [];

    public List<DocumentationCoverage> GetCoverageDetails() => [.. _coverageDetails];

    public override async Task<List<DocumentationIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext? context = null)
    {
        _coverageDetails.Clear();
        var issues = new List<DocumentationIssue>();
        var filePath = document.FilePath ?? "";

        // Check types
        issues.AddRange(await CheckTypeCompletenessAsync(root, semanticModel, filePath));

        // Check methods
        issues.AddRange(await CheckMethodCompletenessAsync(root, semanticModel, filePath));

        // Check properties
        issues.AddRange(await CheckPropertyCompletenessAsync(root, semanticModel, filePath));

        return issues;
    }

    private Task<List<DocumentationIssue>> CheckTypeCompletenessAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        var typeDeclarations = root.DescendantNodes()
            .OfType<TypeDeclarationSyntax>()
            .Where(t => t.Modifiers.Any(m => m.IsKind(SyntaxKind.PublicKeyword)));

        foreach (var typeDecl in typeDeclarations)
        {
            var symbol = semanticModel.GetDeclaredSymbol(typeDecl);
            if (symbol == null || !IsPubliclyVisible(symbol)) continue;

            var (startLine, endLine) = GetLineSpan(typeDecl.Identifier);
            var typeName = typeDecl.Identifier.Text;
            var typeKind = GetTypeKind(typeDecl);

            var xmlDoc = symbol.GetDocumentationCommentXml();
            var coverage = CalculateTypeCoverage(symbol, xmlDoc);
            coverage = coverage with { FilePath = filePath };
            _coverageDetails.Add(coverage);

            if (string.IsNullOrEmpty(xmlDoc) || !xmlDoc.Contains("<summary>"))
            {
                continue; // Missing doc handled by MissingDocDetector
            }

            // Parse and check XML documentation
            try
            {
                var doc = XDocument.Parse($"<root>{xmlDoc}</root>");

                // Check summary quality
                var summary = doc.Descendants("summary").FirstOrDefault()?.Value.Trim() ?? "";
                var summaryIssue = CheckTextQuality(summary, "summary", typeName, typeKind);
                if (summaryIssue != null)
                {
                    issues.Add(CreateIssue(
                        summaryIssue.Value.Type,
                        summaryIssue.Value.Severity,
                        filePath,
                        startLine,
                        endLine,
                        typeName,
                        typeKind,
                        summaryIssue.Value.Message,
                        summaryIssue.Value.Suggestion,
                        currentCode: $"<summary>{summary}</summary>",
                        confidence: summaryIssue.Value.Confidence));
                }

                // Check remarks if present
                var remarks = doc.Descendants("remarks").FirstOrDefault()?.Value.Trim() ?? "";
                if (!string.IsNullOrEmpty(remarks))
                {
                    var remarksIssue = CheckTextQuality(remarks, "remarks", typeName, typeKind);
                    if (remarksIssue != null)
                    {
                        issues.Add(CreateIssue(
                            remarksIssue.Value.Type,
                            DocIssueSeverity.Info,
                            filePath,
                            startLine,
                            endLine,
                            typeName,
                            typeKind,
                            remarksIssue.Value.Message.Replace("summary", "remarks"),
                            remarksIssue.Value.Suggestion,
                            confidence: remarksIssue.Value.Confidence - 10));
                    }
                }

                // Check type parameters
                if (symbol.TypeParameters.Any())
                {
                    foreach (var typeParam in symbol.TypeParameters)
                    {
                        var typeParamDoc = doc.Descendants("typeparam")
                            .FirstOrDefault(e => e.Attribute("name")?.Value == typeParam.Name)?
                            .Value.Trim() ?? "";

                        if (!string.IsNullOrEmpty(typeParamDoc))
                        {
                            var paramIssue = CheckTextQuality(typeParamDoc, "type parameter", typeParam.Name, "TypeParameter");
                            if (paramIssue != null)
                            {
                                issues.Add(CreateIssue(
                                    paramIssue.Value.Type,
                                    DocIssueSeverity.Info,
                                    filePath,
                                    startLine,
                                    endLine,
                                    $"{typeName}.{typeParam.Name}",
                                    "TypeParameter",
                                    paramIssue.Value.Message,
                                    paramIssue.Value.Suggestion,
                                    confidence: paramIssue.Value.Confidence));
                            }
                        }
                    }
                }
            }
            catch
            {
                // XML parsing failed - malformed documentation
                issues.Add(CreateIssue(
                    DocumentationIssueType.EmptyDocumentation,
                    DocIssueSeverity.Warning,
                    filePath,
                    startLine,
                    endLine,
                    typeName,
                    typeKind,
                    $"XML documentation for '{typeName}' is malformed",
                    "Fix the XML structure of the documentation",
                    confidence: 100));
            }
        }

        return Task.FromResult(issues);
    }

    private Task<List<DocumentationIssue>> CheckMethodCompletenessAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        var methods = root.DescendantNodes()
            .OfType<MethodDeclarationSyntax>()
            .Where(m => m.Modifiers.Any(mod => mod.IsKind(SyntaxKind.PublicKeyword) || mod.IsKind(SyntaxKind.ProtectedKeyword)));

        foreach (var method in methods)
        {
            var symbol = semanticModel.GetDeclaredSymbol(method);
            if (symbol == null || !IsPubliclyVisible(symbol)) continue;

            var (startLine, endLine) = GetLineSpan(method.Identifier);
            var methodName = method.Identifier.Text;

            var xmlDoc = symbol.GetDocumentationCommentXml();
            var coverage = CalculateMethodCoverage(symbol, xmlDoc);
            coverage = coverage with { FilePath = filePath };
            _coverageDetails.Add(coverage);

            if (string.IsNullOrEmpty(xmlDoc) || !xmlDoc.Contains("<summary>"))
            {
                continue; // Missing doc handled by MissingDocDetector
            }

            try
            {
                var doc = XDocument.Parse($"<root>{xmlDoc}</root>");

                // Check summary quality
                var summary = doc.Descendants("summary").FirstOrDefault()?.Value.Trim() ?? "";
                var summaryIssue = CheckTextQuality(summary, "summary", methodName, "Method");
                if (summaryIssue != null)
                {
                    issues.Add(CreateIssue(
                        summaryIssue.Value.Type,
                        summaryIssue.Value.Severity,
                        filePath,
                        startLine,
                        endLine,
                        methodName,
                        "Method",
                        summaryIssue.Value.Message,
                        summaryIssue.Value.Suggestion,
                        currentCode: $"<summary>{summary}</summary>",
                        confidence: summaryIssue.Value.Confidence));
                }

                // Check parameter documentation quality
                foreach (var param in symbol.Parameters)
                {
                    var paramDoc = doc.Descendants("param")
                        .FirstOrDefault(e => e.Attribute("name")?.Value == param.Name)?
                        .Value.Trim() ?? "";

                    if (!string.IsNullOrEmpty(paramDoc))
                    {
                        var paramIssue = CheckTextQuality(paramDoc, "parameter", param.Name, "Parameter", MinParamWords);
                        if (paramIssue != null)
                        {
                            issues.Add(CreateIssue(
                                paramIssue.Value.Type,
                                DocIssueSeverity.Info,
                                filePath,
                                startLine,
                                endLine,
                                $"{methodName}.{param.Name}",
                                "Parameter",
                                paramIssue.Value.Message,
                                paramIssue.Value.Suggestion,
                                confidence: paramIssue.Value.Confidence));
                        }
                    }
                }

                // Check returns documentation quality
                if (!symbol.ReturnsVoid)
                {
                    var returnsDoc = doc.Descendants("returns").FirstOrDefault()?.Value.Trim() ?? "";
                    if (!string.IsNullOrEmpty(returnsDoc))
                    {
                        var returnsIssue = CheckTextQuality(returnsDoc, "returns", methodName, "Return", MinReturnWords);
                        if (returnsIssue != null)
                        {
                            issues.Add(CreateIssue(
                                returnsIssue.Value.Type,
                                DocIssueSeverity.Info,
                                filePath,
                                startLine,
                                endLine,
                                methodName,
                                "Method",
                                returnsIssue.Value.Message.Replace("summary", "returns"),
                                returnsIssue.Value.Suggestion,
                                confidence: returnsIssue.Value.Confidence));
                        }
                    }
                }

                // Check for documented exceptions that might not be thrown
                var exceptions = doc.Descendants("exception").ToList();
                if (exceptions.Any())
                {
                    var methodThrows = method.DescendantNodes()
                        .Any(n => n is ThrowStatementSyntax or ThrowExpressionSyntax);

                    if (!methodThrows)
                    {
                        foreach (var ex in exceptions)
                        {
                            var exType = ex.Attribute("cref")?.Value ?? "Exception";
                            issues.Add(CreateIssue(
                                DocumentationIssueType.GenericDocumentation,
                                DocIssueSeverity.Info,
                                filePath,
                                startLine,
                                endLine,
                                methodName,
                                "Method",
                                $"Method documents throwing '{exType}' but contains no throw statements",
                                "Verify exception documentation is accurate or remove if not applicable",
                                confidence: 50));
                        }
                    }
                }
            }
            catch
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.EmptyDocumentation,
                    DocIssueSeverity.Warning,
                    filePath,
                    startLine,
                    endLine,
                    methodName,
                    "Method",
                    $"XML documentation for '{methodName}' is malformed",
                    "Fix the XML structure of the documentation",
                    confidence: 100));
            }
        }

        return Task.FromResult(issues);
    }

    private Task<List<DocumentationIssue>> CheckPropertyCompletenessAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        var properties = root.DescendantNodes()
            .OfType<PropertyDeclarationSyntax>()
            .Where(p => p.Modifiers.Any(m => m.IsKind(SyntaxKind.PublicKeyword) || m.IsKind(SyntaxKind.ProtectedKeyword)));

        foreach (var property in properties)
        {
            var symbol = semanticModel.GetDeclaredSymbol(property);
            if (symbol == null || !IsPubliclyVisible(symbol)) continue;

            var (startLine, endLine) = GetLineSpan(property.Identifier);
            var propName = property.Identifier.Text;

            var xmlDoc = symbol.GetDocumentationCommentXml();
            var coverage = CalculatePropertyCoverage(symbol, xmlDoc);
            coverage = coverage with { FilePath = filePath };
            _coverageDetails.Add(coverage);

            if (string.IsNullOrEmpty(xmlDoc) || !xmlDoc.Contains("<summary>"))
            {
                continue; // Missing doc handled by MissingDocDetector
            }

            try
            {
                var doc = XDocument.Parse($"<root>{xmlDoc}</root>");

                var summary = doc.Descendants("summary").FirstOrDefault()?.Value.Trim() ?? "";
                var summaryIssue = CheckTextQuality(summary, "summary", propName, "Property");
                if (summaryIssue != null)
                {
                    issues.Add(CreateIssue(
                        summaryIssue.Value.Type,
                        summaryIssue.Value.Severity,
                        filePath,
                        startLine,
                        endLine,
                        propName,
                        "Property",
                        summaryIssue.Value.Message,
                        summaryIssue.Value.Suggestion,
                        currentCode: $"<summary>{summary}</summary>",
                        confidence: summaryIssue.Value.Confidence));
                }

                // Check for very generic property documentation
                var isGenericGetSet = summary.Contains("gets or sets", StringComparison.OrdinalIgnoreCase) &&
                                     CountWords(summary) < 6;
                if (isGenericGetSet)
                {
                    issues.Add(CreateIssue(
                        DocumentationIssueType.GenericDocumentation,
                        DocIssueSeverity.Info,
                        filePath,
                        startLine,
                        endLine,
                        propName,
                        "Property",
                        $"Property '{propName}' has generic 'gets or sets' documentation without meaningful description",
                        "Describe what the property represents, valid values, or usage constraints",
                        currentCode: $"<summary>{summary}</summary>",
                        confidence: 75));
                }
            }
            catch
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.EmptyDocumentation,
                    DocIssueSeverity.Warning,
                    filePath,
                    startLine,
                    endLine,
                    propName,
                    "Property",
                    $"XML documentation for '{propName}' is malformed",
                    "Fix the XML structure of the documentation",
                    confidence: 100));
            }
        }

        return Task.FromResult(issues);
    }

    private (DocumentationIssueType Type, DocIssueSeverity Severity, string Message, string Suggestion, int Confidence)?
        CheckTextQuality(string text, string elementType, string symbolName, string symbolKind, int minWords = 3)
    {
        if (minWords == 0) minWords = MinSummaryWords;

        // Check for empty
        if (string.IsNullOrWhiteSpace(text))
        {
            return (
                DocumentationIssueType.EmptyDocumentation,
                DocIssueSeverity.Warning,
                $"{symbolKind} '{symbolName}' has empty {elementType} documentation",
                $"Add meaningful description to the {elementType}",
                100);
        }

        // Check for too brief
        var wordCount = CountWords(text);
        if (wordCount < minWords)
        {
            return (
                DocumentationIssueType.GenericDocumentation,
                DocIssueSeverity.Info,
                $"{symbolKind} '{symbolName}' has very brief {elementType} ({wordCount} words)",
                $"Expand the {elementType} to be more descriptive (at least {minWords} words)",
                80);
        }

        // Check for generic phrases
        var lowerText = text.ToLower();
        foreach (var phrase in GenericPhrases)
        {
            if (lowerText.Contains(phrase) && wordCount < 8)
            {
                return (
                    DocumentationIssueType.GenericDocumentation,
                    DocIssueSeverity.Info,
                    $"{symbolKind} '{symbolName}' has generic documentation using '{phrase}'",
                    "Provide more specific documentation describing purpose and behavior",
                    70);
            }
        }

        // Check if documentation just repeats the name
        var simplifiedName = SimplifyName(symbolName).ToLower();
        var simplifiedText = text.ToLower();
        if (simplifiedText == simplifiedName || simplifiedText == $"the {simplifiedName}")
        {
            return (
                DocumentationIssueType.GenericDocumentation,
                DocIssueSeverity.Info,
                $"{symbolKind} '{symbolName}' documentation just repeats the name",
                "Explain what it does, not just what it's called",
                85);
        }

        return null;
    }

    private DocumentationCoverage CalculateTypeCoverage(INamedTypeSymbol symbol, string? xmlDoc)
    {
        var hasSummary = xmlDoc?.Contains("<summary>") ?? false;
        var hasRemarks = xmlDoc?.Contains("<remarks>") ?? false;
        var hasExample = xmlDoc?.Contains("<example>") ?? false;

        var typeParamCount = symbol.TypeParameters.Length;
        var docTypeParamCount = 0;
        if (xmlDoc != null && typeParamCount > 0)
        {
            foreach (var tp in symbol.TypeParameters)
            {
                if (xmlDoc.Contains($"<typeparam name=\"{tp.Name}\""))
                    docTypeParamCount++;
            }
        }

        var score = 0.0;
        if (hasSummary) score += 60;
        if (hasRemarks) score += 20;
        if (hasExample) score += 10;
        if (typeParamCount > 0)
        {
            score += 10 * ((double)docTypeParamCount / typeParamCount);
        }
        else
        {
            score += 10;
        }

        return new DocumentationCoverage
        {
            SymbolName = symbol.Name,
            SymbolKind = symbol.TypeKind.ToString(),
            FilePath = "",
            HasSummary = hasSummary,
            HasRemarks = hasRemarks,
            HasExample = hasExample,
            TypeParameterCount = typeParamCount,
            DocumentedTypeParameterCount = docTypeParamCount,
            CoverageScore = score
        };
    }

    private DocumentationCoverage CalculateMethodCoverage(IMethodSymbol symbol, string? xmlDoc)
    {
        var hasSummary = xmlDoc?.Contains("<summary>") ?? false;
        var hasRemarks = xmlDoc?.Contains("<remarks>") ?? false;
        var hasExample = xmlDoc?.Contains("<example>") ?? false;
        var hasReturn = symbol.ReturnsVoid || (xmlDoc?.Contains("<returns>") ?? false);

        var paramCount = symbol.Parameters.Length;
        var docParamCount = 0;
        if (xmlDoc != null && paramCount > 0)
        {
            foreach (var p in symbol.Parameters)
            {
                if (xmlDoc.Contains($"<param name=\"{p.Name}\""))
                    docParamCount++;
            }
        }

        var typeParamCount = symbol.TypeParameters.Length;
        var docTypeParamCount = 0;
        if (xmlDoc != null && typeParamCount > 0)
        {
            foreach (var tp in symbol.TypeParameters)
            {
                if (xmlDoc.Contains($"<typeparam name=\"{tp.Name}\""))
                    docTypeParamCount++;
            }
        }

        // Count potential exceptions
        var exceptionCount = 0; // Would need syntax analysis for accurate count

        var score = 0.0;
        if (hasSummary) score += 40;
        if (hasReturn) score += 20;
        if (hasRemarks) score += 10;
        if (hasExample) score += 10;

        if (paramCount > 0)
        {
            score += 20 * ((double)docParamCount / paramCount);
        }
        else
        {
            score += 20;
        }

        return new DocumentationCoverage
        {
            SymbolName = symbol.Name,
            SymbolKind = "Method",
            FilePath = "",
            HasSummary = hasSummary,
            HasRemarks = hasRemarks,
            HasExample = hasExample,
            HasReturnDoc = symbol.ReturnsVoid ? null : hasReturn,
            ParameterCount = paramCount,
            DocumentedParameterCount = docParamCount,
            TypeParameterCount = typeParamCount,
            DocumentedTypeParameterCount = docTypeParamCount,
            ExceptionCount = exceptionCount,
            CoverageScore = score
        };
    }

    private DocumentationCoverage CalculatePropertyCoverage(IPropertySymbol symbol, string? xmlDoc)
    {
        var hasSummary = xmlDoc?.Contains("<summary>") ?? false;
        var hasRemarks = xmlDoc?.Contains("<remarks>") ?? false;
        var hasExample = xmlDoc?.Contains("<example>") ?? false;

        var score = 0.0;
        if (hasSummary) score += 80;
        if (hasRemarks) score += 10;
        if (hasExample) score += 10;

        return new DocumentationCoverage
        {
            SymbolName = symbol.Name,
            SymbolKind = "Property",
            FilePath = "",
            HasSummary = hasSummary,
            HasRemarks = hasRemarks,
            HasExample = hasExample,
            CoverageScore = score
        };
    }

    private static int CountWords(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return 0;
        return text.Split([' ', '\t', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries).Length;
    }

    private static string SimplifyName(string name)
    {
        // Convert PascalCase to words
        var result = new System.Text.StringBuilder();
        foreach (var c in name)
        {
            if (char.IsUpper(c) && result.Length > 0)
            {
                result.Append(' ');
            }
            result.Append(c);
        }
        return result.ToString();
    }

    private static string GetTypeKind(TypeDeclarationSyntax typeDecl)
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
}
