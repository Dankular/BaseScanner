using Microsoft.CodeAnalysis;
using BaseScanner.Context;
using BaseScanner.Analyzers.Documentation.Models;

namespace BaseScanner.Analyzers.Documentation;

/// <summary>
/// Interface for documentation quality detectors.
/// Each detector is responsible for finding a specific category of documentation issues.
/// </summary>
public interface IDocDetector
{
    /// <summary>
    /// The category of documentation issues this detector finds.
    /// </summary>
    DocIssueCategory Category { get; }

    /// <summary>
    /// Human-readable name of this detector.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Brief description of what this detector looks for.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Detect documentation issues in the given document.
    /// </summary>
    /// <param name="document">The Roslyn document to analyze.</param>
    /// <param name="semanticModel">The semantic model for the document.</param>
    /// <param name="root">The syntax root of the document.</param>
    /// <param name="context">Optional code context for additional analysis.</param>
    /// <returns>List of documentation issues found.</returns>
    Task<List<DocumentationIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext? context = null);
}

/// <summary>
/// Base class for documentation detectors with common utility methods.
/// </summary>
public abstract class DocDetectorBase : IDocDetector
{
    public abstract DocIssueCategory Category { get; }
    public abstract string Name { get; }
    public abstract string Description { get; }

    public abstract Task<List<DocumentationIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext? context = null);

    /// <summary>
    /// Gets the line span for a syntax node.
    /// </summary>
    protected static (int StartLine, int EndLine) GetLineSpan(SyntaxNode node)
    {
        var span = node.GetLocation().GetLineSpan();
        return (span.StartLinePosition.Line + 1, span.EndLinePosition.Line + 1);
    }

    /// <summary>
    /// Gets the line span for a syntax token.
    /// </summary>
    protected static (int StartLine, int EndLine) GetLineSpan(SyntaxToken token)
    {
        var span = token.GetLocation().GetLineSpan();
        return (span.StartLinePosition.Line + 1, span.EndLinePosition.Line + 1);
    }

    /// <summary>
    /// Creates a documentation issue with common fields populated.
    /// </summary>
    protected DocumentationIssue CreateIssue(
        DocumentationIssueType issueType,
        DocIssueSeverity severity,
        string filePath,
        int startLine,
        int endLine,
        string symbolName,
        string symbolKind,
        string description,
        string? suggestion = null,
        string? currentCode = null,
        string? suggestedCode = null,
        int confidence = 100,
        Dictionary<string, object>? metadata = null)
    {
        return new DocumentationIssue
        {
            IssueType = issueType,
            Category = Category,
            Severity = severity,
            FilePath = filePath,
            StartLine = startLine,
            EndLine = endLine,
            SymbolName = symbolName,
            SymbolKind = symbolKind,
            Description = description,
            Suggestion = suggestion ?? "",
            CurrentCode = currentCode ?? "",
            SuggestedCode = suggestedCode ?? "",
            Confidence = confidence,
            Metadata = metadata ?? []
        };
    }

    /// <summary>
    /// Checks if a symbol is publicly visible.
    /// </summary>
    protected static bool IsPubliclyVisible(ISymbol symbol)
    {
        if (symbol.DeclaredAccessibility != Accessibility.Public &&
            symbol.DeclaredAccessibility != Accessibility.Protected &&
            symbol.DeclaredAccessibility != Accessibility.ProtectedOrInternal)
        {
            return false;
        }

        // Check containing types are also public
        var containingType = symbol.ContainingType;
        while (containingType != null)
        {
            if (containingType.DeclaredAccessibility != Accessibility.Public)
            {
                return false;
            }
            containingType = containingType.ContainingType;
        }

        return true;
    }

    /// <summary>
    /// Gets the XML documentation comment for a symbol.
    /// </summary>
    protected static string? GetXmlDocumentation(ISymbol symbol)
    {
        return symbol.GetDocumentationCommentXml();
    }

    /// <summary>
    /// Checks if a symbol has any XML documentation.
    /// </summary>
    protected static bool HasXmlDocumentation(ISymbol symbol)
    {
        var xml = symbol.GetDocumentationCommentXml();
        return !string.IsNullOrWhiteSpace(xml) && xml.Contains("<summary>");
    }
}
