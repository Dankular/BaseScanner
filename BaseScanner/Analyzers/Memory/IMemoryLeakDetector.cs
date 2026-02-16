using Microsoft.CodeAnalysis;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Memory;

/// <summary>
/// Interface for memory leak detectors.
/// Each detector is responsible for finding a specific category of memory leaks.
/// </summary>
public interface IMemoryLeakDetector
{
    /// <summary>
    /// The category of memory leaks this detector finds.
    /// </summary>
    string Category { get; }

    /// <summary>
    /// Detect memory leaks in the given document.
    /// </summary>
    /// <param name="document">The document to analyze</param>
    /// <param name="semanticModel">Semantic model for type information</param>
    /// <param name="root">Syntax root of the document</param>
    /// <param name="context">Codebase context for cross-file analysis</param>
    /// <returns>List of detected memory leaks</returns>
    Task<List<MemoryLeak>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context);
}
