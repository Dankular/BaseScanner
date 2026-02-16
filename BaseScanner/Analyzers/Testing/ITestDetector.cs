using Microsoft.CodeAnalysis;
using BaseScanner.Analyzers.Testing.Models;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Testing;

/// <summary>
/// Interface for test-related detectors.
/// Each detector is responsible for finding a specific category of testing issues.
/// </summary>
public interface ITestDetector
{
    /// <summary>
    /// The category of testing issues this detector finds.
    /// </summary>
    string Category { get; }

    /// <summary>
    /// Human-readable description of what this detector finds.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// Detect testing issues in the given project.
    /// </summary>
    /// <param name="project">The Roslyn project to analyze.</param>
    /// <param name="coverageData">Optional coverage data from a coverage report.</param>
    /// <param name="context">Code context for cross-file analysis.</param>
    /// <returns>Detection results containing found issues.</returns>
    Task<TestDetectionResult> DetectAsync(
        Project project,
        RawCoverageData? coverageData,
        CodeContext context);
}

/// <summary>
/// Interface for coverage-aware test detectors that need line-level coverage data.
/// </summary>
public interface ICoverageAwareDetector : ITestDetector
{
    /// <summary>
    /// Whether this detector requires coverage data to function.
    /// </summary>
    bool RequiresCoverageData { get; }
}

/// <summary>
/// Interface for test smell detectors that analyze test code quality.
/// </summary>
public interface ITestSmellDetector : ITestDetector
{
    /// <summary>
    /// The types of test smells this detector can identify.
    /// </summary>
    IReadOnlyList<TestSmellType> DetectableSmells { get; }
}

/// <summary>
/// Interface for critical path detectors that identify untested security-sensitive code.
/// </summary>
public interface ICriticalPathDetector : ITestDetector
{
    /// <summary>
    /// The types of critical paths this detector can identify.
    /// </summary>
    IReadOnlyList<CriticalPathType> DetectablePathTypes { get; }
}

/// <summary>
/// Base class for test detectors providing common functionality.
/// </summary>
public abstract class TestDetectorBase : ITestDetector
{
    public abstract string Category { get; }
    public abstract string Description { get; }

    public abstract Task<TestDetectionResult> DetectAsync(
        Project project,
        RawCoverageData? coverageData,
        CodeContext context);

    /// <summary>
    /// Creates an empty detection result.
    /// </summary>
    protected TestDetectionResult EmptyResult() => new()
    {
        DetectorName = Category,
        Smells = [],
        QualityIssues = [],
        CriticalPaths = [],
        UncoveredMethods = [],
        UncoveredBranches = []
    };

    /// <summary>
    /// Checks if a file should be skipped (generated files, etc.).
    /// </summary>
    protected bool ShouldSkipFile(string? filePath)
    {
        if (string.IsNullOrEmpty(filePath))
            return true;

        var fileName = Path.GetFileName(filePath);
        return fileName.EndsWith(".g.cs") ||
               fileName.EndsWith(".Designer.cs") ||
               fileName.EndsWith(".generated.cs") ||
               filePath.Contains("obj" + Path.DirectorySeparatorChar) ||
               filePath.Contains("bin" + Path.DirectorySeparatorChar);
    }

    /// <summary>
    /// Checks if a class is a test class based on naming conventions and attributes.
    /// </summary>
    protected bool IsTestClass(Microsoft.CodeAnalysis.CSharp.Syntax.ClassDeclarationSyntax classDecl)
    {
        var className = classDecl.Identifier.Text;

        // Check naming conventions
        if (className.EndsWith("Tests") ||
            className.EndsWith("Test") ||
            className.EndsWith("Specs") ||
            className.EndsWith("Spec"))
            return true;

        // Check for test framework attributes
        foreach (var attrList in classDecl.AttributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                var attrName = attr.Name.ToString();
                if (attrName is "TestFixture" or "TestClass" or "Collection" or "Trait")
                    return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Checks if a method is a test method based on attributes.
    /// </summary>
    protected bool IsTestMethod(Microsoft.CodeAnalysis.CSharp.Syntax.MethodDeclarationSyntax method)
    {
        foreach (var attrList in method.AttributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                var attrName = attr.Name.ToString();
                if (attrName is "Test" or "TestMethod" or "Fact" or "Theory" or
                    "TestCase" or "TestCaseSource" or "InlineData" or
                    "MemberData" or "ClassData")
                    return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Gets the line span for a syntax node.
    /// </summary>
    protected (int StartLine, int EndLine) GetLineSpan(SyntaxNode node)
    {
        var span = node.GetLocation().GetLineSpan();
        return (span.StartLinePosition.Line + 1, span.EndLinePosition.Line + 1);
    }

    /// <summary>
    /// Extracts a code snippet from source text.
    /// </summary>
    protected string GetCodeSnippet(SyntaxNode node, int maxLines = 5)
    {
        var text = node.GetText().ToString();
        var lines = text.Split('\n');

        if (lines.Length <= maxLines)
            return text.Trim();

        return string.Join("\n", lines.Take(maxLines)) + "\n// ...";
    }
}
