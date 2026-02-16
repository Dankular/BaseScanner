using Microsoft.CodeAnalysis;
using BaseScanner.Analyzers.Concurrency.Models;

namespace BaseScanner.Analyzers.Concurrency;

/// <summary>
/// Interface for thread safety detectors.
/// Each detector is responsible for identifying a specific category of thread safety issues.
/// </summary>
public interface IThreadSafetyDetector
{
    /// <summary>
    /// The unique name of this detector.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// A brief description of what this detector looks for.
    /// </summary>
    string Description { get; }

    /// <summary>
    /// The rule IDs that this detector can report.
    /// </summary>
    IReadOnlyList<string> SupportedRules { get; }

    /// <summary>
    /// Analyzes a document for thread safety issues.
    /// </summary>
    /// <param name="document">The Roslyn document to analyze.</param>
    /// <param name="semanticModel">The semantic model for type resolution.</param>
    /// <param name="root">The syntax tree root node.</param>
    /// <param name="context">Optional analysis context with shared state.</param>
    /// <returns>A list of detected thread safety issues.</returns>
    Task<List<ThreadSafetyIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        ThreadSafetyAnalysisContext? context = null);
}

/// <summary>
/// Context passed to detectors containing shared analysis state.
/// </summary>
public class ThreadSafetyAnalysisContext
{
    /// <summary>
    /// Shared fields detected across all files.
    /// </summary>
    public Dictionary<string, SharedFieldInfo> SharedFields { get; } = new();

    /// <summary>
    /// Lock patterns detected across all files.
    /// </summary>
    public List<LockInfo> LockPatterns { get; } = [];

    /// <summary>
    /// Classes that have been analyzed.
    /// </summary>
    public HashSet<string> AnalyzedClasses { get; } = [];

    /// <summary>
    /// Methods that access shared state.
    /// </summary>
    public Dictionary<string, HashSet<string>> MethodToFieldAccess { get; } = new();

    /// <summary>
    /// Fields that are accessed from async methods.
    /// </summary>
    public HashSet<string> AsyncAccessedFields { get; } = [];

    /// <summary>
    /// Static methods that access static fields.
    /// </summary>
    public Dictionary<string, HashSet<string>> StaticMethodToStaticFields { get; } = new();

    /// <summary>
    /// Track which fields are protected by which lock expressions.
    /// </summary>
    public Dictionary<string, HashSet<string>> FieldToLockExpressions { get; } = new();

    /// <summary>
    /// Registers a field access from a method.
    /// </summary>
    public void RegisterFieldAccess(string methodFullName, string fieldFullName, bool isWrite)
    {
        if (!MethodToFieldAccess.TryGetValue(methodFullName, out var fields))
        {
            fields = new HashSet<string>();
            MethodToFieldAccess[methodFullName] = fields;
        }
        fields.Add(fieldFullName);

        if (SharedFields.TryGetValue(fieldFullName, out var fieldInfo))
        {
            if (isWrite)
            {
                if (!fieldInfo.WritingMethods.Contains(methodFullName))
                    fieldInfo.WritingMethods.Add(methodFullName);
            }
            else
            {
                if (!fieldInfo.ReadingMethods.Contains(methodFullName))
                    fieldInfo.ReadingMethods.Add(methodFullName);
            }
        }
    }

    /// <summary>
    /// Registers a shared field.
    /// </summary>
    public void RegisterSharedField(SharedFieldInfo fieldInfo)
    {
        var key = $"{fieldInfo.ClassName}.{fieldInfo.FieldName}";
        SharedFields[key] = fieldInfo;
    }

    /// <summary>
    /// Registers a lock pattern.
    /// </summary>
    public void RegisterLockPattern(LockInfo lockInfo)
    {
        LockPatterns.Add(lockInfo);
    }

    /// <summary>
    /// Checks if a field is accessed from multiple methods.
    /// </summary>
    public bool IsFieldAccessedFromMultipleMethods(string fieldFullName)
    {
        if (!SharedFields.TryGetValue(fieldFullName, out var fieldInfo))
            return false;

        return fieldInfo.WritingMethods.Count > 1 ||
               (fieldInfo.WritingMethods.Count > 0 && fieldInfo.ReadingMethods.Count > 0);
    }

    /// <summary>
    /// Gets all fields modified by a method.
    /// </summary>
    public IEnumerable<string> GetFieldsModifiedBy(string methodFullName)
    {
        return SharedFields.Values
            .Where(f => f.WritingMethods.Contains(methodFullName))
            .Select(f => $"{f.ClassName}.{f.FieldName}");
    }
}
