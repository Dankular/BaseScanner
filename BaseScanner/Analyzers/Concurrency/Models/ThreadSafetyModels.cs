using Microsoft.CodeAnalysis;

namespace BaseScanner.Analyzers.Concurrency.Models;

/// <summary>
/// Represents a thread safety issue detected in the code.
/// </summary>
public record ThreadSafetyIssue
{
    /// <summary>
    /// The type of thread safety issue (e.g., SharedMutableStatic, RaceCondition, etc.)
    /// </summary>
    public required string IssueType { get; init; }

    /// <summary>
    /// The specific rule that was violated.
    /// </summary>
    public required string RuleId { get; init; }

    /// <summary>
    /// Severity level: Critical, High, Medium, Low, Info
    /// </summary>
    public required string Severity { get; init; }

    /// <summary>
    /// Human-readable description of the issue.
    /// </summary>
    public required string Message { get; init; }

    /// <summary>
    /// Path to the file containing the issue.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Starting line number (1-based).
    /// </summary>
    public required int Line { get; init; }

    /// <summary>
    /// Ending line number (1-based).
    /// </summary>
    public required int EndLine { get; init; }

    /// <summary>
    /// Column number where the issue starts.
    /// </summary>
    public int Column { get; init; }

    /// <summary>
    /// The code snippet that triggered the issue.
    /// </summary>
    public string? CodeSnippet { get; init; }

    /// <summary>
    /// Suggested fix for the issue.
    /// </summary>
    public string? SuggestedFix { get; init; }

    /// <summary>
    /// CWE (Common Weakness Enumeration) ID if applicable.
    /// </summary>
    public string? CweId { get; init; }

    /// <summary>
    /// Name of the containing class.
    /// </summary>
    public string? ClassName { get; init; }

    /// <summary>
    /// Name of the containing method.
    /// </summary>
    public string? MethodName { get; init; }

    /// <summary>
    /// Name of the affected field or property.
    /// </summary>
    public string? MemberName { get; init; }

    /// <summary>
    /// Additional context about the issue.
    /// </summary>
    public Dictionary<string, object>? Metadata { get; init; }
}

/// <summary>
/// Represents a field that may be shared across threads.
/// </summary>
public record SharedFieldInfo
{
    /// <summary>
    /// The name of the field.
    /// </summary>
    public required string FieldName { get; init; }

    /// <summary>
    /// The type of the field.
    /// </summary>
    public required string FieldType { get; init; }

    /// <summary>
    /// The containing class name.
    /// </summary>
    public required string ClassName { get; init; }

    /// <summary>
    /// Whether the field is static.
    /// </summary>
    public bool IsStatic { get; init; }

    /// <summary>
    /// Whether the field is volatile.
    /// </summary>
    public bool IsVolatile { get; init; }

    /// <summary>
    /// Whether the field is readonly.
    /// </summary>
    public bool IsReadOnly { get; init; }

    /// <summary>
    /// Methods that read this field.
    /// </summary>
    public List<string> ReadingMethods { get; init; } = [];

    /// <summary>
    /// Methods that write to this field.
    /// </summary>
    public List<string> WritingMethods { get; init; } = [];

    /// <summary>
    /// The file path where the field is declared.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Line number of the field declaration.
    /// </summary>
    public int DeclarationLine { get; init; }

    /// <summary>
    /// The Roslyn symbol for the field (not serialized).
    /// </summary>
    public IFieldSymbol? Symbol { get; init; }
}

/// <summary>
/// Information about a lock statement in the code.
/// </summary>
public record LockInfo
{
    /// <summary>
    /// The expression being locked on.
    /// </summary>
    public required string LockExpression { get; init; }

    /// <summary>
    /// The type of lock target (This, String, Type, Field, NewObject, etc.)
    /// </summary>
    public required string LockTargetType { get; init; }

    /// <summary>
    /// The containing method name.
    /// </summary>
    public required string MethodName { get; init; }

    /// <summary>
    /// The containing class name.
    /// </summary>
    public required string ClassName { get; init; }

    /// <summary>
    /// The file path.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Line number.
    /// </summary>
    public int Line { get; init; }

    /// <summary>
    /// Nested lock expressions (for deadlock detection).
    /// </summary>
    public List<string> NestedLocks { get; init; } = [];
}

/// <summary>
/// Result of thread safety analysis for a project.
/// </summary>
public record ThreadSafetyAnalysisResult
{
    /// <summary>
    /// Total number of issues found.
    /// </summary>
    public int TotalIssues { get; init; }

    /// <summary>
    /// Number of critical severity issues.
    /// </summary>
    public int CriticalCount { get; init; }

    /// <summary>
    /// Number of high severity issues.
    /// </summary>
    public int HighCount { get; init; }

    /// <summary>
    /// Number of medium severity issues.
    /// </summary>
    public int MediumCount { get; init; }

    /// <summary>
    /// Number of low severity issues.
    /// </summary>
    public int LowCount { get; init; }

    /// <summary>
    /// Number of informational issues.
    /// </summary>
    public int InfoCount { get; init; }

    /// <summary>
    /// All detected issues.
    /// </summary>
    public List<ThreadSafetyIssue> Issues { get; init; } = [];

    /// <summary>
    /// Issues grouped by type.
    /// </summary>
    public Dictionary<string, List<ThreadSafetyIssue>> IssuesByType { get; init; } = [];

    /// <summary>
    /// Issues grouped by rule ID.
    /// </summary>
    public Dictionary<string, int> IssueCountByRule { get; init; } = [];

    /// <summary>
    /// Shared fields detected in the codebase.
    /// </summary>
    public List<SharedFieldInfo> SharedFields { get; init; } = [];

    /// <summary>
    /// Lock patterns detected in the codebase.
    /// </summary>
    public List<LockInfo> LockPatterns { get; init; } = [];

    /// <summary>
    /// Files analyzed.
    /// </summary>
    public int FilesAnalyzed { get; init; }

    /// <summary>
    /// Analysis duration in milliseconds.
    /// </summary>
    public long AnalysisDurationMs { get; init; }
}

/// <summary>
/// Thread safety rule definitions.
/// </summary>
public static class ThreadSafetyRules
{
    public const string SharedMutableStatic = "TS001";
    public const string UnprotectedFieldAccess = "TS002";
    public const string NonAtomicIncrement = "TS003";
    public const string DoubleCheckedLocking = "TS004";
    public const string AsyncVoidReentrancy = "TS005";
    public const string LockOnThis = "TS006";
    public const string LockOnString = "TS007";
    public const string NestedLocks = "TS008";
    public const string TaskResultBlocking = "TS009";
    public const string LockOnType = "TS010";
    public const string LockOnValueType = "TS011";
    public const string LockOnNewObject = "TS012";
    public const string CheckThenActRace = "TS013";
    public const string UnsynchronizedCollectionAccess = "TS014";
    public const string TaskRunInConstructor = "TS015";

    /// <summary>
    /// Gets the description for a rule ID.
    /// </summary>
    public static string GetRuleDescription(string ruleId) => ruleId switch
    {
        SharedMutableStatic => "Static field modified from multiple methods without synchronization",
        UnprotectedFieldAccess => "Field accessed without lock in async/multithreaded context",
        NonAtomicIncrement => "Non-atomic compound operation (e.g., counter++) on shared state",
        DoubleCheckedLocking => "Broken double-checked locking pattern (missing volatile)",
        AsyncVoidReentrancy => "Async void event handler with shared state modification",
        LockOnThis => "Locking on 'this' allows external code to cause deadlocks",
        LockOnString => "Locking on interned strings can cause unintended synchronization",
        NestedLocks => "Nested locks may cause deadlock if acquired in different order",
        TaskResultBlocking => "Synchronously blocking on Task (.Result/.Wait()) risks deadlock",
        LockOnType => "Locking on Type object allows external code to cause deadlocks",
        LockOnValueType => "Locking on value type causes boxing - each lock is on different object",
        LockOnNewObject => "Locking on new object() provides no synchronization",
        CheckThenActRace => "Check-then-act pattern may race in concurrent context",
        UnsynchronizedCollectionAccess => "Collection accessed without synchronization in static context",
        TaskRunInConstructor => "Starting tasks in constructor with partially constructed object",
        _ => "Unknown thread safety issue"
    };

    /// <summary>
    /// Gets the default severity for a rule.
    /// </summary>
    public static string GetDefaultSeverity(string ruleId) => ruleId switch
    {
        SharedMutableStatic => "High",
        UnprotectedFieldAccess => "Medium",
        NonAtomicIncrement => "Medium",
        DoubleCheckedLocking => "High",
        AsyncVoidReentrancy => "High",
        LockOnThis => "Medium",
        LockOnString => "High",
        NestedLocks => "Medium",
        TaskResultBlocking => "High",
        LockOnType => "High",
        LockOnValueType => "Critical",
        LockOnNewObject => "Critical",
        CheckThenActRace => "High",
        UnsynchronizedCollectionAccess => "High",
        TaskRunInConstructor => "Medium",
        _ => "Medium"
    };

    /// <summary>
    /// Gets the CWE ID for a rule if applicable.
    /// </summary>
    public static string? GetCweId(string ruleId) => ruleId switch
    {
        SharedMutableStatic => "CWE-366",
        UnprotectedFieldAccess => "CWE-366",
        NonAtomicIncrement => "CWE-366",
        DoubleCheckedLocking => "CWE-609",
        AsyncVoidReentrancy => "CWE-367",
        LockOnThis => "CWE-667",
        LockOnString => "CWE-667",
        NestedLocks => "CWE-833",
        TaskResultBlocking => "CWE-833",
        LockOnType => "CWE-667",
        LockOnValueType => "CWE-667",
        LockOnNewObject => "CWE-667",
        CheckThenActRace => "CWE-362",
        UnsynchronizedCollectionAccess => "CWE-366",
        TaskRunInConstructor => "CWE-543",
        _ => null
    };
}
