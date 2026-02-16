using Microsoft.CodeAnalysis;

namespace BaseScanner.Analyzers.Memory;

/// <summary>
/// Represents a detected memory leak or potential memory issue.
/// </summary>
public record MemoryLeak
{
    /// <summary>
    /// Type of memory leak (e.g., "EventHandlerLeak", "ClosureCapture", "StaticGrowth")
    /// </summary>
    public required string LeakType { get; init; }

    /// <summary>
    /// Severity level: Critical, High, Medium, Low
    /// </summary>
    public required string Severity { get; init; }

    /// <summary>
    /// Path to the file containing the leak
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Starting line number (1-based)
    /// </summary>
    public required int StartLine { get; init; }

    /// <summary>
    /// Ending line number (1-based)
    /// </summary>
    public required int EndLine { get; init; }

    /// <summary>
    /// Human-readable description of the memory leak
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Recommended fix or mitigation
    /// </summary>
    public required string Recommendation { get; init; }

    /// <summary>
    /// The problematic code snippet
    /// </summary>
    public required string ProblematicCode { get; init; }

    /// <summary>
    /// Suggested fixed code
    /// </summary>
    public required string SuggestedFix { get; init; }

    /// <summary>
    /// Confidence level of the detection: High, Medium, Low
    /// </summary>
    public string Confidence { get; init; } = "Medium";

    /// <summary>
    /// CWE identifier for memory-related issues
    /// </summary>
    public string CweId { get; init; } = "CWE-401";

    /// <summary>
    /// Estimated memory impact in bytes (if known)
    /// </summary>
    public long? EstimatedMemoryImpact { get; init; }

    /// <summary>
    /// Whether this leak occurs in a hot path (loop, frequently called method)
    /// </summary>
    public bool IsInHotPath { get; init; }

    /// <summary>
    /// Additional context about captured variables, event sources, etc.
    /// </summary>
    public List<string> Details { get; init; } = [];

    /// <summary>
    /// Link to CWE reference
    /// </summary>
    public string CweLink => $"https://cwe.mitre.org/data/definitions/{CweId.Replace("CWE-", "")}.html";
}

/// <summary>
/// Information about an event subscription pair (subscribe/unsubscribe).
/// </summary>
public record EventSubscriptionInfo
{
    /// <summary>
    /// The event name
    /// </summary>
    public required string EventName { get; init; }

    /// <summary>
    /// The expression representing the event source (e.g., "button.Click")
    /// </summary>
    public required string EventSource { get; init; }

    /// <summary>
    /// The handler expression
    /// </summary>
    public required string Handler { get; init; }

    /// <summary>
    /// Location of the subscription
    /// </summary>
    public required Location SubscriptionLocation { get; init; }

    /// <summary>
    /// Whether there's a corresponding unsubscription
    /// </summary>
    public bool HasUnsubscription { get; init; }

    /// <summary>
    /// Location of unsubscription (if exists)
    /// </summary>
    public Location? UnsubscriptionLocation { get; init; }

    /// <summary>
    /// The containing type name
    /// </summary>
    public string ContainingType { get; init; } = "";

    /// <summary>
    /// The containing method name
    /// </summary>
    public string ContainingMethod { get; init; } = "";
}

/// <summary>
/// Information about a closure that captures variables.
/// </summary>
public record ClosureCaptureInfo
{
    /// <summary>
    /// Names of captured variables
    /// </summary>
    public required List<string> CapturedVariables { get; init; }

    /// <summary>
    /// Whether 'this' is captured
    /// </summary>
    public bool CapturesThis { get; init; }

    /// <summary>
    /// Whether large objects are captured
    /// </summary>
    public bool CapturesLargeObjects { get; init; }

    /// <summary>
    /// Estimated size of captured data
    /// </summary>
    public long EstimatedCaptureSize { get; init; }

    /// <summary>
    /// The context where the closure is created (e.g., "event handler", "LINQ query", "Task")
    /// </summary>
    public string Context { get; init; } = "";

    /// <summary>
    /// Whether the closure escapes the current scope
    /// </summary>
    public bool EscapesScope { get; init; }
}

/// <summary>
/// Information about a static collection.
/// </summary>
public record StaticCollectionInfo
{
    /// <summary>
    /// Name of the static field/property
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Collection type (e.g., "List<T>", "Dictionary<K,V>")
    /// </summary>
    public required string CollectionType { get; init; }

    /// <summary>
    /// Count of Add/Insert operations found
    /// </summary>
    public int AddOperations { get; init; }

    /// <summary>
    /// Count of Remove/Clear operations found
    /// </summary>
    public int RemoveOperations { get; init; }

    /// <summary>
    /// Whether the collection has a size limit
    /// </summary>
    public bool HasSizeLimit { get; init; }

    /// <summary>
    /// Whether weak references are used
    /// </summary>
    public bool UsesWeakReferences { get; init; }

    /// <summary>
    /// Whether Add operations occur inside a loop
    /// </summary>
    public bool AddInLoop { get; init; }
}

/// <summary>
/// Information about Large Object Heap allocations.
/// </summary>
public record LOHAllocationInfo
{
    /// <summary>
    /// The allocation expression
    /// </summary>
    public required string AllocationExpression { get; init; }

    /// <summary>
    /// Estimated size of allocation in bytes
    /// </summary>
    public required long EstimatedSize { get; init; }

    /// <summary>
    /// Whether the allocation is in a loop
    /// </summary>
    public bool IsInLoop { get; init; }

    /// <summary>
    /// The type being allocated
    /// </summary>
    public string AllocatedType { get; init; } = "";

    /// <summary>
    /// Whether the size is exactly known (vs estimated)
    /// </summary>
    public bool IsExactSize { get; init; }
}

/// <summary>
/// Summary of memory leak analysis results.
/// </summary>
public record MemoryLeakSummary
{
    public int TotalLeaks { get; init; }
    public int CriticalCount { get; init; }
    public int HighCount { get; init; }
    public int MediumCount { get; init; }
    public int LowCount { get; init; }
    public Dictionary<string, int> LeaksByType { get; init; } = [];
    public long TotalEstimatedMemoryImpact { get; init; }
    public int HotPathLeaks { get; init; }
}

/// <summary>
/// Complete result of memory leak analysis.
/// </summary>
public record MemoryLeakResult
{
    public List<MemoryLeak> Leaks { get; init; } = [];
    public MemoryLeakSummary Summary { get; init; } = new();
}
