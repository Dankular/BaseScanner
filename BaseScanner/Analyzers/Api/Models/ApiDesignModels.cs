using Microsoft.CodeAnalysis;

namespace BaseScanner.Analyzers.Api.Models;

/// <summary>
/// Represents an API design issue detected during analysis.
/// </summary>
public record ApiDesignIssue
{
    /// <summary>
    /// Category of the issue (e.g., "Consistency", "BreakingChange", "REST", "Versioning")
    /// </summary>
    public required string Category { get; init; }

    /// <summary>
    /// Specific type of issue (e.g., "InconsistentNaming", "RemovedPublicMember")
    /// </summary>
    public required string IssueType { get; init; }

    /// <summary>
    /// Severity level: Critical, High, Medium, Low
    /// </summary>
    public required string Severity { get; init; }

    /// <summary>
    /// Human-readable description of the issue
    /// </summary>
    public required string Message { get; init; }

    /// <summary>
    /// Path to the file containing the issue
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Line number (1-based)
    /// </summary>
    public required int Line { get; init; }

    /// <summary>
    /// The affected code element (method, property, class name)
    /// </summary>
    public required string AffectedElement { get; init; }

    /// <summary>
    /// Recommendation for fixing the issue
    /// </summary>
    public string? Recommendation { get; init; }

    /// <summary>
    /// Related elements (e.g., similar methods with inconsistent naming)
    /// </summary>
    public List<string> RelatedElements { get; init; } = [];

    /// <summary>
    /// Impact score (1-10) indicating how severe the issue is
    /// </summary>
    public int ImpactScore { get; init; } = 5;
}

/// <summary>
/// Represents a potential breaking change in the API.
/// </summary>
public record BreakingChange
{
    /// <summary>
    /// Type of breaking change
    /// </summary>
    public required BreakingChangeType ChangeType { get; init; }

    /// <summary>
    /// Severity: Critical (will break), High (likely break), Medium (may break)
    /// </summary>
    public required string Severity { get; init; }

    /// <summary>
    /// The affected public API member
    /// </summary>
    public required string AffectedMember { get; init; }

    /// <summary>
    /// Description of the change
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// File path
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Line number
    /// </summary>
    public required int Line { get; init; }

    /// <summary>
    /// Previous signature/state (if applicable)
    /// </summary>
    public string? PreviousState { get; init; }

    /// <summary>
    /// Current signature/state
    /// </summary>
    public string? CurrentState { get; init; }

    /// <summary>
    /// Suggested mitigation (e.g., add obsolete attribute first)
    /// </summary>
    public string? Mitigation { get; init; }
}

/// <summary>
/// Types of breaking changes
/// </summary>
public enum BreakingChangeType
{
    RemovedPublicMember,
    ChangedSignature,
    ChangedReturnType,
    RemovedOptionalParameter,
    AddedRequiredParameter,
    ChangedException,
    SealedClass,
    RemovedVirtual,
    ChangedAccessibility,
    RemovedInterface,
    ChangedBaseClass,
    RemovedOverload
}

/// <summary>
/// Represents a REST API endpoint analysis result.
/// </summary>
public record RestEndpointIssue
{
    /// <summary>
    /// The HTTP method (GET, POST, PUT, DELETE, PATCH)
    /// </summary>
    public required string HttpMethod { get; init; }

    /// <summary>
    /// The route template
    /// </summary>
    public required string Route { get; init; }

    /// <summary>
    /// Controller name
    /// </summary>
    public required string Controller { get; init; }

    /// <summary>
    /// Action name
    /// </summary>
    public required string Action { get; init; }

    /// <summary>
    /// Issue type
    /// </summary>
    public required RestIssueType IssueType { get; init; }

    /// <summary>
    /// Severity level
    /// </summary>
    public required string Severity { get; init; }

    /// <summary>
    /// Description of the issue
    /// </summary>
    public required string Message { get; init; }

    /// <summary>
    /// File path
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Line number
    /// </summary>
    public required int Line { get; init; }

    /// <summary>
    /// Recommendation
    /// </summary>
    public string? Recommendation { get; init; }
}

/// <summary>
/// Types of REST API issues
/// </summary>
public enum RestIssueType
{
    VerbMismatch,              // GET that mutates state
    InconsistentRoute,         // Inconsistent route patterns
    MissingResponseType,       // Missing [ProducesResponseType]
    InappropriateStatusCode,   // Wrong status code for action type
    MissingAuthorization,      // Missing [Authorize] on sensitive endpoints
    InconsistentNaming,        // Route doesn't match action name pattern
    MissingVersioning,         // No API versioning
    InvalidRouteParameter,     // Route parameter issues
    MixedRoutingStyles,        // Mixing attribute and conventional routing
    MissingContentType         // Missing content type specification
}

/// <summary>
/// Represents an API versioning issue.
/// </summary>
public record VersioningIssue
{
    /// <summary>
    /// Type of versioning issue
    /// </summary>
    public required VersioningIssueType IssueType { get; init; }

    /// <summary>
    /// Severity level
    /// </summary>
    public required string Severity { get; init; }

    /// <summary>
    /// Description
    /// </summary>
    public required string Message { get; init; }

    /// <summary>
    /// File path
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Line number
    /// </summary>
    public required int Line { get; init; }

    /// <summary>
    /// Affected element
    /// </summary>
    public required string AffectedElement { get; init; }

    /// <summary>
    /// Recommendation
    /// </summary>
    public string? Recommendation { get; init; }

    /// <summary>
    /// Current version (if applicable)
    /// </summary>
    public string? CurrentVersion { get; init; }

    /// <summary>
    /// Suggested version pattern
    /// </summary>
    public string? SuggestedPattern { get; init; }
}

/// <summary>
/// Types of versioning issues
/// </summary>
public enum VersioningIssueType
{
    MissingVersioning,          // No versioning strategy
    InconsistentVersioning,     // Mixed versioning strategies
    DeprecatedWithoutReplacement, // Deprecated without pointing to new version
    MissingDeprecation,         // Old version not marked deprecated
    VersionInUrl,               // Version in URL instead of header (can be intentional)
    MultipleVersionAttributes,  // Conflicting version attributes
    InvalidVersionFormat        // Invalid version format
}

/// <summary>
/// Represents an API consistency group for analysis.
/// </summary>
public record ApiConsistencyGroup
{
    /// <summary>
    /// The operation type (e.g., "Get", "Fetch", "Retrieve")
    /// </summary>
    public required string Operation { get; init; }

    /// <summary>
    /// Methods in this group
    /// </summary>
    public required List<ApiMethodInfo> Methods { get; init; }

    /// <summary>
    /// Whether this group has consistency issues
    /// </summary>
    public bool HasIssues => Methods.Select(m => m.NamingPattern).Distinct().Count() > 1;
}

/// <summary>
/// Information about an API method.
/// </summary>
public record ApiMethodInfo
{
    public required string TypeName { get; init; }
    public required string MethodName { get; init; }
    public required string FullSignature { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required string ReturnType { get; init; }
    public required List<string> Parameters { get; init; }
    public required bool IsAsync { get; init; }
    public string? NamingPattern { get; init; }
    public bool HasAsyncCounterpart { get; init; }
}

/// <summary>
/// Complete result of API design analysis.
/// </summary>
public record ApiDesignResult
{
    /// <summary>
    /// All detected issues
    /// </summary>
    public List<ApiDesignIssue> Issues { get; init; } = [];

    /// <summary>
    /// Breaking changes detected
    /// </summary>
    public List<BreakingChange> BreakingChanges { get; init; } = [];

    /// <summary>
    /// REST endpoint issues
    /// </summary>
    public List<RestEndpointIssue> RestIssues { get; init; } = [];

    /// <summary>
    /// Versioning issues
    /// </summary>
    public List<VersioningIssue> VersioningIssues { get; init; } = [];

    /// <summary>
    /// Summary statistics
    /// </summary>
    public ApiDesignSummary Summary { get; init; } = new();
}

/// <summary>
/// Summary of API design analysis.
/// </summary>
public record ApiDesignSummary
{
    public int TotalIssues { get; init; }
    public int ConsistencyIssues { get; init; }
    public int BreakingChangeRisks { get; init; }
    public int RestIssues { get; init; }
    public int VersioningIssues { get; init; }
    public int CriticalCount { get; init; }
    public int HighCount { get; init; }
    public int MediumCount { get; init; }
    public int LowCount { get; init; }
    public Dictionary<string, int> IssuesByCategory { get; init; } = [];
    public Dictionary<string, int> IssuesByType { get; init; } = [];
    public double ApiHealthScore { get; init; }
}

/// <summary>
/// Represents an API endpoint for REST analysis.
/// </summary>
public record ApiEndpoint
{
    public required string Controller { get; init; }
    public required string Action { get; init; }
    public required string HttpMethod { get; init; }
    public required string Route { get; init; }
    public required string ReturnType { get; init; }
    public required List<string> Parameters { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public List<string> ResponseTypes { get; init; } = [];
    public List<int> StatusCodes { get; init; } = [];
    public bool RequiresAuth { get; init; }
    public string? Version { get; init; }
    public bool IsDeprecated { get; init; }
}

/// <summary>
/// Represents a public API surface for breaking change detection.
/// </summary>
public record PublicApiSurface
{
    public required string TypeName { get; init; }
    public required string Namespace { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required ApiElementType ElementType { get; init; }
    public required string Signature { get; init; }
    public required Accessibility Accessibility { get; init; }
    public bool IsVirtual { get; init; }
    public bool IsSealed { get; init; }
    public bool IsAbstract { get; init; }
    public bool IsObsolete { get; init; }
    public string? ObsoleteMessage { get; init; }
    public List<string> Interfaces { get; init; } = [];
    public string? BaseType { get; init; }
}

/// <summary>
/// Type of API element
/// </summary>
public enum ApiElementType
{
    Class,
    Interface,
    Struct,
    Record,
    Method,
    Property,
    Field,
    Event,
    Constructor
}
