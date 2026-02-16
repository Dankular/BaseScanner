using System.Collections.Immutable;

namespace BaseScanner.Analyzers.Debt.Models;

/// <summary>
/// Result of technical debt analysis.
/// </summary>
public record TechnicalDebtResult
{
    /// <summary>
    /// Overall debt rating from A (best) to E (worst).
    /// </summary>
    public required string Rating { get; init; }

    /// <summary>
    /// Overall debt score (0-100, lower is better).
    /// </summary>
    public required double Score { get; init; }

    /// <summary>
    /// Total estimated time to fix all debt (in minutes).
    /// </summary>
    public required int TotalDebtMinutes { get; init; }

    /// <summary>
    /// Estimated debt interest - ongoing cost of not fixing (minutes/week).
    /// </summary>
    public required int DebtInterestPerWeek { get; init; }

    /// <summary>
    /// Summary of debt by category.
    /// </summary>
    public required DebtSummary Summary { get; init; }

    /// <summary>
    /// All debt items ranked by payoff.
    /// </summary>
    public required List<DebtItem> Items { get; init; }

    /// <summary>
    /// Quick wins - high payoff, low effort.
    /// </summary>
    public required List<DebtItem> QuickWins { get; init; }

    /// <summary>
    /// Major projects - high impact but high effort.
    /// </summary>
    public required List<DebtItem> MajorProjects { get; init; }

    /// <summary>
    /// Low priority - low impact items.
    /// </summary>
    public required List<DebtItem> LowPriority { get; init; }

    /// <summary>
    /// Debt trend over git history.
    /// </summary>
    public required DebtTrend Trend { get; init; }

    /// <summary>
    /// Debt breakdown by file (hotspots).
    /// </summary>
    public required List<FileDebt> FileHotspots { get; init; }

    /// <summary>
    /// When this analysis was generated.
    /// </summary>
    public DateTime GeneratedAt { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Summary of technical debt by category.
/// </summary>
public record DebtSummary
{
    public int TotalItems { get; init; }
    public int CriticalItems { get; init; }
    public int HighItems { get; init; }
    public int MediumItems { get; init; }
    public int LowItems { get; init; }

    /// <summary>
    /// Debt minutes by category.
    /// </summary>
    public Dictionary<string, int> DebtByCategory { get; init; } = [];

    /// <summary>
    /// Item count by category.
    /// </summary>
    public Dictionary<string, int> ItemsByCategory { get; init; } = [];

    /// <summary>
    /// Debt minutes by severity.
    /// </summary>
    public Dictionary<string, int> DebtBySeverity { get; init; } = [];
}

/// <summary>
/// Individual debt item.
/// </summary>
public record DebtItem
{
    /// <summary>
    /// Unique identifier for tracking.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// Category of debt (CodeSmell, Security, Performance, etc.).
    /// </summary>
    public required string Category { get; init; }

    /// <summary>
    /// Specific type within category (LongMethod, GodClass, etc.).
    /// </summary>
    public required string Type { get; init; }

    /// <summary>
    /// Severity level (Critical, High, Medium, Low).
    /// </summary>
    public required string Severity { get; init; }

    /// <summary>
    /// Human-readable description.
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// File path where the debt exists.
    /// </summary>
    public required string FilePath { get; init; }

    /// <summary>
    /// Starting line number.
    /// </summary>
    public required int Line { get; init; }

    /// <summary>
    /// Ending line number.
    /// </summary>
    public int EndLine { get; init; }

    /// <summary>
    /// Estimated time to fix (in minutes).
    /// </summary>
    public required int TimeToFixMinutes { get; init; }

    /// <summary>
    /// Estimated ongoing cost if not fixed (minutes/week of wasted effort).
    /// </summary>
    public required int InterestPerWeek { get; init; }

    /// <summary>
    /// Impact score (0-100).
    /// </summary>
    public required double ImpactScore { get; init; }

    /// <summary>
    /// Effort score (0-100, higher = more effort).
    /// </summary>
    public required double EffortScore { get; init; }

    /// <summary>
    /// Frequency/occurrence count.
    /// </summary>
    public int Frequency { get; init; } = 1;

    /// <summary>
    /// Calculated payoff score: (Impact * Frequency) / Effort.
    /// Higher is better ROI.
    /// </summary>
    public required double PayoffScore { get; init; }

    /// <summary>
    /// Priority bucket.
    /// </summary>
    public required DebtPriority Priority { get; init; }

    /// <summary>
    /// Suggested fix or approach.
    /// </summary>
    public string? Suggestion { get; init; }

    /// <summary>
    /// Related CWE ID for security issues.
    /// </summary>
    public string? CweId { get; init; }

    /// <summary>
    /// Source analyzer that found this issue.
    /// </summary>
    public required string Source { get; init; }

    /// <summary>
    /// Additional context or code snippet.
    /// </summary>
    public string? Context { get; init; }
}

/// <summary>
/// Priority classification for debt items.
/// </summary>
public enum DebtPriority
{
    /// <summary>
    /// High impact, low effort - do first.
    /// </summary>
    QuickWin,

    /// <summary>
    /// High impact, high effort - plan for sprints.
    /// </summary>
    MajorProject,

    /// <summary>
    /// Low impact - defer or address opportunistically.
    /// </summary>
    LowPriority,

    /// <summary>
    /// Critical security/safety - must fix immediately.
    /// </summary>
    Critical
}

/// <summary>
/// Debt trend over time.
/// </summary>
public record DebtTrend
{
    /// <summary>
    /// Whether git history analysis was available.
    /// </summary>
    public bool GitAvailable { get; init; }

    /// <summary>
    /// Direction of debt change.
    /// </summary>
    public required TrendDirection Direction { get; init; }

    /// <summary>
    /// Percentage change over analysis period.
    /// </summary>
    public double PercentageChange { get; init; }

    /// <summary>
    /// Historical data points.
    /// </summary>
    public List<TrendDataPoint> History { get; init; } = [];

    /// <summary>
    /// Projected debt if current trend continues (in months).
    /// </summary>
    public List<TrendProjection> Projections { get; init; } = [];

    /// <summary>
    /// Files with improving debt.
    /// </summary>
    public List<string> ImprovingFiles { get; init; } = [];

    /// <summary>
    /// Files with worsening debt.
    /// </summary>
    public List<string> WorseningFiles { get; init; } = [];
}

/// <summary>
/// Direction of debt trend.
/// </summary>
public enum TrendDirection
{
    Improving,
    Stable,
    Worsening,
    Unknown
}

/// <summary>
/// Historical data point for debt tracking.
/// </summary>
public record TrendDataPoint
{
    public required DateTime Date { get; init; }
    public required string CommitHash { get; init; }
    public required int TotalDebtMinutes { get; init; }
    public required int ItemCount { get; init; }
    public required double Score { get; init; }
}

/// <summary>
/// Projected future debt.
/// </summary>
public record TrendProjection
{
    public required int MonthsFromNow { get; init; }
    public required int ProjectedDebtMinutes { get; init; }
    public required double ProjectedScore { get; init; }
}

/// <summary>
/// Debt aggregated by file.
/// </summary>
public record FileDebt
{
    public required string FilePath { get; init; }
    public required int TotalDebtMinutes { get; init; }
    public required int ItemCount { get; init; }
    public required int CriticalCount { get; init; }
    public required int HighCount { get; init; }
    public required double AveragePayoff { get; init; }
    public List<string> TopIssueTypes { get; init; } = [];
}

/// <summary>
/// Debt category constants.
/// </summary>
public static class DebtCategory
{
    public const string CodeSmells = "CodeSmells";
    public const string Security = "Security";
    public const string Performance = "Performance";
    public const string Maintainability = "Maintainability";
    public const string Testing = "Testing";
    public const string Documentation = "Documentation";
    public const string Dependencies = "Dependencies";
    public const string Architecture = "Architecture";
    public const string Concurrency = "Concurrency";
}

/// <summary>
/// Debt type constants for consistent naming.
/// </summary>
public static class DebtType
{
    // Code Smells
    public const string LongMethod = "LongMethod";
    public const string GodClass = "GodClass";
    public const string DuplicateCode = "DuplicateCode";
    public const string FeatureEnvy = "FeatureEnvy";
    public const string DataClump = "DataClump";
    public const string LongParameterList = "LongParameterList";
    public const string DeepNesting = "DeepNesting";
    public const string MagicNumber = "MagicNumber";
    public const string PrimitiveObsession = "PrimitiveObsession";

    // Security
    public const string SqlInjection = "SqlInjection";
    public const string Xss = "Xss";
    public const string HardcodedSecret = "HardcodedSecret";
    public const string InsecureCrypto = "InsecureCrypto";
    public const string PathTraversal = "PathTraversal";
    public const string InsecureDeserialization = "InsecureDeserialization";

    // Performance
    public const string AsyncVoid = "AsyncVoid";
    public const string IneffientLoop = "InefficientLoop";
    public const string MissingDispose = "MissingDispose";
    public const string UnoptimizedLinq = "UnoptimizedLinq";
    public const string StringConcatenation = "StringConcatenation";

    // Maintainability
    public const string HighComplexity = "HighComplexity";
    public const string LowCohesion = "LowCohesion";
    public const string HighCoupling = "HighCoupling";
    public const string DeepInheritance = "DeepInheritance";
    public const string CircularDependency = "CircularDependency";

    // Testing
    public const string MissingTests = "MissingTests";
    public const string TestSmell = "TestSmell";
    public const string LowCoverage = "LowCoverage";

    // Documentation
    public const string MissingDocs = "MissingDocs";
    public const string StaleDocs = "StaleDocs";

    // Dependencies
    public const string OutdatedDependency = "OutdatedDependency";
    public const string VulnerableDependency = "VulnerableDependency";
    public const string DeprecatedDependency = "DeprecatedDependency";
}

/// <summary>
/// Base cost in minutes for fixing each type of debt.
/// </summary>
public static class DebtCost
{
    // Code Smells
    public const int LongMethod = 30;
    public const int GodClass = 120;
    public const int DuplicateCode = 15;
    public const int FeatureEnvy = 20;
    public const int DataClump = 30;
    public const int LongParameterList = 15;
    public const int DeepNesting = 20;
    public const int MagicNumber = 5;
    public const int PrimitiveObsession = 45;

    // Security by severity
    public const int SecurityCritical = 480;  // 8 hours
    public const int SecurityHigh = 240;      // 4 hours
    public const int SecurityMedium = 60;     // 1 hour
    public const int SecurityLow = 30;        // 30 min

    // Performance
    public const int AsyncIssue = 45;
    public const int InefficientPattern = 30;
    public const int MissingDispose = 20;
    public const int UnoptimizedLinq = 15;
    public const int StringConcatenation = 10;

    // Maintainability
    public const int HighComplexity = 60;
    public const int LowCohesion = 90;
    public const int HighCoupling = 45;
    public const int DeepInheritance = 60;
    public const int CircularDependency = 120;

    // Testing
    public const int MissingTests = 30;
    public const int TestSmell = 15;
    public const int LowCoverage = 60;

    // Documentation
    public const int MissingDocs = 10;
    public const int StaleDocs = 15;

    // Dependencies
    public const int OutdatedDependency = 30;
    public const int VulnerableDependency = 240;
    public const int DeprecatedDependency = 60;

    /// <summary>
    /// Get cost for security issues by severity.
    /// </summary>
    public static int GetSecurityCost(string severity) => severity switch
    {
        "Critical" => SecurityCritical,
        "High" => SecurityHigh,
        "Medium" => SecurityMedium,
        "Low" => SecurityLow,
        _ => SecurityMedium
    };
}

/// <summary>
/// Interest rate - ongoing cost of not fixing (minutes per week).
/// </summary>
public static class DebtInterest
{
    // Code Smells
    public const int LongMethod = 5;        // Slows down every change
    public const int GodClass = 15;         // Major friction
    public const int DuplicateCode = 10;    // Changes needed in multiple places
    public const int FeatureEnvy = 3;
    public const int DataClump = 2;
    public const int LongParameterList = 2;
    public const int DeepNesting = 3;
    public const int MagicNumber = 1;
    public const int PrimitiveObsession = 5;

    // Security - ongoing risk
    public const int SecurityCritical = 60; // High risk per week
    public const int SecurityHigh = 30;
    public const int SecurityMedium = 10;
    public const int SecurityLow = 2;

    // Performance - user impact
    public const int PerformanceHigh = 20;
    public const int PerformanceMedium = 5;
    public const int PerformanceLow = 1;

    // Maintainability
    public const int HighComplexity = 10;
    public const int LowCohesion = 8;
    public const int HighCoupling = 5;

    // Testing - bugs slip through
    public const int MissingTests = 15;
    public const int TestSmell = 3;

    // Documentation - onboarding cost
    public const int MissingDocs = 2;
    public const int StaleDocs = 3;

    // Dependencies - security exposure
    public const int VulnerableDependency = 30;
    public const int OutdatedDependency = 5;

    /// <summary>
    /// Get interest for security issues by severity.
    /// </summary>
    public static int GetSecurityInterest(string severity) => severity switch
    {
        "Critical" => SecurityCritical,
        "High" => SecurityHigh,
        "Medium" => SecurityMedium,
        "Low" => SecurityLow,
        _ => SecurityMedium
    };
}
