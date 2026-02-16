namespace BaseScanner.Analyzers.Testing.Models;

/// <summary>
/// Comprehensive result of test coverage analysis.
/// </summary>
public record TestCoverageResult
{
    /// <summary>
    /// Overall coverage statistics.
    /// </summary>
    public required CoverageStatistics Statistics { get; init; }

    /// <summary>
    /// Methods with no test coverage.
    /// </summary>
    public required List<UncoveredMethod> UncoveredMethods { get; init; }

    /// <summary>
    /// Branches with no test coverage.
    /// </summary>
    public required List<UncoveredBranch> UncoveredBranches { get; init; }

    /// <summary>
    /// Detected test smells.
    /// </summary>
    public required List<TestSmell> TestSmells { get; init; }

    /// <summary>
    /// Test quality issues.
    /// </summary>
    public required List<TestQualityIssue> QualityIssues { get; init; }

    /// <summary>
    /// Critical code paths without tests.
    /// </summary>
    public required List<CriticalPathWithoutTests> CriticalPaths { get; init; }

    /// <summary>
    /// Coverage breakdown by namespace.
    /// </summary>
    public required Dictionary<string, NamespaceCoverage> CoverageByNamespace { get; init; }

    /// <summary>
    /// Summary of the analysis.
    /// </summary>
    public required TestCoverageSummary Summary { get; init; }
}

/// <summary>
/// Overall coverage statistics.
/// </summary>
public record CoverageStatistics
{
    public required int TotalLines { get; init; }
    public required int CoveredLines { get; init; }
    public required int TotalBranches { get; init; }
    public required int CoveredBranches { get; init; }
    public required int TotalMethods { get; init; }
    public required int CoveredMethods { get; init; }
    public required int TotalClasses { get; init; }
    public required int CoveredClasses { get; init; }

    public double LineCoverage => TotalLines > 0 ? (double)CoveredLines / TotalLines * 100 : 0;
    public double BranchCoverage => TotalBranches > 0 ? (double)CoveredBranches / TotalBranches * 100 : 0;
    public double MethodCoverage => TotalMethods > 0 ? (double)CoveredMethods / TotalMethods * 100 : 0;
    public double ClassCoverage => TotalClasses > 0 ? (double)CoveredClasses / TotalClasses * 100 : 0;
}

/// <summary>
/// Coverage data for a namespace.
/// </summary>
public record NamespaceCoverage
{
    public required string Namespace { get; init; }
    public required int TotalLines { get; init; }
    public required int CoveredLines { get; init; }
    public required int TotalMethods { get; init; }
    public required int CoveredMethods { get; init; }
    public required int TotalBranches { get; init; }
    public required int CoveredBranches { get; init; }
    public required List<ClassCoverage> Classes { get; init; }

    public double LineCoverage => TotalLines > 0 ? (double)CoveredLines / TotalLines * 100 : 0;
    public double MethodCoverage => TotalMethods > 0 ? (double)CoveredMethods / TotalMethods * 100 : 0;
    public double BranchCoverage => TotalBranches > 0 ? (double)CoveredBranches / TotalBranches * 100 : 0;
}

/// <summary>
/// Coverage data for a class.
/// </summary>
public record ClassCoverage
{
    public required string ClassName { get; init; }
    public required string FullName { get; init; }
    public required string FilePath { get; init; }
    public required int TotalLines { get; init; }
    public required int CoveredLines { get; init; }
    public required int TotalMethods { get; init; }
    public required int CoveredMethods { get; init; }
    public required int TotalBranches { get; init; }
    public required int CoveredBranches { get; init; }
    public required List<MethodCoverage> Methods { get; init; }

    public double LineCoverage => TotalLines > 0 ? (double)CoveredLines / TotalLines * 100 : 0;
    public double MethodCoverage => TotalMethods > 0 ? (double)CoveredMethods / TotalMethods * 100 : 0;
    public double BranchCoverage => TotalBranches > 0 ? (double)CoveredBranches / TotalBranches * 100 : 0;
}

/// <summary>
/// Coverage data for a method.
/// </summary>
public record MethodCoverage
{
    public required string MethodName { get; init; }
    public required string FullName { get; init; }
    public required string FilePath { get; init; }
    public required int StartLine { get; init; }
    public required int EndLine { get; init; }
    public required int TotalLines { get; init; }
    public required int CoveredLines { get; init; }
    public required int TotalBranches { get; init; }
    public required int CoveredBranches { get; init; }
    public required int CyclomaticComplexity { get; init; }
    public required List<BranchCoverage> Branches { get; init; }

    public double LineCoverage => TotalLines > 0 ? (double)CoveredLines / TotalLines * 100 : 0;
    public double BranchCoverage => TotalBranches > 0 ? (double)CoveredBranches / TotalBranches * 100 : 0;
    public bool IsCovered => CoveredLines > 0;
}

/// <summary>
/// Coverage data for a branch.
/// </summary>
public record BranchCoverage
{
    public required int Line { get; init; }
    public required int Offset { get; init; }
    public required int PathIndex { get; init; }
    public required bool IsCovered { get; init; }
    public required int HitCount { get; init; }
    public required BranchType Type { get; init; }
}

/// <summary>
/// Type of branch in code.
/// </summary>
public enum BranchType
{
    If,
    Else,
    Switch,
    Case,
    TernaryTrue,
    TernaryFalse,
    NullCoalescing,
    PatternMatch,
    Unknown
}

/// <summary>
/// A method with no test coverage.
/// </summary>
public record UncoveredMethod
{
    public required string MethodName { get; init; }
    public required string ClassName { get; init; }
    public required string Namespace { get; init; }
    public required string FilePath { get; init; }
    public required int StartLine { get; init; }
    public required int EndLine { get; init; }
    public required int CyclomaticComplexity { get; init; }
    public required UncoveredPriority Priority { get; init; }
    public required string PriorityReason { get; init; }
    public required bool IsPublic { get; init; }
    public required bool HasSecurityImplications { get; init; }
    public required bool HasDataValidation { get; init; }
}

/// <summary>
/// Priority for covering an uncovered method.
/// </summary>
public enum UncoveredPriority
{
    Critical,
    High,
    Medium,
    Low
}

/// <summary>
/// An uncovered branch in code.
/// </summary>
public record UncoveredBranch
{
    public required string MethodName { get; init; }
    public required string ClassName { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required BranchType Type { get; init; }
    public required string CodeSnippet { get; init; }
    public required string SuggestedTest { get; init; }
}

/// <summary>
/// A detected test smell.
/// </summary>
public record TestSmell
{
    public required string TestMethodName { get; init; }
    public required string TestClassName { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required TestSmellType SmellType { get; init; }
    public required string Severity { get; init; }
    public required string Description { get; init; }
    public required string Recommendation { get; init; }
    public required string CodeSnippet { get; init; }
}

/// <summary>
/// Types of test smells.
/// </summary>
public enum TestSmellType
{
    EmptyTest,
    NoAssertions,
    ExcessiveMocking,
    OnlyMockVerification,
    MagicStrings,
    HardcodedValues,
    ThreadSleep,
    DateTimeNow,
    DuplicateTestLogic,
    IgnoredTest,
    CommentedOutCode,
    MultipleArrange,
    LongTest,
    TestNameNotDescriptive,
    MissingActSection,
    AssertionRoulette,
    EagerTest
}

/// <summary>
/// A test quality issue.
/// </summary>
public record TestQualityIssue
{
    public required string TestMethodName { get; init; }
    public required string TestClassName { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required TestQualityIssueType IssueType { get; init; }
    public required string Severity { get; init; }
    public required string Description { get; init; }
    public required string Recommendation { get; init; }
    public string? ExpectedAssertion { get; init; }
}

/// <summary>
/// Types of test quality issues.
/// </summary>
public enum TestQualityIssueType
{
    WeakAssertion,
    MissingBoundaryTest,
    MissingNullTest,
    MissingEmptyTest,
    MissingExceptionTest,
    MissingNegativeTest,
    InsufficientCoverage,
    NoEdgeCases,
    NoErrorCases,
    UnverifiedSideEffects,
    IncompleteArrangement,
    MissingCleanup,
    OverlyBroadAssertion,
    TrueOnlyAssertion,
    StringContainsWithoutPosition
}

/// <summary>
/// A critical code path without test coverage.
/// </summary>
public record CriticalPathWithoutTests
{
    public required string MethodName { get; init; }
    public required string ClassName { get; init; }
    public required string FilePath { get; init; }
    public required int StartLine { get; init; }
    public required int EndLine { get; init; }
    public required CriticalPathType PathType { get; init; }
    public required string Severity { get; init; }
    public required string Description { get; init; }
    public required string RiskAssessment { get; init; }
    public required List<string> SuggestedTests { get; init; }
}

/// <summary>
/// Types of critical paths.
/// </summary>
public enum CriticalPathType
{
    Authentication,
    Authorization,
    DataValidation,
    SqlQuery,
    FileAccess,
    NetworkAccess,
    Cryptography,
    Deserialization,
    ErrorHandling,
    FinancialCalculation,
    PersonalDataProcessing,
    ConfigurationLoading,
    ExternalApiCall,
    DataPersistence
}

/// <summary>
/// Summary of test coverage analysis.
/// </summary>
public record TestCoverageSummary
{
    public required double OverallLineCoverage { get; init; }
    public required double OverallBranchCoverage { get; init; }
    public required double OverallMethodCoverage { get; init; }
    public required int TotalTestSmells { get; init; }
    public required int TotalQualityIssues { get; init; }
    public required int CriticalUncoveredPaths { get; init; }
    public required int HighPriorityUncoveredMethods { get; init; }
    public required string OverallGrade { get; init; }
    public required Dictionary<TestSmellType, int> SmellsByType { get; init; }
    public required Dictionary<CriticalPathType, int> CriticalPathsByType { get; init; }
    public required List<string> TopRecommendations { get; init; }
}

/// <summary>
/// Raw coverage data from a report file.
/// </summary>
public record RawCoverageData
{
    public required CoverageReportFormat Format { get; init; }
    public required DateTime GeneratedAt { get; init; }
    public required List<ModuleCoverageData> Modules { get; init; }
}

/// <summary>
/// Coverage report format.
/// </summary>
public enum CoverageReportFormat
{
    OpenCoverXml,
    CoverletXml,
    CoverletJson,
    DotCoverXml,
    DotCoverJson,
    Cobertura,
    Unknown
}

/// <summary>
/// Coverage data for a module/assembly.
/// </summary>
public record ModuleCoverageData
{
    public required string ModuleName { get; init; }
    public required string AssemblyPath { get; init; }
    public required List<FileCoverageData> Files { get; init; }
}

/// <summary>
/// Coverage data for a source file.
/// </summary>
public record FileCoverageData
{
    public required string FilePath { get; init; }
    public required List<ClassCoverageData> Classes { get; init; }
    public required Dictionary<int, int> LineHits { get; init; }
}

/// <summary>
/// Coverage data for a class in a coverage report.
/// </summary>
public record ClassCoverageData
{
    public required string ClassName { get; init; }
    public required string Namespace { get; init; }
    public required List<MethodCoverageData> Methods { get; init; }
}

/// <summary>
/// Coverage data for a method in a coverage report.
/// </summary>
public record MethodCoverageData
{
    public required string MethodName { get; init; }
    public required string FullName { get; init; }
    public required int StartLine { get; init; }
    public required int EndLine { get; init; }
    public required int CyclomaticComplexity { get; init; }
    public required int SequencePointsCovered { get; init; }
    public required int SequencePointsTotal { get; init; }
    public required int BranchPointsCovered { get; init; }
    public required int BranchPointsTotal { get; init; }
    public required List<SequencePointData> SequencePoints { get; init; }
    public required List<BranchPointData> BranchPoints { get; init; }
}

/// <summary>
/// A sequence point (line of code) in coverage data.
/// </summary>
public record SequencePointData
{
    public required int Line { get; init; }
    public required int Column { get; init; }
    public required int EndLine { get; init; }
    public required int EndColumn { get; init; }
    public required int HitCount { get; init; }
}

/// <summary>
/// A branch point in coverage data.
/// </summary>
public record BranchPointData
{
    public required int Line { get; init; }
    public required int Offset { get; init; }
    public required int Path { get; init; }
    public required int HitCount { get; init; }
}

/// <summary>
/// Detection result from a test detector.
/// </summary>
public record TestDetectionResult
{
    public required string DetectorName { get; init; }
    public required List<TestSmell> Smells { get; init; }
    public required List<TestQualityIssue> QualityIssues { get; init; }
    public required List<CriticalPathWithoutTests> CriticalPaths { get; init; }
    public required List<UncoveredMethod> UncoveredMethods { get; init; }
    public required List<UncoveredBranch> UncoveredBranches { get; init; }
}

/// <summary>
/// Severity levels for test issues.
/// </summary>
public static class TestIssueSeverity
{
    public const string Critical = "Critical";
    public const string High = "High";
    public const string Medium = "Medium";
    public const string Low = "Low";

    public static int ToSortOrder(string severity)
    {
        return severity switch
        {
            Critical => 0,
            High => 1,
            Medium => 2,
            Low => 3,
            _ => 4
        };
    }
}

/// <summary>
/// Test grading levels.
/// </summary>
public static class TestGrade
{
    public const string A = "A";  // >= 90% coverage, no critical issues
    public const string B = "B";  // >= 80% coverage, no high+ issues
    public const string C = "C";  // >= 70% coverage
    public const string D = "D";  // >= 60% coverage
    public const string F = "F";  // < 60% coverage or critical issues

    public static string Calculate(double coverage, int criticalIssues, int highIssues)
    {
        if (criticalIssues > 0) return F;
        if (coverage >= 90 && highIssues == 0) return A;
        if (coverage >= 80 && highIssues <= 2) return B;
        if (coverage >= 70) return C;
        if (coverage >= 60) return D;
        return F;
    }
}
