using Microsoft.CodeAnalysis;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Security;

/// <summary>
/// Interface for security vulnerability detectors.
/// Each detector is responsible for finding a specific category of security issues.
/// </summary>
public interface ISecurityDetector
{
    /// <summary>
    /// The category of security issues this detector finds.
    /// </summary>
    string Category { get; }

    /// <summary>
    /// Detect security vulnerabilities in the given document.
    /// </summary>
    Task<List<SecurityVulnerability>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context);
}

/// <summary>
/// Represents a detected security vulnerability.
/// </summary>
public record SecurityVulnerability
{
    /// <summary>
    /// Type of vulnerability (e.g., "SQL Injection", "XSS", "Hardcoded Secret")
    /// </summary>
    public required string VulnerabilityType { get; init; }

    /// <summary>
    /// Severity level: Critical, High, Medium, Low
    /// </summary>
    public required string Severity { get; init; }

    /// <summary>
    /// CWE identifier (e.g., "CWE-89" for SQL Injection)
    /// </summary>
    public required string CweId { get; init; }

    /// <summary>
    /// Path to the file containing the vulnerability
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
    /// Human-readable description of the vulnerability
    /// </summary>
    public required string Description { get; init; }

    /// <summary>
    /// Recommended fix or mitigation
    /// </summary>
    public required string Recommendation { get; init; }

    /// <summary>
    /// The vulnerable code snippet
    /// </summary>
    public required string VulnerableCode { get; init; }

    /// <summary>
    /// Suggested secure code replacement
    /// </summary>
    public required string SecureCode { get; init; }

    /// <summary>
    /// Data flow path showing how tainted data reaches the sink (if applicable)
    /// </summary>
    public List<string> DataFlowPath { get; init; } = [];

    /// <summary>
    /// Confidence level of the detection: High, Medium, Low
    /// </summary>
    public string Confidence { get; init; } = "Medium";

    /// <summary>
    /// Link to CWE reference
    /// </summary>
    public string CweLink => $"https://cwe.mitre.org/data/definitions/{CweId.Replace("CWE-", "")}.html";
}

/// <summary>
/// Summary of security analysis results.
/// </summary>
public record SecuritySummary
{
    public int TotalVulnerabilities { get; init; }
    public int CriticalCount { get; init; }
    public int HighCount { get; init; }
    public int MediumCount { get; init; }
    public int LowCount { get; init; }
    public Dictionary<string, int> VulnerabilitiesByType { get; init; } = [];
    public Dictionary<string, int> VulnerabilitiesByCwe { get; init; } = [];
}

/// <summary>
/// Complete result of security analysis.
/// </summary>
public record SecurityResult
{
    public List<SecurityVulnerability> Vulnerabilities { get; init; } = [];
    public SecuritySummary Summary { get; init; } = new();
}
