using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Security;
using BaseScanner.Analyzers.Optimizations;

namespace BaseScanner.Analysis;

/// <summary>
/// Aggregates and visualizes code quality metrics.
/// </summary>
public class MetricsDashboard
{
    private readonly SecurityAnalyzer _securityAnalyzer;

    public MetricsDashboard()
    {
        _securityAnalyzer = new SecurityAnalyzer();
    }

    /// <summary>
    /// Generate a comprehensive project dashboard.
    /// </summary>
    public async Task<ProjectMetrics> GenerateDashboardAsync(Project project)
    {
        var metrics = new ProjectMetrics
        {
            ProjectName = project.Name,
            GeneratedAt = DateTime.UtcNow
        };

        // Gather all metrics in parallel
        var fileMetricsTask = CollectFileMetricsAsync(project);
        var securityTask = _securityAnalyzer.AnalyzeAsync(project);
        var complexityTask = CalculateComplexityMetricsAsync(project);
        var maintainabilityTask = CalculateMaintainabilityMetricsAsync(project);

        await Task.WhenAll(fileMetricsTask, securityTask, complexityTask, maintainabilityTask);

        var fileMetrics = await fileMetricsTask;
        var securityResult = await securityTask;
        var complexityMetrics = await complexityTask;
        var maintainability = await maintainabilityTask;

        // Aggregate file metrics
        metrics.TotalFiles = fileMetrics.Count;
        metrics.TotalLines = fileMetrics.Sum(f => f.Lines);
        metrics.TotalMethods = fileMetrics.Sum(f => f.Methods);
        metrics.TotalClasses = fileMetrics.Sum(f => f.Classes);

        // Security summary
        metrics.SecurityVulnerabilities = securityResult.Vulnerabilities.Count;
        metrics.CriticalSecurityIssues = securityResult.Summary.CriticalCount;
        metrics.HighSecurityIssues = securityResult.Summary.HighCount;
        metrics.MediumSecurityIssues = securityResult.Summary.MediumCount;
        metrics.LowSecurityIssues = securityResult.Summary.LowCount;
        metrics.VulnerabilitiesByCwe = securityResult.Summary.VulnerabilitiesByCwe;

        // Complexity metrics
        metrics.AverageCyclomaticComplexity = complexityMetrics.Average;
        metrics.MaxCyclomaticComplexity = complexityMetrics.Max;
        metrics.MethodsAboveThreshold = complexityMetrics.AboveThreshold;
        metrics.ComplexMethods = complexityMetrics.ComplexMethods;

        // Maintainability
        metrics.MaintainabilityIndex = maintainability.Index;
        metrics.TechnicalDebtMinutes = maintainability.DebtMinutes;
        metrics.DuplicatedCodePercentage = maintainability.DuplicationPercentage;

        // Calculate health score
        metrics.HealthScore = CalculateHealthScore(metrics);

        // Find hotspots
        metrics.Hotspots = IdentifyHotspots(fileMetrics, securityResult);

        // Issue breakdown
        metrics.IssuesByCategory = BuildCategoryBreakdown(securityResult);
        metrics.IssuesBySeverity = BuildSeverityBreakdown(securityResult);

        return metrics;
    }

    private async Task<List<FileMetrics>> CollectFileMetricsAsync(Project project)
    {
        var fileMetrics = new List<FileMetrics>();

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null)
                continue;

            if (IsGeneratedFile(document.FilePath))
                continue;

            var syntaxRoot = await document.GetSyntaxRootAsync();
            if (syntaxRoot == null)
                continue;

            var metrics = new FileMetrics
            {
                FilePath = document.FilePath,
                Lines = syntaxRoot.GetText().Lines.Count,
                Classes = syntaxRoot.DescendantNodes().OfType<ClassDeclarationSyntax>().Count(),
                Methods = syntaxRoot.DescendantNodes().OfType<MethodDeclarationSyntax>().Count(),
                Properties = syntaxRoot.DescendantNodes().OfType<PropertyDeclarationSyntax>().Count(),
                Fields = syntaxRoot.DescendantNodes().OfType<FieldDeclarationSyntax>().Count()
            };

            fileMetrics.Add(metrics);
        }

        return fileMetrics;
    }

    private async Task<ComplexityMetrics> CalculateComplexityMetricsAsync(Project project)
    {
        var complexities = new List<int>();
        var complexMethods = new List<ComplexMethod>();
        const int threshold = 10; // Cyclomatic complexity threshold

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null || IsGeneratedFile(document.FilePath))
                continue;

            var syntaxRoot = await document.GetSyntaxRootAsync();
            if (syntaxRoot == null)
                continue;

            foreach (var method in syntaxRoot.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                var complexity = CalculateCyclomaticComplexity(method);
                complexities.Add(complexity);

                if (complexity > threshold)
                {
                    complexMethods.Add(new ComplexMethod
                    {
                        FilePath = document.FilePath,
                        MethodName = method.Identifier.Text,
                        Line = method.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        Complexity = complexity
                    });
                }
            }
        }

        return new ComplexityMetrics
        {
            Average = complexities.Count > 0 ? complexities.Average() : 0,
            Max = complexities.Count > 0 ? complexities.Max() : 0,
            AboveThreshold = complexMethods.Count,
            ComplexMethods = complexMethods.OrderByDescending(m => m.Complexity).Take(10).ToList()
        };
    }

    private int CalculateCyclomaticComplexity(MethodDeclarationSyntax method)
    {
        int complexity = 1; // Base complexity

        foreach (var node in method.DescendantNodes())
        {
            switch (node)
            {
                case IfStatementSyntax:
                case WhileStatementSyntax:
                case ForStatementSyntax:
                case ForEachStatementSyntax:
                case CaseSwitchLabelSyntax:
                case CatchClauseSyntax:
                case ConditionalExpressionSyntax:
                    complexity++;
                    break;
                case BinaryExpressionSyntax binary when
                    binary.Kind() == SyntaxKind.LogicalAndExpression ||
                    binary.Kind() == SyntaxKind.LogicalOrExpression ||
                    binary.Kind() == SyntaxKind.CoalesceExpression:
                    complexity++;
                    break;
            }
        }

        return complexity;
    }

    private async Task<MaintainabilityMetrics> CalculateMaintainabilityMetricsAsync(Project project)
    {
        var totalLines = 0;
        var totalComplexity = 0;
        var methodCount = 0;
        var debtMinutes = 0;

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null || IsGeneratedFile(document.FilePath))
                continue;

            var syntaxRoot = await document.GetSyntaxRootAsync();
            if (syntaxRoot == null)
                continue;

            totalLines += syntaxRoot.GetText().Lines.Count;

            foreach (var method in syntaxRoot.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                var complexity = CalculateCyclomaticComplexity(method);
                totalComplexity += complexity;
                methodCount++;

                // Calculate debt based on complexity
                if (complexity > 10)
                    debtMinutes += (complexity - 10) * 10; // 10 min per complexity point above threshold
            }
        }

        // Calculate Maintainability Index (0-100 scale)
        // Based on the Visual Studio formula: MI = MAX(0, (171 - 5.2 * ln(HV) - 0.23 * CC - 16.2 * ln(LOC)) * 100 / 171)
        double avgComplexity = methodCount > 0 ? (double)totalComplexity / methodCount : 1;
        double halsteadVolume = totalLines * Math.Log2(totalLines + 1); // Simplified
        double maintainabilityIndex = Math.Max(0,
            (171 - 5.2 * Math.Log(halsteadVolume + 1) - 0.23 * avgComplexity - 16.2 * Math.Log(totalLines + 1)) * 100 / 171);

        return new MaintainabilityMetrics
        {
            Index = maintainabilityIndex,
            DebtMinutes = debtMinutes,
            DuplicationPercentage = 0 // Would need separate analysis
        };
    }

    private int CalculateHealthScore(ProjectMetrics metrics)
    {
        int score = 100;

        // Security deductions
        score -= metrics.CriticalSecurityIssues * 10;
        score -= metrics.HighSecurityIssues * 5;
        score -= metrics.MediumSecurityIssues * 2;
        score -= metrics.LowSecurityIssues * 1;

        // Complexity deductions
        if (metrics.AverageCyclomaticComplexity > 15)
            score -= 10;
        else if (metrics.AverageCyclomaticComplexity > 10)
            score -= 5;

        score -= metrics.MethodsAboveThreshold;

        // Maintainability bonus
        if (metrics.MaintainabilityIndex > 80)
            score += 5;
        else if (metrics.MaintainabilityIndex < 50)
            score -= 10;

        return Math.Max(0, Math.Min(100, score));
    }

    private List<FileHotspot> IdentifyHotspots(List<FileMetrics> fileMetrics, SecurityResult securityResult)
    {
        var hotspots = new Dictionary<string, FileHotspot>();

        // Count security issues per file
        foreach (var vuln in securityResult.Vulnerabilities)
        {
            var filePath = vuln.FilePath;
            if (!hotspots.TryGetValue(filePath, out var hotspot))
            {
                hotspot = new FileHotspot
                {
                    FilePath = filePath,
                    IssueCount = 0,
                    SecurityIssues = 0,
                    ComplexityIssues = 0
                };
                hotspots[filePath] = hotspot;
            }

            hotspot.IssueCount++;
            hotspot.SecurityIssues++;

            if (vuln.Severity is "Critical" or "High")
                hotspot.CriticalOrHigh++;
        }

        // Add file metrics
        foreach (var file in fileMetrics)
        {
            if (hotspots.TryGetValue(file.FilePath, out var hotspot))
            {
                hotspot.Lines = file.Lines;
                hotspot.Methods = file.Methods;
            }
        }

        return hotspots.Values
            .OrderByDescending(h => h.CriticalOrHigh)
            .ThenByDescending(h => h.IssueCount)
            .Take(10)
            .ToList();
    }

    private Dictionary<string, int> BuildCategoryBreakdown(SecurityResult securityResult)
    {
        return securityResult.Vulnerabilities
            .GroupBy(v => v.VulnerabilityType)
            .ToDictionary(g => g.Key, g => g.Count());
    }

    private Dictionary<string, int> BuildSeverityBreakdown(SecurityResult securityResult)
    {
        return new Dictionary<string, int>
        {
            ["Critical"] = securityResult.Summary.CriticalCount,
            ["High"] = securityResult.Summary.HighCount,
            ["Medium"] = securityResult.Summary.MediumCount,
            ["Low"] = securityResult.Summary.LowCount
        };
    }

    private bool IsGeneratedFile(string filePath)
    {
        var fileName = Path.GetFileName(filePath);
        return fileName.EndsWith(".g.cs") ||
               fileName.EndsWith(".Designer.cs") ||
               fileName.EndsWith(".generated.cs") ||
               filePath.Contains("obj" + Path.DirectorySeparatorChar);
    }

    /// <summary>
    /// Generate a formatted summary report.
    /// </summary>
    public string GenerateReport(ProjectMetrics metrics)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("=" .PadRight(60, '='));
        sb.AppendLine($"  PROJECT HEALTH DASHBOARD: {metrics.ProjectName}");
        sb.AppendLine("=" .PadRight(60, '='));
        sb.AppendLine();

        // Health Score
        var healthIcon = metrics.HealthScore >= 80 ? "[OK]" : metrics.HealthScore >= 60 ? "[WARN]" : "[CRIT]";
        sb.AppendLine($"  HEALTH SCORE: {metrics.HealthScore}/100 {healthIcon}");
        sb.AppendLine();

        // Quick Stats
        sb.AppendLine("  QUICK STATS");
        sb.AppendLine($"  - Files: {metrics.TotalFiles}");
        sb.AppendLine($"  - Lines of Code: {metrics.TotalLines:N0}");
        sb.AppendLine($"  - Classes: {metrics.TotalClasses}");
        sb.AppendLine($"  - Methods: {metrics.TotalMethods}");
        sb.AppendLine();

        // Security
        sb.AppendLine("  SECURITY");
        sb.AppendLine($"  - Critical: {metrics.CriticalSecurityIssues}");
        sb.AppendLine($"  - High: {metrics.HighSecurityIssues}");
        sb.AppendLine($"  - Medium: {metrics.MediumSecurityIssues}");
        sb.AppendLine($"  - Low: {metrics.LowSecurityIssues}");
        sb.AppendLine();

        // Complexity
        sb.AppendLine("  COMPLEXITY");
        sb.AppendLine($"  - Average Cyclomatic: {metrics.AverageCyclomaticComplexity:F1}");
        sb.AppendLine($"  - Maximum: {metrics.MaxCyclomaticComplexity}");
        sb.AppendLine($"  - Methods > 10: {metrics.MethodsAboveThreshold}");
        sb.AppendLine();

        // Maintainability
        sb.AppendLine("  MAINTAINABILITY");
        sb.AppendLine($"  - Index: {metrics.MaintainabilityIndex:F1}/100");
        sb.AppendLine($"  - Technical Debt: {metrics.TechnicalDebtMinutes / 60:F1} hours");
        sb.AppendLine();

        // Hotspots
        if (metrics.Hotspots.Count > 0)
        {
            sb.AppendLine("  TOP HOTSPOTS");
            foreach (var hotspot in metrics.Hotspots.Take(5))
            {
                var fileName = Path.GetFileName(hotspot.FilePath);
                sb.AppendLine($"  - {fileName}: {hotspot.IssueCount} issues ({hotspot.CriticalOrHigh} critical/high)");
            }
        }

        sb.AppendLine();
        sb.AppendLine($"  Generated: {metrics.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine("=" .PadRight(60, '='));

        return sb.ToString();
    }
}

/// <summary>
/// Comprehensive project metrics.
/// </summary>
public record ProjectMetrics
{
    public string ProjectName { get; init; } = "";
    public DateTime GeneratedAt { get; init; }

    // Code stats
    public int TotalFiles { get; set; }
    public int TotalLines { get; set; }
    public int TotalMethods { get; set; }
    public int TotalClasses { get; set; }

    // Health
    public int HealthScore { get; set; }

    // Security
    public int SecurityVulnerabilities { get; set; }
    public int CriticalSecurityIssues { get; set; }
    public int HighSecurityIssues { get; set; }
    public int MediumSecurityIssues { get; set; }
    public int LowSecurityIssues { get; set; }
    public Dictionary<string, int> VulnerabilitiesByCwe { get; set; } = [];

    // Complexity
    public double AverageCyclomaticComplexity { get; set; }
    public int MaxCyclomaticComplexity { get; set; }
    public int MethodsAboveThreshold { get; set; }
    public List<ComplexMethod> ComplexMethods { get; set; } = [];

    // Maintainability
    public double MaintainabilityIndex { get; set; }
    public int TechnicalDebtMinutes { get; set; }
    public double DuplicatedCodePercentage { get; set; }

    // Breakdown
    public Dictionary<string, int> IssuesByCategory { get; set; } = [];
    public Dictionary<string, int> IssuesBySeverity { get; set; } = [];

    // Hotspots
    public List<FileHotspot> Hotspots { get; set; } = [];
}

public record FileMetrics
{
    public required string FilePath { get; init; }
    public int Lines { get; init; }
    public int Classes { get; init; }
    public int Methods { get; init; }
    public int Properties { get; init; }
    public int Fields { get; init; }
}

public record ComplexityMetrics
{
    public double Average { get; init; }
    public int Max { get; init; }
    public int AboveThreshold { get; init; }
    public List<ComplexMethod> ComplexMethods { get; init; } = [];
}

public record ComplexMethod
{
    public required string FilePath { get; init; }
    public required string MethodName { get; init; }
    public required int Line { get; init; }
    public required int Complexity { get; init; }
}

public record MaintainabilityMetrics
{
    public double Index { get; init; }
    public int DebtMinutes { get; init; }
    public double DuplicationPercentage { get; init; }
}

public record FileHotspot
{
    public required string FilePath { get; init; }
    public int IssueCount { get; set; }
    public int SecurityIssues { get; set; }
    public int ComplexityIssues { get; set; }
    public int CriticalOrHigh { get; set; }
    public int Lines { get; set; }
    public int Methods { get; set; }
}
