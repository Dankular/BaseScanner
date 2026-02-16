using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Testing.Models;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Testing.Detectors;

/// <summary>
/// Detects methods and branches with 0% test coverage.
/// Maps coverage data to code elements and identifies gaps.
/// </summary>
public class CoverageGapDetector : TestDetectorBase, ICoverageAwareDetector
{
    public override string Category => "CoverageGap";
    public override string Description => "Identifies methods and branches with no test coverage";
    public bool RequiresCoverageData => true;

    public override async Task<TestDetectionResult> DetectAsync(
        Project project,
        RawCoverageData? coverageData,
        CodeContext context)
    {
        var uncoveredMethods = new List<UncoveredMethod>();
        var uncoveredBranches = new List<UncoveredBranch>();

        if (coverageData == null)
        {
            // Without coverage data, we can only analyze code structure
            // but cannot determine actual coverage
            return await DetectWithoutCoverageDataAsync(project, context);
        }

        // Build a lookup from file path to coverage data
        var coverageLookup = BuildCoverageLookup(coverageData);

        foreach (var document in project.Documents)
        {
            if (ShouldSkipFile(document.FilePath))
                continue;

            var semanticModel = await document.GetSemanticModelAsync();
            var root = await document.GetSyntaxRootAsync();

            if (semanticModel == null || root == null)
                continue;

            // Skip test files
            if (IsTestFile(document.FilePath))
                continue;

            // Get coverage data for this file
            var fileCoverage = GetFileCoverage(coverageLookup, document.FilePath!);

            // Analyze each method
            foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                var symbol = semanticModel.GetDeclaredSymbol(method);
                if (symbol == null)
                    continue;

                // Skip compiler-generated methods
                if (symbol.IsImplicitlyDeclared)
                    continue;

                var (startLine, endLine) = GetLineSpan(method);
                var methodCoverage = GetMethodCoverage(fileCoverage, method, symbol);

                if (methodCoverage == null || !methodCoverage.IsCovered)
                {
                    var uncovered = CreateUncoveredMethod(method, symbol, document, semanticModel);
                    uncoveredMethods.Add(uncovered);
                }
                else
                {
                    // Check for uncovered branches within covered methods
                    var branches = DetectUncoveredBranches(method, methodCoverage, document);
                    uncoveredBranches.AddRange(branches);
                }
            }
        }

        return new TestDetectionResult
        {
            DetectorName = Category,
            Smells = [],
            QualityIssues = [],
            CriticalPaths = [],
            UncoveredMethods = uncoveredMethods.OrderByDescending(m => PriorityOrder(m.Priority)).ToList(),
            UncoveredBranches = uncoveredBranches
        };
    }

    /// <summary>
    /// Detect potential coverage gaps without actual coverage data.
    /// Identifies methods that likely need tests based on code analysis.
    /// </summary>
    private async Task<TestDetectionResult> DetectWithoutCoverageDataAsync(Project project, CodeContext context)
    {
        var potentialGaps = new List<UncoveredMethod>();

        foreach (var document in project.Documents)
        {
            if (ShouldSkipFile(document.FilePath))
                continue;

            var semanticModel = await document.GetSemanticModelAsync();
            var root = await document.GetSyntaxRootAsync();

            if (semanticModel == null || root == null)
                continue;

            if (IsTestFile(document.FilePath))
                continue;

            // Find methods that look like they need tests
            foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                var symbol = semanticModel.GetDeclaredSymbol(method);
                if (symbol == null || symbol.IsImplicitlyDeclared)
                    continue;

                // Check if this method appears to need testing
                if (ShouldHaveTests(method, symbol, semanticModel))
                {
                    var uncovered = CreateUncoveredMethod(method, symbol, document, semanticModel);
                    potentialGaps.Add(uncovered);
                }
            }
        }

        return new TestDetectionResult
        {
            DetectorName = Category,
            Smells = [],
            QualityIssues = [],
            CriticalPaths = [],
            UncoveredMethods = potentialGaps.OrderByDescending(m => PriorityOrder(m.Priority)).ToList(),
            UncoveredBranches = []
        };
    }

    private Dictionary<string, FileCoverageData> BuildCoverageLookup(RawCoverageData coverageData)
    {
        var lookup = new Dictionary<string, FileCoverageData>(StringComparer.OrdinalIgnoreCase);

        foreach (var module in coverageData.Modules)
        {
            foreach (var file in module.Files)
            {
                if (!string.IsNullOrEmpty(file.FilePath))
                {
                    // Normalize path
                    var normalizedPath = NormalizePath(file.FilePath);
                    lookup[normalizedPath] = file;
                }
            }
        }

        return lookup;
    }

    private FileCoverageData? GetFileCoverage(Dictionary<string, FileCoverageData> lookup, string filePath)
    {
        var normalizedPath = NormalizePath(filePath);

        if (lookup.TryGetValue(normalizedPath, out var coverage))
            return coverage;

        // Try with just the filename
        var fileName = Path.GetFileName(normalizedPath);
        return lookup.Values.FirstOrDefault(f =>
            Path.GetFileName(NormalizePath(f.FilePath)).Equals(fileName, StringComparison.OrdinalIgnoreCase));
    }

    private MethodCoverage? GetMethodCoverage(
        FileCoverageData? fileCoverage,
        MethodDeclarationSyntax method,
        IMethodSymbol symbol)
    {
        if (fileCoverage == null)
            return null;

        var (startLine, endLine) = GetLineSpan(method);
        var methodName = symbol.Name;
        var className = symbol.ContainingType?.Name ?? "";

        // Find matching method in coverage data
        foreach (var classCoverage in fileCoverage.Classes)
        {
            if (classCoverage.ClassName == className)
            {
                foreach (var methodCov in classCoverage.Methods)
                {
                    // Match by name and line range
                    if (methodCov.MethodName == methodName ||
                        methodCov.MethodName.StartsWith(methodName + "("))
                    {
                        if (methodCov.StartLine <= startLine && methodCov.EndLine >= endLine ||
                            Math.Abs(methodCov.StartLine - startLine) <= 2)
                        {
                            return ConvertToMethodCoverage(methodCov, fileCoverage.FilePath);
                        }
                    }
                }
            }
        }

        // Try to find by line range alone
        var lineHits = new Dictionary<int, int>();
        for (var line = startLine; line <= endLine; line++)
        {
            if (fileCoverage.LineHits.TryGetValue(line, out var hits))
            {
                lineHits[line] = hits;
            }
        }

        if (lineHits.Any())
        {
            var covered = lineHits.Count(kvp => kvp.Value > 0);
            return new MethodCoverage
            {
                MethodName = methodName,
                FullName = symbol.ToDisplayString(),
                FilePath = fileCoverage.FilePath,
                StartLine = startLine,
                EndLine = endLine,
                TotalLines = lineHits.Count,
                CoveredLines = covered,
                TotalBranches = 0,
                CoveredBranches = 0,
                CyclomaticComplexity = 1,
                Branches = []
            };
        }

        return null;
    }

    private MethodCoverage ConvertToMethodCoverage(MethodCoverageData data, string filePath)
    {
        return new MethodCoverage
        {
            MethodName = data.MethodName,
            FullName = data.FullName,
            FilePath = filePath,
            StartLine = data.StartLine,
            EndLine = data.EndLine,
            TotalLines = data.SequencePointsTotal,
            CoveredLines = data.SequencePointsCovered,
            TotalBranches = data.BranchPointsTotal,
            CoveredBranches = data.BranchPointsCovered,
            CyclomaticComplexity = data.CyclomaticComplexity,
            Branches = data.BranchPoints.Select(bp => new BranchCoverage
            {
                Line = bp.Line,
                Offset = bp.Offset,
                PathIndex = bp.Path,
                IsCovered = bp.HitCount > 0,
                HitCount = bp.HitCount,
                Type = BranchType.Unknown
            }).ToList()
        };
    }

    private UncoveredMethod CreateUncoveredMethod(
        MethodDeclarationSyntax method,
        IMethodSymbol symbol,
        Document document,
        SemanticModel semanticModel)
    {
        var (startLine, endLine) = GetLineSpan(method);
        var complexity = CalculateCyclomaticComplexity(method);
        var (priority, reason) = DeterminePriority(method, symbol, semanticModel, complexity);

        return new UncoveredMethod
        {
            MethodName = symbol.Name,
            ClassName = symbol.ContainingType?.Name ?? "Unknown",
            Namespace = symbol.ContainingNamespace?.ToDisplayString() ?? "",
            FilePath = document.FilePath ?? "",
            StartLine = startLine,
            EndLine = endLine,
            CyclomaticComplexity = complexity,
            Priority = priority,
            PriorityReason = reason,
            IsPublic = symbol.DeclaredAccessibility == Accessibility.Public,
            HasSecurityImplications = HasSecurityImplications(method, semanticModel),
            HasDataValidation = HasDataValidation(method, semanticModel)
        };
    }

    private List<UncoveredBranch> DetectUncoveredBranches(
        MethodDeclarationSyntax method,
        MethodCoverage coverage,
        Document document)
    {
        var uncovered = new List<UncoveredBranch>();

        // Find if statements with uncovered branches
        foreach (var ifStatement in method.DescendantNodes().OfType<IfStatementSyntax>())
        {
            var (line, _) = GetLineSpan(ifStatement);

            var branch = coverage.Branches.FirstOrDefault(b => b.Line == line);
            if (branch != null && !branch.IsCovered)
            {
                uncovered.Add(new UncoveredBranch
                {
                    MethodName = method.Identifier.Text,
                    ClassName = GetContainingClassName(method),
                    FilePath = document.FilePath ?? "",
                    Line = line,
                    Type = BranchType.If,
                    CodeSnippet = GetCodeSnippet(ifStatement, 3),
                    SuggestedTest = GenerateSuggestedTest(ifStatement, BranchType.If)
                });
            }

            // Check else branch
            if (ifStatement.Else != null)
            {
                var (elseLine, _) = GetLineSpan(ifStatement.Else);
                var elseBranch = coverage.Branches.FirstOrDefault(b => b.Line == elseLine);
                if (elseBranch != null && !elseBranch.IsCovered)
                {
                    uncovered.Add(new UncoveredBranch
                    {
                        MethodName = method.Identifier.Text,
                        ClassName = GetContainingClassName(method),
                        FilePath = document.FilePath ?? "",
                        Line = elseLine,
                        Type = BranchType.Else,
                        CodeSnippet = GetCodeSnippet(ifStatement.Else, 3),
                        SuggestedTest = GenerateSuggestedTest(ifStatement.Else, BranchType.Else)
                    });
                }
            }
        }

        // Find switch cases with uncovered branches
        foreach (var switchStatement in method.DescendantNodes().OfType<SwitchStatementSyntax>())
        {
            foreach (var section in switchStatement.Sections)
            {
                var (line, _) = GetLineSpan(section);
                var branch = coverage.Branches.FirstOrDefault(b => b.Line == line);
                if (branch != null && !branch.IsCovered)
                {
                    var caseLabel = section.Labels.FirstOrDefault()?.ToString() ?? "case";
                    uncovered.Add(new UncoveredBranch
                    {
                        MethodName = method.Identifier.Text,
                        ClassName = GetContainingClassName(method),
                        FilePath = document.FilePath ?? "",
                        Line = line,
                        Type = BranchType.Case,
                        CodeSnippet = GetCodeSnippet(section, 3),
                        SuggestedTest = $"Test {caseLabel} path"
                    });
                }
            }
        }

        // Find ternary conditionals
        foreach (var conditional in method.DescendantNodes().OfType<ConditionalExpressionSyntax>())
        {
            var (line, _) = GetLineSpan(conditional);
            var branches = coverage.Branches.Where(b => b.Line == line).ToList();

            foreach (var branch in branches.Where(b => !b.IsCovered))
            {
                uncovered.Add(new UncoveredBranch
                {
                    MethodName = method.Identifier.Text,
                    ClassName = GetContainingClassName(method),
                    FilePath = document.FilePath ?? "",
                    Line = line,
                    Type = branch.PathIndex == 0 ? BranchType.TernaryTrue : BranchType.TernaryFalse,
                    CodeSnippet = GetCodeSnippet(conditional, 1),
                    SuggestedTest = $"Test {(branch.PathIndex == 0 ? "true" : "false")} path of ternary"
                });
            }
        }

        return uncovered;
    }

    private (UncoveredPriority Priority, string Reason) DeterminePriority(
        MethodDeclarationSyntax method,
        IMethodSymbol symbol,
        SemanticModel semanticModel,
        int complexity)
    {
        // Critical: Security-related methods
        if (HasSecurityImplications(method, semanticModel))
            return (UncoveredPriority.Critical, "Security-sensitive code without tests");

        // Critical: Public API methods
        if (symbol.DeclaredAccessibility == Accessibility.Public &&
            symbol.ContainingType?.DeclaredAccessibility == Accessibility.Public)
        {
            return (UncoveredPriority.Critical, "Public API method without tests");
        }

        // High: Data validation
        if (HasDataValidation(method, semanticModel))
            return (UncoveredPriority.High, "Data validation code without tests");

        // High: Complex methods (high cyclomatic complexity)
        if (complexity >= 10)
            return (UncoveredPriority.High, $"Complex method (CC={complexity}) without tests");

        // Medium: Error handling
        if (HasErrorHandling(method))
            return (UncoveredPriority.Medium, "Error handling code without tests");

        // Medium: Entry points
        if (IsEntryPoint(method, symbol))
            return (UncoveredPriority.Medium, "Entry point without tests");

        // Low: Simple private methods
        if (symbol.DeclaredAccessibility == Accessibility.Private && complexity <= 3)
            return (UncoveredPriority.Low, "Simple private method");

        return (UncoveredPriority.Medium, "General method without tests");
    }

    private bool ShouldHaveTests(MethodDeclarationSyntax method, IMethodSymbol symbol, SemanticModel semanticModel)
    {
        // Skip property accessors and simple methods
        if (method.Body == null && method.ExpressionBody == null)
            return false;

        // Skip very simple methods (single statement)
        var statementCount = method.Body?.Statements.Count ?? 1;
        if (statementCount <= 1 && !HasSecurityImplications(method, semanticModel))
            return false;

        // Public methods should have tests
        if (symbol.DeclaredAccessibility == Accessibility.Public)
            return true;

        // Methods with validation logic
        if (HasDataValidation(method, semanticModel))
            return true;

        // Complex methods
        if (CalculateCyclomaticComplexity(method) >= 5)
            return true;

        // Methods with error handling
        if (HasErrorHandling(method))
            return true;

        return false;
    }

    private bool HasSecurityImplications(MethodDeclarationSyntax method, SemanticModel semanticModel)
    {
        var methodText = method.ToString().ToLowerInvariant();

        // Check for security-related patterns
        var securityPatterns = new[]
        {
            "password", "credential", "auth", "token", "secret",
            "encrypt", "decrypt", "hash", "salt", "verify",
            "permission", "role", "access", "grant", "deny"
        };

        if (securityPatterns.Any(p => methodText.Contains(p)))
            return true;

        // Check for SQL/database operations
        if (methodText.Contains("execute") || methodText.Contains("query") ||
            methodText.Contains("sqlcommand") || methodText.Contains("dbcommand"))
            return true;

        // Check for file operations
        if (methodText.Contains("file.") || methodText.Contains("directory."))
            return true;

        return false;
    }

    private bool HasDataValidation(MethodDeclarationSyntax method, SemanticModel semanticModel)
    {
        var methodText = method.ToString().ToLowerInvariant();

        var validationPatterns = new[]
        {
            "validate", "isvalid", "check", "verify", "parse",
            "isnullorempty", "isnullorwhitespace", "tryparse"
        };

        if (validationPatterns.Any(p => methodText.Contains(p)))
            return true;

        // Check for throw statements in validation patterns
        foreach (var throwStatement in method.DescendantNodes().OfType<ThrowStatementSyntax>())
        {
            var exceptionName = throwStatement.Expression?.ToString() ?? "";
            if (exceptionName.Contains("ArgumentException") ||
                exceptionName.Contains("ArgumentNullException") ||
                exceptionName.Contains("ValidationException"))
                return true;
        }

        return false;
    }

    private bool HasErrorHandling(MethodDeclarationSyntax method)
    {
        return method.DescendantNodes().OfType<TryStatementSyntax>().Any();
    }

    private bool IsEntryPoint(MethodDeclarationSyntax method, IMethodSymbol symbol)
    {
        // Check for common entry point patterns
        var name = symbol.Name;
        if (name is "Main" or "Execute" or "Run" or "Start" or "Process" or "Handle")
            return true;

        // Check for controller actions
        foreach (var attr in method.AttributeLists.SelectMany(al => al.Attributes))
        {
            var attrName = attr.Name.ToString();
            if (attrName is "HttpGet" or "HttpPost" or "HttpPut" or "HttpDelete" or
                "Route" or "ApiController" or "Authorize")
                return true;
        }

        return false;
    }

    private int CalculateCyclomaticComplexity(MethodDeclarationSyntax method)
    {
        var complexity = 1;

        foreach (var node in method.DescendantNodes())
        {
            switch (node)
            {
                case IfStatementSyntax:
                case WhileStatementSyntax:
                case ForStatementSyntax:
                case ForEachStatementSyntax:
                case CaseSwitchLabelSyntax:
                case CasePatternSwitchLabelSyntax:
                case ConditionalExpressionSyntax:
                case CatchClauseSyntax:
                    complexity++;
                    break;
                case BinaryExpressionSyntax binary when binary.Kind() is
                    SyntaxKind.LogicalAndExpression or
                    SyntaxKind.LogicalOrExpression or
                    SyntaxKind.CoalesceExpression:
                    complexity++;
                    break;
            }
        }

        return complexity;
    }

    private string GetContainingClassName(MethodDeclarationSyntax method)
    {
        var parent = method.Parent;
        while (parent != null)
        {
            if (parent is ClassDeclarationSyntax classDecl)
                return classDecl.Identifier.Text;
            if (parent is StructDeclarationSyntax structDecl)
                return structDecl.Identifier.Text;
            if (parent is RecordDeclarationSyntax recordDecl)
                return recordDecl.Identifier.Text;
            parent = parent.Parent;
        }
        return "Unknown";
    }

    private string GenerateSuggestedTest(SyntaxNode node, BranchType branchType)
    {
        var condition = branchType switch
        {
            BranchType.If => (node as IfStatementSyntax)?.Condition?.ToString(),
            BranchType.Else => (node.Parent as IfStatementSyntax)?.Condition?.ToString() + " is false",
            _ => null
        };

        return condition != null
            ? $"Test when {condition}"
            : $"Test {branchType} branch";
    }

    private bool IsTestFile(string? filePath)
    {
        if (string.IsNullOrEmpty(filePath))
            return false;

        var fileName = Path.GetFileNameWithoutExtension(filePath);
        return fileName.EndsWith("Tests") ||
               fileName.EndsWith("Test") ||
               fileName.EndsWith("Specs") ||
               fileName.EndsWith("Spec") ||
               filePath.Contains("Tests" + Path.DirectorySeparatorChar) ||
               filePath.Contains("Test" + Path.DirectorySeparatorChar);
    }

    private string NormalizePath(string path)
    {
        return path.Replace('\\', '/').ToLowerInvariant();
    }

    private int PriorityOrder(UncoveredPriority priority) => priority switch
    {
        UncoveredPriority.Critical => 3,
        UncoveredPriority.High => 2,
        UncoveredPriority.Medium => 1,
        UncoveredPriority.Low => 0,
        _ => 0
    };
}
