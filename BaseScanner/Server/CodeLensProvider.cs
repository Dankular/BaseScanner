using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Server.Models;
using System.Collections.Concurrent;

namespace BaseScanner.Server;

/// <summary>
/// Provides code lens for LSP integration.
/// Shows inline metrics for methods including complexity, LOC, and optional coverage.
/// </summary>
public class CodeLensProvider
{
    private readonly ConcurrentDictionary<string, List<MethodMetricsInfo>> _metricsCache = new();
    private readonly ConcurrentDictionary<string, Dictionary<string, double>> _coverageCache = new();

    /// <summary>
    /// Get code lenses for a document.
    /// </summary>
    public async Task<List<LspCodeLens>> GetCodeLensesAsync(
        string documentUri,
        string content,
        CancellationToken cancellationToken = default)
    {
        var codeLenses = new List<LspCodeLens>();

        try
        {
            var syntaxTree = CSharpSyntaxTree.ParseText(content, cancellationToken: cancellationToken);
            var root = await syntaxTree.GetRootAsync(cancellationToken);

            var metrics = new List<MethodMetricsInfo>();

            // Analyze each method
            foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                var methodMetrics = AnalyzeMethod(method, documentUri);
                if (methodMetrics != null)
                {
                    metrics.Add(methodMetrics);

                    // Create code lens for this method
                    var codeLens = CreateCodeLens(methodMetrics, documentUri);
                    codeLenses.Add(codeLens);
                }
            }

            // Also add code lens for properties with complex getters/setters
            foreach (var property in root.DescendantNodes().OfType<PropertyDeclarationSyntax>())
            {
                var propertyMetrics = AnalyzeProperty(property, documentUri);
                if (propertyMetrics != null && (propertyMetrics.CyclomaticComplexity > 3 || propertyMetrics.LineCount > 10))
                {
                    metrics.Add(propertyMetrics);
                    codeLenses.Add(CreateCodeLens(propertyMetrics, documentUri));
                }
            }

            // Cache the metrics
            _metricsCache[documentUri] = metrics;
        }
        catch (Exception)
        {
            // Return empty list on parse error
        }

        return codeLenses;
    }

    /// <summary>
    /// Resolve a code lens with complete information.
    /// </summary>
    public LspCodeLens ResolveCodeLens(LspCodeLens codeLens, string documentUri)
    {
        if (codeLens.Data is not LspCodeLensData data)
            return codeLens;

        // Look up cached metrics
        if (_metricsCache.TryGetValue(documentUri, out var metrics))
        {
            var methodMetrics = metrics.FirstOrDefault(m =>
                m.MethodName == data.MethodName && m.Line == data.Line);

            if (methodMetrics != null)
            {
                return codeLens with
                {
                    Command = CreateCommand(methodMetrics)
                };
            }
        }

        return codeLens;
    }

    /// <summary>
    /// Update test coverage data for a document.
    /// </summary>
    public void UpdateCoverage(string documentUri, Dictionary<string, double> coverageByMethod)
    {
        _coverageCache[documentUri] = coverageByMethod;
    }

    /// <summary>
    /// Get all method metrics for a document.
    /// </summary>
    public List<MethodMetricsInfo> GetMethodMetrics(string documentUri)
    {
        return _metricsCache.TryGetValue(documentUri, out var metrics) ? metrics : [];
    }

    private MethodMetricsInfo? AnalyzeMethod(MethodDeclarationSyntax method, string documentUri)
    {
        var body = (SyntaxNode?)method.Body ?? method.ExpressionBody;
        if (body == null) return null;

        var lineSpan = method.GetLocation().GetLineSpan();
        var lineCount = lineSpan.EndLinePosition.Line - lineSpan.StartLinePosition.Line + 1;

        var className = method.Ancestors()
            .OfType<TypeDeclarationSyntax>()
            .FirstOrDefault()?.Identifier.Text ?? "Unknown";

        var methodName = method.Identifier.Text;
        var fullName = $"{className}.{methodName}";

        // Get coverage if available
        double? coverage = null;
        if (_coverageCache.TryGetValue(documentUri, out var coverageData))
        {
            if (coverageData.TryGetValue(fullName, out var cov))
            {
                coverage = cov;
            }
        }

        return new MethodMetricsInfo
        {
            MethodName = methodName,
            ClassName = className,
            FilePath = UriToPath(documentUri),
            Line = lineSpan.StartLinePosition.Line,
            CyclomaticComplexity = CalculateCyclomaticComplexity(body),
            LineCount = lineCount,
            TestCoverage = coverage,
            NestingDepth = CalculateMaxNestingDepth(body),
            ParameterCount = method.ParameterList.Parameters.Count
        };
    }

    private MethodMetricsInfo? AnalyzeProperty(PropertyDeclarationSyntax property, string documentUri)
    {
        // Only analyze properties with accessors that have bodies
        var getter = property.AccessorList?.Accessors
            .FirstOrDefault(a => a.IsKind(SyntaxKind.GetAccessorDeclaration));
        var setter = property.AccessorList?.Accessors
            .FirstOrDefault(a => a.IsKind(SyntaxKind.SetAccessorDeclaration));

        var getterBody = (SyntaxNode?)getter?.Body ?? getter?.ExpressionBody;
        var setterBody = (SyntaxNode?)setter?.Body ?? setter?.ExpressionBody;

        if (getterBody == null && setterBody == null)
            return null;

        var lineSpan = property.GetLocation().GetLineSpan();
        var lineCount = lineSpan.EndLinePosition.Line - lineSpan.StartLinePosition.Line + 1;

        var className = property.Ancestors()
            .OfType<TypeDeclarationSyntax>()
            .FirstOrDefault()?.Identifier.Text ?? "Unknown";

        var complexity = 0;
        var maxNesting = 0;

        if (getterBody != null)
        {
            complexity += CalculateCyclomaticComplexity(getterBody);
            maxNesting = Math.Max(maxNesting, CalculateMaxNestingDepth(getterBody));
        }
        if (setterBody != null)
        {
            complexity += CalculateCyclomaticComplexity(setterBody);
            maxNesting = Math.Max(maxNesting, CalculateMaxNestingDepth(setterBody));
        }

        return new MethodMetricsInfo
        {
            MethodName = property.Identifier.Text + " (property)",
            ClassName = className,
            FilePath = UriToPath(documentUri),
            Line = lineSpan.StartLinePosition.Line,
            CyclomaticComplexity = complexity,
            LineCount = lineCount,
            NestingDepth = maxNesting,
            ParameterCount = 0
        };
    }

    private LspCodeLens CreateCodeLens(MethodMetricsInfo metrics, string documentUri)
    {
        return new LspCodeLens
        {
            Range = new LspRange
            {
                Start = new LspPosition { Line = metrics.Line, Character = 0 },
                End = new LspPosition { Line = metrics.Line, Character = 0 }
            },
            Command = CreateCommand(metrics),
            Data = new LspCodeLensData
            {
                DocumentUri = documentUri,
                MethodName = metrics.MethodName,
                Line = metrics.Line
            }
        };
    }

    private LspCommand CreateCommand(MethodMetricsInfo metrics)
    {
        var parts = new List<string>
        {
            $"CC: {metrics.CyclomaticComplexity}",
            $"LOC: {metrics.LineCount}"
        };

        if (metrics.TestCoverage.HasValue)
        {
            parts.Add($"Coverage: {metrics.TestCoverage.Value:F0}%");
        }

        if (metrics.NestingDepth.HasValue && metrics.NestingDepth.Value > 3)
        {
            parts.Add($"Nesting: {metrics.NestingDepth.Value}");
        }

        if (metrics.ParameterCount.HasValue && metrics.ParameterCount.Value > 4)
        {
            parts.Add($"Params: {metrics.ParameterCount.Value}");
        }

        var title = string.Join(" | ", parts);

        // Add visual indicators for problematic metrics
        var warnings = new List<string>();
        if (metrics.CyclomaticComplexity > 15)
            warnings.Add("high complexity");
        if (metrics.LineCount > 50)
            warnings.Add("long method");
        if (metrics.TestCoverage.HasValue && metrics.TestCoverage.Value < 50)
            warnings.Add("low coverage");

        if (warnings.Count > 0)
        {
            title = $"[!] {title}";
        }

        return new LspCommand
        {
            Title = title,
            CommandId = "basescanner.showMethodMetrics",
            Arguments = [metrics.ClassName, metrics.MethodName, metrics.Line]
        };
    }

    private static int CalculateCyclomaticComplexity(SyntaxNode body)
    {
        var complexity = 1;

        foreach (var node in body.DescendantNodes())
        {
            switch (node)
            {
                case IfStatementSyntax:
                case ConditionalExpressionSyntax:
                case CaseSwitchLabelSyntax:
                case CasePatternSwitchLabelSyntax:
                case ForStatementSyntax:
                case ForEachStatementSyntax:
                case WhileStatementSyntax:
                case DoStatementSyntax:
                case CatchClauseSyntax:
                    complexity++;
                    break;
                case BinaryExpressionSyntax binary when
                    binary.IsKind(SyntaxKind.LogicalAndExpression) ||
                    binary.IsKind(SyntaxKind.LogicalOrExpression) ||
                    binary.IsKind(SyntaxKind.CoalesceExpression):
                    complexity++;
                    break;
                case SwitchExpressionArmSyntax:
                    complexity++;
                    break;
            }
        }

        return complexity;
    }

    private static int CalculateMaxNestingDepth(SyntaxNode body)
    {
        var maxDepth = 0;

        void Visit(SyntaxNode node, int currentDepth)
        {
            var newDepth = currentDepth;

            if (node is IfStatementSyntax or ForStatementSyntax or ForEachStatementSyntax
                or WhileStatementSyntax or DoStatementSyntax or TryStatementSyntax
                or SwitchStatementSyntax or LockStatementSyntax)
            {
                newDepth = currentDepth + 1;
                maxDepth = Math.Max(maxDepth, newDepth);
            }

            foreach (var child in node.ChildNodes())
            {
                Visit(child, newDepth);
            }
        }

        Visit(body, 0);
        return maxDepth;
    }

    private static string UriToPath(string uri)
    {
        if (uri.StartsWith("file:///"))
        {
            var path = Uri.UnescapeDataString(uri.Substring(8));
            if (Path.DirectorySeparatorChar == '\\')
            {
                path = path.Replace('/', '\\');
            }
            return path;
        }
        return uri;
    }
}
