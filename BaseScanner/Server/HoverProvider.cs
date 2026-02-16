using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Server.Models;
using System.Text;

namespace BaseScanner.Server;

/// <summary>
/// Provides hover information for LSP integration.
/// Shows issue details, metrics, and documentation on hover.
/// </summary>
public class HoverProvider
{
    private readonly DiagnosticsProvider _diagnosticsProvider;
    private readonly CodeLensProvider _codeLensProvider;

    public HoverProvider(DiagnosticsProvider diagnosticsProvider, CodeLensProvider codeLensProvider)
    {
        _diagnosticsProvider = diagnosticsProvider;
        _codeLensProvider = codeLensProvider;
    }

    /// <summary>
    /// Get hover information at a position.
    /// </summary>
    public async Task<LspHover?> GetHoverAsync(
        string documentUri,
        LspPosition position,
        string content,
        CancellationToken cancellationToken = default)
    {
        var hover = new StringBuilder();

        // Check for diagnostic at this position
        var diagnosticHover = GetDiagnosticHover(documentUri, position);
        if (!string.IsNullOrEmpty(diagnosticHover))
        {
            hover.AppendLine(diagnosticHover);
        }

        // Check for method metrics at this position
        var metricsHover = await GetMetricsHoverAsync(documentUri, position, content, cancellationToken);
        if (!string.IsNullOrEmpty(metricsHover))
        {
            if (hover.Length > 0) hover.AppendLine("\n---\n");
            hover.AppendLine(metricsHover);
        }

        // Parse and get semantic information
        var semanticHover = await GetSemanticHoverAsync(documentUri, position, content, cancellationToken);
        if (!string.IsNullOrEmpty(semanticHover))
        {
            if (hover.Length > 0) hover.AppendLine("\n---\n");
            hover.AppendLine(semanticHover);
        }

        if (hover.Length == 0)
            return null;

        return new LspHover
        {
            Contents = new LspMarkupContent
            {
                Kind = LspMarkupKind.Markdown,
                Value = hover.ToString().Trim()
            },
            Range = new LspRange
            {
                Start = position,
                End = position
            }
        };
    }

    private string? GetDiagnosticHover(string documentUri, LspPosition position)
    {
        var diagnostics = _diagnosticsProvider.GetDiagnostics(documentUri);

        var relevantDiagnostics = diagnostics
            .Where(d => PositionInRange(position, d.Range))
            .ToList();

        if (relevantDiagnostics.Count == 0)
            return null;

        var sb = new StringBuilder();

        foreach (var diagnostic in relevantDiagnostics)
        {
            var icon = diagnostic.Severity switch
            {
                LspDiagnosticSeverity.Error => "Error",
                LspDiagnosticSeverity.Warning => "Warning",
                LspDiagnosticSeverity.Information => "Info",
                LspDiagnosticSeverity.Hint => "Hint",
                _ => "Note"
            };

            sb.AppendLine($"**{icon}**: {diagnostic.Message}");

            if (diagnostic.Code != null)
            {
                sb.AppendLine($"*Code: {diagnostic.Code}*");
            }

            if (diagnostic.Data != null)
            {
                if (diagnostic.Data.Category != null)
                {
                    sb.AppendLine($"*Category: {diagnostic.Data.Category}*");
                }

                if (diagnostic.Data.HasQuickFix)
                {
                    sb.AppendLine("\n**Quick fix available** - Use Ctrl+. or Cmd+.");
                }

                if (!string.IsNullOrEmpty(diagnostic.Data.SuggestedCode))
                {
                    sb.AppendLine("\n**Suggested fix:**");
                    sb.AppendLine($"```csharp\n{diagnostic.Data.SuggestedCode}\n```");
                }

                // Add documentation links based on issue type
                var docUrl = GetDocumentationUrl(diagnostic.Data.IssueType);
                if (docUrl != null)
                {
                    sb.AppendLine($"\n[Learn more]({docUrl})");
                }
            }

            sb.AppendLine();
        }

        return sb.ToString().Trim();
    }

    private async Task<string?> GetMetricsHoverAsync(
        string documentUri,
        LspPosition position,
        string content,
        CancellationToken cancellationToken)
    {
        var metrics = _codeLensProvider.GetMethodMetrics(documentUri);

        // Find method at position
        var methodMetrics = metrics.FirstOrDefault(m => m.Line == position.Line);
        if (methodMetrics == null)
        {
            // Try to find if we're inside a method
            try
            {
                var syntaxTree = CSharpSyntaxTree.ParseText(content, cancellationToken: cancellationToken);
                var root = await syntaxTree.GetRootAsync(cancellationToken);
                var pos = GetPositionFromLine(content, position);
                var node = root.FindNode(new Microsoft.CodeAnalysis.Text.TextSpan(pos, 1));
                var method = node.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().FirstOrDefault();

                if (method != null)
                {
                    var methodLine = method.GetLocation().GetLineSpan().StartLinePosition.Line;
                    methodMetrics = metrics.FirstOrDefault(m => m.Line == methodLine);
                }
            }
            catch
            {
                return null;
            }
        }

        if (methodMetrics == null)
            return null;

        var sb = new StringBuilder();
        sb.AppendLine($"### Method: {methodMetrics.ClassName}.{methodMetrics.MethodName}");
        sb.AppendLine();
        sb.AppendLine("| Metric | Value | Status |");
        sb.AppendLine("|--------|-------|--------|");

        // Cyclomatic Complexity
        var ccStatus = methodMetrics.CyclomaticComplexity switch
        {
            <= 10 => "Good",
            <= 15 => "Moderate",
            <= 25 => "Complex",
            _ => "Very Complex"
        };
        sb.AppendLine($"| Cyclomatic Complexity | {methodMetrics.CyclomaticComplexity} | {ccStatus} |");

        // Lines of Code
        var locStatus = methodMetrics.LineCount switch
        {
            <= 20 => "Good",
            <= 50 => "Moderate",
            <= 100 => "Long",
            _ => "Very Long"
        };
        sb.AppendLine($"| Lines of Code | {methodMetrics.LineCount} | {locStatus} |");

        // Test Coverage
        if (methodMetrics.TestCoverage.HasValue)
        {
            var covStatus = methodMetrics.TestCoverage.Value switch
            {
                >= 80 => "Excellent",
                >= 60 => "Good",
                >= 40 => "Moderate",
                _ => "Low"
            };
            sb.AppendLine($"| Test Coverage | {methodMetrics.TestCoverage.Value:F0}% | {covStatus} |");
        }

        // Nesting Depth
        if (methodMetrics.NestingDepth.HasValue)
        {
            var nestStatus = methodMetrics.NestingDepth.Value switch
            {
                <= 2 => "Good",
                <= 4 => "Moderate",
                _ => "Deep"
            };
            sb.AppendLine($"| Max Nesting | {methodMetrics.NestingDepth.Value} | {nestStatus} |");
        }

        // Parameters
        if (methodMetrics.ParameterCount.HasValue)
        {
            var paramStatus = methodMetrics.ParameterCount.Value switch
            {
                <= 3 => "Good",
                <= 5 => "Moderate",
                _ => "Many"
            };
            sb.AppendLine($"| Parameters | {methodMetrics.ParameterCount.Value} | {paramStatus} |");
        }

        // Add recommendations if metrics are concerning
        var recommendations = new List<string>();

        if (methodMetrics.CyclomaticComplexity > 15)
        {
            recommendations.Add("Consider breaking this method into smaller, focused methods");
        }

        if (methodMetrics.LineCount > 50)
        {
            recommendations.Add("This method is long. Look for opportunities to extract helper methods");
        }

        if (methodMetrics.NestingDepth.HasValue && methodMetrics.NestingDepth.Value > 4)
        {
            recommendations.Add("Deep nesting reduces readability. Consider using guard clauses or early returns");
        }

        if (methodMetrics.ParameterCount.HasValue && methodMetrics.ParameterCount.Value > 5)
        {
            recommendations.Add("Many parameters may indicate the need for a parameter object");
        }

        if (recommendations.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("**Recommendations:**");
            foreach (var rec in recommendations)
            {
                sb.AppendLine($"- {rec}");
            }
        }

        return sb.ToString();
    }

    private async Task<string?> GetSemanticHoverAsync(
        string documentUri,
        LspPosition position,
        string content,
        CancellationToken cancellationToken)
    {
        try
        {
            var syntaxTree = CSharpSyntaxTree.ParseText(content, cancellationToken: cancellationToken);
            var root = await syntaxTree.GetRootAsync(cancellationToken);
            var pos = GetPositionFromLine(content, position);
            var node = root.FindNode(new Microsoft.CodeAnalysis.Text.TextSpan(pos, 1));

            // Get additional context based on node type
            var sb = new StringBuilder();

            // Show pattern information
            if (node.Parent is PatternSyntax pattern)
            {
                sb.AppendLine("**Pattern Matching**");
                sb.AppendLine($"Pattern type: `{pattern.GetType().Name.Replace("Syntax", "")}`");
            }

            // Show attribute information
            if (node is AttributeSyntax attr)
            {
                sb.AppendLine($"**Attribute**: `{attr.Name}`");
            }

            // Check for common anti-patterns at this location
            var antiPatternInfo = AnalyzeForAntiPatterns(node);
            if (!string.IsNullOrEmpty(antiPatternInfo))
            {
                if (sb.Length > 0) sb.AppendLine();
                sb.AppendLine(antiPatternInfo);
            }

            return sb.Length > 0 ? sb.ToString() : null;
        }
        catch
        {
            return null;
        }
    }

    private string? AnalyzeForAntiPatterns(SyntaxNode node)
    {
        var sb = new StringBuilder();

        // Check for specific anti-patterns based on node context
        if (node is CatchClauseSyntax catchClause)
        {
            if (catchClause.Block.Statements.Count == 0)
            {
                sb.AppendLine("**Anti-pattern detected**: Empty catch block");
                sb.AppendLine("Empty catch blocks silently swallow exceptions, making debugging difficult.");
                sb.AppendLine("\n*Best practice*: Log the exception or rethrow with additional context.");
            }
            else if (catchClause.Declaration?.Type.ToString() == "Exception")
            {
                sb.AppendLine("**Pattern note**: Catching base Exception");
                sb.AppendLine("Catching the base `Exception` type can mask specific errors.");
                sb.AppendLine("\n*Consider*: Catch specific exception types when possible.");
            }
        }

        if (node is InvocationExpressionSyntax invocation)
        {
            var methodName = invocation.Expression.ToString();

            // Check for blocking calls on async code
            if (methodName.EndsWith(".Result") || methodName.EndsWith(".Wait()"))
            {
                sb.AppendLine("**Potential issue**: Blocking on async code");
                sb.AppendLine("Using `.Result` or `.Wait()` can cause deadlocks in UI/ASP.NET contexts.");
                sb.AppendLine("\n*Best practice*: Use `await` instead.");
            }

            // Check for new Guid() instead of Guid.NewGuid()
            if (methodName.Contains("new Guid()"))
            {
                sb.AppendLine("**Common mistake**: `new Guid()` creates empty GUID");
                sb.AppendLine("Use `Guid.NewGuid()` to generate a unique identifier.");
            }
        }

        if (node is BinaryExpressionSyntax binary)
        {
            // Check for string comparison issues
            if (binary.IsKind(SyntaxKind.EqualsExpression) || binary.IsKind(SyntaxKind.NotEqualsExpression))
            {
                var leftType = binary.Left.ToString();
                var rightType = binary.Right.ToString();

                if ((leftType.Contains("null") || rightType.Contains("null")) &&
                    !(binary.Left is LiteralExpressionSyntax || binary.Right is LiteralExpressionSyntax))
                {
                    // This might be comparing against a variable that could be null
                }
            }
        }

        if (node is ObjectCreationExpressionSyntax creation)
        {
            var typeName = creation.Type.ToString();

            // Common performance issues
            if (typeName == "StringBuilder" && creation.ArgumentList?.Arguments.Count == 0)
            {
                // Check if this is in a context where initial capacity would help
                var inLoop = node.Ancestors().Any(a => a is ForStatementSyntax or ForEachStatementSyntax or WhileStatementSyntax);
                if (!inLoop)
                {
                    // Potentially suggest initial capacity
                }
            }
        }

        return sb.Length > 0 ? sb.ToString() : null;
    }

    private static string? GetDocumentationUrl(string issueType)
    {
        return issueType switch
        {
            "AsyncVoid" => "https://docs.microsoft.com/en-us/archive/msdn-magazine/2013/march/async-await-best-practices-in-asynchronous-programming",
            "MissingConfigureAwait" => "https://devblogs.microsoft.com/dotnet/configureawait-faq/",
            "SqlInjection" => "https://owasp.org/www-community/attacks/SQL_Injection",
            "HardcodedSecret" => "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
            "EmptyCatch" => "https://docs.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions",
            "MissingUsing" => "https://docs.microsoft.com/en-us/dotnet/standard/garbage-collection/implementing-dispose",
            "HighComplexity" => "https://docs.microsoft.com/en-us/visualstudio/code-quality/code-metrics-cyclomatic-complexity",
            "GodClass" => "https://refactoring.guru/smells/large-class",
            "LongMethod" => "https://refactoring.guru/smells/long-method",
            _ => null
        };
    }

    private static bool PositionInRange(LspPosition position, LspRange range)
    {
        if (position.Line < range.Start.Line || position.Line > range.End.Line)
            return false;

        if (position.Line == range.Start.Line && position.Character < range.Start.Character)
            return false;

        if (position.Line == range.End.Line && position.Character > range.End.Character)
            return false;

        return true;
    }

    private static int GetPositionFromLine(string content, LspPosition position)
    {
        var lines = content.Split('\n');
        var offset = 0;
        for (var i = 0; i < position.Line && i < lines.Length; i++)
        {
            offset += lines[i].Length + 1;
        }
        return offset + Math.Min(position.Character, lines.Length > position.Line ? lines[position.Line].Length : 0);
    }
}
