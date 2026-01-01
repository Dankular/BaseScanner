using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Optimizations;

/// <summary>
/// Detects opportunities for caching to improve performance.
/// </summary>
public class CachingOptimizationDetector : IOptimizationDetector
{
    public string Category => "Performance";

    public Task<List<OptimizationOpportunity>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context)
    {
        var opportunities = new List<OptimizationOpportunity>();
        var filePath = document.FilePath ?? "";

        // Detect repeated method calls in same scope
        DetectRepeatedMethodCalls(root, semanticModel, filePath, opportunities);

        // Detect expensive property access in loops
        DetectPropertyAccessInLoops(root, semanticModel, filePath, opportunities);

        // Detect repeated Regex compilation
        DetectRepeatedRegex(root, semanticModel, filePath, opportunities);

        // Detect repeated reflection calls
        DetectRepeatedReflection(root, semanticModel, filePath, opportunities);

        // Detect repeated LINQ queries
        DetectRepeatedLinqQueries(root, semanticModel, filePath, opportunities);

        return Task.FromResult(opportunities);
    }

    private void DetectRepeatedMethodCalls(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        // Group method calls by their full text within each method body
        var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>();

        foreach (var method in methods)
        {
            if (method.Body == null && method.ExpressionBody == null)
                continue;

            var invocations = (method.Body?.DescendantNodes() ?? method.ExpressionBody!.DescendantNodes())
                .OfType<InvocationExpressionSyntax>()
                .ToList();

            // Group by the invocation text (ignoring whitespace differences)
            var grouped = invocations
                .GroupBy(inv => NormalizeInvocation(inv))
                .Where(g => g.Count() >= 2)
                .Where(g => IsExpensiveCall(g.First(), semanticModel))
                .ToList();

            foreach (var group in grouped)
            {
                var first = group.First();
                var lineSpan = first.GetLocation().GetLineSpan();
                var callCount = group.Count();
                var callText = first.ToFullString().Trim();

                // Skip very short calls (likely cheap)
                if (callText.Length < 10)
                    continue;

                opportunities.Add(new OptimizationOpportunity
                {
                    Category = Category,
                    Type = "RepeatedMethodCall",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = $"Method call appears {callCount} times in this method. Consider caching the result.",
                    CurrentCode = callText,
                    SuggestedCode = $"var cached = {callText}; // Use 'cached' instead of repeated calls",
                    Confidence = OptimizationConfidence.Medium,
                    Impact = OptimizationImpact.Medium,
                    IsSemanticallySafe = false,
                    Assumptions = ["Method has no side effects", "Return value doesn't change between calls"]
                });
            }
        }
    }

    private string NormalizeInvocation(InvocationExpressionSyntax invocation)
    {
        // Normalize whitespace for comparison
        return invocation.ToFullString().Trim()
            .Replace("\r\n", " ")
            .Replace("\n", " ")
            .Replace("  ", " ");
    }

    private bool IsExpensiveCall(InvocationExpressionSyntax invocation, SemanticModel semanticModel)
    {
        var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
        if (symbol == null)
            return false;

        // Consider I/O operations, database calls, parsing as expensive
        var methodName = symbol.Name.ToLowerInvariant();
        var typeName = symbol.ContainingType?.Name.ToLowerInvariant() ?? "";

        // Known expensive patterns
        if (methodName.Contains("parse") ||
            methodName.Contains("read") ||
            methodName.Contains("load") ||
            methodName.Contains("fetch") ||
            methodName.Contains("query") ||
            methodName.Contains("get") && typeName.Contains("service") ||
            methodName.Contains("calculate") ||
            methodName.Contains("compute"))
            return true;

        // Check if it's a property getter that might be expensive
        if (symbol.IsExtensionMethod || symbol.Parameters.Length == 0)
        {
            // Parameterless methods are often property-like and may be expensive
            return true;
        }

        return false;
    }

    private void DetectPropertyAccessInLoops(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        var loops = root.DescendantNodes()
            .Where(n => n is ForStatementSyntax or ForEachStatementSyntax or
                       WhileStatementSyntax or DoStatementSyntax);

        foreach (var loop in loops)
        {
            var memberAccesses = loop.DescendantNodes()
                .OfType<MemberAccessExpressionSyntax>()
                .ToList();

            // Group by the full access expression
            var grouped = memberAccesses
                .GroupBy(ma => ma.ToFullString().Trim())
                .Where(g => g.Count() >= 2)
                .ToList();

            foreach (var group in grouped)
            {
                var first = group.First();

                // Check if it's a property access (not a method call)
                var parent = first.Parent;
                if (parent is InvocationExpressionSyntax)
                    continue; // It's a method call, handled elsewhere

                var symbol = semanticModel.GetSymbolInfo(first).Symbol;
                if (symbol is not IPropertySymbol prop)
                    continue;

                // Skip simple auto-properties (they're cheap)
                if (IsAutoProperty(prop))
                    continue;

                var accessText = first.ToFullString().Trim();
                var lineSpan = first.GetLocation().GetLineSpan();
                var accessCount = group.Count();

                opportunities.Add(new OptimizationOpportunity
                {
                    Category = Category,
                    Type = "PropertyAccessInLoop",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = $"Property '{accessText}' accessed {accessCount} times in loop. Cache before the loop if value doesn't change.",
                    CurrentCode = accessText,
                    SuggestedCode = $"var cached{prop.Name} = {accessText}; // Cache before loop",
                    Confidence = OptimizationConfidence.Medium,
                    Impact = OptimizationImpact.Medium,
                    IsSemanticallySafe = false,
                    Assumptions = ["Property value doesn't change during loop iteration"]
                });
            }
        }
    }

    private bool IsAutoProperty(IPropertySymbol property)
    {
        // Auto-properties have compiler-generated backing field
        return property.GetMethod?.IsImplicitlyDeclared == true ||
               property.SetMethod?.IsImplicitlyDeclared == true;
    }

    private void DetectRepeatedRegex(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        // Find new Regex() or Regex.Match/Replace with pattern string
        var regexCreations = root.DescendantNodes()
            .OfType<ObjectCreationExpressionSyntax>()
            .Where(oc => IsRegexType(oc, semanticModel))
            .ToList();

        var regexStaticCalls = root.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(inv => IsStaticRegexCall(inv, semanticModel))
            .ToList();

        // Check if Regex is created multiple times with the same pattern
        var patternGroups = regexCreations
            .Select(rc => GetRegexPattern(rc))
            .Where(p => p != null)
            .GroupBy(p => p)
            .Where(g => g.Count() >= 2)
            .ToList();

        foreach (var group in patternGroups)
        {
            var pattern = group.Key!;
            var creation = regexCreations.First(rc => GetRegexPattern(rc) == pattern);
            var lineSpan = creation.GetLocation().GetLineSpan();

            opportunities.Add(new OptimizationOpportunity
            {
                Category = Category,
                Type = "RepeatedRegexCreation",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                Description = $"Regex with pattern \"{TruncatePattern(pattern)}\" is created {group.Count()} times. Compile once and reuse.",
                CurrentCode = creation.ToFullString().Trim(),
                SuggestedCode = $"private static readonly Regex _regex = new Regex(@\"{pattern}\", RegexOptions.Compiled);",
                Confidence = OptimizationConfidence.High,
                Impact = OptimizationImpact.High,
                IsSemanticallySafe = true
            });
        }

        // Check for static Regex calls that should use compiled instance
        foreach (var call in regexStaticCalls)
        {
            var lineSpan = call.GetLocation().GetLineSpan();
            opportunities.Add(new OptimizationOpportunity
            {
                Category = Category,
                Type = "StaticRegexCall",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                Description = "Static Regex methods recompile the pattern on each call. Use a compiled Regex instance for repeated use.",
                CurrentCode = call.ToFullString().Trim(),
                SuggestedCode = "// private static readonly Regex _regex = new Regex(pattern, RegexOptions.Compiled);\n// _regex.Match/Replace(...)",
                Confidence = OptimizationConfidence.Medium,
                Impact = OptimizationImpact.Medium,
                IsSemanticallySafe = true
            });
        }
    }

    private bool IsRegexType(ObjectCreationExpressionSyntax creation, SemanticModel semanticModel)
    {
        var typeInfo = semanticModel.GetTypeInfo(creation);
        return typeInfo.Type?.ToDisplayString() == "System.Text.RegularExpressions.Regex";
    }

    private bool IsStaticRegexCall(InvocationExpressionSyntax invocation, SemanticModel semanticModel)
    {
        var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
        if (symbol == null || !symbol.IsStatic)
            return false;

        return symbol.ContainingType?.ToDisplayString() == "System.Text.RegularExpressions.Regex" &&
               (symbol.Name == "Match" || symbol.Name == "Matches" ||
                symbol.Name == "Replace" || symbol.Name == "Split" || symbol.Name == "IsMatch");
    }

    private string? GetRegexPattern(ObjectCreationExpressionSyntax creation)
    {
        if (creation.ArgumentList?.Arguments.Count > 0)
        {
            var firstArg = creation.ArgumentList.Arguments[0].Expression;
            if (firstArg is LiteralExpressionSyntax literal)
            {
                return literal.Token.ValueText;
            }
        }
        return null;
    }

    private string TruncatePattern(string pattern)
    {
        return pattern.Length > 30 ? pattern.Substring(0, 30) + "..." : pattern;
    }

    private void DetectRepeatedReflection(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        var reflectionCalls = root.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(inv => IsReflectionCall(inv, semanticModel))
            .ToList();

        // Group by the full invocation text
        var grouped = reflectionCalls
            .GroupBy(inv => inv.ToFullString().Trim())
            .Where(g => g.Count() >= 2)
            .ToList();

        foreach (var group in grouped)
        {
            var first = group.First();
            var lineSpan = first.GetLocation().GetLineSpan();
            var callCount = group.Count();

            opportunities.Add(new OptimizationOpportunity
            {
                Category = Category,
                Type = "RepeatedReflection",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                Description = $"Reflection call appears {callCount} times. Cache the MethodInfo/PropertyInfo in a static field.",
                CurrentCode = first.ToFullString().Trim(),
                SuggestedCode = "// private static readonly MethodInfo _methodInfo = typeof(T).GetMethod(\"...\");\n// Use _methodInfo.Invoke(...)",
                Confidence = OptimizationConfidence.High,
                Impact = OptimizationImpact.High,
                IsSemanticallySafe = true
            });
        }
    }

    private bool IsReflectionCall(InvocationExpressionSyntax invocation, SemanticModel semanticModel)
    {
        var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
        if (symbol == null)
            return false;

        var typeName = symbol.ContainingType?.ToDisplayString() ?? "";

        // Common reflection methods
        if (typeName == "System.Type")
        {
            return symbol.Name is "GetMethod" or "GetProperty" or "GetField" or
                   "GetMember" or "GetMethods" or "GetProperties" or "GetFields" or
                   "GetConstructor" or "GetEvent";
        }

        return false;
    }

    private void DetectRepeatedLinqQueries(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        // Find LINQ queries that are executed multiple times
        var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>();

        foreach (var method in methods)
        {
            if (method.Body == null)
                continue;

            var linqChains = method.Body.DescendantNodes()
                .OfType<InvocationExpressionSyntax>()
                .Where(inv => IsLinqTerminalOperation(inv, semanticModel))
                .ToList();

            // Find LINQ queries that share the same base expression
            var queryBases = linqChains
                .Select(inv => GetLinqQueryBase(inv))
                .Where(b => b != null)
                .GroupBy(b => b)
                .Where(g => g.Count() >= 2)
                .ToList();

            foreach (var group in queryBases)
            {
                var queryBase = group.Key!;
                var first = linqChains.First(inv => GetLinqQueryBase(inv) == queryBase);
                var lineSpan = first.GetLocation().GetLineSpan();

                opportunities.Add(new OptimizationOpportunity
                {
                    Category = Category,
                    Type = "RepeatedLinqQuery",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = $"LINQ query on '{TruncateText(queryBase)}' is materialized {group.Count()} times. Call ToList()/ToArray() once and reuse.",
                    CurrentCode = first.ToFullString().Trim(),
                    SuggestedCode = $"var materialized = {queryBase}.ToList(); // Reuse this list",
                    Confidence = OptimizationConfidence.Medium,
                    Impact = OptimizationImpact.Medium,
                    IsSemanticallySafe = false,
                    Assumptions = ["Source collection doesn't change between queries"]
                });
            }
        }
    }

    private bool IsLinqTerminalOperation(InvocationExpressionSyntax invocation, SemanticModel semanticModel)
    {
        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
            return false;

        var methodName = memberAccess.Name.Identifier.Text;

        // Terminal LINQ operations that execute the query
        var terminals = new[] { "ToList", "ToArray", "ToDictionary", "ToHashSet",
                               "First", "FirstOrDefault", "Single", "SingleOrDefault",
                               "Last", "LastOrDefault", "Count", "Any", "All",
                               "Sum", "Average", "Min", "Max", "Aggregate" };

        if (!terminals.Contains(methodName))
            return false;

        var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
        return symbol?.ContainingNamespace?.ToDisplayString()?.StartsWith("System.Linq") ?? false;
    }

    private string? GetLinqQueryBase(InvocationExpressionSyntax invocation)
    {
        // Walk up the LINQ chain to find the base collection
        ExpressionSyntax? current = invocation;

        while (current is InvocationExpressionSyntax inv)
        {
            if (inv.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                current = memberAccess.Expression;
            }
            else
            {
                break;
            }
        }

        return current?.ToFullString().Trim();
    }

    private string TruncateText(string text)
    {
        return text.Length > 40 ? text.Substring(0, 40) + "..." : text;
    }
}
