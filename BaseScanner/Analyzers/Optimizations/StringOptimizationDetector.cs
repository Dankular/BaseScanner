using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Optimizations;

/// <summary>
/// Detects string manipulation patterns that can be optimized.
/// </summary>
public class StringOptimizationDetector : IOptimizationDetector
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

        // Detect string.Format -> string interpolation
        DetectStringFormat(root, semanticModel, filePath, opportunities);

        // Detect string concatenation -> interpolation
        DetectStringConcatenation(root, semanticModel, filePath, opportunities);

        // Detect string concatenation in loops -> StringBuilder
        DetectConcatInLoop(root, semanticModel, filePath, opportunities);

        // Detect ToLower/ToUpper for comparison -> StringComparison
        DetectCaseInsensitiveComparison(root, semanticModel, filePath, opportunities);

        // Detect multiple Replace chains
        DetectReplaceChains(root, semanticModel, filePath, opportunities);

        // Detect repeated ToString calls
        DetectRepeatedToString(root, semanticModel, filePath, opportunities);

        return Task.FromResult(opportunities);
    }

    private void DetectStringFormat(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
                continue;

            if (memberAccess.Name.Identifier.Text != "Format")
                continue;

            // Check if it's string.Format
            var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
            if (symbol?.ContainingType?.SpecialType != SpecialType.System_String)
                continue;

            var args = invocation.ArgumentList.Arguments;
            if (args.Count < 2)
                continue;

            // Get the format string
            var formatArg = args[0].Expression;
            if (formatArg is not LiteralExpressionSyntax literal)
                continue;

            var formatString = literal.Token.ValueText;
            var lineSpan = invocation.GetLocation().GetLineSpan();

            // Build interpolated string suggestion
            var interpolated = BuildInterpolatedString(formatString, args.Skip(1).ToList());

            opportunities.Add(new OptimizationOpportunity
            {
                Category = Category,
                Type = "StringFormatToInterpolation",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                Description = "Replace string.Format with string interpolation for better readability and performance.",
                CurrentCode = invocation.ToFullString().Trim(),
                SuggestedCode = interpolated,
                Confidence = OptimizationConfidence.High,
                Impact = OptimizationImpact.Low,
                IsSemanticallySafe = true
            });
        }
    }

    private string BuildInterpolatedString(string format, List<ArgumentSyntax> args)
    {
        var result = format;
        for (int i = 0; i < args.Count; i++)
        {
            var argText = args[i].Expression.ToFullString().Trim();
            result = result.Replace($"{{{i}}}", $"{{{argText}}}");
        }
        return $"$\"{result}\"";
    }

    private void DetectStringConcatenation(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        foreach (var binary in root.DescendantNodes().OfType<BinaryExpressionSyntax>())
        {
            if (binary.Kind() != SyntaxKind.AddExpression)
                continue;

            // Check if it's string concatenation with multiple parts
            var parts = FlattenConcatenation(binary);
            if (parts.Count < 3)
                continue;

            // Check if at least one part is a string literal and one is not
            var hasLiteral = parts.Any(p => p is LiteralExpressionSyntax lit &&
                lit.Token.IsKind(SyntaxKind.StringLiteralToken));
            var hasNonLiteral = parts.Any(p => p is not LiteralExpressionSyntax);

            if (!hasLiteral || !hasNonLiteral)
                continue;

            // Verify it's string concatenation
            var typeInfo = semanticModel.GetTypeInfo(binary);
            if (typeInfo.Type?.SpecialType != SpecialType.System_String)
                continue;

            var lineSpan = binary.GetLocation().GetLineSpan();
            var interpolated = BuildInterpolatedFromParts(parts);

            opportunities.Add(new OptimizationOpportunity
            {
                Category = Category,
                Type = "ConcatToInterpolation",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                Description = "Replace string concatenation with string interpolation for better readability.",
                CurrentCode = binary.ToFullString().Trim(),
                SuggestedCode = interpolated,
                Confidence = OptimizationConfidence.High,
                Impact = OptimizationImpact.Low,
                IsSemanticallySafe = true
            });
        }
    }

    private List<ExpressionSyntax> FlattenConcatenation(BinaryExpressionSyntax binary)
    {
        var parts = new List<ExpressionSyntax>();

        void Flatten(ExpressionSyntax expr)
        {
            if (expr is BinaryExpressionSyntax bin && bin.Kind() == SyntaxKind.AddExpression)
            {
                Flatten(bin.Left);
                Flatten(bin.Right);
            }
            else
            {
                parts.Add(expr);
            }
        }

        Flatten(binary);
        return parts;
    }

    private string BuildInterpolatedFromParts(List<ExpressionSyntax> parts)
    {
        var sb = new System.Text.StringBuilder("$\"");
        foreach (var part in parts)
        {
            if (part is LiteralExpressionSyntax literal &&
                literal.Token.IsKind(SyntaxKind.StringLiteralToken))
            {
                sb.Append(literal.Token.ValueText);
            }
            else
            {
                sb.Append('{');
                sb.Append(part.ToFullString().Trim());
                sb.Append('}');
            }
        }
        sb.Append('"');
        return sb.ToString();
    }

    private void DetectConcatInLoop(
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
            // Find string assignments using += or = with +
            foreach (var assignment in loop.DescendantNodes().OfType<AssignmentExpressionSyntax>())
            {
                bool isConcatAssignment = false;
                string? varName = null;

                if (assignment.Kind() == SyntaxKind.AddAssignmentExpression)
                {
                    // str += something
                    var leftType = semanticModel.GetTypeInfo(assignment.Left).Type;
                    if (leftType?.SpecialType == SpecialType.System_String)
                    {
                        isConcatAssignment = true;
                        varName = assignment.Left.ToFullString().Trim();
                    }
                }
                else if (assignment.Kind() == SyntaxKind.SimpleAssignmentExpression &&
                         assignment.Right is BinaryExpressionSyntax binary &&
                         binary.Kind() == SyntaxKind.AddExpression)
                {
                    // str = str + something
                    var leftType = semanticModel.GetTypeInfo(assignment.Left).Type;
                    if (leftType?.SpecialType == SpecialType.System_String)
                    {
                        var leftName = assignment.Left.ToFullString().Trim();
                        var binaryLeftName = binary.Left.ToFullString().Trim();
                        if (leftName == binaryLeftName)
                        {
                            isConcatAssignment = true;
                            varName = leftName;
                        }
                    }
                }

                if (isConcatAssignment && varName != null)
                {
                    var lineSpan = assignment.GetLocation().GetLineSpan();
                    opportunities.Add(new OptimizationOpportunity
                    {
                        Category = Category,
                        Type = "StringConcatInLoop",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = "String concatenation in a loop creates many intermediate strings. Use StringBuilder instead.",
                        CurrentCode = assignment.ToFullString().Trim(),
                        SuggestedCode = $"// Use StringBuilder: var sb = new StringBuilder();\n// sb.Append(...);\n// {varName} = sb.ToString();",
                        Confidence = OptimizationConfidence.High,
                        Impact = OptimizationImpact.High,
                        IsSemanticallySafe = true
                    });
                }
            }
        }
    }

    private void DetectCaseInsensitiveComparison(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        foreach (var binary in root.DescendantNodes().OfType<BinaryExpressionSyntax>())
        {
            if (binary.Kind() != SyntaxKind.EqualsExpression &&
                binary.Kind() != SyntaxKind.NotEqualsExpression)
                continue;

            // Check for patterns like str1.ToLower() == str2.ToLower()
            var leftToLower = GetToLowerOrUpperCall(binary.Left, semanticModel);
            var rightToLower = GetToLowerOrUpperCall(binary.Right, semanticModel);

            if (leftToLower == null && rightToLower == null)
                continue;

            string leftExpr, rightExpr;
            if (leftToLower != null && rightToLower != null)
            {
                leftExpr = leftToLower;
                rightExpr = rightToLower;
            }
            else if (leftToLower != null)
            {
                leftExpr = leftToLower;
                rightExpr = binary.Right.ToFullString().Trim();
            }
            else
            {
                leftExpr = binary.Left.ToFullString().Trim();
                rightExpr = rightToLower!;
            }

            var lineSpan = binary.GetLocation().GetLineSpan();
            var comparison = binary.Kind() == SyntaxKind.EqualsExpression ? "Equals" : "!... Equals";
            var suggested = $"string.Equals({leftExpr}, {rightExpr}, StringComparison.OrdinalIgnoreCase)";
            if (binary.Kind() == SyntaxKind.NotEqualsExpression)
                suggested = $"!string.Equals({leftExpr}, {rightExpr}, StringComparison.OrdinalIgnoreCase)";

            opportunities.Add(new OptimizationOpportunity
            {
                Category = Category,
                Type = "CaseInsensitiveComparison",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                Description = "Using ToLower()/ToUpper() for case-insensitive comparison allocates new strings. Use StringComparison.OrdinalIgnoreCase instead.",
                CurrentCode = binary.ToFullString().Trim(),
                SuggestedCode = suggested,
                Confidence = OptimizationConfidence.High,
                Impact = OptimizationImpact.Medium,
                IsSemanticallySafe = true
            });
        }
    }

    private string? GetToLowerOrUpperCall(ExpressionSyntax expr, SemanticModel semanticModel)
    {
        if (expr is InvocationExpressionSyntax invocation &&
            invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            var methodName = memberAccess.Name.Identifier.Text;
            if (methodName == "ToLower" || methodName == "ToUpper" ||
                methodName == "ToLowerInvariant" || methodName == "ToUpperInvariant")
            {
                var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                if (symbol?.ContainingType?.SpecialType == SpecialType.System_String)
                {
                    return memberAccess.Expression.ToFullString().Trim();
                }
            }
        }
        return null;
    }

    private void DetectReplaceChains(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            // Count consecutive Replace calls
            var replaceCount = CountReplaceChain(invocation, semanticModel);
            if (replaceCount < 3)
                continue;

            var lineSpan = invocation.GetLocation().GetLineSpan();
            opportunities.Add(new OptimizationOpportunity
            {
                Category = Category,
                Type = "MultipleReplaceChain",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                Description = $"Chain of {replaceCount} Replace() calls creates intermediate strings. Consider using Regex.Replace() or StringBuilder for better performance.",
                CurrentCode = invocation.ToFullString().Trim(),
                SuggestedCode = "// Consider: Regex.Replace(str, pattern, replacement)\n// Or use StringBuilder with multiple replacements",
                Confidence = OptimizationConfidence.Medium,
                Impact = OptimizationImpact.Medium,
                IsSemanticallySafe = false,
                Assumptions = ["The replacement order and overlaps are handled correctly by regex"]
            });
        }
    }

    private int CountReplaceChain(InvocationExpressionSyntax invocation, SemanticModel semanticModel)
    {
        int count = 0;
        ExpressionSyntax? current = invocation;

        while (current is InvocationExpressionSyntax inv &&
               inv.Expression is MemberAccessExpressionSyntax memberAccess &&
               memberAccess.Name.Identifier.Text == "Replace")
        {
            var symbol = semanticModel.GetSymbolInfo(inv).Symbol as IMethodSymbol;
            if (symbol?.ContainingType?.SpecialType != SpecialType.System_String)
                break;

            count++;
            current = memberAccess.Expression;
        }

        return count;
    }

    private void DetectRepeatedToString(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        // Group ToString() calls by the expression they're called on
        var toStringCalls = new Dictionary<string, List<InvocationExpressionSyntax>>();

        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
                continue;

            if (memberAccess.Name.Identifier.Text != "ToString")
                continue;

            // Get the receiver expression
            var receiver = memberAccess.Expression.ToFullString().Trim();

            // Skip simple identifiers (they're cheap to call ToString on)
            if (memberAccess.Expression is IdentifierNameSyntax)
                continue;

            if (!toStringCalls.ContainsKey(receiver))
                toStringCalls[receiver] = new List<InvocationExpressionSyntax>();

            toStringCalls[receiver].Add(invocation);
        }

        // Report expressions with multiple ToString() calls
        foreach (var (receiver, calls) in toStringCalls)
        {
            if (calls.Count < 2)
                continue;

            var firstCall = calls[0];
            var lineSpan = firstCall.GetLocation().GetLineSpan();

            opportunities.Add(new OptimizationOpportunity
            {
                Category = Category,
                Type = "RepeatedToString",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                Description = $"ToString() called {calls.Count} times on the same expression. Cache the result in a local variable.",
                CurrentCode = firstCall.ToFullString().Trim(),
                SuggestedCode = $"var cachedString = {receiver}.ToString();",
                Confidence = OptimizationConfidence.Medium,
                Impact = OptimizationImpact.Low,
                IsSemanticallySafe = true,
                Assumptions = ["The underlying value doesn't change between calls"]
            });
        }
    }
}
