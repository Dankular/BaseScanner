using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Transformers.Core;

namespace BaseScanner.Transformers.Optimizations;

/// <summary>
/// Transforms string operations for better performance and readability.
/// </summary>
public class StringTransformer : ICodeTransformer
{
    public string TransformationType => "StringOptimization";

    public bool CanTransform(SyntaxNode node, SemanticModel semanticModel)
    {
        return IsStringFormatPattern(node, semanticModel) ||
               IsStringConcatenationPattern(node, semanticModel) ||
               IsToLowerEqualsPattern(node, semanticModel) ||
               IsEmptyStringComparison(node, semanticModel);
    }

    public async Task<TransformationResult> TransformAsync(TransformationContext context, SyntaxNode targetNode)
    {
        string? transformedCode = null;
        string? description = null;

        if (IsStringFormatPattern(targetNode, context.SemanticModel))
        {
            transformedCode = TransformStringFormat(targetNode as InvocationExpressionSyntax);
            description = "string.Format to string interpolation";
        }
        else if (IsStringConcatenationPattern(targetNode, context.SemanticModel))
        {
            transformedCode = TransformConcatenation(targetNode as BinaryExpressionSyntax);
            description = "String concatenation to interpolation";
        }
        else if (IsToLowerEqualsPattern(targetNode, context.SemanticModel))
        {
            transformedCode = TransformToLowerEquals(targetNode as InvocationExpressionSyntax);
            description = "ToLower().Equals() to Equals with OrdinalIgnoreCase";
        }
        else if (IsEmptyStringComparison(targetNode, context.SemanticModel))
        {
            transformedCode = TransformEmptyStringComparison(targetNode as BinaryExpressionSyntax);
            description = "== \"\" to string.IsNullOrEmpty";
        }

        if (transformedCode == null)
            return TransformationResult.Failed(TransformationType, "Could not determine transformation");

        var originalCode = targetNode.ToFullString().Trim();
        var diff = DiffGenerator.GenerateUnifiedDiff(originalCode, transformedCode, context.Document.FilePath ?? "");

        return TransformationResult.Succeeded(TransformationType, new List<FileChange>
        {
            new FileChange
            {
                FilePath = context.Document.FilePath ?? "",
                OriginalCode = originalCode,
                TransformedCode = transformedCode,
                UnifiedDiff = diff,
                StartLine = targetNode.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                EndLine = targetNode.GetLocation().GetLineSpan().EndLinePosition.Line + 1
            }
        });
    }

    private bool IsStringFormatPattern(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not InvocationExpressionSyntax invocation)
            return false;

        if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            if (memberAccess.Name.Identifier.Text == "Format" &&
                memberAccess.Expression.ToString() == "string")
            {
                // Check it has at least format string + 1 argument
                return invocation.ArgumentList.Arguments.Count >= 2;
            }
        }

        return false;
    }

    private bool IsStringConcatenationPattern(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not BinaryExpressionSyntax binary)
            return false;

        if (binary.Kind() != SyntaxKind.AddExpression)
            return false;

        // Check if this is string concatenation
        var typeInfo = semanticModel.GetTypeInfo(binary);
        if (typeInfo.Type?.SpecialType != SpecialType.System_String)
            return false;

        // Look for pattern: "..." + variable or variable + "..."
        return HasMixedStringAndVariable(binary);
    }

    private bool IsToLowerEqualsPattern(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not InvocationExpressionSyntax invocation)
            return false;

        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
            return false;

        var methodName = memberAccess.Name.Identifier.Text;
        if (methodName != "Equals")
            return false;

        // Check if called on ToLower() or ToUpper()
        if (memberAccess.Expression is InvocationExpressionSyntax innerInvocation &&
            innerInvocation.Expression is MemberAccessExpressionSyntax innerMember)
        {
            var innerMethod = innerMember.Name.Identifier.Text;
            return innerMethod is "ToLower" or "ToUpper" or "ToLowerInvariant" or "ToUpperInvariant";
        }

        return false;
    }

    private bool IsEmptyStringComparison(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not BinaryExpressionSyntax binary)
            return false;

        if (binary.Kind() != SyntaxKind.EqualsExpression)
            return false;

        // Check for == "" or == string.Empty
        return IsEmptyString(binary.Left) || IsEmptyString(binary.Right);
    }

    private bool IsEmptyString(ExpressionSyntax expr)
    {
        if (expr is LiteralExpressionSyntax literal &&
            literal.IsKind(SyntaxKind.StringLiteralExpression) &&
            literal.Token.ValueText == "")
        {
            return true;
        }

        if (expr is MemberAccessExpressionSyntax memberAccess &&
            memberAccess.Name.Identifier.Text == "Empty" &&
            memberAccess.Expression.ToString() == "string")
        {
            return true;
        }

        return false;
    }

    private bool HasMixedStringAndVariable(BinaryExpressionSyntax binary)
    {
        var hasLiteral = false;
        var hasVariable = false;

        CheckNode(binary.Left, ref hasLiteral, ref hasVariable);
        CheckNode(binary.Right, ref hasLiteral, ref hasVariable);

        return hasLiteral && hasVariable;
    }

    private void CheckNode(ExpressionSyntax expr, ref bool hasLiteral, ref bool hasVariable)
    {
        if (expr is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression))
        {
            hasLiteral = true;
        }
        else if (expr is IdentifierNameSyntax || expr is MemberAccessExpressionSyntax ||
                 expr is InvocationExpressionSyntax)
        {
            hasVariable = true;
        }
        else if (expr is BinaryExpressionSyntax innerBinary)
        {
            CheckNode(innerBinary.Left, ref hasLiteral, ref hasVariable);
            CheckNode(innerBinary.Right, ref hasLiteral, ref hasVariable);
        }
    }

    private string? TransformStringFormat(InvocationExpressionSyntax? invocation)
    {
        if (invocation == null)
            return null;

        var args = invocation.ArgumentList.Arguments;
        if (args.Count < 2)
            return null;

        var formatArg = args[0].Expression;
        if (formatArg is not LiteralExpressionSyntax formatLiteral)
            return null;

        var formatString = formatLiteral.Token.ValueText;
        var arguments = args.Skip(1).Select(a => a.Expression.ToFullString().Trim()).ToList();

        // Replace {0}, {1}, etc. with actual expressions
        var result = formatString;
        for (int i = 0; i < arguments.Count; i++)
        {
            result = result.Replace($"{{{i}}}", $"{{{arguments[i]}}}");
        }

        return $"$\"{result}\"";
    }

    private string? TransformConcatenation(BinaryExpressionSyntax? binary)
    {
        if (binary == null)
            return null;

        var parts = new List<string>();
        CollectConcatenationParts(binary, parts);

        // Build interpolated string
        var builder = new System.Text.StringBuilder("$\"");
        foreach (var part in parts)
        {
            if (part.StartsWith("\"") && part.EndsWith("\""))
            {
                // String literal - remove quotes and add directly
                builder.Append(part.Substring(1, part.Length - 2));
            }
            else
            {
                // Expression - wrap in braces
                builder.Append('{');
                builder.Append(part);
                builder.Append('}');
            }
        }
        builder.Append('"');

        return builder.ToString();
    }

    private void CollectConcatenationParts(ExpressionSyntax expr, List<string> parts)
    {
        if (expr is BinaryExpressionSyntax binary && binary.Kind() == SyntaxKind.AddExpression)
        {
            CollectConcatenationParts(binary.Left, parts);
            CollectConcatenationParts(binary.Right, parts);
        }
        else
        {
            parts.Add(expr.ToFullString().Trim());
        }
    }

    private string? TransformToLowerEquals(InvocationExpressionSyntax? invocation)
    {
        if (invocation == null)
            return null;

        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
            return null;

        if (memberAccess.Expression is not InvocationExpressionSyntax toLowerInvocation)
            return null;

        if (toLowerInvocation.Expression is not MemberAccessExpressionSyntax toLowerMember)
            return null;

        var source = toLowerMember.Expression.ToFullString().Trim();
        var compareValue = invocation.ArgumentList.Arguments.Count > 0
            ? invocation.ArgumentList.Arguments[0].ToFullString().Trim()
            : "\"\"";

        // Remove .ToLower() from compare value if present
        if (compareValue.EndsWith(".ToLower()") || compareValue.EndsWith(".ToUpper()"))
        {
            compareValue = compareValue.Substring(0, compareValue.LastIndexOf('.'));
        }
        if (compareValue.EndsWith(".ToLowerInvariant()") || compareValue.EndsWith(".ToUpperInvariant()"))
        {
            compareValue = compareValue.Substring(0, compareValue.LastIndexOf('.'));
        }

        return $"string.Equals({source}, {compareValue}, StringComparison.OrdinalIgnoreCase)";
    }

    private string? TransformEmptyStringComparison(BinaryExpressionSyntax? binary)
    {
        if (binary == null)
            return null;

        var variable = IsEmptyString(binary.Left) ? binary.Right : binary.Left;
        return $"string.IsNullOrEmpty({variable.ToFullString().Trim()})";
    }
}
