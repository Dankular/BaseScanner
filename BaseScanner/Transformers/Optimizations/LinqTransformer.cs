using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Transformers.Core;

namespace BaseScanner.Transformers.Optimizations;

/// <summary>
/// Transforms LINQ patterns for better performance.
/// </summary>
public class LinqTransformer : ICodeTransformer
{
    public string TransformationType => "LinqOptimization";

    public bool CanTransform(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not InvocationExpressionSyntax invocation)
            return false;

        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
            return false;

        var methodName = memberAccess.Name.Identifier.Text;

        // Check for patterns we can transform
        return IsCountEqualsZeroPattern(invocation, memberAccess, methodName) ||
               IsCountGreaterThanZeroPattern(invocation, memberAccess, methodName) ||
               IsWhereFollowedByFirstPattern(invocation, memberAccess, methodName) ||
               IsWhereFollowedByCountPattern(invocation, memberAccess, methodName) ||
               IsOrderByFollowedByFirstPattern(invocation, memberAccess, methodName) ||
               IsToListInForeachPattern(invocation, memberAccess, methodName);
    }

    public async Task<TransformationResult> TransformAsync(TransformationContext context, SyntaxNode targetNode)
    {
        if (targetNode is not InvocationExpressionSyntax invocation)
            return TransformationResult.Failed(TransformationType, "Target is not an invocation expression");

        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
            return TransformationResult.Failed(TransformationType, "Invalid member access");

        var methodName = memberAccess.Name.Identifier.Text;
        string? transformedCode = null;
        string? description = null;

        if (IsCountEqualsZeroPattern(invocation, memberAccess, methodName))
        {
            var source = GetSourceExpression(invocation);
            transformedCode = $"!{source}.Any()";
            description = "Count() == 0 to !Any()";
        }
        else if (IsCountGreaterThanZeroPattern(invocation, memberAccess, methodName))
        {
            var source = GetSourceExpression(invocation);
            transformedCode = $"{source}.Any()";
            description = "Count() > 0 to Any()";
        }
        else if (IsWhereFollowedByFirstPattern(invocation, memberAccess, methodName))
        {
            transformedCode = TransformWhereFirst(invocation, memberAccess);
            description = "Where().First() to First()";
        }
        else if (IsWhereFollowedByCountPattern(invocation, memberAccess, methodName))
        {
            transformedCode = TransformWhereCount(invocation, memberAccess);
            description = "Where().Count() to Count()";
        }
        else if (IsOrderByFollowedByFirstPattern(invocation, memberAccess, methodName))
        {
            transformedCode = TransformOrderByFirst(invocation, memberAccess);
            description = "OrderBy().First() to MinBy()/MaxBy()";
        }

        if (transformedCode == null)
            return TransformationResult.Failed(TransformationType, "Could not determine transformation");

        var originalCode = invocation.ToFullString().Trim();
        var diff = DiffGenerator.GenerateUnifiedDiff(originalCode, transformedCode, context.Document.FilePath ?? "");

        return TransformationResult.Succeeded(TransformationType, new List<FileChange>
        {
            new FileChange
            {
                FilePath = context.Document.FilePath ?? "",
                OriginalCode = originalCode,
                TransformedCode = transformedCode,
                UnifiedDiff = diff,
                StartLine = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                EndLine = invocation.GetLocation().GetLineSpan().EndLinePosition.Line + 1
            }
        });
    }

    private bool IsCountEqualsZeroPattern(InvocationExpressionSyntax invocation, MemberAccessExpressionSyntax memberAccess, string methodName)
    {
        if (methodName != "Count")
            return false;

        // Check if parent is == 0
        if (invocation.Parent is BinaryExpressionSyntax binary &&
            binary.Kind() == SyntaxKind.EqualsExpression)
        {
            var otherSide = binary.Left == invocation ? binary.Right : binary.Left;
            if (otherSide is LiteralExpressionSyntax literal &&
                literal.Token.Value is int value && value == 0)
            {
                return true;
            }
        }

        return false;
    }

    private bool IsCountGreaterThanZeroPattern(InvocationExpressionSyntax invocation, MemberAccessExpressionSyntax memberAccess, string methodName)
    {
        if (methodName != "Count")
            return false;

        // Check if parent is > 0
        if (invocation.Parent is BinaryExpressionSyntax binary &&
            binary.Kind() == SyntaxKind.GreaterThanExpression)
        {
            if (binary.Left == invocation &&
                binary.Right is LiteralExpressionSyntax literal &&
                literal.Token.Value is int value && value == 0)
            {
                return true;
            }
        }

        return false;
    }

    private bool IsWhereFollowedByFirstPattern(InvocationExpressionSyntax invocation, MemberAccessExpressionSyntax memberAccess, string methodName)
    {
        if (methodName is not ("First" or "FirstOrDefault" or "Single" or "SingleOrDefault"))
            return false;

        // Check if no predicate in First/FirstOrDefault
        if (invocation.ArgumentList.Arguments.Count > 0)
            return false;

        // Check if called on a Where()
        if (memberAccess.Expression is InvocationExpressionSyntax innerInvocation &&
            innerInvocation.Expression is MemberAccessExpressionSyntax innerMember &&
            innerMember.Name.Identifier.Text == "Where")
        {
            return true;
        }

        return false;
    }

    private bool IsWhereFollowedByCountPattern(InvocationExpressionSyntax invocation, MemberAccessExpressionSyntax memberAccess, string methodName)
    {
        if (methodName != "Count")
            return false;

        // Check if no predicate in Count
        if (invocation.ArgumentList.Arguments.Count > 0)
            return false;

        // Check if called on a Where()
        if (memberAccess.Expression is InvocationExpressionSyntax innerInvocation &&
            innerInvocation.Expression is MemberAccessExpressionSyntax innerMember &&
            innerMember.Name.Identifier.Text == "Where")
        {
            return true;
        }

        return false;
    }

    private bool IsOrderByFollowedByFirstPattern(InvocationExpressionSyntax invocation, MemberAccessExpressionSyntax memberAccess, string methodName)
    {
        if (methodName is not ("First" or "FirstOrDefault"))
            return false;

        // Check if no predicate in First
        if (invocation.ArgumentList.Arguments.Count > 0)
            return false;

        // Check if called on OrderBy/OrderByDescending
        if (memberAccess.Expression is InvocationExpressionSyntax innerInvocation &&
            innerInvocation.Expression is MemberAccessExpressionSyntax innerMember &&
            innerMember.Name.Identifier.Text is "OrderBy" or "OrderByDescending")
        {
            return true;
        }

        return false;
    }

    private bool IsToListInForeachPattern(InvocationExpressionSyntax invocation, MemberAccessExpressionSyntax memberAccess, string methodName)
    {
        if (methodName is not ("ToList" or "ToArray"))
            return false;

        // Check if used directly in foreach
        if (invocation.Parent is ForEachStatementSyntax)
            return true;

        return false;
    }

    private string GetSourceExpression(InvocationExpressionSyntax invocation)
    {
        if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            return memberAccess.Expression.ToFullString().Trim();
        }
        return invocation.Expression.ToFullString().Trim();
    }

    private string? TransformWhereFirst(InvocationExpressionSyntax invocation, MemberAccessExpressionSyntax memberAccess)
    {
        // Get the Where invocation
        if (memberAccess.Expression is not InvocationExpressionSyntax whereInvocation)
            return null;

        if (whereInvocation.Expression is not MemberAccessExpressionSyntax whereMember)
            return null;

        var source = whereMember.Expression.ToFullString().Trim();
        var predicate = whereInvocation.ArgumentList.Arguments[0].ToFullString().Trim();
        var methodName = memberAccess.Name.Identifier.Text;

        return $"{source}.{methodName}({predicate})";
    }

    private string? TransformWhereCount(InvocationExpressionSyntax invocation, MemberAccessExpressionSyntax memberAccess)
    {
        // Get the Where invocation
        if (memberAccess.Expression is not InvocationExpressionSyntax whereInvocation)
            return null;

        if (whereInvocation.Expression is not MemberAccessExpressionSyntax whereMember)
            return null;

        var source = whereMember.Expression.ToFullString().Trim();
        var predicate = whereInvocation.ArgumentList.Arguments[0].ToFullString().Trim();

        return $"{source}.Count({predicate})";
    }

    private string? TransformOrderByFirst(InvocationExpressionSyntax invocation, MemberAccessExpressionSyntax memberAccess)
    {
        // Get the OrderBy invocation
        if (memberAccess.Expression is not InvocationExpressionSyntax orderByInvocation)
            return null;

        if (orderByInvocation.Expression is not MemberAccessExpressionSyntax orderByMember)
            return null;

        var source = orderByMember.Expression.ToFullString().Trim();
        var selector = orderByInvocation.ArgumentList.Arguments[0].ToFullString().Trim();
        var isDescending = orderByMember.Name.Identifier.Text == "OrderByDescending";
        var methodName = memberAccess.Name.Identifier.Text;
        var suffix = methodName.EndsWith("OrDefault") ? "OrDefault" : "";

        // Use MinBy for ascending, MaxBy for descending
        var newMethod = isDescending ? "MaxBy" : "MinBy";

        return $"{source}.{newMethod}{suffix}({selector})";
    }
}
