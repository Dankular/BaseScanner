using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Transformers.Core;

namespace BaseScanner.Transformers.Optimizations;

/// <summary>
/// Transforms collection operations for better performance.
/// </summary>
public class CollectionTransformer : ICodeTransformer
{
    public string TransformationType => "CollectionOptimization";

    public bool CanTransform(SyntaxNode node, SemanticModel semanticModel)
    {
        return IsListWithoutCapacity(node, semanticModel) ||
               IsDictionaryWithoutCapacity(node, semanticModel) ||
               IsListForContainsCheck(node, semanticModel) ||
               IsArrayCopyPattern(node, semanticModel) ||
               IsForEachToFor(node, semanticModel);
    }

    public async Task<TransformationResult> TransformAsync(TransformationContext context, SyntaxNode targetNode)
    {
        string? transformedCode = null;
        string? description = null;

        if (IsListWithoutCapacity(targetNode, context.SemanticModel))
        {
            transformedCode = TransformListWithCapacity(targetNode as ObjectCreationExpressionSyntax, context.SemanticModel);
            description = "Add List capacity hint";
        }
        else if (IsDictionaryWithoutCapacity(targetNode, context.SemanticModel))
        {
            transformedCode = TransformDictionaryWithCapacity(targetNode as ObjectCreationExpressionSyntax, context.SemanticModel);
            description = "Add Dictionary capacity hint";
        }
        else if (IsListForContainsCheck(targetNode, context.SemanticModel))
        {
            transformedCode = TransformListToHashSet(targetNode as ObjectCreationExpressionSyntax, context.SemanticModel);
            description = "List to HashSet for contains checks";
        }
        else if (IsArrayCopyPattern(targetNode, context.SemanticModel))
        {
            transformedCode = TransformArrayCopy(targetNode as ForStatementSyntax);
            description = "For loop copy to Array.Copy/Span";
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

    private bool IsListWithoutCapacity(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not ObjectCreationExpressionSyntax creation)
            return false;

        var typeInfo = semanticModel.GetTypeInfo(creation);
        var typeName = typeInfo.Type?.ToDisplayString() ?? "";

        if (!typeName.StartsWith("System.Collections.Generic.List<"))
            return false;

        // Check if it has no constructor arguments (no capacity)
        if (creation.ArgumentList?.Arguments.Count > 0)
            return false;

        // Check if there's a collection initializer and it's reasonably sized
        if (creation.Initializer == null)
            return false;

        var elementCount = creation.Initializer.Expressions.Count;
        return elementCount >= 4; // Only suggest capacity for lists with 4+ initial elements
    }

    private bool IsDictionaryWithoutCapacity(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not ObjectCreationExpressionSyntax creation)
            return false;

        var typeInfo = semanticModel.GetTypeInfo(creation);
        var typeName = typeInfo.Type?.ToDisplayString() ?? "";

        if (!typeName.StartsWith("System.Collections.Generic.Dictionary<"))
            return false;

        // Check if it has no constructor arguments (no capacity)
        if (creation.ArgumentList?.Arguments.Count > 0)
            return false;

        // Check if there's a collection initializer
        if (creation.Initializer == null)
            return false;

        var elementCount = creation.Initializer.Expressions.Count;
        return elementCount >= 4; // Only suggest capacity for dictionaries with 4+ initial elements
    }

    private bool IsListForContainsCheck(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not ObjectCreationExpressionSyntax creation)
            return false;

        var typeInfo = semanticModel.GetTypeInfo(creation);
        var typeName = typeInfo.Type?.ToDisplayString() ?? "";

        if (!typeName.StartsWith("System.Collections.Generic.List<"))
            return false;

        // Check if the list is only used for Contains operations
        var variableDecl = creation.Ancestors().OfType<VariableDeclaratorSyntax>().FirstOrDefault();
        if (variableDecl == null)
            return false;

        var method = creation.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
        if (method == null)
            return false;

        var varName = variableDecl.Identifier.Text;

        // Look for .Contains() calls on this variable
        var containsCalls = method.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(inv =>
            {
                if (inv.Expression is MemberAccessExpressionSyntax ma &&
                    ma.Name.Identifier.Text == "Contains" &&
                    ma.Expression is IdentifierNameSyntax id &&
                    id.Identifier.Text == varName)
                {
                    return true;
                }
                return false;
            })
            .ToList();

        // Look for other usage (Add, Remove, index access, etc.)
        var otherUsages = method.DescendantNodes()
            .OfType<IdentifierNameSyntax>()
            .Where(id => id.Identifier.Text == varName)
            .Where(id =>
            {
                var parent = id.Parent;
                if (parent is MemberAccessExpressionSyntax ma)
                {
                    var methodName = ma.Name.Identifier.Text;
                    return methodName != "Contains";
                }
                if (parent is ArgumentSyntax)
                    return true;
                if (parent is ElementAccessExpressionSyntax)
                    return true;
                return false;
            })
            .ToList();

        // Suggest HashSet if primarily used for Contains and has enough elements
        var initializerCount = creation.Initializer?.Expressions.Count ?? 0;
        return containsCalls.Count > 0 && otherUsages.Count == 0 && initializerCount >= 3;
    }

    private bool IsArrayCopyPattern(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not ForStatementSyntax forStmt)
            return false;

        // Check if the body is a single array element copy: dest[i] = src[i]
        var body = GetSingleStatement(forStmt.Statement);
        if (body is not ExpressionStatementSyntax exprStmt)
            return false;

        if (exprStmt.Expression is not AssignmentExpressionSyntax assignment)
            return false;

        if (assignment.Left is not ElementAccessExpressionSyntax leftAccess)
            return false;

        if (assignment.Right is not ElementAccessExpressionSyntax rightAccess)
            return false;

        // Both should use the loop variable
        var loopVar = GetLoopVariable(forStmt);
        if (loopVar == null)
            return false;

        var leftIndex = leftAccess.ArgumentList.Arguments[0].ToString();
        var rightIndex = rightAccess.ArgumentList.Arguments[0].ToString();

        return leftIndex == loopVar && rightIndex == loopVar;
    }

    private bool IsForEachToFor(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not ForEachStatementSyntax forEachStmt)
            return false;

        // Check if iterating over array/list and using indexer access would be better
        var typeInfo = semanticModel.GetTypeInfo(forEachStmt.Expression);
        var typeName = typeInfo.Type?.ToDisplayString() ?? "";

        // Only for arrays and lists where index access is needed
        if (!typeName.EndsWith("[]") && !typeName.StartsWith("System.Collections.Generic.List<"))
            return false;

        // Check if body uses index (we'd need to track index manually in foreach)
        var body = forEachStmt.Statement;
        var varName = forEachStmt.Identifier.Text;

        // Look for patterns that would benefit from index
        // This is a simple heuristic - could be expanded
        return false; // Disabled for now - needs more sophisticated analysis
    }

    private StatementSyntax? GetSingleStatement(StatementSyntax statement)
    {
        if (statement is BlockSyntax block && block.Statements.Count == 1)
            return block.Statements[0];
        return statement;
    }

    private string? GetLoopVariable(ForStatementSyntax forStmt)
    {
        if (forStmt.Declaration?.Variables.Count == 1)
        {
            return forStmt.Declaration.Variables[0].Identifier.Text;
        }
        return null;
    }

    private string? TransformListWithCapacity(ObjectCreationExpressionSyntax? creation, SemanticModel semanticModel)
    {
        if (creation?.Initializer == null)
            return null;

        var typeInfo = semanticModel.GetTypeInfo(creation);
        var typeName = typeInfo.Type?.ToDisplayString() ?? "";

        // Extract generic type parameter
        var startIndex = typeName.IndexOf('<');
        var endIndex = typeName.LastIndexOf('>');
        if (startIndex < 0 || endIndex < 0)
            return null;

        var elementType = typeName.Substring(startIndex + 1, endIndex - startIndex - 1);
        var count = creation.Initializer.Expressions.Count;

        var elements = string.Join(", ", creation.Initializer.Expressions.Select(e => e.ToFullString().Trim()));
        return $"new List<{elementType}>({count}) {{ {elements} }}";
    }

    private string? TransformDictionaryWithCapacity(ObjectCreationExpressionSyntax? creation, SemanticModel semanticModel)
    {
        if (creation?.Initializer == null)
            return null;

        var typeInfo = semanticModel.GetTypeInfo(creation);
        var typeName = typeInfo.Type?.ToDisplayString() ?? "";

        // Extract generic type parameters
        var startIndex = typeName.IndexOf('<');
        var endIndex = typeName.LastIndexOf('>');
        if (startIndex < 0 || endIndex < 0)
            return null;

        var typeParams = typeName.Substring(startIndex + 1, endIndex - startIndex - 1);
        var count = creation.Initializer.Expressions.Count;

        var elements = string.Join(", ", creation.Initializer.Expressions.Select(e => e.ToFullString().Trim()));
        return $"new Dictionary<{typeParams}>({count}) {{ {elements} }}";
    }

    private string? TransformListToHashSet(ObjectCreationExpressionSyntax? creation, SemanticModel semanticModel)
    {
        if (creation?.Initializer == null)
            return null;

        var typeInfo = semanticModel.GetTypeInfo(creation);
        var typeName = typeInfo.Type?.ToDisplayString() ?? "";

        // Extract generic type parameter
        var startIndex = typeName.IndexOf('<');
        var endIndex = typeName.LastIndexOf('>');
        if (startIndex < 0 || endIndex < 0)
            return null;

        var elementType = typeName.Substring(startIndex + 1, endIndex - startIndex - 1);
        var elements = string.Join(", ", creation.Initializer.Expressions.Select(e => e.ToFullString().Trim()));

        return $"new HashSet<{elementType}> {{ {elements} }}";
    }

    private string? TransformArrayCopy(ForStatementSyntax? forStmt)
    {
        if (forStmt == null)
            return null;

        var body = GetSingleStatement(forStmt.Statement);
        if (body is not ExpressionStatementSyntax exprStmt)
            return null;

        if (exprStmt.Expression is not AssignmentExpressionSyntax assignment)
            return null;

        if (assignment.Left is not ElementAccessExpressionSyntax leftAccess)
            return null;

        if (assignment.Right is not ElementAccessExpressionSyntax rightAccess)
            return null;

        var destArray = leftAccess.Expression.ToFullString().Trim();
        var srcArray = rightAccess.Expression.ToFullString().Trim();

        // Get the length from the condition
        var condition = forStmt.Condition;
        if (condition is BinaryExpressionSyntax binary)
        {
            string length;
            if (binary.Right is MemberAccessExpressionSyntax ma && ma.Name.Identifier.Text == "Length")
            {
                length = binary.Right.ToFullString().Trim();
            }
            else
            {
                length = binary.Right.ToFullString().Trim();
            }

            return $"Array.Copy({srcArray}, {destArray}, {length});";
        }

        return null;
    }
}
