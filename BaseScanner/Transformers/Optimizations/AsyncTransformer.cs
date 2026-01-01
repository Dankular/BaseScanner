using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Transformers.Core;

namespace BaseScanner.Transformers.Optimizations;

/// <summary>
/// Transforms async patterns for correctness and best practices.
/// </summary>
public class AsyncTransformer : ICodeTransformer
{
    public string TransformationType => "AsyncOptimization";

    public bool CanTransform(SyntaxNode node, SemanticModel semanticModel)
    {
        return IsAsyncVoidMethod(node, semanticModel) ||
               IsBlockingCall(node, semanticModel) ||
               IsUnnecessaryAsyncAwait(node, semanticModel) ||
               IsMissingConfigureAwait(node, semanticModel);
    }

    public async Task<TransformationResult> TransformAsync(TransformationContext context, SyntaxNode targetNode)
    {
        string? transformedCode = null;
        string? description = null;

        if (IsAsyncVoidMethod(targetNode, context.SemanticModel))
        {
            transformedCode = TransformAsyncVoid(targetNode as MethodDeclarationSyntax);
            description = "async void to async Task";
        }
        else if (IsBlockingCall(targetNode, context.SemanticModel))
        {
            transformedCode = TransformBlockingCall(targetNode as MemberAccessExpressionSyntax);
            description = "Blocking .Result/.Wait() to await";
        }
        else if (IsUnnecessaryAsyncAwait(targetNode, context.SemanticModel))
        {
            transformedCode = TransformUnnecessaryAsyncAwait(targetNode as MethodDeclarationSyntax);
            description = "Remove unnecessary async/await";
        }
        else if (IsMissingConfigureAwait(targetNode, context.SemanticModel))
        {
            transformedCode = TransformMissingConfigureAwait(targetNode as AwaitExpressionSyntax);
            description = "Add ConfigureAwait(false)";
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

    private bool IsAsyncVoidMethod(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not MethodDeclarationSyntax method)
            return false;

        // Check if method is async
        if (!method.Modifiers.Any(SyntaxKind.AsyncKeyword))
            return false;

        // Check if return type is void
        if (method.ReturnType is not PredefinedTypeSyntax predefined)
            return false;

        if (!predefined.Keyword.IsKind(SyntaxKind.VoidKeyword))
            return false;

        // Skip event handlers (they're allowed to be async void)
        if (IsEventHandler(method, semanticModel))
            return false;

        return true;
    }

    private bool IsEventHandler(MethodDeclarationSyntax method, SemanticModel semanticModel)
    {
        // Check if it matches event handler pattern: (object sender, EventArgs e)
        if (method.ParameterList.Parameters.Count != 2)
            return false;

        var firstParam = method.ParameterList.Parameters[0];
        var secondParam = method.ParameterList.Parameters[1];

        var firstType = firstParam.Type?.ToString() ?? "";
        var secondType = secondParam.Type?.ToString() ?? "";

        return (firstType == "object" || firstType == "object?") &&
               (secondType.Contains("EventArgs") || secondType == "EventArgs");
    }

    private bool IsBlockingCall(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not MemberAccessExpressionSyntax memberAccess)
            return false;

        var name = memberAccess.Name.Identifier.Text;

        // Check for .Result or .Wait() on Task
        if (name == "Result")
        {
            var typeInfo = semanticModel.GetTypeInfo(memberAccess.Expression);
            var typeName = typeInfo.Type?.ToDisplayString() ?? "";
            return typeName.StartsWith("System.Threading.Tasks.Task");
        }

        // Check parent for Wait() invocation
        if (name == "Wait" && node.Parent is InvocationExpressionSyntax invocation)
        {
            var typeInfo = semanticModel.GetTypeInfo(memberAccess.Expression);
            var typeName = typeInfo.Type?.ToDisplayString() ?? "";
            return typeName.StartsWith("System.Threading.Tasks.Task");
        }

        return false;
    }

    private bool IsUnnecessaryAsyncAwait(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not MethodDeclarationSyntax method)
            return false;

        // Must be async
        if (!method.Modifiers.Any(SyntaxKind.AsyncKeyword))
            return false;

        // Check if body is just a single return await statement
        if (method.Body != null)
        {
            var statements = method.Body.Statements;
            if (statements.Count == 1 &&
                statements[0] is ReturnStatementSyntax returnStmt &&
                returnStmt.Expression is AwaitExpressionSyntax)
            {
                return true;
            }
        }
        else if (method.ExpressionBody != null)
        {
            // Expression body: async Task Foo() => await something;
            if (method.ExpressionBody.Expression is AwaitExpressionSyntax)
            {
                return true;
            }
        }

        return false;
    }

    private bool IsMissingConfigureAwait(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not AwaitExpressionSyntax awaitExpr)
            return false;

        // Check if already has ConfigureAwait
        var awaitedExpr = awaitExpr.Expression;
        if (awaitedExpr is InvocationExpressionSyntax invocation &&
            invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
            memberAccess.Name.Identifier.Text == "ConfigureAwait")
        {
            return false; // Already has ConfigureAwait
        }

        // Check if we're in a library context (not UI code)
        var containingType = awaitExpr.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
        if (containingType != null)
        {
            var className = containingType.Identifier.Text;
            // Skip if it looks like UI code
            if (className.EndsWith("Controller") ||
                className.EndsWith("Page") ||
                className.EndsWith("Form") ||
                className.EndsWith("Window") ||
                className.EndsWith("View"))
            {
                return false;
            }
        }

        return true;
    }

    private string? TransformAsyncVoid(MethodDeclarationSyntax? method)
    {
        if (method == null)
            return null;

        // Replace void with Task in the method signature
        var newMethod = method.WithReturnType(
            SyntaxFactory.IdentifierName("Task")
                .WithLeadingTrivia(method.ReturnType.GetLeadingTrivia())
                .WithTrailingTrivia(method.ReturnType.GetTrailingTrivia()));

        return newMethod.ToFullString().Trim();
    }

    private string? TransformBlockingCall(MemberAccessExpressionSyntax? memberAccess)
    {
        if (memberAccess == null)
            return null;

        var name = memberAccess.Name.Identifier.Text;
        var expression = memberAccess.Expression.ToFullString().Trim();

        if (name == "Result")
        {
            return $"await {expression}";
        }
        else if (name == "Wait")
        {
            return $"await {expression}";
        }

        return null;
    }

    private string? TransformUnnecessaryAsyncAwait(MethodDeclarationSyntax? method)
    {
        if (method == null)
            return null;

        ExpressionSyntax? awaitedExpression = null;

        if (method.Body != null && method.Body.Statements.Count == 1)
        {
            if (method.Body.Statements[0] is ReturnStatementSyntax returnStmt &&
                returnStmt.Expression is AwaitExpressionSyntax awaitExpr)
            {
                awaitedExpression = awaitExpr.Expression;
            }
        }
        else if (method.ExpressionBody?.Expression is AwaitExpressionSyntax exprAwait)
        {
            awaitedExpression = exprAwait.Expression;
        }

        if (awaitedExpression == null)
            return null;

        // Remove async modifier
        var newModifiers = SyntaxFactory.TokenList(
            method.Modifiers.Where(m => !m.IsKind(SyntaxKind.AsyncKeyword)));

        // Create new method that just returns the task
        if (method.Body != null)
        {
            var newBody = SyntaxFactory.Block(
                SyntaxFactory.ReturnStatement(awaitedExpression));

            return method
                .WithModifiers(newModifiers)
                .WithBody(newBody)
                .ToFullString().Trim();
        }
        else if (method.ExpressionBody != null)
        {
            return method
                .WithModifiers(newModifiers)
                .WithExpressionBody(SyntaxFactory.ArrowExpressionClause(awaitedExpression))
                .ToFullString().Trim();
        }

        return null;
    }

    private string? TransformMissingConfigureAwait(AwaitExpressionSyntax? awaitExpr)
    {
        if (awaitExpr == null)
            return null;

        var expression = awaitExpr.Expression.ToFullString().Trim();
        return $"await {expression}.ConfigureAwait(false)";
    }
}
