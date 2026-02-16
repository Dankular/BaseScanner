using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Concurrency.Models;

namespace BaseScanner.Analyzers.Concurrency.Detectors;

/// <summary>
/// Detects async reentrancy issues including:
/// - Async void event handlers that modify shared state
/// - Task.Result/.Wait() blocking in async context (deadlock risk)
/// - Reentrancy in async methods without proper synchronization
/// </summary>
public class AsyncReentrancyDetector : IThreadSafetyDetector
{
    public string Name => "AsyncReentrancy";

    public string Description => "Detects async void event handler issues and blocking async calls";

    public IReadOnlyList<string> SupportedRules =>
    [
        ThreadSafetyRules.AsyncVoidReentrancy,
        ThreadSafetyRules.TaskResultBlocking
    ];

    public Task<List<ThreadSafetyIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        ThreadSafetyAnalysisContext? context = null)
    {
        var issues = new List<ThreadSafetyIssue>();

        issues.AddRange(DetectAsyncVoidWithSharedState(root, semanticModel, document.FilePath ?? ""));
        issues.AddRange(DetectTaskResultBlocking(root, semanticModel, document.FilePath ?? ""));
        issues.AddRange(DetectAsyncLambdaWithSharedState(root, semanticModel, document.FilePath ?? ""));

        return Task.FromResult(issues);
    }

    private IEnumerable<ThreadSafetyIssue> DetectAsyncVoidWithSharedState(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<ThreadSafetyIssue>();

        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            // Check if async void
            if (!method.Modifiers.Any(SyntaxKind.AsyncKeyword)) continue;
            if (method.ReturnType is not PredefinedTypeSyntax pts) continue;
            if (!pts.Keyword.IsKind(SyntaxKind.VoidKeyword)) continue;

            // Check if it's an event handler pattern
            if (!IsEventHandlerPattern(method)) continue;

            var body = (SyntaxNode?)method.Body ?? method.ExpressionBody;
            if (body == null) continue;

            // Find shared state modifications
            var sharedStateModifications = FindSharedStateModifications(body, semanticModel);

            if (sharedStateModifications.Count > 0)
            {
                var location = method.GetLocation().GetLineSpan();
                var classDecl = method.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();

                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "AsyncVoidReentrancy",
                    RuleId = ThreadSafetyRules.AsyncVoidReentrancy,
                    Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.AsyncVoidReentrancy),
                    Message = $"Async void event handler '{method.Identifier.Text}' modifies shared state - may cause reentrancy issues",
                    FilePath = filePath,
                    Line = location.StartLinePosition.Line + 1,
                    EndLine = location.EndLinePosition.Line + 1,
                    Column = location.StartLinePosition.Character + 1,
                    ClassName = classDecl?.Identifier.Text,
                    MethodName = method.Identifier.Text,
                    CodeSnippet = $"async void {method.Identifier.Text}({GetParametersSummary(method)})",
                    SuggestedFix = "Use SemaphoreSlim to prevent reentrancy, or debounce the event handler",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.AsyncVoidReentrancy),
                    Metadata = new Dictionary<string, object>
                    {
                        ["ModifiedFields"] = sharedStateModifications,
                        ["IsEventHandler"] = true
                    }
                });
            }

            // Check for unawaited tasks in async void (fire-and-forget that swallows exceptions)
            var floatingTasks = FindFloatingTasks(body, semanticModel);
            if (floatingTasks.Count > 0)
            {
                var location = method.GetLocation().GetLineSpan();
                var classDecl = method.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();

                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "AsyncVoidReentrancy",
                    RuleId = ThreadSafetyRules.AsyncVoidReentrancy,
                    Severity = "High",
                    Message = $"Async void method '{method.Identifier.Text}' has unawaited tasks - exceptions will be lost",
                    FilePath = filePath,
                    Line = location.StartLinePosition.Line + 1,
                    EndLine = location.EndLinePosition.Line + 1,
                    ClassName = classDecl?.Identifier.Text,
                    MethodName = method.Identifier.Text,
                    CodeSnippet = $"async void {method.Identifier.Text}(...)",
                    SuggestedFix = "Await all tasks or add try-catch to handle exceptions",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.AsyncVoidReentrancy),
                    Metadata = new Dictionary<string, object>
                    {
                        ["FloatingTasks"] = floatingTasks.Count
                    }
                });
            }
        }

        return issues;
    }

    private IEnumerable<ThreadSafetyIssue> DetectTaskResultBlocking(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<ThreadSafetyIssue>();

        foreach (var memberAccess in root.DescendantNodes().OfType<MemberAccessExpressionSyntax>())
        {
            var memberName = memberAccess.Name.Identifier.Text;

            // Check for .Result
            if (memberName == "Result")
            {
                var typeInfo = semanticModel.GetTypeInfo(memberAccess.Expression);
                if (!IsTaskType(typeInfo.Type)) continue;

                // Check if we're inside an async context
                var isInAsyncContext = IsInAsyncContext(memberAccess);

                // Also check if we're in a synchronization context (UI thread, ASP.NET, etc.)
                var containingMethod = memberAccess.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

                if (isInAsyncContext || IsPotentiallySyncContextBound(containingMethod))
                {
                    var location = memberAccess.GetLocation().GetLineSpan();
                    var classDecl = memberAccess.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();

                    issues.Add(new ThreadSafetyIssue
                    {
                        IssueType = "TaskResultBlocking",
                        RuleId = ThreadSafetyRules.TaskResultBlocking,
                        Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.TaskResultBlocking),
                        Message = ".Result on Task can cause deadlock when called in synchronization context",
                        FilePath = filePath,
                        Line = location.StartLinePosition.Line + 1,
                        EndLine = location.EndLinePosition.Line + 1,
                        Column = location.StartLinePosition.Character + 1,
                        ClassName = classDecl?.Identifier.Text,
                        MethodName = containingMethod?.Identifier.Text,
                        CodeSnippet = memberAccess.ToString(),
                        SuggestedFix = "Use 'await' instead, or ensure ConfigureAwait(false) is used throughout the call chain",
                        CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.TaskResultBlocking)
                    });
                }
            }

            // Check for .Wait()
            if (memberName == "Wait")
            {
                var parent = memberAccess.Parent;
                if (parent is not InvocationExpressionSyntax) continue;

                var typeInfo = semanticModel.GetTypeInfo(memberAccess.Expression);
                if (!IsTaskType(typeInfo.Type)) continue;

                var isInAsyncContext = IsInAsyncContext(memberAccess);
                var containingMethod = memberAccess.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

                if (isInAsyncContext || IsPotentiallySyncContextBound(containingMethod))
                {
                    var location = memberAccess.GetLocation().GetLineSpan();
                    var classDecl = memberAccess.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();

                    issues.Add(new ThreadSafetyIssue
                    {
                        IssueType = "TaskResultBlocking",
                        RuleId = ThreadSafetyRules.TaskResultBlocking,
                        Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.TaskResultBlocking),
                        Message = ".Wait() on Task can cause deadlock when called in synchronization context",
                        FilePath = filePath,
                        Line = location.StartLinePosition.Line + 1,
                        EndLine = location.EndLinePosition.Line + 1,
                        Column = location.StartLinePosition.Character + 1,
                        ClassName = classDecl?.Identifier.Text,
                        MethodName = containingMethod?.Identifier.Text,
                        CodeSnippet = parent?.ToString() ?? memberAccess.ToString(),
                        SuggestedFix = "Use 'await' instead, or ensure ConfigureAwait(false) is used throughout",
                        CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.TaskResultBlocking)
                    });
                }
            }

            // Check for .GetAwaiter().GetResult()
            if (memberName == "GetAwaiter")
            {
                var typeInfo = semanticModel.GetTypeInfo(memberAccess.Expression);
                if (!IsTaskType(typeInfo.Type)) continue;

                // Check if followed by .GetResult()
                if (memberAccess.Parent is InvocationExpressionSyntax getAwaiterCall &&
                    getAwaiterCall.Parent is MemberAccessExpressionSyntax getResultAccess &&
                    getResultAccess.Name.Identifier.Text == "GetResult")
                {
                    var isInAsyncContext = IsInAsyncContext(memberAccess);
                    var containingMethod = memberAccess.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

                    if (isInAsyncContext || IsPotentiallySyncContextBound(containingMethod))
                    {
                        var location = memberAccess.GetLocation().GetLineSpan();
                        var classDecl = memberAccess.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();

                        issues.Add(new ThreadSafetyIssue
                        {
                            IssueType = "TaskResultBlocking",
                            RuleId = ThreadSafetyRules.TaskResultBlocking,
                            Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.TaskResultBlocking),
                            Message = ".GetAwaiter().GetResult() can cause deadlock in synchronization context",
                            FilePath = filePath,
                            Line = location.StartLinePosition.Line + 1,
                            EndLine = location.EndLinePosition.Line + 1,
                            Column = location.StartLinePosition.Character + 1,
                            ClassName = classDecl?.Identifier.Text,
                            MethodName = containingMethod?.Identifier.Text,
                            CodeSnippet = getResultAccess.Parent?.ToString() ?? memberAccess.ToString(),
                            SuggestedFix = "Use 'await' instead",
                            CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.TaskResultBlocking)
                        });
                    }
                }
            }
        }

        return issues;
    }

    private IEnumerable<ThreadSafetyIssue> DetectAsyncLambdaWithSharedState(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<ThreadSafetyIssue>();

        // Check for async lambdas used as event handlers
        foreach (var lambda in root.DescendantNodes().OfType<ParenthesizedLambdaExpressionSyntax>())
        {
            if (!lambda.AsyncKeyword.IsKind(SyntaxKind.AsyncKeyword)) continue;

            // Check if lambda is void (event handler pattern)
            var typeInfo = semanticModel.GetTypeInfo(lambda);
            if (typeInfo.ConvertedType is not INamedTypeSymbol delegateType) continue;

            var invokeMethod = delegateType.DelegateInvokeMethod;
            if (invokeMethod?.ReturnType.SpecialType != SpecialType.System_Void) continue;

            // Check if lambda modifies shared state
            var sharedStateModifications = FindSharedStateModifications(lambda.Body, semanticModel);

            if (sharedStateModifications.Count > 0)
            {
                var location = lambda.GetLocation().GetLineSpan();
                var containingMethod = lambda.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
                var classDecl = lambda.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();

                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "AsyncVoidReentrancy",
                    RuleId = ThreadSafetyRules.AsyncVoidReentrancy,
                    Severity = "Medium",
                    Message = "Async void lambda modifies shared state - may cause reentrancy issues",
                    FilePath = filePath,
                    Line = location.StartLinePosition.Line + 1,
                    EndLine = location.EndLinePosition.Line + 1,
                    ClassName = classDecl?.Identifier.Text,
                    MethodName = containingMethod?.Identifier.Text,
                    CodeSnippet = GetLambdaSnippet(lambda),
                    SuggestedFix = "Use SemaphoreSlim to prevent reentrancy, or track in-flight operations",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.AsyncVoidReentrancy),
                    Metadata = new Dictionary<string, object>
                    {
                        ["ModifiedFields"] = sharedStateModifications,
                        ["DelegateType"] = delegateType.ToDisplayString()
                    }
                });
            }
        }

        return issues;
    }

    private bool IsEventHandlerPattern(MethodDeclarationSyntax method)
    {
        var parameters = method.ParameterList.Parameters;
        if (parameters.Count != 2) return false;

        var firstParam = parameters[0].Type?.ToString() ?? "";
        var secondParam = parameters[1].Type?.ToString() ?? "";

        // Standard event handler pattern
        if ((firstParam == "object" || firstParam == "object?") &&
            secondParam.EndsWith("EventArgs"))
        {
            return true;
        }

        // Also check method name patterns
        var methodName = method.Identifier.Text;
        if (methodName.StartsWith("On") || methodName.Contains("_") ||
            methodName.EndsWith("Handler") || methodName.EndsWith("Clicked") ||
            methodName.EndsWith("Changed") || methodName.EndsWith("Loaded"))
        {
            return true;
        }

        return false;
    }

    private List<string> FindSharedStateModifications(SyntaxNode? body, SemanticModel semanticModel)
    {
        var modifications = new List<string>();
        if (body == null) return modifications;

        // Find assignments to fields
        foreach (var assignment in body.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            var symbol = semanticModel.GetSymbolInfo(assignment.Left).Symbol;
            if (symbol is IFieldSymbol field && !field.IsConst && !field.IsReadOnly)
            {
                modifications.Add(field.Name);
            }
        }

        // Find increment/decrement operations
        foreach (var postfix in body.DescendantNodes().OfType<PostfixUnaryExpressionSyntax>())
        {
            if (postfix.IsKind(SyntaxKind.PostIncrementExpression) ||
                postfix.IsKind(SyntaxKind.PostDecrementExpression))
            {
                var symbol = semanticModel.GetSymbolInfo(postfix.Operand).Symbol;
                if (symbol is IFieldSymbol field)
                    modifications.Add(field.Name);
            }
        }

        foreach (var prefix in body.DescendantNodes().OfType<PrefixUnaryExpressionSyntax>())
        {
            if (prefix.IsKind(SyntaxKind.PreIncrementExpression) ||
                prefix.IsKind(SyntaxKind.PreDecrementExpression))
            {
                var symbol = semanticModel.GetSymbolInfo(prefix.Operand).Symbol;
                if (symbol is IFieldSymbol field)
                    modifications.Add(field.Name);
            }
        }

        // Find collection modifications
        foreach (var invocation in body.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var methodName = memberAccess.Name.Identifier.Text;
                if (IsCollectionMutatingMethod(methodName))
                {
                    var collectionSymbol = semanticModel.GetSymbolInfo(memberAccess.Expression).Symbol;
                    if (collectionSymbol is IFieldSymbol field)
                        modifications.Add(field.Name);
                }
            }
        }

        return modifications.Distinct().ToList();
    }

    private List<InvocationExpressionSyntax> FindFloatingTasks(SyntaxNode? body, SemanticModel semanticModel)
    {
        var floatingTasks = new List<InvocationExpressionSyntax>();
        if (body == null) return floatingTasks;

        foreach (var invocation in body.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var typeInfo = semanticModel.GetTypeInfo(invocation);
            if (!IsTaskType(typeInfo.Type)) continue;

            // Check if properly handled
            if (IsAwaited(invocation)) continue;
            if (IsAssigned(invocation)) continue;
            if (IsReturned(invocation)) continue;

            floatingTasks.Add(invocation);
        }

        return floatingTasks;
    }

    private bool IsCollectionMutatingMethod(string methodName)
    {
        return methodName is "Add" or "Remove" or "Clear" or "Insert" or "RemoveAt" or
            "AddRange" or "Push" or "Pop" or "Enqueue" or "Dequeue" or
            "TryAdd" or "TryRemove" or "TryUpdate";
    }

    private bool IsTaskType(ITypeSymbol? type)
    {
        if (type == null) return false;
        var name = type.ToDisplayString();
        return name.StartsWith("System.Threading.Tasks.Task") ||
               name.StartsWith("System.Threading.Tasks.ValueTask");
    }

    private bool IsInAsyncContext(SyntaxNode node)
    {
        var method = node.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
        if (method != null && method.Modifiers.Any(SyntaxKind.AsyncKeyword))
            return true;

        var lambda = node.Ancestors().OfType<LambdaExpressionSyntax>().FirstOrDefault();
        if (lambda != null)
        {
            if (lambda is ParenthesizedLambdaExpressionSyntax pLambda &&
                pLambda.AsyncKeyword.IsKind(SyntaxKind.AsyncKeyword))
                return true;
            if (lambda is SimpleLambdaExpressionSyntax sLambda &&
                sLambda.AsyncKeyword.IsKind(SyntaxKind.AsyncKeyword))
                return true;
        }

        return false;
    }

    private bool IsPotentiallySyncContextBound(MethodDeclarationSyntax? method)
    {
        if (method == null) return false;

        // Check if in a class that inherits from UI types
        var classDecl = method.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
        if (classDecl?.BaseList != null)
        {
            var baseTypes = classDecl.BaseList.Types.Select(t => t.ToString()).ToList();
            if (baseTypes.Any(t => t.Contains("Form") || t.Contains("Control") ||
                                    t.Contains("Window") || t.Contains("Page") ||
                                    t.Contains("Component") || t.Contains("Controller")))
            {
                return true;
            }
        }

        // Check for common UI event handler patterns
        var methodName = method.Identifier.Text;
        if (methodName.EndsWith("_Click") || methodName.EndsWith("_Load") ||
            methodName.EndsWith("_Changed") || methodName.StartsWith("On"))
        {
            return true;
        }

        return false;
    }

    private bool IsAwaited(InvocationExpressionSyntax invocation)
    {
        return invocation.Parent is AwaitExpressionSyntax ||
               (invocation.Parent is MemberAccessExpressionSyntax ma &&
                ma.Parent is AwaitExpressionSyntax);
    }

    private bool IsAssigned(InvocationExpressionSyntax invocation)
    {
        return invocation.Parent is EqualsValueClauseSyntax ||
               invocation.Parent is AssignmentExpressionSyntax;
    }

    private bool IsReturned(InvocationExpressionSyntax invocation)
    {
        return invocation.Parent is ReturnStatementSyntax ||
               invocation.Parent is ArrowExpressionClauseSyntax;
    }

    private string GetParametersSummary(MethodDeclarationSyntax method)
    {
        var parameters = method.ParameterList.Parameters;
        if (parameters.Count == 0) return "";
        if (parameters.Count <= 2)
        {
            return string.Join(", ", parameters.Select(p => $"{p.Type} {p.Identifier}"));
        }
        return $"{parameters.Count} parameters";
    }

    private string GetLambdaSnippet(ParenthesizedLambdaExpressionSyntax lambda)
    {
        var text = lambda.ToString();
        if (text.Length > 60)
        {
            return text.Substring(0, 57) + "...";
        }
        return text;
    }
}
