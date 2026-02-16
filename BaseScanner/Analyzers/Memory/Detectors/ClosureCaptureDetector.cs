using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Memory.Detectors;

/// <summary>
/// Detects closures that capture 'this' or large objects,
/// which can prevent garbage collection of the containing object.
/// Uses Roslyn's DataFlowAnalysis for accurate capture detection.
/// </summary>
public class ClosureCaptureDetector : IMemoryLeakDetector
{
    public string Category => "ClosureCapture";

    // Threshold for what we consider a "large" captured object (by field count)
    private const int LargeObjectFieldThreshold = 5;

    public Task<List<MemoryLeak>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context)
    {
        var leaks = new List<MemoryLeak>();
        var filePath = document.FilePath ?? "";

        // Find all lambda expressions and anonymous methods
        var lambdas = root.DescendantNodes()
            .Where(n => n is LambdaExpressionSyntax or AnonymousMethodExpressionSyntax);

        foreach (var lambda in lambdas)
        {
            var captureInfo = AnalyzeClosure(lambda, semanticModel);
            if (captureInfo == null)
                continue;

            // Check for problematic captures
            var issues = new List<string>();

            if (captureInfo.CapturesThis)
            {
                issues.Add("Captures 'this' reference");
            }

            if (captureInfo.CapturesLargeObjects)
            {
                issues.Add("Captures large objects");
            }

            // Only report if there are actual issues and the closure escapes scope
            if (issues.Count > 0 && captureInfo.EscapesScope)
            {
                var lineSpan = lambda.GetLocation().GetLineSpan();
                var severity = DetermineSeverity(captureInfo, lambda, root);

                leaks.Add(new MemoryLeak
                {
                    LeakType = Category,
                    Severity = severity,
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = $"Closure {string.Join(" and ", issues).ToLower()}. " +
                                 $"This may prevent garbage collection of captured objects.",
                    Recommendation = GenerateRecommendation(captureInfo),
                    ProblematicCode = TruncateCode(lambda.ToString()),
                    SuggestedFix = GenerateSuggestedFix(captureInfo, lambda),
                    Confidence = captureInfo.CapturesThis ? "High" : "Medium",
                    CweId = "CWE-401",
                    EstimatedMemoryImpact = captureInfo.EstimatedCaptureSize,
                    IsInHotPath = IsInHotPath(lambda, root),
                    Details = BuildDetails(captureInfo)
                });
            }
        }

        return Task.FromResult(leaks);
    }

    private ClosureCaptureInfo? AnalyzeClosure(SyntaxNode lambda, SemanticModel semanticModel)
    {
        try
        {
            // Use Roslyn's DataFlowAnalysis to detect captured variables
            var dataFlow = semanticModel.AnalyzeDataFlow(lambda);
            if (dataFlow == null || !dataFlow.Succeeded)
                return null;

            var capturedSymbols = dataFlow.Captured.ToList();
            if (capturedSymbols.Count == 0)
                return null;

            var capturedVariables = new List<string>();
            var capturesThis = false;
            var capturesLargeObjects = false;
            long estimatedSize = 0;

            foreach (var symbol in capturedSymbols)
            {
                capturedVariables.Add(symbol.Name);

                // Check if 'this' is captured (implicitly or explicitly)
                if (symbol is IParameterSymbol param && param.IsThis)
                {
                    capturesThis = true;
                    estimatedSize += EstimateTypeSize(param.Type, semanticModel);
                }
                else if (symbol is ILocalSymbol local)
                {
                    var typeSize = EstimateTypeSize(local.Type, semanticModel);
                    estimatedSize += typeSize;

                    if (IsLargeObject(local.Type, semanticModel))
                    {
                        capturesLargeObjects = true;
                    }
                }
                else if (symbol is IFieldSymbol field)
                {
                    // If a field is captured, 'this' is implicitly captured
                    if (!field.IsStatic)
                    {
                        capturesThis = true;
                    }
                    estimatedSize += EstimateTypeSize(field.Type, semanticModel);
                }
            }

            // Also check for explicit 'this' references in the lambda
            if (!capturesThis)
            {
                capturesThis = lambda.DescendantNodes()
                    .OfType<ThisExpressionSyntax>()
                    .Any();
            }

            // Check for instance member access that implies 'this' capture
            if (!capturesThis)
            {
                capturesThis = HasImplicitThisCapture(lambda, semanticModel);
            }

            var escapesScope = DetermineIfEscapesScope(lambda, semanticModel);

            return new ClosureCaptureInfo
            {
                CapturedVariables = capturedVariables,
                CapturesThis = capturesThis,
                CapturesLargeObjects = capturesLargeObjects,
                EstimatedCaptureSize = estimatedSize,
                Context = DetermineClosureContext(lambda),
                EscapesScope = escapesScope
            };
        }
        catch
        {
            return null;
        }
    }

    private bool HasImplicitThisCapture(SyntaxNode lambda, SemanticModel semanticModel)
    {
        // Check for member access to instance members
        foreach (var identifier in lambda.DescendantNodes().OfType<IdentifierNameSyntax>())
        {
            var symbol = semanticModel.GetSymbolInfo(identifier).Symbol;
            if (symbol is IFieldSymbol field && !field.IsStatic)
                return true;
            if (symbol is IPropertySymbol prop && !prop.IsStatic)
                return true;
            if (symbol is IMethodSymbol method && !method.IsStatic)
                return true;
        }

        return false;
    }

    private bool DetermineIfEscapesScope(SyntaxNode lambda, SemanticModel semanticModel)
    {
        var parent = lambda.Parent;

        // Check various escape patterns
        while (parent != null)
        {
            // Returned from method
            if (parent is ReturnStatementSyntax or ArrowExpressionClauseSyntax)
                return true;

            // Assigned to field
            if (parent is AssignmentExpressionSyntax assignment)
            {
                var leftSymbol = semanticModel.GetSymbolInfo(assignment.Left).Symbol;
                if (leftSymbol is IFieldSymbol or IPropertySymbol)
                    return true;
            }

            // Passed to event subscription
            if (parent is AssignmentExpressionSyntax eventAssignment &&
                eventAssignment.IsKind(SyntaxKind.AddAssignmentExpression))
                return true;

            // Passed as argument to method
            if (parent is ArgumentSyntax)
            {
                // Check if the method stores the delegate (e.g., event handlers, callbacks)
                var invocation = parent.Ancestors().OfType<InvocationExpressionSyntax>().FirstOrDefault();
                if (invocation != null)
                {
                    var methodSymbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                    if (methodSymbol != null)
                    {
                        // Common patterns that store delegates
                        var methodName = methodSymbol.Name;
                        if (methodName.Contains("Subscribe") ||
                            methodName.Contains("Add") ||
                            methodName.Contains("Register") ||
                            methodName.Contains("Attach") ||
                            methodName == "ContinueWith" ||
                            methodName == "Then")
                        {
                            return true;
                        }
                    }
                }
            }

            // Used with Task.Run, Task.ContinueWith, etc.
            if (parent is InvocationExpressionSyntax inv)
            {
                var methodSymbol = semanticModel.GetSymbolInfo(inv).Symbol as IMethodSymbol;
                if (methodSymbol != null)
                {
                    var containingType = methodSymbol.ContainingType?.Name ?? "";
                    if (containingType is "Task" or "TaskFactory" or "Parallel" or "Thread" or "ThreadPool")
                        return true;
                }
            }

            parent = parent.Parent;
        }

        return false;
    }

    private string DetermineClosureContext(SyntaxNode lambda)
    {
        var parent = lambda.Parent;
        while (parent != null)
        {
            if (parent is InvocationExpressionSyntax invocation)
            {
                var methodName = GetMethodName(invocation);
                if (methodName != null)
                {
                    if (IsLinqMethod(methodName))
                        return "LINQ query";
                    if (methodName.Contains("Task") || methodName == "Run" || methodName == "ContinueWith")
                        return "async Task";
                    if (methodName.Contains("Subscribe") || methodName.Contains("Handler"))
                        return "event handler";
                }
            }

            if (parent is AssignmentExpressionSyntax assignment &&
                assignment.IsKind(SyntaxKind.AddAssignmentExpression))
            {
                return "event subscription";
            }

            parent = parent.Parent;
        }

        return "delegate";
    }

    private string? GetMethodName(InvocationExpressionSyntax invocation)
    {
        return invocation.Expression switch
        {
            MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
            IdentifierNameSyntax id => id.Identifier.Text,
            _ => null
        };
    }

    private bool IsLinqMethod(string methodName)
    {
        return methodName is "Where" or "Select" or "SelectMany" or "OrderBy" or "OrderByDescending" or
            "GroupBy" or "Join" or "Any" or "All" or "First" or "FirstOrDefault" or
            "Single" or "SingleOrDefault" or "Last" or "LastOrDefault" or "Count" or
            "Sum" or "Average" or "Min" or "Max" or "Aggregate" or "ToList" or "ToArray" or
            "ToDictionary" or "ToHashSet" or "Distinct" or "Union" or "Intersect" or "Except";
    }

    private long EstimateTypeSize(ITypeSymbol type, SemanticModel semanticModel)
    {
        if (type.IsReferenceType)
        {
            // Reference types: pointer size + object header + fields
            var fieldCount = type.GetMembers()
                .OfType<IFieldSymbol>()
                .Count(f => !f.IsStatic);
            return 8 + 16 + (fieldCount * 8); // Rough estimate
        }

        // Value types
        return type.SpecialType switch
        {
            SpecialType.System_Byte or SpecialType.System_SByte => 1,
            SpecialType.System_Int16 or SpecialType.System_UInt16 => 2,
            SpecialType.System_Int32 or SpecialType.System_UInt32 => 4,
            SpecialType.System_Int64 or SpecialType.System_UInt64 => 8,
            SpecialType.System_Single => 4,
            SpecialType.System_Double => 8,
            SpecialType.System_Decimal => 16,
            SpecialType.System_Boolean => 1,
            SpecialType.System_Char => 2,
            _ => 8 // Default estimate
        };
    }

    private bool IsLargeObject(ITypeSymbol type, SemanticModel semanticModel)
    {
        if (!type.IsReferenceType)
            return false;

        var fieldCount = type.GetMembers()
            .OfType<IFieldSymbol>()
            .Count(f => !f.IsStatic);

        return fieldCount >= LargeObjectFieldThreshold;
    }

    private string DetermineSeverity(ClosureCaptureInfo captureInfo, SyntaxNode lambda, SyntaxNode root)
    {
        // Critical: Captures 'this' in event handler
        if (captureInfo.CapturesThis && captureInfo.Context == "event subscription")
            return "Critical";

        // High: Captures 'this' in long-lived delegate
        if (captureInfo.CapturesThis && captureInfo.Context is "async Task" or "event handler")
            return "High";

        // High: Captures large objects
        if (captureInfo.CapturesLargeObjects)
            return "High";

        // Medium: Captures 'this' in other contexts
        if (captureInfo.CapturesThis)
            return "Medium";

        // Low: Other captures
        return "Low";
    }

    private bool IsInHotPath(SyntaxNode node, SyntaxNode root)
    {
        return node.Ancestors().Any(a =>
            a is ForStatementSyntax or
                ForEachStatementSyntax or
                WhileStatementSyntax or
                DoStatementSyntax);
    }

    private string TruncateCode(string code)
    {
        var lines = code.Split('\n');
        if (lines.Length > 5)
        {
            return string.Join("\n", lines.Take(5)) + "\n// ...";
        }
        return code.Length > 200 ? code.Substring(0, 200) + "..." : code;
    }

    private List<string> BuildDetails(ClosureCaptureInfo captureInfo)
    {
        var details = new List<string>
        {
            $"Context: {captureInfo.Context}",
            $"Captured variables: {string.Join(", ", captureInfo.CapturedVariables)}",
            $"Estimated capture size: {captureInfo.EstimatedCaptureSize} bytes"
        };

        if (captureInfo.CapturesThis)
            details.Add("Captures 'this' reference");

        if (captureInfo.CapturesLargeObjects)
            details.Add("Captures large object(s)");

        if (captureInfo.EscapesScope)
            details.Add("Closure escapes current scope");

        return details;
    }

    private string GenerateRecommendation(ClosureCaptureInfo captureInfo)
    {
        if (captureInfo.CapturesThis && captureInfo.Context == "event subscription")
        {
            return "Use a weak event pattern or ensure proper unsubscription in Dispose(). " +
                   "Consider using WeakEventManager or storing the subscription for later removal.";
        }

        if (captureInfo.CapturesThis)
        {
            return "Extract the lambda to a static method and pass required data as parameters, " +
                   "or capture only the specific fields needed instead of 'this'.";
        }

        if (captureInfo.CapturesLargeObjects)
        {
            return "Capture only the specific data needed from large objects, not the objects themselves. " +
                   "Consider extracting relevant values before the closure.";
        }

        return "Review the closure to minimize captured state and prevent memory leaks.";
    }

    private string GenerateSuggestedFix(ClosureCaptureInfo captureInfo, SyntaxNode lambda)
    {
        if (captureInfo.CapturesThis)
        {
            return $@"// Option 1: Extract to static method
private static void ProcessItem(SpecificData data)
{{
    // Use only the data you need
}}

// Then use:
items.Select(item => ProcessItem(specificData));

// Option 2: Capture only needed values
var localValue = this.SomeProperty;
items.Select(item => ProcessWithLocal(item, localValue));

// Option 3: For event handlers, use weak references
WeakEventManager<TSource, TArgs>.AddHandler(source, ""EventName"", OnEventHandler);";
        }

        return $@"// Capture only the specific data needed:
var neededValue = largeObject.SpecificProperty;
var result = items.Select(item => UseValue(item, neededValue));";
    }
}
