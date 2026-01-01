using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Optimizations;

/// <summary>
/// Detects memory allocation patterns that can be optimized.
/// </summary>
public class MemoryOptimizationDetector : IOptimizationDetector
{
    public string Category => "Performance";

    private const int LargeArrayThreshold = 1024;
    private const int SmallStackAllocThreshold = 256;

    public Task<List<OptimizationOpportunity>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context)
    {
        var opportunities = new List<OptimizationOpportunity>();
        var filePath = document.FilePath ?? "";

        // Detect array allocations in loops -> ArrayPool
        DetectArrayAllocationsInLoops(root, semanticModel, filePath, opportunities);

        // Detect small byte array allocations -> stackalloc
        DetectStackAllocOpportunities(root, semanticModel, filePath, opportunities);

        // Detect boxing in generic collections
        DetectBoxingInCollections(root, semanticModel, filePath, opportunities);

        // Detect closure allocations in LINQ
        DetectClosureAllocations(root, semanticModel, filePath, opportunities);

        // Detect large struct copies
        DetectLargeStructCopies(root, semanticModel, filePath, opportunities);

        // Detect params array allocations
        DetectParamsAllocations(root, semanticModel, filePath, opportunities);

        return Task.FromResult(opportunities);
    }

    private void DetectArrayAllocationsInLoops(
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
            foreach (var creation in loop.DescendantNodes().OfType<ArrayCreationExpressionSyntax>())
            {
                // Check if array size is significant
                var sizeExpr = creation.Type.RankSpecifiers.FirstOrDefault()?.Sizes.FirstOrDefault();
                if (sizeExpr == null)
                    continue;

                // Try to get the constant size
                var constantValue = semanticModel.GetConstantValue(sizeExpr);
                if (constantValue.HasValue && constantValue.Value is int size && size < LargeArrayThreshold)
                    continue;

                var elementType = GetArrayElementType(creation.Type, semanticModel);
                if (elementType == null)
                    continue;

                var lineSpan = creation.GetLocation().GetLineSpan();
                opportunities.Add(new OptimizationOpportunity
                {
                    Category = Category,
                    Type = "ArrayAllocationInLoop",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = "Array allocation inside a loop creates garbage on each iteration. Consider using ArrayPool<T>.Shared.",
                    CurrentCode = creation.ToFullString().Trim(),
                    SuggestedCode = $"// var array = ArrayPool<{elementType}>.Shared.Rent(size);\n// try {{ ... }}\n// finally {{ ArrayPool<{elementType}>.Shared.Return(array); }}",
                    Confidence = OptimizationConfidence.Medium,
                    Impact = OptimizationImpact.High,
                    IsSemanticallySafe = false,
                    Assumptions = ["Array size is predictable", "Pooled arrays may be larger than requested"],
                    Risks = ["Must return array to pool", "Array contains previous data"]
                });
            }
        }
    }

    private string? GetArrayElementType(ArrayTypeSyntax arrayType, SemanticModel semanticModel)
    {
        var typeInfo = semanticModel.GetTypeInfo(arrayType.ElementType);
        return typeInfo.Type?.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat);
    }

    private void DetectStackAllocOpportunities(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        foreach (var creation in root.DescendantNodes().OfType<ArrayCreationExpressionSyntax>())
        {
            // Only for byte[] or small value type arrays
            var elementType = semanticModel.GetTypeInfo(creation.Type.ElementType).Type;
            if (elementType == null)
                continue;

            // Check for byte[], char[], int[], etc.
            if (!IsStackAllocCompatibleType(elementType))
                continue;

            // Check size
            var sizeExpr = creation.Type.RankSpecifiers.FirstOrDefault()?.Sizes.FirstOrDefault();
            if (sizeExpr == null)
                continue;

            var constantValue = semanticModel.GetConstantValue(sizeExpr);
            if (!constantValue.HasValue || constantValue.Value is not int size)
                continue;

            if (size > SmallStackAllocThreshold)
                continue;

            // Check if it's inside a method (not a field)
            var containingMethod = creation.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            if (containingMethod == null)
                continue;

            var typeName = elementType.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat);
            var lineSpan = creation.GetLocation().GetLineSpan();

            opportunities.Add(new OptimizationOpportunity
            {
                Category = Category,
                Type = "StackAllocOpportunity",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                Description = $"Small {typeName}[{size}] allocation could use stackalloc to avoid heap allocation.",
                CurrentCode = creation.ToFullString().Trim(),
                SuggestedCode = $"Span<{typeName}> buffer = stackalloc {typeName}[{size}];",
                Confidence = OptimizationConfidence.Medium,
                Impact = OptimizationImpact.Medium,
                IsSemanticallySafe = false,
                Assumptions = ["Method doesn't return or store the array", "Stack space is sufficient"],
                Risks = ["stackalloc memory is only valid within the method"]
            });
        }
    }

    private bool IsStackAllocCompatibleType(ITypeSymbol type)
    {
        if (!type.IsValueType)
            return false;

        // Common stackalloc types
        return type.SpecialType switch
        {
            SpecialType.System_Byte => true,
            SpecialType.System_SByte => true,
            SpecialType.System_Int16 => true,
            SpecialType.System_UInt16 => true,
            SpecialType.System_Int32 => true,
            SpecialType.System_UInt32 => true,
            SpecialType.System_Int64 => true,
            SpecialType.System_UInt64 => true,
            SpecialType.System_Char => true,
            SpecialType.System_Single => true,
            SpecialType.System_Double => true,
            _ => false
        };
    }

    private void DetectBoxingInCollections(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        // Detect List<object> or similar with value types being added
        foreach (var creation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            var typeInfo = semanticModel.GetTypeInfo(creation);
            if (typeInfo.Type is not INamedTypeSymbol namedType)
                continue;

            // Check if it's a generic collection with object type argument
            if (!namedType.IsGenericType)
                continue;

            var typeArgs = namedType.TypeArguments;
            if (typeArgs.Length == 0)
                continue;

            var firstArg = typeArgs[0];
            if (firstArg.SpecialType != SpecialType.System_Object)
                continue;

            // Check if the collection has Add calls with value types
            var parent = creation.Parent;
            if (parent is EqualsValueClauseSyntax equalsClause &&
                equalsClause.Parent is VariableDeclaratorSyntax declarator)
            {
                var variableName = declarator.Identifier.Text;
                var containingMethod = creation.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
                if (containingMethod == null)
                    continue;

                // Look for Add calls on this variable with value types
                var addCalls = containingMethod.DescendantNodes()
                    .OfType<InvocationExpressionSyntax>()
                    .Where(inv =>
                    {
                        if (inv.Expression is not MemberAccessExpressionSyntax ma)
                            return false;
                        if (ma.Name.Identifier.Text != "Add")
                            return false;
                        if (ma.Expression is not IdentifierNameSyntax id)
                            return false;
                        return id.Identifier.Text == variableName;
                    })
                    .ToList();

                var hasValueTypeAdds = addCalls.Any(add =>
                {
                    if (add.ArgumentList.Arguments.Count == 0)
                        return false;
                    var argType = semanticModel.GetTypeInfo(add.ArgumentList.Arguments[0].Expression).Type;
                    return argType?.IsValueType ?? false;
                });

                if (hasValueTypeAdds)
                {
                    var lineSpan = creation.GetLocation().GetLineSpan();
                    opportunities.Add(new OptimizationOpportunity
                    {
                        Category = Category,
                        Type = "BoxingInCollection",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = "Value types are being boxed when added to this collection. Use a strongly-typed collection or generic constraint.",
                        CurrentCode = creation.ToFullString().Trim(),
                        SuggestedCode = "// Use List<int>, List<T> where T : struct, or typed collection",
                        Confidence = OptimizationConfidence.Medium,
                        Impact = OptimizationImpact.Medium,
                        IsSemanticallySafe = false,
                        Assumptions = ["All values are of the same type"]
                    });
                }
            }
        }
    }

    private void DetectClosureAllocations(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        // Detect lambdas that capture local variables in hot paths
        var loops = root.DescendantNodes()
            .Where(n => n is ForStatementSyntax or ForEachStatementSyntax or
                       WhileStatementSyntax or DoStatementSyntax);

        foreach (var loop in loops)
        {
            foreach (var lambda in loop.DescendantNodes().OfType<LambdaExpressionSyntax>())
            {
                // Check if lambda captures any variables
                var dataFlow = semanticModel.AnalyzeDataFlow(lambda);
                if (dataFlow == null || !dataFlow.Captured.Any())
                    continue;

                // Check if used in LINQ
                var isInLinq = lambda.Ancestors()
                    .OfType<InvocationExpressionSyntax>()
                    .Any(inv => IsLinqMethod(inv, semanticModel));

                if (!isInLinq)
                    continue;

                var capturedVars = string.Join(", ", dataFlow.Captured.Select(s => s.Name));
                var lineSpan = lambda.GetLocation().GetLineSpan();

                opportunities.Add(new OptimizationOpportunity
                {
                    Category = Category,
                    Type = "ClosureAllocationInLoop",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = $"Lambda captures variables ({capturedVars}) inside a loop, causing closure allocation on each iteration.",
                    CurrentCode = lambda.ToFullString().Trim(),
                    SuggestedCode = "// Consider: Extract to a static method, or cache the delegate outside the loop",
                    Confidence = OptimizationConfidence.Medium,
                    Impact = OptimizationImpact.Medium,
                    IsSemanticallySafe = false,
                    Assumptions = ["Captured variables don't need to change per iteration"]
                });
            }
        }
    }

    private bool IsLinqMethod(InvocationExpressionSyntax invocation, SemanticModel semanticModel)
    {
        var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
        if (symbol == null)
            return false;

        var ns = symbol.ContainingNamespace?.ToDisplayString() ?? "";
        return ns.StartsWith("System.Linq");
    }

    private void DetectLargeStructCopies(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        const int LargeStructThreshold = 16; // bytes

        foreach (var parameter in root.DescendantNodes().OfType<ParameterSyntax>())
        {
            if (parameter.Type == null)
                continue;

            var typeInfo = semanticModel.GetTypeInfo(parameter.Type);
            if (typeInfo.Type is not INamedTypeSymbol namedType)
                continue;

            if (!namedType.IsValueType || namedType.IsReferenceType)
                continue;

            // Estimate struct size (simplified)
            var fieldCount = namedType.GetMembers()
                .OfType<IFieldSymbol>()
                .Count(f => !f.IsStatic);

            if (fieldCount < 3) // Rough heuristic: small struct
                continue;

            // Check if parameter is passed by value (not in, ref, out)
            if (parameter.Modifiers.Any(m => m.IsKind(SyntaxKind.InKeyword) ||
                                             m.IsKind(SyntaxKind.RefKeyword) ||
                                             m.IsKind(SyntaxKind.OutKeyword)))
                continue;

            var typeName = namedType.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat);
            var lineSpan = parameter.GetLocation().GetLineSpan();

            opportunities.Add(new OptimizationOpportunity
            {
                Category = Category,
                Type = "LargeStructCopy",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                Description = $"Large struct '{typeName}' is passed by value, causing a copy. Consider using 'in' parameter modifier.",
                CurrentCode = parameter.ToFullString().Trim(),
                SuggestedCode = $"in {parameter.ToFullString().Trim()}",
                Confidence = OptimizationConfidence.Low,
                Impact = OptimizationImpact.Low,
                IsSemanticallySafe = true,
                Assumptions = ["Struct is not modified in the method", "This is a performance-critical path"]
            });
        }
    }

    private void DetectParamsAllocations(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        // Detect frequent params array allocations
        var loops = root.DescendantNodes()
            .Where(n => n is ForStatementSyntax or ForEachStatementSyntax or
                       WhileStatementSyntax or DoStatementSyntax);

        foreach (var loop in loops)
        {
            foreach (var invocation in loop.DescendantNodes().OfType<InvocationExpressionSyntax>())
            {
                var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                if (symbol == null)
                    continue;

                // Check if any parameter is params
                var paramsParam = symbol.Parameters.FirstOrDefault(p => p.IsParams);
                if (paramsParam == null)
                    continue;

                // Check if we're passing individual arguments (not an array)
                var paramsIndex = symbol.Parameters.IndexOf(paramsParam);
                var argCount = invocation.ArgumentList.Arguments.Count;

                if (argCount <= paramsIndex)
                    continue; // No params args

                var paramsArgCount = argCount - paramsIndex;
                if (paramsArgCount == 1)
                {
                    // Check if it's an array being passed
                    var arg = invocation.ArgumentList.Arguments[paramsIndex];
                    var argType = semanticModel.GetTypeInfo(arg.Expression).Type;
                    if (argType is IArrayTypeSymbol)
                        continue; // Already passing an array
                }

                var lineSpan = invocation.GetLocation().GetLineSpan();
                var methodName = symbol.Name;

                opportunities.Add(new OptimizationOpportunity
                {
                    Category = Category,
                    Type = "ParamsAllocationInLoop",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = $"Call to '{methodName}' with params creates a new array on each iteration. Consider using Span<T> overload or pre-allocating the array.",
                    CurrentCode = invocation.ToFullString().Trim(),
                    SuggestedCode = "// Pre-allocate array outside loop, or use Span<T>/ReadOnlySpan<T> overload if available",
                    Confidence = OptimizationConfidence.Medium,
                    Impact = OptimizationImpact.Medium,
                    IsSemanticallySafe = true
                });
            }
        }
    }
}
