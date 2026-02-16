using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Memory.Detectors;

/// <summary>
/// Detects allocations of large objects (85KB+) inside loops,
/// which can cause Large Object Heap (LOH) fragmentation and performance issues.
/// </summary>
public class LargeObjectDetector : IMemoryLeakDetector
{
    public string Category => "LOHInLoop";

    // LOH threshold is 85,000 bytes
    private const int LOHThreshold = 85000;

    // Common element sizes for estimation
    private static readonly Dictionary<SpecialType, int> TypeSizes = new()
    {
        { SpecialType.System_Byte, 1 },
        { SpecialType.System_SByte, 1 },
        { SpecialType.System_Int16, 2 },
        { SpecialType.System_UInt16, 2 },
        { SpecialType.System_Int32, 4 },
        { SpecialType.System_UInt32, 4 },
        { SpecialType.System_Int64, 8 },
        { SpecialType.System_UInt64, 8 },
        { SpecialType.System_Single, 4 },
        { SpecialType.System_Double, 8 },
        { SpecialType.System_Decimal, 16 },
        { SpecialType.System_Char, 2 },
        { SpecialType.System_Boolean, 1 },
        { SpecialType.System_Object, 8 },
        { SpecialType.System_String, 8 } // Reference size
    };

    public Task<List<MemoryLeak>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context)
    {
        var leaks = new List<MemoryLeak>();
        var filePath = document.FilePath ?? "";

        // Find all loop constructs
        var loops = root.DescendantNodes()
            .Where(n => n is ForStatementSyntax or
                       ForEachStatementSyntax or
                       WhileStatementSyntax or
                       DoStatementSyntax);

        foreach (var loop in loops)
        {
            // Find array allocations in loops
            AnalyzeArrayAllocations(loop, semanticModel, filePath, leaks);

            // Find string allocations that might be large
            AnalyzeLargeStringAllocations(loop, semanticModel, filePath, leaks);

            // Find large object creations (List, StringBuilder with large capacity)
            AnalyzeLargeObjectCreations(loop, semanticModel, filePath, leaks);

            // Find byte[] allocations used for buffers
            AnalyzeBufferAllocations(loop, semanticModel, filePath, leaks);
        }

        return Task.FromResult(leaks);
    }

    private void AnalyzeArrayAllocations(
        SyntaxNode loop,
        SemanticModel semanticModel,
        string filePath,
        List<MemoryLeak> leaks)
    {
        foreach (var arrayCreation in loop.DescendantNodes().OfType<ArrayCreationExpressionSyntax>())
        {
            var allocationInfo = AnalyzeArrayAllocation(arrayCreation, semanticModel);
            if (allocationInfo == null)
                continue;

            if (allocationInfo.EstimatedSize >= LOHThreshold)
            {
                var lineSpan = arrayCreation.GetLocation().GetLineSpan();

                leaks.Add(new MemoryLeak
                {
                    LeakType = Category,
                    Severity = "High",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = $"Large array allocation ({FormatSize(allocationInfo.EstimatedSize)}) inside a loop. " +
                                 $"Objects >= 85KB are allocated on the Large Object Heap, causing fragmentation.",
                    Recommendation = "Use ArrayPool<T>.Shared.Rent() and Return() to reuse large arrays, " +
                                    "or allocate the array outside the loop if possible.",
                    ProblematicCode = arrayCreation.ToString(),
                    SuggestedFix = GenerateArrayPoolFix(allocationInfo),
                    Confidence = allocationInfo.IsExactSize ? "High" : "Medium",
                    CweId = "CWE-401",
                    EstimatedMemoryImpact = allocationInfo.EstimatedSize,
                    IsInHotPath = true,
                    Details = new List<string>
                    {
                        $"Estimated size: {FormatSize(allocationInfo.EstimatedSize)}",
                        $"Element type: {allocationInfo.AllocatedType}",
                        $"LOH threshold: 85,000 bytes",
                        "LOH allocations are not compacted by GC"
                    }
                });
            }
        }
    }

    private LOHAllocationInfo? AnalyzeArrayAllocation(
        ArrayCreationExpressionSyntax arrayCreation,
        SemanticModel semanticModel)
    {
        var rankSpecifier = arrayCreation.Type.RankSpecifiers.FirstOrDefault();
        if (rankSpecifier == null)
            return null;

        var sizeExpr = rankSpecifier.Sizes.FirstOrDefault();
        if (sizeExpr == null || sizeExpr is OmittedArraySizeExpressionSyntax)
            return null;

        // Try to get the array size
        var arraySize = GetArraySize(sizeExpr, semanticModel);
        if (arraySize == null)
            return null;

        // Get element size
        var elementType = semanticModel.GetTypeInfo(arrayCreation.Type.ElementType).Type;
        if (elementType == null)
            return null;

        var elementSize = GetTypeSize(elementType);
        var estimatedSize = (long)arraySize.Value * elementSize;

        return new LOHAllocationInfo
        {
            AllocationExpression = arrayCreation.ToString(),
            EstimatedSize = estimatedSize,
            IsInLoop = true,
            AllocatedType = elementType.ToDisplayString()
        };
    }

    private int? GetArraySize(ExpressionSyntax sizeExpr, SemanticModel semanticModel)
    {
        // Try to get constant value
        var constantValue = semanticModel.GetConstantValue(sizeExpr);
        if (constantValue.HasValue && constantValue.Value is int size)
            return size;

        // Try to infer from common patterns
        if (sizeExpr is LiteralExpressionSyntax literal)
        {
            if (int.TryParse(literal.Token.ValueText, out var literalSize))
                return literalSize;
        }

        // Check for common size constants/expressions
        var exprText = sizeExpr.ToString();

        // Look for multiplication patterns like 1024 * 1024
        if (exprText.Contains("*"))
        {
            var parts = exprText.Split('*').Select(p => p.Trim()).ToList();
            var product = 1;
            foreach (var part in parts)
            {
                if (int.TryParse(part, out var value))
                    product *= value;
                else if (part.Contains("1024") || part.ToLower().Contains("kb"))
                    product *= 1024;
                else
                    return null; // Can't determine
            }
            return product;
        }

        // Common buffer size patterns
        if (exprText.Contains("BufferSize", StringComparison.OrdinalIgnoreCase))
            return 65536; // Common buffer size estimate

        return null;
    }

    private int GetTypeSize(ITypeSymbol type)
    {
        if (TypeSizes.TryGetValue(type.SpecialType, out var size))
            return size;

        if (type.IsReferenceType)
            return 8; // Reference size on 64-bit

        // For value types, estimate based on fields
        if (type.IsValueType)
        {
            var fieldCount = type.GetMembers()
                .OfType<IFieldSymbol>()
                .Count(f => !f.IsStatic);
            return Math.Max(4, fieldCount * 8); // Rough estimate
        }

        return 8; // Default
    }

    private void AnalyzeLargeStringAllocations(
        SyntaxNode loop,
        SemanticModel semanticModel,
        string filePath,
        List<MemoryLeak> leaks)
    {
        // Find string concatenation in loops that could create large strings
        foreach (var binary in loop.DescendantNodes().OfType<BinaryExpressionSyntax>())
        {
            if (!binary.IsKind(SyntaxKind.AddExpression))
                continue;

            var typeInfo = semanticModel.GetTypeInfo(binary);
            if (typeInfo.Type?.SpecialType != SpecialType.System_String)
                continue;

            // Check if this is accumulating (assigning back to same variable)
            if (binary.Parent is AssignmentExpressionSyntax assignment &&
                assignment.IsKind(SyntaxKind.AddAssignmentExpression))
            {
                var lineSpan = binary.GetLocation().GetLineSpan();

                leaks.Add(new MemoryLeak
                {
                    LeakType = Category,
                    Severity = "Medium",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = "String concatenation inside a loop can create many large temporary strings " +
                                 "that may end up on the LOH.",
                    Recommendation = "Use StringBuilder to accumulate string content in loops.",
                    ProblematicCode = binary.Parent.ToString(),
                    SuggestedFix = GenerateStringBuilderFix(binary),
                    Confidence = "Medium",
                    CweId = "CWE-401",
                    IsInHotPath = true,
                    Details = new List<string>
                    {
                        "String concatenation creates new string objects",
                        "Large strings (85KB+) are allocated on LOH",
                        "StringBuilder reuses internal buffer"
                    }
                });
            }
        }
    }

    private void AnalyzeLargeObjectCreations(
        SyntaxNode loop,
        SemanticModel semanticModel,
        string filePath,
        List<MemoryLeak> leaks)
    {
        foreach (var objectCreation in loop.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            var typeInfo = semanticModel.GetTypeInfo(objectCreation);
            if (typeInfo.Type == null)
                continue;

            var typeName = typeInfo.Type.Name;

            // Check for collections with large initial capacity
            if (IsCollectionType(typeName) && objectCreation.ArgumentList?.Arguments.Count > 0)
            {
                var capacityArg = objectCreation.ArgumentList.Arguments.First();
                var capacity = GetCapacityValue(capacityArg.Expression, semanticModel);

                if (capacity != null)
                {
                    var estimatedSize = EstimateCollectionSize(typeName, capacity.Value);
                    if (estimatedSize >= LOHThreshold)
                    {
                        var lineSpan = objectCreation.GetLocation().GetLineSpan();

                        leaks.Add(new MemoryLeak
                        {
                            LeakType = Category,
                            Severity = "Medium",
                            FilePath = filePath,
                            StartLine = lineSpan.StartLinePosition.Line + 1,
                            EndLine = lineSpan.EndLinePosition.Line + 1,
                            Description = $"Large {typeName} allocation (capacity: {capacity}, estimated: {FormatSize(estimatedSize)}) " +
                                         $"inside a loop may cause LOH allocations.",
                            Recommendation = "Consider reusing the collection by clearing it instead of creating new instances, " +
                                            "or use object pooling.",
                            ProblematicCode = objectCreation.ToString(),
                            SuggestedFix = GenerateCollectionPoolingFix(typeName),
                            Confidence = "Medium",
                            CweId = "CWE-401",
                            EstimatedMemoryImpact = estimatedSize,
                            IsInHotPath = true,
                            Details = new List<string>
                            {
                                $"Collection type: {typeName}",
                                $"Initial capacity: {capacity}",
                                $"Estimated backing array size: {FormatSize(estimatedSize)}"
                            }
                        });
                    }
                }
            }

            // Check for MemoryStream with large capacity
            if (typeName == "MemoryStream" && objectCreation.ArgumentList?.Arguments.Count > 0)
            {
                var capacityArg = objectCreation.ArgumentList.Arguments.First();
                var capacity = GetCapacityValue(capacityArg.Expression, semanticModel);

                if (capacity != null && capacity >= LOHThreshold)
                {
                    var lineSpan = objectCreation.GetLocation().GetLineSpan();

                    leaks.Add(new MemoryLeak
                    {
                        LeakType = Category,
                        Severity = "High",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = $"Large MemoryStream allocation ({FormatSize(capacity.Value)}) inside a loop " +
                                     $"causes LOH allocations.",
                        Recommendation = "Use RecyclableMemoryStreamManager for pooling MemoryStream instances.",
                        ProblematicCode = objectCreation.ToString(),
                        SuggestedFix = GenerateMemoryStreamFix(),
                        Confidence = "High",
                        CweId = "CWE-401",
                        EstimatedMemoryImpact = capacity.Value,
                        IsInHotPath = true,
                        Details = new List<string>
                        {
                            $"MemoryStream capacity: {FormatSize(capacity.Value)}",
                            "Consider using Microsoft.IO.RecyclableMemoryStream"
                        }
                    });
                }
            }
        }
    }

    private void AnalyzeBufferAllocations(
        SyntaxNode loop,
        SemanticModel semanticModel,
        string filePath,
        List<MemoryLeak> leaks)
    {
        // Look for common buffer allocation patterns
        foreach (var local in loop.DescendantNodes().OfType<LocalDeclarationStatementSyntax>())
        {
            foreach (var variable in local.Declaration.Variables)
            {
                if (variable.Initializer?.Value is ArrayCreationExpressionSyntax arrayCreation)
                {
                    var varName = variable.Identifier.Text.ToLower();
                    if (varName.Contains("buffer") || varName.Contains("bytes") || varName.Contains("data"))
                    {
                        var allocationInfo = AnalyzeArrayAllocation(arrayCreation, semanticModel);
                        if (allocationInfo != null && allocationInfo.EstimatedSize >= LOHThreshold)
                        {
                            // Already handled in AnalyzeArrayAllocations, but add specific buffer guidance
                            continue;
                        }
                    }
                }
            }
        }
    }

    private bool IsCollectionType(string typeName)
    {
        return typeName is "List" or "Dictionary" or "HashSet" or
            "StringBuilder" or "SortedList" or "SortedSet" or "SortedDictionary";
    }

    private int? GetCapacityValue(ExpressionSyntax expr, SemanticModel semanticModel)
    {
        var constantValue = semanticModel.GetConstantValue(expr);
        if (constantValue.HasValue && constantValue.Value is int capacity)
            return capacity;

        if (expr is LiteralExpressionSyntax literal && int.TryParse(literal.Token.ValueText, out var literalValue))
            return literalValue;

        return null;
    }

    private long EstimateCollectionSize(string typeName, int capacity)
    {
        return typeName switch
        {
            "List" => capacity * 8, // Reference size
            "Dictionary" => capacity * 24, // Entry size estimate
            "HashSet" => capacity * 12,
            "StringBuilder" => capacity * 2, // Char size
            _ => capacity * 8
        };
    }

    private string FormatSize(long bytes)
    {
        if (bytes >= 1024 * 1024)
            return $"{bytes / (1024 * 1024):N0} MB";
        if (bytes >= 1024)
            return $"{bytes / 1024:N0} KB";
        return $"{bytes:N0} bytes";
    }

    private string GenerateArrayPoolFix(LOHAllocationInfo info)
    {
        var elementType = info.AllocatedType.Split('.').Last();
        return $@"// Use ArrayPool to avoid LOH allocations
var array = ArrayPool<{elementType}>.Shared.Rent(size);
try
{{
    // Use array[0..size] (rented array may be larger)
    ProcessData(array.AsSpan(0, size));
}}
finally
{{
    ArrayPool<{elementType}>.Shared.Return(array);
}}

// Or allocate outside the loop if the size is constant:
var buffer = new {elementType}[size];
foreach (var item in items)
{{
    // Reuse buffer
    Array.Clear(buffer);
    ProcessData(buffer);
}}";
    }

    private string GenerateStringBuilderFix(BinaryExpressionSyntax binary)
    {
        return @"// Use StringBuilder for string accumulation
var sb = new StringBuilder();
foreach (var item in items)
{
    sb.Append(item);
}
var result = sb.ToString();";
    }

    private string GenerateCollectionPoolingFix(string typeName)
    {
        return $@"// Option 1: Reuse collection by clearing
var collection = new {typeName}<T>();
foreach (var batch in batches)
{{
    collection.Clear();
    // ... use collection
}}

// Option 2: Use object pooling
private static readonly ObjectPool<{typeName}<T>> _pool =
    new DefaultObjectPoolProvider().Create<{typeName}<T>>();

var collection = _pool.Get();
try
{{
    // ... use collection
}}
finally
{{
    collection.Clear();
    _pool.Return(collection);
}}";
    }

    private string GenerateMemoryStreamFix()
    {
        return @"// Use RecyclableMemoryStreamManager (Microsoft.IO.RecyclableMemoryStream NuGet)
private static readonly RecyclableMemoryStreamManager _streamManager = new();

foreach (var item in items)
{
    using var stream = _streamManager.GetStream();
    // ... use stream
}

// Or reuse a single stream:
using var stream = new MemoryStream(capacity);
foreach (var item in items)
{
    stream.SetLength(0); // Reset without reallocating
    // ... use stream
}";
    }
}
