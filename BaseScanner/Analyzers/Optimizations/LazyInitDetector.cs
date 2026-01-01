using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Optimizations;

/// <summary>
/// Detects lazy initialization patterns that can be improved.
/// </summary>
public class LazyInitDetector : IOptimizationDetector
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

        // Detect null-check + initialize pattern -> Lazy<T>
        DetectNullCheckInitPattern(root, semanticModel, filePath, opportunities);

        // Detect double-check locking issues
        DetectDoubleCheckLocking(root, semanticModel, filePath, opportunities);

        // Detect static constructor heavy initialization
        DetectHeavyStaticConstructor(root, semanticModel, filePath, opportunities);

        // Detect eager initialization of rarely-used resources
        DetectEagerInitialization(root, semanticModel, filePath, opportunities);

        return Task.FromResult(opportunities);
    }

    private void DetectNullCheckInitPattern(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        // Find patterns like: if (_field == null) _field = new Something();
        foreach (var ifStatement in root.DescendantNodes().OfType<IfStatementSyntax>())
        {
            // Check for null comparison
            if (ifStatement.Condition is not BinaryExpressionSyntax binary)
                continue;

            if (binary.Kind() != SyntaxKind.EqualsExpression)
                continue;

            ExpressionSyntax? fieldExpr = null;
            if (binary.Right is LiteralExpressionSyntax rightLiteral &&
                rightLiteral.Kind() == SyntaxKind.NullLiteralExpression)
            {
                fieldExpr = binary.Left;
            }
            else if (binary.Left is LiteralExpressionSyntax leftLiteral &&
                     leftLiteral.Kind() == SyntaxKind.NullLiteralExpression)
            {
                fieldExpr = binary.Right;
            }

            if (fieldExpr == null)
                continue;

            // Check if it's a field or property access
            var symbol = semanticModel.GetSymbolInfo(fieldExpr).Symbol;
            if (symbol is not IFieldSymbol and not IPropertySymbol)
                continue;

            // Check if the then-block assigns to the same field
            var assignment = FindAssignmentInStatement(ifStatement.Statement, fieldExpr.ToFullString().Trim());
            if (assignment == null)
                continue;

            var fieldName = symbol.Name;
            var lineSpan = ifStatement.GetLocation().GetLineSpan();
            var typeInfo = semanticModel.GetTypeInfo(fieldExpr);
            var typeName = typeInfo.Type?.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat) ?? "T";

            opportunities.Add(new OptimizationOpportunity
            {
                Category = Category,
                Type = "NullCheckInitPattern",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                Description = $"Null-check + initialize pattern for '{fieldName}'. Consider using Lazy<T> for thread-safe lazy initialization.",
                CurrentCode = ifStatement.ToFullString().Trim(),
                SuggestedCode = $"// private readonly Lazy<{typeName}> _{fieldName} = new Lazy<{typeName}>(() => /* initialization */);\n// Usage: _{fieldName}.Value",
                Confidence = OptimizationConfidence.Medium,
                Impact = OptimizationImpact.Low,
                IsSemanticallySafe = false,
                Assumptions = ["Thread-safety is desired", "Initialization is deterministic"],
                Risks = ["Lazy<T> has slight overhead for thread-safety"]
            });
        }
    }

    private AssignmentExpressionSyntax? FindAssignmentInStatement(StatementSyntax statement, string targetName)
    {
        IEnumerable<StatementSyntax> statements = statement switch
        {
            BlockSyntax block => block.Statements,
            _ => new[] { statement }
        };

        foreach (var stmt in statements)
        {
            if (stmt is ExpressionStatementSyntax exprStmt &&
                exprStmt.Expression is AssignmentExpressionSyntax assignment)
            {
                if (assignment.Left.ToFullString().Trim() == targetName)
                    return assignment;
            }
        }

        return null;
    }

    private void DetectDoubleCheckLocking(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        // Find lock statements
        foreach (var lockStatement in root.DescendantNodes().OfType<LockStatementSyntax>())
        {
            // Check if there's a null check before the lock
            var parent = lockStatement.Parent;
            if (parent is not BlockSyntax block)
                continue;

            var index = block.Statements.IndexOf(lockStatement);
            if (index <= 0)
                continue;

            var previousStatement = block.Statements[index - 1];
            if (previousStatement is not IfStatementSyntax outerIf)
                continue;

            // Check for null comparison in outer if
            if (outerIf.Condition is not BinaryExpressionSyntax outerBinary)
                continue;

            if (outerBinary.Kind() != SyntaxKind.EqualsExpression)
                continue;

            // Check for inner null check inside lock
            var innerIf = lockStatement.Statement.DescendantNodes()
                .OfType<IfStatementSyntax>()
                .FirstOrDefault();

            if (innerIf == null)
                continue;

            // This is a double-check locking pattern
            var lineSpan = outerIf.GetLocation().GetLineSpan();

            // Check if the field is marked volatile
            var fieldExpr = outerBinary.Left is LiteralExpressionSyntax ? outerBinary.Right : outerBinary.Left;
            var symbol = semanticModel.GetSymbolInfo(fieldExpr).Symbol as IFieldSymbol;
            var isVolatile = symbol?.IsVolatile ?? false;
            var fieldName = symbol?.Name ?? "field";
            var typeInfo = semanticModel.GetTypeInfo(fieldExpr);
            var typeName = typeInfo.Type?.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat) ?? "T";

            if (!isVolatile)
            {
                opportunities.Add(new OptimizationOpportunity
                {
                    Category = Category,
                    Type = "DoubleCheckLockingWithoutVolatile",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = $"Double-check locking pattern without volatile field. Use LazyInitializer.EnsureInitialized for correct implementation.",
                    CurrentCode = $"// Current pattern around line {lineSpan.StartLinePosition.Line + 1}",
                    SuggestedCode = $"// LazyInitializer.EnsureInitialized(ref _{fieldName}, () => /* initialization */);\n// Or: private readonly Lazy<{typeName}> _{fieldName} = new(...);",
                    Confidence = OptimizationConfidence.High,
                    Impact = OptimizationImpact.High,
                    IsSemanticallySafe = false,
                    Risks = ["Without volatile, JIT may reorder reads and break thread-safety"]
                });
            }
            else
            {
                opportunities.Add(new OptimizationOpportunity
                {
                    Category = Category,
                    Type = "DoubleCheckLockingSimplification",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = "Double-check locking can be replaced with simpler LazyInitializer.EnsureInitialized.",
                    CurrentCode = $"// Double-check locking pattern",
                    SuggestedCode = $"// LazyInitializer.EnsureInitialized(ref _{fieldName}, ref _lock, () => /* initialization */);",
                    Confidence = OptimizationConfidence.Medium,
                    Impact = OptimizationImpact.Low,
                    IsSemanticallySafe = true
                });
            }
        }
    }

    private void DetectHeavyStaticConstructor(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        foreach (var staticCtor in root.DescendantNodes().OfType<ConstructorDeclarationSyntax>())
        {
            if (!staticCtor.Modifiers.Any(SyntaxKind.StaticKeyword))
                continue;

            if (staticCtor.Body == null)
                continue;

            // Count statements and check for expensive operations
            var statementCount = staticCtor.Body.Statements.Count;
            var hasExpensiveOps = HasExpensiveOperations(staticCtor.Body, semanticModel);

            if (statementCount < 5 && !hasExpensiveOps)
                continue;

            var lineSpan = staticCtor.GetLocation().GetLineSpan();
            var className = (staticCtor.Parent as ClassDeclarationSyntax)?.Identifier.Text ?? "Class";

            opportunities.Add(new OptimizationOpportunity
            {
                Category = Category,
                Type = "HeavyStaticConstructor",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                Description = $"Static constructor in '{className}' has {statementCount} statements. Heavy static constructors delay type loading. Consider lazy initialization.",
                CurrentCode = $"static {className}() {{ /* {statementCount} statements */ }}",
                SuggestedCode = "// Move expensive initialization to Lazy<T> fields\n// private static readonly Lazy<ExpensiveType> _instance = new(...);",
                Confidence = OptimizationConfidence.Medium,
                Impact = OptimizationImpact.Medium,
                IsSemanticallySafe = false,
                Assumptions = ["Lazy initialization is acceptable", "Not all values are needed immediately"],
                Risks = ["Initialization order may change"]
            });
        }
    }

    private bool HasExpensiveOperations(BlockSyntax block, SemanticModel semanticModel)
    {
        // Check for I/O, database, or other expensive operations
        foreach (var invocation in block.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
            if (symbol == null)
                continue;

            var methodName = symbol.Name.ToLowerInvariant();
            var typeName = symbol.ContainingType?.Name.ToLowerInvariant() ?? "";

            // Known expensive operations
            if (methodName.Contains("read") ||
                methodName.Contains("load") ||
                methodName.Contains("parse") ||
                methodName.Contains("connect") ||
                methodName.Contains("open") ||
                typeName.Contains("file") ||
                typeName.Contains("stream") ||
                typeName.Contains("database") ||
                typeName.Contains("http") ||
                typeName.Contains("socket"))
            {
                return true;
            }
        }

        // Check for object creations that might be expensive
        var creationCount = block.DescendantNodes().OfType<ObjectCreationExpressionSyntax>().Count();
        return creationCount > 5;
    }

    private void DetectEagerInitialization(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<OptimizationOpportunity> opportunities)
    {
        // Find field initializations that might benefit from lazy loading
        foreach (var field in root.DescendantNodes().OfType<FieldDeclarationSyntax>())
        {
            foreach (var variable in field.Declaration.Variables)
            {
                if (variable.Initializer == null)
                    continue;

                // Check if it's an expensive initialization
                var initExpr = variable.Initializer.Value;
                if (!IsExpensiveInitialization(initExpr, semanticModel))
                    continue;

                // Check usage in the containing class
                var containingType = field.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault();
                if (containingType == null)
                    continue;

                var fieldName = variable.Identifier.Text;
                var usageCount = CountFieldUsages(containingType, fieldName, semanticModel);

                // If field is used in few places, suggest lazy initialization
                if (usageCount > 5)
                    continue;

                var lineSpan = variable.GetLocation().GetLineSpan();
                var typeInfo = semanticModel.GetTypeInfo(initExpr);
                var typeName = typeInfo.Type?.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat) ?? "T";

                opportunities.Add(new OptimizationOpportunity
                {
                    Category = Category,
                    Type = "EagerInitialization",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = $"Field '{fieldName}' has expensive initialization but is only used {usageCount} times. Consider lazy initialization.",
                    CurrentCode = field.ToFullString().Trim(),
                    SuggestedCode = $"private readonly Lazy<{typeName}> _{fieldName} = new Lazy<{typeName}>(() => {initExpr.ToFullString().Trim()});",
                    Confidence = OptimizationConfidence.Low,
                    Impact = OptimizationImpact.Low,
                    IsSemanticallySafe = false,
                    Assumptions = ["Field is not always needed", "Initialization can be deferred"],
                    Risks = ["Initialization happens on first access, which may be in a critical path"]
                });
            }
        }
    }

    private bool IsExpensiveInitialization(ExpressionSyntax expr, SemanticModel semanticModel)
    {
        // New object creation
        if (expr is ObjectCreationExpressionSyntax creation)
        {
            // Check if it's creating something expensive
            var typeInfo = semanticModel.GetTypeInfo(creation);
            var typeName = typeInfo.Type?.ToDisplayString() ?? "";

            // Known expensive types
            if (typeName.Contains("Dictionary") ||
                typeName.Contains("HashSet") ||
                typeName.Contains("Collection") ||
                typeName.Contains("Database") ||
                typeName.Contains("Connection") ||
                typeName.Contains("Client") ||
                typeName.Contains("Service"))
            {
                return true;
            }

            // Check if constructor has arguments
            if (creation.ArgumentList?.Arguments.Count > 2)
                return true;

            // Check for collection initializer
            if (creation.Initializer?.Expressions.Count > 3)
                return true;
        }

        // Method invocation
        if (expr is InvocationExpressionSyntax invocation)
        {
            var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
            var methodName = symbol?.Name.ToLowerInvariant() ?? "";

            return methodName.Contains("create") ||
                   methodName.Contains("build") ||
                   methodName.Contains("load") ||
                   methodName.Contains("parse") ||
                   methodName.Contains("initialize");
        }

        return false;
    }

    private int CountFieldUsages(TypeDeclarationSyntax type, string fieldName, SemanticModel semanticModel)
    {
        var count = 0;
        foreach (var identifier in type.DescendantNodes().OfType<IdentifierNameSyntax>())
        {
            if (identifier.Identifier.Text == fieldName)
            {
                // Verify it's actually referencing the field
                var symbol = semanticModel.GetSymbolInfo(identifier).Symbol;
                if (symbol is IFieldSymbol)
                    count++;
            }
        }
        return count;
    }
}
