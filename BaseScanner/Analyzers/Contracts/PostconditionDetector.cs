using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Contracts.Models;

namespace BaseScanner.Analyzers.Contracts;

/// <summary>
/// Detects postconditions and return value guarantees in methods.
/// Identifies patterns where methods implicitly guarantee certain return value properties.
/// </summary>
public class PostconditionDetector
{
    /// <summary>
    /// Detect postconditions in a syntax tree.
    /// </summary>
    public List<PostconditionIssue> Detect(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<PostconditionIssue>();

        var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>();

        foreach (var method in methods)
        {
            var className = GetClassName(method);
            var body = (SyntaxNode?)method.Body ?? method.ExpressionBody;
            if (body == null) continue;

            var returnType = method.ReturnType.ToString();
            if (returnType == "void" || returnType == "Task")
                continue;

            // Detect return value guarantees
            issues.AddRange(DetectNullGuarantees(method, body, semanticModel, filePath, className));
            issues.AddRange(DetectCollectionGuarantees(method, body, semanticModel, filePath, className));
            issues.AddRange(DetectRangeGuarantees(method, body, semanticModel, filePath, className));
            issues.AddRange(DetectStateGuarantees(method, body, semanticModel, filePath, className));
        }

        return issues;
    }

    private IEnumerable<PostconditionIssue> DetectNullGuarantees(
        MethodDeclarationSyntax method,
        SyntaxNode body,
        SemanticModel semanticModel,
        string filePath,
        string className)
    {
        var issues = new List<PostconditionIssue>();
        var returnType = method.ReturnType.ToString();

        // Check if return type is nullable
        bool isNullableReturnType = returnType.EndsWith("?") ||
                                    returnType.StartsWith("Nullable<");

        // Analyze all return statements
        var returnStatements = body.DescendantNodes().OfType<ReturnStatementSyntax>().ToList();

        if (returnStatements.Count == 0 && method.ExpressionBody != null)
        {
            // Expression-bodied method
            var exprValue = method.ExpressionBody.Expression;
            returnStatements.Add(SyntaxFactory.ReturnStatement(exprValue));
        }

        bool hasNullReturn = false;
        bool hasNewObjectReturn = false;
        bool allPathsReturnNonNull = true;

        foreach (var ret in returnStatements)
        {
            if (ret.Expression == null)
                continue;

            if (IsNullLiteral(ret.Expression))
            {
                hasNullReturn = true;
                allPathsReturnNonNull = false;
            }
            else if (IsDefinitelyNotNull(ret.Expression, semanticModel))
            {
                hasNewObjectReturn = true;
            }
            else
            {
                // Unknown - could be null
                allPathsReturnNonNull = false;
            }
        }

        // Report if method never returns null but type suggests it could
        if (allPathsReturnNonNull && hasNewObjectReturn && !isNullableReturnType && returnStatements.Count > 0)
        {
            var lineSpan = method.ReturnType.GetLocation().GetLineSpan();
            issues.Add(new PostconditionIssue
            {
                Type = ContractType.Postcondition,
                Severity = ContractSeverity.Info,
                FilePath = filePath,
                Line = lineSpan.StartLinePosition.Line + 1,
                Column = lineSpan.StartLinePosition.Character + 1,
                ClassName = className,
                MethodName = method.Identifier.Text,
                Description = $"Method '{method.Identifier.Text}' never returns null",
                Suggestion = "Consider documenting this guarantee with [NotNull] attribute or XML docs",
                CodeSnippet = method.ReturnType.ToString(),
                SuggestedFix = $"/// <returns>Never null.</returns>\n[return: NotNull]",
                TargetExpression = "return value",
                Guarantee = "Never returns null",
                IsInferred = true,
                Confidence = 0.9
            });
        }

        // Report if method returns null but type is not nullable
        if (hasNullReturn && !isNullableReturnType && !returnType.Contains("?"))
        {
            var nullReturn = returnStatements.First(r => r.Expression != null && IsNullLiteral(r.Expression));
            var lineSpan = nullReturn.GetLocation().GetLineSpan();
            issues.Add(new PostconditionIssue
            {
                Type = ContractType.Postcondition,
                Severity = ContractSeverity.Warning,
                FilePath = filePath,
                Line = lineSpan.StartLinePosition.Line + 1,
                Column = lineSpan.StartLinePosition.Character + 1,
                ClassName = className,
                MethodName = method.Identifier.Text,
                Description = $"Method returns null but return type '{returnType}' is not nullable",
                Suggestion = $"Change return type to '{returnType}?' or return a default value",
                CodeSnippet = nullReturn.ToString(),
                SuggestedFix = $"public {returnType}? {method.Identifier.Text}(...)",
                TargetExpression = "return value",
                Guarantee = "May return null",
                IsInferred = true,
                Confidence = 1.0
            });
        }

        return issues;
    }

    private IEnumerable<PostconditionIssue> DetectCollectionGuarantees(
        MethodDeclarationSyntax method,
        SyntaxNode body,
        SemanticModel semanticModel,
        string filePath,
        string className)
    {
        var issues = new List<PostconditionIssue>();
        var returnType = method.ReturnType.ToString();

        // Check if return type is a collection
        if (!IsCollectionType(returnType))
            return issues;

        var returnStatements = GetAllReturnExpressions(body, method);

        bool alwaysReturnsEmpty = false;
        bool neverReturnsEmpty = false;
        bool alwaysReturnsNewCollection = true;

        foreach (var expr in returnStatements)
        {
            if (IsEmptyCollection(expr))
            {
                alwaysReturnsEmpty = true;
            }
            else if (IsNewCollection(expr))
            {
                // Good - returns new collection
            }
            else
            {
                alwaysReturnsNewCollection = false;
            }
        }

        // Detect methods that always return non-empty collections
        var methodName = method.Identifier.Text.ToLower();
        if (methodName.StartsWith("get") && returnStatements.Any() &&
            returnStatements.All(e => IsNewCollectionWithElements(e)))
        {
            var lineSpan = method.ReturnType.GetLocation().GetLineSpan();
            issues.Add(new PostconditionIssue
            {
                Type = ContractType.Postcondition,
                Severity = ContractSeverity.Info,
                FilePath = filePath,
                Line = lineSpan.StartLinePosition.Line + 1,
                Column = lineSpan.StartLinePosition.Character + 1,
                ClassName = className,
                MethodName = method.Identifier.Text,
                Description = "Method always returns a non-empty collection",
                Suggestion = "Document this guarantee for callers",
                CodeSnippet = returnType,
                SuggestedFix = "/// <returns>A non-empty collection.</returns>",
                TargetExpression = "return value",
                Guarantee = "Never returns empty collection",
                IsInferred = true,
                Confidence = 0.7
            });
        }

        // Detect if method could return the internal collection (aliasing issue)
        var fieldReturns = returnStatements
            .Where(e => IsFieldOrPropertyAccess(e, semanticModel))
            .ToList();

        if (fieldReturns.Any())
        {
            var firstReturn = fieldReturns.First();
            var lineSpan = firstReturn.GetLocation().GetLineSpan();
            issues.Add(new PostconditionIssue
            {
                Type = ContractType.Postcondition,
                Severity = ContractSeverity.Warning,
                FilePath = filePath,
                Line = lineSpan.StartLinePosition.Line + 1,
                Column = lineSpan.StartLinePosition.Character + 1,
                ClassName = className,
                MethodName = method.Identifier.Text,
                Description = "Method returns internal collection - callers can modify class state",
                Suggestion = "Return a copy or use IReadOnlyList/IReadOnlyCollection",
                CodeSnippet = firstReturn.ToString(),
                SuggestedFix = $"return {firstReturn}.ToList(); // or .AsReadOnly()",
                TargetExpression = "return value",
                Guarantee = "Returns mutable reference to internal state",
                IsInferred = true,
                Confidence = 0.85
            });
        }

        return issues;
    }

    private IEnumerable<PostconditionIssue> DetectRangeGuarantees(
        MethodDeclarationSyntax method,
        SyntaxNode body,
        SemanticModel semanticModel,
        string filePath,
        string className)
    {
        var issues = new List<PostconditionIssue>();
        var returnType = method.ReturnType.ToString();

        // Check for numeric return types
        if (!IsNumericType(returnType))
            return issues;

        var returnStatements = GetAllReturnExpressions(body, method);
        var methodName = method.Identifier.Text.ToLower();

        // Detect methods that return counts/sizes (always non-negative)
        if (methodName.Contains("count") || methodName.Contains("length") ||
            methodName.Contains("size") || methodName.StartsWith("get") && methodName.Contains("count"))
        {
            var allNonNegative = returnStatements.All(e => IsGuaranteedNonNegative(e, semanticModel));
            if (allNonNegative)
            {
                var lineSpan = method.ReturnType.GetLocation().GetLineSpan();
                issues.Add(new PostconditionIssue
                {
                    Type = ContractType.Postcondition,
                    Severity = ContractSeverity.Info,
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    ClassName = className,
                    MethodName = method.Identifier.Text,
                    Description = "Method always returns a non-negative value",
                    Suggestion = "Document this range guarantee",
                    CodeSnippet = returnType,
                    SuggestedFix = "/// <returns>A non-negative integer.</returns>",
                    TargetExpression = "return value",
                    Guarantee = "Always >= 0",
                    IsInferred = true,
                    Confidence = 0.75
                });
            }
        }

        // Detect methods with index/position in name that might return -1 for not found
        if (methodName.Contains("index") || methodName.Contains("find") ||
            methodName.Contains("search") || methodName.Contains("position"))
        {
            var mightReturnNegative = returnStatements.Any(e =>
                IsNegativeLiteral(e) || e.ToString().Contains("-1"));

            if (mightReturnNegative)
            {
                var lineSpan = method.ReturnType.GetLocation().GetLineSpan();
                issues.Add(new PostconditionIssue
                {
                    Type = ContractType.Postcondition,
                    Severity = ContractSeverity.Info,
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    ClassName = className,
                    MethodName = method.Identifier.Text,
                    Description = "Method may return -1 to indicate 'not found'",
                    Suggestion = "Document this behavior or consider using nullable int or TryGet pattern",
                    CodeSnippet = returnType,
                    SuggestedFix = "/// <returns>The index, or -1 if not found.</returns>\n// Or use: public int? TryFind...()",
                    TargetExpression = "return value",
                    Guarantee = "Returns -1 when not found",
                    IsInferred = true,
                    Confidence = 0.8
                });
            }
        }

        return issues;
    }

    private IEnumerable<PostconditionIssue> DetectStateGuarantees(
        MethodDeclarationSyntax method,
        SyntaxNode body,
        SemanticModel semanticModel,
        string filePath,
        string className)
    {
        var issues = new List<PostconditionIssue>();
        var methodName = method.Identifier.Text;

        // Factory methods should return initialized objects
        if (methodName.StartsWith("Create") || methodName.StartsWith("Build") ||
            methodName.StartsWith("Make") || methodName.StartsWith("New"))
        {
            var returnStatements = GetAllReturnExpressions(body, method);
            var allReturnNew = returnStatements.All(e =>
                e is ObjectCreationExpressionSyntax ||
                e is ImplicitObjectCreationExpressionSyntax);

            if (allReturnNew && returnStatements.Any())
            {
                var lineSpan = method.Identifier.GetLocation().GetLineSpan();
                issues.Add(new PostconditionIssue
                {
                    Type = ContractType.Postcondition,
                    Severity = ContractSeverity.Info,
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    ClassName = className,
                    MethodName = methodName,
                    Description = "Factory method always returns a newly created instance",
                    Suggestion = "Document this guarantee",
                    CodeSnippet = method.ReturnType.ToString(),
                    SuggestedFix = "/// <returns>A new instance, never null.</returns>",
                    TargetExpression = "return value",
                    Guarantee = "Returns new instance",
                    IsInferred = true,
                    Confidence = 0.9
                });
            }
        }

        // Detect async methods that should return completed tasks in some paths
        var returnType = method.ReturnType.ToString();
        if (returnType.StartsWith("Task") || returnType.StartsWith("ValueTask"))
        {
            var returnStatements = GetAllReturnExpressions(body, method);
            var hasCompletedTaskReturn = returnStatements.Any(e =>
                e.ToString().Contains("Task.CompletedTask") ||
                e.ToString().Contains("Task.FromResult") ||
                e.ToString().Contains("ValueTask.CompletedTask"));

            if (hasCompletedTaskReturn)
            {
                var lineSpan = method.Identifier.GetLocation().GetLineSpan();
                issues.Add(new PostconditionIssue
                {
                    Type = ContractType.Postcondition,
                    Severity = ContractSeverity.Info,
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    ClassName = className,
                    MethodName = methodName,
                    Description = "Method may return synchronously in some code paths",
                    Suggestion = "Consider using ValueTask for better performance if synchronous returns are common",
                    CodeSnippet = returnType,
                    SuggestedFix = $"public ValueTask<...> {methodName}Async(...)",
                    TargetExpression = "return value",
                    Guarantee = "May complete synchronously",
                    IsInferred = true,
                    Confidence = 0.7
                });
            }
        }

        return issues;
    }

    private List<ExpressionSyntax> GetAllReturnExpressions(SyntaxNode body, MethodDeclarationSyntax method)
    {
        var expressions = new List<ExpressionSyntax>();

        var returnStatements = body.DescendantNodes().OfType<ReturnStatementSyntax>();
        foreach (var ret in returnStatements)
        {
            if (ret.Expression != null)
                expressions.Add(ret.Expression);
        }

        if (method.ExpressionBody != null)
        {
            expressions.Add(method.ExpressionBody.Expression);
        }

        return expressions;
    }

    private bool IsNullLiteral(ExpressionSyntax expr)
    {
        return expr is LiteralExpressionSyntax literal &&
               literal.IsKind(SyntaxKind.NullLiteralExpression);
    }

    private bool IsDefinitelyNotNull(ExpressionSyntax expr, SemanticModel semanticModel)
    {
        // New object creation
        if (expr is ObjectCreationExpressionSyntax or ImplicitObjectCreationExpressionSyntax)
            return true;

        // Array creation
        if (expr is ArrayCreationExpressionSyntax or ImplicitArrayCreationExpressionSyntax)
            return true;

        // String literal
        if (expr is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression))
            return true;

        // Collection expressions
        if (expr is CollectionExpressionSyntax)
            return true;

        // Null-coalescing with non-null fallback
        if (expr is BinaryExpressionSyntax binary &&
            binary.IsKind(SyntaxKind.CoalesceExpression) &&
            IsDefinitelyNotNull(binary.Right, semanticModel))
            return true;

        // throw expression (never returns)
        if (expr is ThrowExpressionSyntax)
            return true;

        return false;
    }

    private bool IsCollectionType(string typeName)
    {
        var collectionPatterns = new[]
        {
            "List<", "IList<", "IEnumerable<", "ICollection<",
            "Array", "[]", "Dictionary<", "HashSet<",
            "IReadOnlyList<", "IReadOnlyCollection<", "ImmutableList<",
            "Queue<", "Stack<", "LinkedList<"
        };

        return collectionPatterns.Any(p => typeName.Contains(p));
    }

    private bool IsEmptyCollection(ExpressionSyntax expr)
    {
        var text = expr.ToString();
        return text.Contains("Empty") ||
               text == "[]" ||
               text.Contains("new List<") && text.Contains("()") ||
               text.Contains("Array.Empty");
    }

    private bool IsNewCollection(ExpressionSyntax expr)
    {
        return expr is ObjectCreationExpressionSyntax ||
               expr is ImplicitObjectCreationExpressionSyntax ||
               expr is ArrayCreationExpressionSyntax ||
               expr is CollectionExpressionSyntax;
    }

    private bool IsNewCollectionWithElements(ExpressionSyntax expr)
    {
        if (expr is ObjectCreationExpressionSyntax objCreate)
        {
            // new List<T> { ... } with initializer
            return objCreate.Initializer?.Expressions.Count > 0;
        }

        if (expr is ArrayCreationExpressionSyntax arrayCreate)
        {
            return arrayCreate.Initializer?.Expressions.Count > 0;
        }

        if (expr is CollectionExpressionSyntax collection)
        {
            return collection.Elements.Count > 0;
        }

        return false;
    }

    private bool IsFieldOrPropertyAccess(ExpressionSyntax expr, SemanticModel semanticModel)
    {
        if (expr is IdentifierNameSyntax id)
        {
            var symbol = semanticModel.GetSymbolInfo(id).Symbol;
            return symbol is IFieldSymbol or IPropertySymbol;
        }

        if (expr is MemberAccessExpressionSyntax memberAccess &&
            memberAccess.Expression is ThisExpressionSyntax)
        {
            return true;
        }

        return false;
    }

    private bool IsNumericType(string typeName)
    {
        return typeName is "int" or "long" or "short" or "byte" or "float" or "double" or "decimal" or
            "Int32" or "Int64" or "UInt32" or "UInt64" or "uint" or "ulong";
    }

    private bool IsGuaranteedNonNegative(ExpressionSyntax expr, SemanticModel semanticModel)
    {
        // Literal values
        if (expr is LiteralExpressionSyntax literal)
        {
            if (int.TryParse(literal.Token.ValueText, out int val))
                return val >= 0;
        }

        // Count/Length properties
        var text = expr.ToString().ToLower();
        if (text.EndsWith(".count") || text.EndsWith(".length") || text.EndsWith(".size"))
            return true;

        // Math.Abs
        if (text.Contains("math.abs"))
            return true;

        return false;
    }

    private bool IsNegativeLiteral(ExpressionSyntax expr)
    {
        if (expr is PrefixUnaryExpressionSyntax prefix &&
            prefix.IsKind(SyntaxKind.UnaryMinusExpression))
        {
            return true;
        }

        var text = expr.ToString();
        return text == "-1" || text.StartsWith("-");
    }

    private string GetClassName(MethodDeclarationSyntax method)
    {
        return method.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault()?.Identifier.Text ?? "Unknown";
    }
}
