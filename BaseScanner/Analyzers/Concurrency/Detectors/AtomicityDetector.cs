using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Concurrency.Models;

namespace BaseScanner.Analyzers.Concurrency.Detectors;

/// <summary>
/// Detects non-atomic compound operations that may cause race conditions:
/// - counter++ / counter-- without Interlocked
/// - field = field + value without lock/Interlocked
/// - Compound assignments (+=, -=, etc.) on shared fields
/// </summary>
public class AtomicityDetector : IThreadSafetyDetector
{
    public string Name => "Atomicity";

    public string Description => "Detects non-atomic compound operations on shared state";

    public IReadOnlyList<string> SupportedRules =>
    [
        ThreadSafetyRules.NonAtomicIncrement
    ];

    public Task<List<ThreadSafetyIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        ThreadSafetyAnalysisContext? context = null)
    {
        var issues = new List<ThreadSafetyIssue>();

        issues.AddRange(DetectNonAtomicIncrementDecrement(root, semanticModel, document.FilePath ?? ""));
        issues.AddRange(DetectNonAtomicCompoundAssignment(root, semanticModel, document.FilePath ?? ""));
        issues.AddRange(DetectNonAtomicReadModifyWrite(root, semanticModel, document.FilePath ?? ""));

        return Task.FromResult(issues);
    }

    private IEnumerable<ThreadSafetyIssue> DetectNonAtomicIncrementDecrement(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<ThreadSafetyIssue>();

        // Detect postfix increment/decrement (counter++)
        foreach (var postfix in root.DescendantNodes().OfType<PostfixUnaryExpressionSyntax>())
        {
            if (!postfix.IsKind(SyntaxKind.PostIncrementExpression) &&
                !postfix.IsKind(SyntaxKind.PostDecrementExpression))
                continue;

            var issue = AnalyzeIncrementDecrement(postfix.Operand, postfix, semanticModel, filePath);
            if (issue != null)
                issues.Add(issue);
        }

        // Detect prefix increment/decrement (++counter)
        foreach (var prefix in root.DescendantNodes().OfType<PrefixUnaryExpressionSyntax>())
        {
            if (!prefix.IsKind(SyntaxKind.PreIncrementExpression) &&
                !prefix.IsKind(SyntaxKind.PreDecrementExpression))
                continue;

            var issue = AnalyzeIncrementDecrement(prefix.Operand, prefix, semanticModel, filePath);
            if (issue != null)
                issues.Add(issue);
        }

        return issues;
    }

    private ThreadSafetyIssue? AnalyzeIncrementDecrement(
        ExpressionSyntax operand,
        ExpressionSyntax fullExpression,
        SemanticModel semanticModel,
        string filePath)
    {
        var symbol = semanticModel.GetSymbolInfo(operand).Symbol;
        if (symbol is not IFieldSymbol field) return null;

        // Check if it's a potentially shared field
        if (!IsPotentiallyShared(field)) return null;

        // Skip if inside a lock
        if (IsInsideLock(fullExpression)) return null;

        // Skip if already using Interlocked
        if (IsPartOfInterlockedCall(fullExpression)) return null;

        var location = fullExpression.GetLocation().GetLineSpan();
        var classDecl = fullExpression.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
        var methodDecl = fullExpression.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

        var operation = fullExpression.IsKind(SyntaxKind.PostIncrementExpression) ||
                        fullExpression.IsKind(SyntaxKind.PreIncrementExpression)
            ? "increment"
            : "decrement";

        return new ThreadSafetyIssue
        {
            IssueType = "NonAtomicIncrement",
            RuleId = ThreadSafetyRules.NonAtomicIncrement,
            Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.NonAtomicIncrement),
            Message = $"Non-atomic {operation} on field '{field.Name}' - use Interlocked.{(operation == "increment" ? "Increment" : "Decrement")}",
            FilePath = filePath,
            Line = location.StartLinePosition.Line + 1,
            EndLine = location.EndLinePosition.Line + 1,
            Column = location.StartLinePosition.Character + 1,
            ClassName = classDecl?.Identifier.Text,
            MethodName = methodDecl?.Identifier.Text,
            MemberName = field.Name,
            CodeSnippet = fullExpression.ToString(),
            SuggestedFix = $"Interlocked.{(operation == "increment" ? "Increment" : "Decrement")}(ref {field.Name})",
            CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.NonAtomicIncrement),
            Metadata = new Dictionary<string, object>
            {
                ["FieldType"] = field.Type.ToDisplayString(),
                ["IsStatic"] = field.IsStatic,
                ["Operation"] = operation
            }
        };
    }

    private IEnumerable<ThreadSafetyIssue> DetectNonAtomicCompoundAssignment(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<ThreadSafetyIssue>();

        var compoundKinds = new[]
        {
            SyntaxKind.AddAssignmentExpression,
            SyntaxKind.SubtractAssignmentExpression,
            SyntaxKind.MultiplyAssignmentExpression,
            SyntaxKind.DivideAssignmentExpression,
            SyntaxKind.ModuloAssignmentExpression,
            SyntaxKind.AndAssignmentExpression,
            SyntaxKind.OrAssignmentExpression,
            SyntaxKind.ExclusiveOrAssignmentExpression
        };

        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (!compoundKinds.Contains(assignment.Kind())) continue;

            var symbol = semanticModel.GetSymbolInfo(assignment.Left).Symbol;
            if (symbol is not IFieldSymbol field) continue;

            // Check if it's a potentially shared field
            if (!IsPotentiallyShared(field)) continue;

            // Skip if inside a lock
            if (IsInsideLock(assignment)) continue;

            var location = assignment.GetLocation().GetLineSpan();
            var classDecl = assignment.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
            var methodDecl = assignment.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

            var operationType = GetOperationType(assignment.Kind());
            var suggestedFix = GetSuggestedFix(assignment, field);

            issues.Add(new ThreadSafetyIssue
            {
                IssueType = "NonAtomicIncrement",
                RuleId = ThreadSafetyRules.NonAtomicIncrement,
                Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.NonAtomicIncrement),
                Message = $"Non-atomic {operationType} on field '{field.Name}' may cause race condition",
                FilePath = filePath,
                Line = location.StartLinePosition.Line + 1,
                EndLine = location.EndLinePosition.Line + 1,
                Column = location.StartLinePosition.Character + 1,
                ClassName = classDecl?.Identifier.Text,
                MethodName = methodDecl?.Identifier.Text,
                MemberName = field.Name,
                CodeSnippet = assignment.ToString(),
                SuggestedFix = suggestedFix,
                CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.NonAtomicIncrement),
                Metadata = new Dictionary<string, object>
                {
                    ["FieldType"] = field.Type.ToDisplayString(),
                    ["IsStatic"] = field.IsStatic,
                    ["Operation"] = operationType
                }
            });
        }

        return issues;
    }

    private IEnumerable<ThreadSafetyIssue> DetectNonAtomicReadModifyWrite(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<ThreadSafetyIssue>();

        // Detect patterns like: field = field + 1
        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (!assignment.IsKind(SyntaxKind.SimpleAssignmentExpression)) continue;

            var leftSymbol = semanticModel.GetSymbolInfo(assignment.Left).Symbol;
            if (leftSymbol is not IFieldSymbol field) continue;

            // Check if right side references the same field
            if (!ReferencesField(assignment.Right, field, semanticModel)) continue;

            // Check if it's a potentially shared field
            if (!IsPotentiallyShared(field)) continue;

            // Skip if inside a lock
            if (IsInsideLock(assignment)) continue;

            // Skip if this is a compare-and-swap pattern
            if (IsCompareAndSwapPattern(assignment)) continue;

            var location = assignment.GetLocation().GetLineSpan();
            var classDecl = assignment.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
            var methodDecl = assignment.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

            issues.Add(new ThreadSafetyIssue
            {
                IssueType = "NonAtomicIncrement",
                RuleId = ThreadSafetyRules.NonAtomicIncrement,
                Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.NonAtomicIncrement),
                Message = $"Non-atomic read-modify-write on field '{field.Name}' - separate read and write may race",
                FilePath = filePath,
                Line = location.StartLinePosition.Line + 1,
                EndLine = location.EndLinePosition.Line + 1,
                Column = location.StartLinePosition.Character + 1,
                ClassName = classDecl?.Identifier.Text,
                MethodName = methodDecl?.Identifier.Text,
                MemberName = field.Name,
                CodeSnippet = assignment.ToString(),
                SuggestedFix = "Use Interlocked operations or lock for atomic update",
                CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.NonAtomicIncrement),
                Metadata = new Dictionary<string, object>
                {
                    ["FieldType"] = field.Type.ToDisplayString(),
                    ["IsStatic"] = field.IsStatic,
                    ["Pattern"] = "read-modify-write"
                }
            });
        }

        return issues;
    }

    private bool IsPotentiallyShared(IFieldSymbol field)
    {
        // Static fields are always potentially shared
        if (field.IsStatic) return true;

        // Volatile fields are explicitly marked as shared
        if (field.IsVolatile) return true;

        // Skip readonly and const
        if (field.IsReadOnly || field.IsConst) return false;

        // Check if the containing type might be shared (e.g., singleton, static class)
        var containingType = field.ContainingType;
        if (containingType != null)
        {
            // If the type has a static instance field of itself, it's likely a singleton
            var hasSingletonPattern = containingType.GetMembers()
                .OfType<IFieldSymbol>()
                .Any(f => f.IsStatic &&
                         SymbolEqualityComparer.Default.Equals(f.Type, containingType));

            if (hasSingletonPattern) return true;
        }

        // Check if field type suggests it's for synchronization
        var fieldTypeName = field.Type.ToDisplayString();
        if (fieldTypeName.Contains("Counter") ||
            fieldTypeName.Contains("Count") ||
            field.Name.Contains("counter", StringComparison.OrdinalIgnoreCase) ||
            field.Name.Contains("count", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // For instance fields in non-singleton classes, check if type is numeric
        // (commonly shared counters, flags, etc.)
        if (IsNumericType(field.Type))
        {
            // Check if the containing type has any async/thread-related members
            var hasAsyncMembers = containingType?.GetMembers()
                .OfType<IMethodSymbol>()
                .Any(m => m.IsAsync) ?? false;

            if (hasAsyncMembers) return true;
        }

        return false;
    }

    private bool IsNumericType(ITypeSymbol type)
    {
        return type.SpecialType switch
        {
            SpecialType.System_Int32 => true,
            SpecialType.System_Int64 => true,
            SpecialType.System_Int16 => true,
            SpecialType.System_Byte => true,
            SpecialType.System_UInt32 => true,
            SpecialType.System_UInt64 => true,
            SpecialType.System_UInt16 => true,
            SpecialType.System_SByte => true,
            SpecialType.System_Double => true,
            SpecialType.System_Single => true,
            SpecialType.System_Decimal => true,
            _ => false
        };
    }

    private bool IsInsideLock(SyntaxNode node)
    {
        var current = node.Parent;
        while (current != null)
        {
            if (current is LockStatementSyntax) return true;
            if (current is MethodDeclarationSyntax) break;
            current = current.Parent;
        }
        return false;
    }

    private bool IsPartOfInterlockedCall(SyntaxNode node)
    {
        var current = node.Parent;
        while (current != null)
        {
            if (current is InvocationExpressionSyntax invocation)
            {
                var expr = invocation.Expression.ToString();
                if (expr.Contains("Interlocked.")) return true;
            }
            if (current is ArgumentSyntax) continue;
            if (current is StatementSyntax) break;
            current = current.Parent;
        }
        return false;
    }

    private bool ReferencesField(ExpressionSyntax expression, IFieldSymbol field, SemanticModel semanticModel)
    {
        foreach (var identifier in expression.DescendantNodesAndSelf().OfType<IdentifierNameSyntax>())
        {
            var symbol = semanticModel.GetSymbolInfo(identifier).Symbol;
            if (SymbolEqualityComparer.Default.Equals(symbol, field))
                return true;
        }
        return false;
    }

    private bool IsCompareAndSwapPattern(AssignmentExpressionSyntax assignment)
    {
        // Check if this assignment is part of an Interlocked.CompareExchange pattern
        var parent = assignment.Parent;
        while (parent != null)
        {
            if (parent is InvocationExpressionSyntax invocation)
            {
                var expr = invocation.Expression.ToString();
                if (expr.Contains("Interlocked.CompareExchange") ||
                    expr.Contains("Interlocked.Exchange"))
                    return true;
            }
            if (parent is StatementSyntax) break;
            parent = parent.Parent;
        }
        return false;
    }

    private string GetOperationType(SyntaxKind kind) => kind switch
    {
        SyntaxKind.AddAssignmentExpression => "addition",
        SyntaxKind.SubtractAssignmentExpression => "subtraction",
        SyntaxKind.MultiplyAssignmentExpression => "multiplication",
        SyntaxKind.DivideAssignmentExpression => "division",
        SyntaxKind.ModuloAssignmentExpression => "modulo",
        SyntaxKind.AndAssignmentExpression => "bitwise AND",
        SyntaxKind.OrAssignmentExpression => "bitwise OR",
        SyntaxKind.ExclusiveOrAssignmentExpression => "XOR",
        _ => "compound assignment"
    };

    private string GetSuggestedFix(AssignmentExpressionSyntax assignment, IFieldSymbol field)
    {
        var kind = assignment.Kind();

        // For simple numeric operations, suggest Interlocked
        if (kind == SyntaxKind.AddAssignmentExpression)
        {
            // Check if adding 1
            if (assignment.Right.ToString().Trim() == "1")
                return $"Interlocked.Increment(ref {field.Name})";
            return $"Interlocked.Add(ref {field.Name}, {assignment.Right})";
        }

        if (kind == SyntaxKind.SubtractAssignmentExpression)
        {
            if (assignment.Right.ToString().Trim() == "1")
                return $"Interlocked.Decrement(ref {field.Name})";
            return $"Interlocked.Add(ref {field.Name}, -{assignment.Right})";
        }

        if (kind is SyntaxKind.AndAssignmentExpression or SyntaxKind.OrAssignmentExpression)
        {
            return $"Use Interlocked.And/Or (requires .NET 5+) or lock";
        }

        return "Use lock or Interlocked.Exchange with manual computation";
    }
}
