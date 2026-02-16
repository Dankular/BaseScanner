using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Concurrency.Models;

namespace BaseScanner.Analyzers.Concurrency.Detectors;

/// <summary>
/// Detects race condition patterns including:
/// - Check-then-act patterns (TOCTOU - Time of Check to Time of Use)
/// - Double-checked locking without volatile
/// - Unsafe lazy initialization
/// </summary>
public class RaceConditionDetector : IThreadSafetyDetector
{
    public string Name => "RaceCondition";

    public string Description => "Detects potential race conditions and TOCTOU vulnerabilities";

    public IReadOnlyList<string> SupportedRules =>
    [
        ThreadSafetyRules.DoubleCheckedLocking,
        ThreadSafetyRules.CheckThenActRace
    ];

    public Task<List<ThreadSafetyIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        ThreadSafetyAnalysisContext? context = null)
    {
        var issues = new List<ThreadSafetyIssue>();

        issues.AddRange(DetectDoubleCheckedLocking(root, semanticModel, document.FilePath ?? ""));
        issues.AddRange(DetectCheckThenActPatterns(root, semanticModel, document.FilePath ?? ""));
        issues.AddRange(DetectUnsafeLazyInitialization(root, semanticModel, document.FilePath ?? ""));

        return Task.FromResult(issues);
    }

    private IEnumerable<ThreadSafetyIssue> DetectDoubleCheckedLocking(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<ThreadSafetyIssue>();

        foreach (var ifStatement in root.DescendantNodes().OfType<IfStatementSyntax>())
        {
            if (!IsDoubleCheckedLockingPattern(ifStatement, out var lockStatement, out var innerIf))
                continue;

            // Get the field being checked
            var fieldAccess = GetFieldAccess(ifStatement.Condition);
            if (fieldAccess == null) continue;

            var symbol = semanticModel.GetSymbolInfo(fieldAccess).Symbol;
            if (symbol is not IFieldSymbol field) continue;

            // Check if field is volatile
            if (field.IsVolatile) continue;

            var location = ifStatement.GetLocation().GetLineSpan();
            var classDecl = ifStatement.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
            var methodDecl = ifStatement.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

            issues.Add(new ThreadSafetyIssue
            {
                IssueType = "DoubleCheckedLocking",
                RuleId = ThreadSafetyRules.DoubleCheckedLocking,
                Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.DoubleCheckedLocking),
                Message = $"Double-checked locking on non-volatile field '{field.Name}' may fail due to memory model",
                FilePath = filePath,
                Line = location.StartLinePosition.Line + 1,
                EndLine = location.EndLinePosition.Line + 1,
                Column = location.StartLinePosition.Character + 1,
                ClassName = classDecl?.Identifier.Text,
                MethodName = methodDecl?.Identifier.Text,
                MemberName = field.Name,
                CodeSnippet = GetDoubleCheckedLockingSnippet(ifStatement),
                SuggestedFix = "Add 'volatile' modifier to field, use Lazy<T>, or use Interlocked.CompareExchange",
                CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.DoubleCheckedLocking),
                Metadata = new Dictionary<string, object>
                {
                    ["FieldType"] = field.Type.ToDisplayString(),
                    ["IsStatic"] = field.IsStatic
                }
            });
        }

        return issues;
    }

    private IEnumerable<ThreadSafetyIssue> DetectCheckThenActPatterns(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<ThreadSafetyIssue>();

        foreach (var ifStatement in root.DescendantNodes().OfType<IfStatementSyntax>())
        {
            // Check for dictionary ContainsKey then indexer access
            if (IsContainsKeyThenAccess(ifStatement, semanticModel, out var collectionName))
            {
                var location = ifStatement.GetLocation().GetLineSpan();
                var classDecl = ifStatement.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
                var methodDecl = ifStatement.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "CheckThenActRace",
                    RuleId = ThreadSafetyRules.CheckThenActRace,
                    Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.CheckThenActRace),
                    Message = $"Check-then-act on '{collectionName}' - ContainsKey followed by indexer access may race",
                    FilePath = filePath,
                    Line = location.StartLinePosition.Line + 1,
                    EndLine = location.EndLinePosition.Line + 1,
                    ClassName = classDecl?.Identifier.Text,
                    MethodName = methodDecl?.Identifier.Text,
                    CodeSnippet = ifStatement.Condition.ToString(),
                    SuggestedFix = "Use TryGetValue or ConcurrentDictionary.GetOrAdd for thread safety",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.CheckThenActRace)
                });
            }

            // Check for collection Count/Any check then access
            if (IsCountCheckThenAccess(ifStatement, semanticModel, out var collName))
            {
                var location = ifStatement.GetLocation().GetLineSpan();
                var classDecl = ifStatement.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
                var methodDecl = ifStatement.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "CheckThenActRace",
                    RuleId = ThreadSafetyRules.CheckThenActRace,
                    Severity = "Medium",
                    Message = $"Check-then-act on '{collName}' - Count check followed by element access may race",
                    FilePath = filePath,
                    Line = location.StartLinePosition.Line + 1,
                    EndLine = location.EndLinePosition.Line + 1,
                    ClassName = classDecl?.Identifier.Text,
                    MethodName = methodDecl?.Identifier.Text,
                    CodeSnippet = ifStatement.Condition.ToString(),
                    SuggestedFix = "Use lock or thread-safe collection with atomic TryDequeue/TryTake",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.CheckThenActRace)
                });
            }

            // Check for null check then access pattern on shared field
            if (IsNullCheckThenAccessOnSharedField(ifStatement, semanticModel, out var fieldName))
            {
                var location = ifStatement.GetLocation().GetLineSpan();
                var classDecl = ifStatement.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
                var methodDecl = ifStatement.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "CheckThenActRace",
                    RuleId = ThreadSafetyRules.CheckThenActRace,
                    Severity = "Medium",
                    Message = $"Null check on shared field '{fieldName}' followed by access may race",
                    FilePath = filePath,
                    Line = location.StartLinePosition.Line + 1,
                    EndLine = location.EndLinePosition.Line + 1,
                    ClassName = classDecl?.Identifier.Text,
                    MethodName = methodDecl?.Identifier.Text,
                    CodeSnippet = ifStatement.Condition.ToString(),
                    SuggestedFix = "Use Interlocked.CompareExchange for thread-safe initialization",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.CheckThenActRace)
                });
            }
        }

        return issues;
    }

    private IEnumerable<ThreadSafetyIssue> DetectUnsafeLazyInitialization(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<ThreadSafetyIssue>();

        // Look for patterns like: if (_instance == null) _instance = new Foo();
        foreach (var ifStatement in root.DescendantNodes().OfType<IfStatementSyntax>())
        {
            // Check if condition is field == null
            if (ifStatement.Condition is not BinaryExpressionSyntax binary) continue;
            if (!binary.IsKind(SyntaxKind.EqualsExpression)) continue;
            if (!IsNullCheck(binary)) continue;

            var fieldExpr = GetNonNullOperand(binary);
            if (fieldExpr == null) continue;

            var symbol = semanticModel.GetSymbolInfo(fieldExpr).Symbol;
            if (symbol is not IFieldSymbol field) continue;
            if (!field.IsStatic) continue; // Focus on static singleton patterns

            // Check if the body assigns to the same field
            var assignments = ifStatement.Statement.DescendantNodes()
                .OfType<AssignmentExpressionSyntax>()
                .Where(a => IsAssignmentToField(a, field, semanticModel))
                .ToList();

            if (assignments.Count == 0) continue;

            // Check if this is inside a lock
            if (IsInsideLock(ifStatement)) continue;

            var location = ifStatement.GetLocation().GetLineSpan();
            var classDecl = ifStatement.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
            var methodDecl = ifStatement.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

            issues.Add(new ThreadSafetyIssue
            {
                IssueType = "CheckThenActRace",
                RuleId = ThreadSafetyRules.CheckThenActRace,
                Severity = "High",
                Message = $"Unsafe lazy initialization of static field '{field.Name}' - multiple instances may be created",
                FilePath = filePath,
                Line = location.StartLinePosition.Line + 1,
                EndLine = location.EndLinePosition.Line + 1,
                ClassName = classDecl?.Identifier.Text,
                MethodName = methodDecl?.Identifier.Text,
                MemberName = field.Name,
                CodeSnippet = ifStatement.ToString().Split('\n')[0],
                SuggestedFix = "Use Lazy<T>, static constructor, or double-checked locking with volatile",
                CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.CheckThenActRace)
            });
        }

        return issues;
    }

    private bool IsDoubleCheckedLockingPattern(
        IfStatementSyntax ifStatement,
        out LockStatementSyntax? lockStatement,
        out IfStatementSyntax? innerIf)
    {
        lockStatement = null;
        innerIf = null;

        // Pattern: if (field == null) { lock (...) { if (field == null) { ... } } }
        if (ifStatement.Statement is not BlockSyntax block) return false;

        foreach (var statement in block.Statements)
        {
            if (statement is LockStatementSyntax lockStmt)
            {
                lockStatement = lockStmt;

                SyntaxNode? lockBody = lockStmt.Statement;
                if (lockBody is BlockSyntax lockBlock)
                {
                    foreach (var inner in lockBlock.Statements)
                    {
                        if (inner is IfStatementSyntax innerIfStmt)
                        {
                            // Check if same condition
                            if (AreConditionsEquivalent(ifStatement.Condition, innerIfStmt.Condition))
                            {
                                innerIf = innerIfStmt;
                                return true;
                            }
                        }
                    }
                }
            }
        }

        return false;
    }

    private bool AreConditionsEquivalent(ExpressionSyntax cond1, ExpressionSyntax cond2)
    {
        // Simple string comparison - could be enhanced with semantic comparison
        return cond1.ToString().Trim() == cond2.ToString().Trim();
    }

    private ExpressionSyntax? GetFieldAccess(ExpressionSyntax condition)
    {
        if (condition is BinaryExpressionSyntax binary)
        {
            if (binary.Left is IdentifierNameSyntax || binary.Left is MemberAccessExpressionSyntax)
                return binary.Left;
            if (binary.Right is IdentifierNameSyntax || binary.Right is MemberAccessExpressionSyntax)
                return binary.Right;
        }
        if (condition is IsPatternExpressionSyntax isPattern)
        {
            return isPattern.Expression;
        }
        return null;
    }

    private string GetDoubleCheckedLockingSnippet(IfStatementSyntax ifStatement)
    {
        var lines = ifStatement.ToString().Split('\n');
        if (lines.Length > 5)
        {
            return string.Join("\n", lines.Take(3)) + "\n    ...";
        }
        return ifStatement.ToString();
    }

    private bool IsContainsKeyThenAccess(
        IfStatementSyntax ifStatement,
        SemanticModel semanticModel,
        out string collectionName)
    {
        collectionName = "";

        // Check for ContainsKey in condition
        var condition = ifStatement.Condition.ToString();
        if (!condition.Contains("ContainsKey") && !condition.Contains(".Contains("))
            return false;

        // Extract collection name from condition
        var containsInvocation = ifStatement.Condition.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .FirstOrDefault(i => i.Expression.ToString().Contains("ContainsKey") ||
                                  i.Expression.ToString().Contains(".Contains"));

        if (containsInvocation?.Expression is MemberAccessExpressionSyntax memberAccess)
        {
            collectionName = memberAccess.Expression.ToString();
            var localCollectionName = collectionName; // Copy for use in lambda

            // Check if body accesses the collection with indexer
            var body = ifStatement.Statement;
            var indexerAccesses = body.DescendantNodes()
                .OfType<ElementAccessExpressionSyntax>()
                .Where(e => e.Expression.ToString() == localCollectionName);

            return indexerAccesses.Any();
        }

        return false;
    }

    private bool IsCountCheckThenAccess(
        IfStatementSyntax ifStatement,
        SemanticModel semanticModel,
        out string collectionName)
    {
        collectionName = "";

        var condition = ifStatement.Condition.ToString();
        if (!condition.Contains(".Count") && !condition.Contains(".Length") && !condition.Contains(".Any()"))
            return false;

        // Find the collection being checked
        var memberAccesses = ifStatement.Condition.DescendantNodes()
            .OfType<MemberAccessExpressionSyntax>()
            .Where(m => m.Name.Identifier.Text is "Count" or "Length" or "Any");

        foreach (var memberAccess in memberAccesses)
        {
            collectionName = memberAccess.Expression.ToString();

            // Check if body accesses the collection by index or First()
            var body = ifStatement.Statement;
            var bodyText = body.ToString();

            if (bodyText.Contains($"{collectionName}[") ||
                bodyText.Contains($"{collectionName}.First") ||
                bodyText.Contains($"{collectionName}.Last") ||
                bodyText.Contains($"{collectionName}.ElementAt"))
            {
                return true;
            }
        }

        return false;
    }

    private bool IsNullCheckThenAccessOnSharedField(
        IfStatementSyntax ifStatement,
        SemanticModel semanticModel,
        out string fieldName)
    {
        fieldName = "";

        if (ifStatement.Condition is not BinaryExpressionSyntax binary) return false;
        if (!binary.IsKind(SyntaxKind.NotEqualsExpression)) return false;
        if (!IsNullCheck(binary)) return false;

        var fieldExpr = GetNonNullOperand(binary);
        if (fieldExpr == null) return false;

        var symbol = semanticModel.GetSymbolInfo(fieldExpr).Symbol;
        if (symbol is not IFieldSymbol field) return false;

        // Only flag static fields as they're more likely to be accessed concurrently
        if (!field.IsStatic) return false;
        if (field.IsReadOnly) return false;

        fieldName = field.Name;

        // Check if the field is used in the body
        var body = ifStatement.Statement;
        return body.DescendantNodes()
            .OfType<IdentifierNameSyntax>()
            .Any(id => id.Identifier.Text == field.Name);
    }

    private bool IsNullCheck(BinaryExpressionSyntax binary)
    {
        return binary.Right is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.NullLiteralExpression) ||
               binary.Left is LiteralExpressionSyntax leftLiteral && leftLiteral.IsKind(SyntaxKind.NullLiteralExpression);
    }

    private ExpressionSyntax? GetNonNullOperand(BinaryExpressionSyntax binary)
    {
        if (binary.Right is LiteralExpressionSyntax && binary.Right.IsKind(SyntaxKind.NullLiteralExpression))
            return binary.Left;
        if (binary.Left is LiteralExpressionSyntax && binary.Left.IsKind(SyntaxKind.NullLiteralExpression))
            return binary.Right;
        return null;
    }

    private bool IsAssignmentToField(AssignmentExpressionSyntax assignment, IFieldSymbol field, SemanticModel semanticModel)
    {
        var leftSymbol = semanticModel.GetSymbolInfo(assignment.Left).Symbol;
        return SymbolEqualityComparer.Default.Equals(leftSymbol, field);
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
}
