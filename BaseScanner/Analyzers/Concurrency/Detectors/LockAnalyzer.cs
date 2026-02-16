using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Concurrency.Models;

namespace BaseScanner.Analyzers.Concurrency.Detectors;

/// <summary>
/// Detects lock anti-patterns including:
/// - lock(this) - allows external code to deadlock
/// - lock("string") - string interning causes shared locks
/// - lock(typeof(T)) - Type objects are globally shared
/// - lock(new object()) - creates new lock each time
/// - lock on value types - boxing creates new objects
/// - Nested locks - potential deadlock from lock ordering
/// </summary>
public class LockAnalyzer : IThreadSafetyDetector
{
    public string Name => "LockAnalyzer";

    public string Description => "Detects lock anti-patterns and potential deadlocks";

    public IReadOnlyList<string> SupportedRules =>
    [
        ThreadSafetyRules.LockOnThis,
        ThreadSafetyRules.LockOnString,
        ThreadSafetyRules.LockOnType,
        ThreadSafetyRules.LockOnValueType,
        ThreadSafetyRules.LockOnNewObject,
        ThreadSafetyRules.NestedLocks
    ];

    public Task<List<ThreadSafetyIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        ThreadSafetyAnalysisContext? context = null)
    {
        var issues = new List<ThreadSafetyIssue>();
        context ??= new ThreadSafetyAnalysisContext();

        issues.AddRange(DetectLockAntiPatterns(root, semanticModel, document.FilePath ?? "", context));
        issues.AddRange(DetectNestedLocks(root, semanticModel, document.FilePath ?? "", context));
        issues.AddRange(DetectInconsistentLocking(root, semanticModel, document.FilePath ?? "", context));

        return Task.FromResult(issues);
    }

    private IEnumerable<ThreadSafetyIssue> DetectLockAntiPatterns(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        ThreadSafetyAnalysisContext context)
    {
        var issues = new List<ThreadSafetyIssue>();

        foreach (var lockStatement in root.DescendantNodes().OfType<LockStatementSyntax>())
        {
            var expression = lockStatement.Expression;
            var location = lockStatement.GetLocation().GetLineSpan();
            var classDecl = lockStatement.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
            var methodDecl = lockStatement.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            var className = classDecl?.Identifier.Text ?? "";
            var methodName = methodDecl?.Identifier.Text ?? "";

            // Register lock pattern for later analysis
            var lockInfo = new LockInfo
            {
                LockExpression = expression.ToString(),
                LockTargetType = GetLockTargetType(expression, semanticModel),
                MethodName = methodName,
                ClassName = className,
                FilePath = filePath,
                Line = location.StartLinePosition.Line + 1
            };
            context.RegisterLockPattern(lockInfo);

            // Check for lock(this)
            if (expression is ThisExpressionSyntax)
            {
                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "LockOnThis",
                    RuleId = ThreadSafetyRules.LockOnThis,
                    Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.LockOnThis),
                    Message = "Locking on 'this' is dangerous - external code can also lock on this instance causing deadlock",
                    FilePath = filePath,
                    Line = location.StartLinePosition.Line + 1,
                    EndLine = location.EndLinePosition.Line + 1,
                    Column = location.StartLinePosition.Character + 1,
                    ClassName = className,
                    MethodName = methodName,
                    CodeSnippet = GetLockSnippet(lockStatement),
                    SuggestedFix = "Use a private readonly object field: private readonly object _lock = new object();",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.LockOnThis)
                });
            }

            // Check for lock("string literal")
            if (expression is LiteralExpressionSyntax literal &&
                literal.IsKind(SyntaxKind.StringLiteralExpression))
            {
                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "LockOnString",
                    RuleId = ThreadSafetyRules.LockOnString,
                    Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.LockOnString),
                    Message = $"Locking on string literal {literal} is dangerous - string interning means any code with same string can deadlock",
                    FilePath = filePath,
                    Line = location.StartLinePosition.Line + 1,
                    EndLine = location.EndLinePosition.Line + 1,
                    Column = location.StartLinePosition.Character + 1,
                    ClassName = className,
                    MethodName = methodName,
                    CodeSnippet = GetLockSnippet(lockStatement),
                    SuggestedFix = "Use a private readonly object field instead of string literal",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.LockOnString),
                    Metadata = new Dictionary<string, object>
                    {
                        ["StringValue"] = literal.ToString()
                    }
                });
            }

            // Check for lock(typeof(T))
            if (expression is TypeOfExpressionSyntax typeOf)
            {
                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "LockOnType",
                    RuleId = ThreadSafetyRules.LockOnType,
                    Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.LockOnType),
                    Message = $"Locking on typeof({typeOf.Type}) is dangerous - Type objects are globally shared",
                    FilePath = filePath,
                    Line = location.StartLinePosition.Line + 1,
                    EndLine = location.EndLinePosition.Line + 1,
                    Column = location.StartLinePosition.Character + 1,
                    ClassName = className,
                    MethodName = methodName,
                    CodeSnippet = GetLockSnippet(lockStatement),
                    SuggestedFix = "Use a private static readonly object field for static synchronization",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.LockOnType),
                    Metadata = new Dictionary<string, object>
                    {
                        ["TypeName"] = typeOf.Type.ToString()
                    }
                });
            }

            // Check for lock(new object())
            if (expression is ObjectCreationExpressionSyntax ||
                expression is ImplicitObjectCreationExpressionSyntax)
            {
                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "LockOnNewObject",
                    RuleId = ThreadSafetyRules.LockOnNewObject,
                    Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.LockOnNewObject),
                    Message = "Locking on new object() creates a unique lock each time - no synchronization occurs!",
                    FilePath = filePath,
                    Line = location.StartLinePosition.Line + 1,
                    EndLine = location.EndLinePosition.Line + 1,
                    Column = location.StartLinePosition.Character + 1,
                    ClassName = className,
                    MethodName = methodName,
                    CodeSnippet = GetLockSnippet(lockStatement),
                    SuggestedFix = "Store the lock object in a field: private readonly object _lock = new object();",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.LockOnNewObject)
                });
            }

            // Check for lock on value type
            var typeInfo = semanticModel.GetTypeInfo(expression);
            if (typeInfo.Type?.IsValueType == true)
            {
                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "LockOnValueType",
                    RuleId = ThreadSafetyRules.LockOnValueType,
                    Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.LockOnValueType),
                    Message = $"Locking on value type '{typeInfo.Type.Name}' causes boxing - each lock is on a different object!",
                    FilePath = filePath,
                    Line = location.StartLinePosition.Line + 1,
                    EndLine = location.EndLinePosition.Line + 1,
                    Column = location.StartLinePosition.Character + 1,
                    ClassName = className,
                    MethodName = methodName,
                    CodeSnippet = GetLockSnippet(lockStatement),
                    SuggestedFix = "Use a reference type (object) for locking",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.LockOnValueType),
                    Metadata = new Dictionary<string, object>
                    {
                        ["ValueType"] = typeInfo.Type.ToDisplayString()
                    }
                });
            }

            // Check for lock on a variable that could be reassigned
            if (expression is IdentifierNameSyntax identifier)
            {
                var symbol = semanticModel.GetSymbolInfo(identifier).Symbol;
                if (symbol is IFieldSymbol field && !field.IsReadOnly && !field.IsConst)
                {
                    issues.Add(new ThreadSafetyIssue
                    {
                        IssueType = "LockOnThis",
                        RuleId = ThreadSafetyRules.LockOnThis,
                        Severity = "Medium",
                        Message = $"Lock field '{field.Name}' is not readonly - it could be reassigned during lock",
                        FilePath = filePath,
                        Line = location.StartLinePosition.Line + 1,
                        EndLine = location.EndLinePosition.Line + 1,
                        Column = location.StartLinePosition.Character + 1,
                        ClassName = className,
                        MethodName = methodName,
                        MemberName = field.Name,
                        CodeSnippet = GetLockSnippet(lockStatement),
                        SuggestedFix = $"Add readonly modifier: private readonly object {field.Name} = new object();",
                        CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.LockOnThis)
                    });
                }
            }
        }

        return issues;
    }

    private IEnumerable<ThreadSafetyIssue> DetectNestedLocks(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        ThreadSafetyAnalysisContext context)
    {
        var issues = new List<ThreadSafetyIssue>();

        foreach (var lockStatement in root.DescendantNodes().OfType<LockStatementSyntax>())
        {
            // Check for nested locks within this lock
            var nestedLocks = lockStatement.Statement.DescendantNodes().OfType<LockStatementSyntax>().ToList();

            if (nestedLocks.Count > 0)
            {
                var outerLockExpr = lockStatement.Expression.ToString();
                var nestedExprs = nestedLocks.Select(nl => nl.Expression.ToString()).ToList();

                var location = lockStatement.GetLocation().GetLineSpan();
                var classDecl = lockStatement.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
                var methodDecl = lockStatement.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "NestedLocks",
                    RuleId = ThreadSafetyRules.NestedLocks,
                    Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.NestedLocks),
                    Message = $"Nested locks detected: {outerLockExpr} -> {string.Join(", ", nestedExprs)} - may cause deadlock if acquired in different order elsewhere",
                    FilePath = filePath,
                    Line = location.StartLinePosition.Line + 1,
                    EndLine = location.EndLinePosition.Line + 1,
                    Column = location.StartLinePosition.Character + 1,
                    ClassName = classDecl?.Identifier.Text,
                    MethodName = methodDecl?.Identifier.Text,
                    CodeSnippet = GetNestedLockSnippet(lockStatement, nestedLocks.First()),
                    SuggestedFix = "Ensure consistent lock ordering throughout the codebase, or use a single coarse-grained lock",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.NestedLocks),
                    Metadata = new Dictionary<string, object>
                    {
                        ["OuterLock"] = outerLockExpr,
                        ["NestedLocks"] = nestedExprs,
                        ["NestingDepth"] = nestedLocks.Count
                    }
                });

                // Update context for cross-method analysis
                var lockInfo = context.LockPatterns.FirstOrDefault(lp =>
                    lp.Line == location.StartLinePosition.Line + 1 && lp.FilePath == filePath);

                if (lockInfo != null)
                {
                    lockInfo.NestedLocks.AddRange(nestedExprs);
                }
            }
        }

        return issues;
    }

    private IEnumerable<ThreadSafetyIssue> DetectInconsistentLocking(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        ThreadSafetyAnalysisContext context)
    {
        var issues = new List<ThreadSafetyIssue>();

        // Track lock orderings: lockA -> lockB means lockA is acquired before lockB
        var lockOrderings = new Dictionary<string, HashSet<string>>();

        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            var methodName = method.Identifier.Text;
            var lockStack = new Stack<string>();

            // Traverse the method body and track lock ordering
            var locks = method.DescendantNodes().OfType<LockStatementSyntax>().ToList();

            foreach (var lockStmt in locks)
            {
                var currentLock = NormalizeLockExpression(lockStmt.Expression, semanticModel);

                // For nested locks, record the ordering
                var parent = lockStmt.Parent;
                while (parent != null && parent != method)
                {
                    if (parent is LockStatementSyntax parentLock)
                    {
                        var parentLockExpr = NormalizeLockExpression(parentLock.Expression, semanticModel);

                        // Record: parentLockExpr is acquired before currentLock
                        if (!lockOrderings.TryGetValue(parentLockExpr, out var afterLocks))
                        {
                            afterLocks = new HashSet<string>();
                            lockOrderings[parentLockExpr] = afterLocks;
                        }
                        afterLocks.Add(currentLock);
                    }
                    parent = parent.Parent;
                }
            }
        }

        // Check for inconsistent orderings (A->B and B->A)
        foreach (var (lockA, locksAfterA) in lockOrderings)
        {
            foreach (var lockB in locksAfterA)
            {
                if (lockOrderings.TryGetValue(lockB, out var locksAfterB) && locksAfterB.Contains(lockA))
                {
                    // Found inconsistent ordering: A->B and B->A
                    var firstOccurrence = context.LockPatterns
                        .FirstOrDefault(lp => lp.FilePath == filePath &&
                                              (lp.LockExpression.Contains(lockA) || lp.LockExpression.Contains(lockB)));

                    if (firstOccurrence != null)
                    {
                        issues.Add(new ThreadSafetyIssue
                        {
                            IssueType = "NestedLocks",
                            RuleId = ThreadSafetyRules.NestedLocks,
                            Severity = "High",
                            Message = $"Inconsistent lock ordering detected: '{lockA}' and '{lockB}' are acquired in different orders - DEADLOCK RISK",
                            FilePath = filePath,
                            Line = firstOccurrence.Line,
                            EndLine = firstOccurrence.Line,
                            ClassName = firstOccurrence.ClassName,
                            MethodName = firstOccurrence.MethodName,
                            CodeSnippet = $"Lock ordering: {lockA} <-> {lockB}",
                            SuggestedFix = "Establish a consistent lock ordering: always acquire locks in the same order",
                            CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.NestedLocks),
                            Metadata = new Dictionary<string, object>
                            {
                                ["LockA"] = lockA,
                                ["LockB"] = lockB,
                                ["Pattern"] = "Inconsistent ordering"
                            }
                        });
                    }
                }
            }
        }

        return issues;
    }

    private string GetLockTargetType(ExpressionSyntax expression, SemanticModel semanticModel)
    {
        return expression switch
        {
            ThisExpressionSyntax => "This",
            LiteralExpressionSyntax lit when lit.IsKind(SyntaxKind.StringLiteralExpression) => "String",
            TypeOfExpressionSyntax => "Type",
            ObjectCreationExpressionSyntax => "NewObject",
            ImplicitObjectCreationExpressionSyntax => "NewObject",
            IdentifierNameSyntax id => GetIdentifierLockType(id, semanticModel),
            MemberAccessExpressionSyntax ma => GetMemberAccessLockType(ma, semanticModel),
            _ => "Unknown"
        };
    }

    private string GetIdentifierLockType(IdentifierNameSyntax identifier, SemanticModel semanticModel)
    {
        var symbol = semanticModel.GetSymbolInfo(identifier).Symbol;
        if (symbol is IFieldSymbol field)
        {
            if (field.IsReadOnly) return "ReadOnlyField";
            return "Field";
        }
        if (symbol is ILocalSymbol) return "LocalVariable";
        if (symbol is IParameterSymbol) return "Parameter";
        return "Identifier";
    }

    private string GetMemberAccessLockType(MemberAccessExpressionSyntax memberAccess, SemanticModel semanticModel)
    {
        var symbol = semanticModel.GetSymbolInfo(memberAccess).Symbol;
        if (symbol is IFieldSymbol field)
        {
            if (field.IsStatic && field.IsReadOnly) return "StaticReadOnlyField";
            if (field.IsStatic) return "StaticField";
            if (field.IsReadOnly) return "ReadOnlyField";
            return "Field";
        }
        if (symbol is IPropertySymbol) return "Property";
        return "MemberAccess";
    }

    private string NormalizeLockExpression(ExpressionSyntax expression, SemanticModel semanticModel)
    {
        var symbol = semanticModel.GetSymbolInfo(expression).Symbol;
        if (symbol != null)
        {
            return symbol.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat);
        }
        return expression.ToString();
    }

    private string GetLockSnippet(LockStatementSyntax lockStatement)
    {
        var text = lockStatement.ToString();
        var firstLine = text.Split('\n')[0].Trim();
        if (firstLine.Length > 80)
        {
            return firstLine.Substring(0, 77) + "...";
        }
        return firstLine;
    }

    private string GetNestedLockSnippet(LockStatementSyntax outer, LockStatementSyntax inner)
    {
        return $"lock ({outer.Expression}) {{ ... lock ({inner.Expression}) {{ ... }} }}";
    }
}
