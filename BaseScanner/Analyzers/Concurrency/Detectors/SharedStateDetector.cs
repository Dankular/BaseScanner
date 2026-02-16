using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Concurrency.Models;

namespace BaseScanner.Analyzers.Concurrency.Detectors;

/// <summary>
/// Detects shared mutable state issues including:
/// - Static fields modified from multiple methods without synchronization
/// - Fields accessed without locks in async/multithreaded contexts
/// </summary>
public class SharedStateDetector : IThreadSafetyDetector
{
    public string Name => "SharedState";

    public string Description => "Detects shared mutable state accessed without proper synchronization";

    public IReadOnlyList<string> SupportedRules =>
    [
        ThreadSafetyRules.SharedMutableStatic,
        ThreadSafetyRules.UnprotectedFieldAccess,
        ThreadSafetyRules.UnsynchronizedCollectionAccess
    ];

    public Task<List<ThreadSafetyIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        ThreadSafetyAnalysisContext? context = null)
    {
        var issues = new List<ThreadSafetyIssue>();
        context ??= new ThreadSafetyAnalysisContext();

        // First pass: collect all static and instance fields
        var fieldInfos = CollectFields(root, semanticModel, document.FilePath ?? "");

        // Register fields in context
        foreach (var fieldInfo in fieldInfos)
        {
            context.RegisterSharedField(fieldInfo);
        }

        // Second pass: find methods that read/write fields
        AnalyzeFieldAccess(root, semanticModel, document.FilePath ?? "", context);

        // Detect issues based on collected data
        issues.AddRange(DetectSharedMutableStatic(root, semanticModel, document.FilePath ?? "", context));
        issues.AddRange(DetectUnprotectedFieldAccess(root, semanticModel, document.FilePath ?? "", context));
        issues.AddRange(DetectUnsynchronizedCollectionAccess(root, semanticModel, document.FilePath ?? "", context));

        return Task.FromResult(issues);
    }

    private List<SharedFieldInfo> CollectFields(SyntaxNode root, SemanticModel semanticModel, string filePath)
    {
        var fields = new List<SharedFieldInfo>();

        foreach (var classDecl in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
        {
            var className = GetFullClassName(classDecl, semanticModel);

            foreach (var fieldDecl in classDecl.Members.OfType<FieldDeclarationSyntax>())
            {
                var isStatic = fieldDecl.Modifiers.Any(SyntaxKind.StaticKeyword);
                var isReadOnly = fieldDecl.Modifiers.Any(SyntaxKind.ReadOnlyKeyword);
                var isConst = fieldDecl.Modifiers.Any(SyntaxKind.ConstKeyword);
                var isVolatile = fieldDecl.Modifiers.Any(SyntaxKind.VolatileKeyword);

                // Skip const and readonly immutable types
                if (isConst) continue;

                foreach (var variable in fieldDecl.Declaration.Variables)
                {
                    var fieldSymbol = semanticModel.GetDeclaredSymbol(variable) as IFieldSymbol;
                    var fieldType = fieldDecl.Declaration.Type.ToString();

                    fields.Add(new SharedFieldInfo
                    {
                        FieldName = variable.Identifier.Text,
                        FieldType = fieldType,
                        ClassName = className,
                        IsStatic = isStatic,
                        IsVolatile = isVolatile,
                        IsReadOnly = isReadOnly,
                        FilePath = filePath,
                        DeclarationLine = fieldDecl.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        Symbol = fieldSymbol
                    });
                }
            }
        }

        return fields;
    }

    private void AnalyzeFieldAccess(SyntaxNode root, SemanticModel semanticModel, string filePath, ThreadSafetyAnalysisContext context)
    {
        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            var classDecl = method.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
            if (classDecl == null) continue;

            var className = GetFullClassName(classDecl, semanticModel);
            var methodFullName = $"{className}.{method.Identifier.Text}";
            var isAsyncMethod = method.Modifiers.Any(SyntaxKind.AsyncKeyword);
            var isStaticMethod = method.Modifiers.Any(SyntaxKind.StaticKeyword);

            var body = (SyntaxNode?)method.Body ?? method.ExpressionBody;
            if (body == null) continue;

            // Track if we're inside a lock
            AnalyzeMethodBody(body, semanticModel, methodFullName, isAsyncMethod, isStaticMethod, context);
        }
    }

    private void AnalyzeMethodBody(
        SyntaxNode body,
        SemanticModel semanticModel,
        string methodFullName,
        bool isAsyncMethod,
        bool isStaticMethod,
        ThreadSafetyAnalysisContext context)
    {
        // Find all identifier references
        foreach (var identifier in body.DescendantNodes().OfType<IdentifierNameSyntax>())
        {
            var symbol = semanticModel.GetSymbolInfo(identifier).Symbol;
            if (symbol is not IFieldSymbol fieldSymbol) continue;

            var fieldFullName = $"{fieldSymbol.ContainingType.Name}.{fieldSymbol.Name}";
            var isWrite = IsWriteAccess(identifier);
            var isInsideLock = IsInsideLock(identifier);

            context.RegisterFieldAccess(methodFullName, fieldFullName, isWrite);

            if (isAsyncMethod)
            {
                context.AsyncAccessedFields.Add(fieldFullName);
            }

            if (isStaticMethod && fieldSymbol.IsStatic)
            {
                if (!context.StaticMethodToStaticFields.TryGetValue(methodFullName, out var fields))
                {
                    fields = new HashSet<string>();
                    context.StaticMethodToStaticFields[methodFullName] = fields;
                }
                fields.Add(fieldFullName);
            }

            if (isInsideLock)
            {
                var lockExpr = GetContainingLockExpression(identifier);
                if (lockExpr != null)
                {
                    if (!context.FieldToLockExpressions.TryGetValue(fieldFullName, out var locks))
                    {
                        locks = new HashSet<string>();
                        context.FieldToLockExpressions[fieldFullName] = locks;
                    }
                    locks.Add(lockExpr);
                }
            }
        }
    }

    private IEnumerable<ThreadSafetyIssue> DetectSharedMutableStatic(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        ThreadSafetyAnalysisContext context)
    {
        var issues = new List<ThreadSafetyIssue>();

        foreach (var fieldInfo in context.SharedFields.Values.Where(f => f.IsStatic && !f.IsReadOnly && f.FilePath == filePath))
        {
            // Check if modified from multiple methods
            if (fieldInfo.WritingMethods.Count > 1)
            {
                var fieldFullName = $"{fieldInfo.ClassName}.{fieldInfo.FieldName}";

                // Check if protected by consistent locking
                if (!context.FieldToLockExpressions.TryGetValue(fieldFullName, out var locks) || locks.Count == 0)
                {
                    issues.Add(new ThreadSafetyIssue
                    {
                        IssueType = "SharedMutableStatic",
                        RuleId = ThreadSafetyRules.SharedMutableStatic,
                        Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.SharedMutableStatic),
                        Message = $"Static field '{fieldInfo.FieldName}' is modified from {fieldInfo.WritingMethods.Count} methods without synchronization",
                        FilePath = filePath,
                        Line = fieldInfo.DeclarationLine,
                        EndLine = fieldInfo.DeclarationLine,
                        ClassName = fieldInfo.ClassName,
                        MemberName = fieldInfo.FieldName,
                        CodeSnippet = $"static {fieldInfo.FieldType} {fieldInfo.FieldName}",
                        SuggestedFix = "Use lock, Interlocked operations, or make readonly with initialization",
                        CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.SharedMutableStatic),
                        Metadata = new Dictionary<string, object>
                        {
                            ["WritingMethods"] = fieldInfo.WritingMethods,
                            ["ReadingMethods"] = fieldInfo.ReadingMethods
                        }
                    });
                }
            }
        }

        return issues;
    }

    private IEnumerable<ThreadSafetyIssue> DetectUnprotectedFieldAccess(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        ThreadSafetyAnalysisContext context)
    {
        var issues = new List<ThreadSafetyIssue>();

        // Check fields accessed from async methods without synchronization
        foreach (var fieldFullName in context.AsyncAccessedFields)
        {
            if (!context.SharedFields.TryGetValue(fieldFullName, out var fieldInfo)) continue;
            if (fieldInfo.IsReadOnly || fieldInfo.IsVolatile) continue;
            if (fieldInfo.FilePath != filePath) continue;

            // Check if there are writes without locks
            var hasUnprotectedWrite = fieldInfo.WritingMethods.Count > 0 &&
                (!context.FieldToLockExpressions.TryGetValue(fieldFullName, out var locks) || locks.Count == 0);

            if (hasUnprotectedWrite && context.IsFieldAccessedFromMultipleMethods(fieldFullName))
            {
                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "UnprotectedFieldAccess",
                    RuleId = ThreadSafetyRules.UnprotectedFieldAccess,
                    Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.UnprotectedFieldAccess),
                    Message = $"Field '{fieldInfo.FieldName}' is accessed from async methods without synchronization",
                    FilePath = filePath,
                    Line = fieldInfo.DeclarationLine,
                    EndLine = fieldInfo.DeclarationLine,
                    ClassName = fieldInfo.ClassName,
                    MemberName = fieldInfo.FieldName,
                    CodeSnippet = $"{fieldInfo.FieldType} {fieldInfo.FieldName}",
                    SuggestedFix = "Use lock, SemaphoreSlim, or volatile keyword",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.UnprotectedFieldAccess)
                });
            }
        }

        return issues;
    }

    private IEnumerable<ThreadSafetyIssue> DetectUnsynchronizedCollectionAccess(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        ThreadSafetyAnalysisContext context)
    {
        var issues = new List<ThreadSafetyIssue>();

        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            if (!method.Modifiers.Any(SyntaxKind.StaticKeyword)) continue;

            var body = (SyntaxNode?)method.Body ?? method.ExpressionBody;
            if (body == null) continue;

            foreach (var access in body.DescendantNodes().OfType<ElementAccessExpressionSyntax>())
            {
                var symbol = semanticModel.GetSymbolInfo(access.Expression).Symbol;
                if (symbol is not IFieldSymbol fieldSymbol) continue;
                if (!fieldSymbol.IsStatic) continue;
                if (IsThreadSafeCollection(fieldSymbol.Type)) continue;
                if (IsInsideLock(access)) continue;

                // Check if it's a mutable collection type
                if (!IsMutableCollectionType(fieldSymbol.Type)) continue;

                var location = access.GetLocation().GetLineSpan();
                var classDecl = method.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
                var className = classDecl?.Identifier.Text ?? "";

                issues.Add(new ThreadSafetyIssue
                {
                    IssueType = "UnsynchronizedCollectionAccess",
                    RuleId = ThreadSafetyRules.UnsynchronizedCollectionAccess,
                    Severity = ThreadSafetyRules.GetDefaultSeverity(ThreadSafetyRules.UnsynchronizedCollectionAccess),
                    Message = $"Static collection '{fieldSymbol.Name}' accessed in static method without synchronization",
                    FilePath = filePath,
                    Line = location.StartLinePosition.Line + 1,
                    EndLine = location.EndLinePosition.Line + 1,
                    ClassName = className,
                    MethodName = method.Identifier.Text,
                    MemberName = fieldSymbol.Name,
                    CodeSnippet = access.ToString(),
                    SuggestedFix = "Use ConcurrentDictionary/ConcurrentBag or add lock statement",
                    CweId = ThreadSafetyRules.GetCweId(ThreadSafetyRules.UnsynchronizedCollectionAccess)
                });
            }
        }

        return issues;
    }

    private string GetFullClassName(ClassDeclarationSyntax classDecl, SemanticModel semanticModel)
    {
        var symbol = semanticModel.GetDeclaredSymbol(classDecl);
        if (symbol != null)
        {
            return symbol.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat);
        }
        return classDecl.Identifier.Text;
    }

    private bool IsWriteAccess(IdentifierNameSyntax identifier)
    {
        var parent = identifier.Parent;

        // Check assignment
        if (parent is AssignmentExpressionSyntax assignment && assignment.Left == identifier)
            return true;

        // Check increment/decrement
        if (parent is PostfixUnaryExpressionSyntax postfix &&
            (postfix.IsKind(SyntaxKind.PostIncrementExpression) || postfix.IsKind(SyntaxKind.PostDecrementExpression)))
            return true;

        if (parent is PrefixUnaryExpressionSyntax prefix &&
            (prefix.IsKind(SyntaxKind.PreIncrementExpression) || prefix.IsKind(SyntaxKind.PreDecrementExpression)))
            return true;

        // Check compound assignment
        if (parent is AssignmentExpressionSyntax compoundAssignment &&
            compoundAssignment.Left == identifier &&
            (compoundAssignment.IsKind(SyntaxKind.AddAssignmentExpression) ||
             compoundAssignment.IsKind(SyntaxKind.SubtractAssignmentExpression) ||
             compoundAssignment.IsKind(SyntaxKind.MultiplyAssignmentExpression) ||
             compoundAssignment.IsKind(SyntaxKind.DivideAssignmentExpression)))
            return true;

        // Check ref/out parameter
        if (parent is ArgumentSyntax arg &&
            (arg.RefOrOutKeyword.IsKind(SyntaxKind.RefKeyword) || arg.RefOrOutKeyword.IsKind(SyntaxKind.OutKeyword)))
            return true;

        return false;
    }

    private bool IsInsideLock(SyntaxNode node)
    {
        var current = node.Parent;
        while (current != null)
        {
            if (current is LockStatementSyntax) return true;
            if (current is MethodDeclarationSyntax) break; // Don't go beyond method boundary
            current = current.Parent;
        }
        return false;
    }

    private string? GetContainingLockExpression(SyntaxNode node)
    {
        var current = node.Parent;
        while (current != null)
        {
            if (current is LockStatementSyntax lockStmt)
            {
                return lockStmt.Expression.ToString();
            }
            if (current is MethodDeclarationSyntax) break;
            current = current.Parent;
        }
        return null;
    }

    private bool IsThreadSafeCollection(ITypeSymbol type)
    {
        var name = type.ToDisplayString();
        return name.StartsWith("System.Collections.Concurrent.");
    }

    private bool IsMutableCollectionType(ITypeSymbol type)
    {
        var name = type.ToDisplayString();
        return name.StartsWith("System.Collections.Generic.List") ||
               name.StartsWith("System.Collections.Generic.Dictionary") ||
               name.StartsWith("System.Collections.Generic.HashSet") ||
               name.StartsWith("System.Collections.Generic.Queue") ||
               name.StartsWith("System.Collections.Generic.Stack") ||
               name.StartsWith("System.Collections.ArrayList") ||
               name.StartsWith("System.Collections.Hashtable");
    }
}
