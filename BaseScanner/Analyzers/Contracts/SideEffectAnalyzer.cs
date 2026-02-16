using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Contracts.Models;

namespace BaseScanner.Analyzers.Contracts;

/// <summary>
/// Analyzes methods for side effects and purity.
/// Detects methods that modify state unexpectedly based on naming conventions.
/// </summary>
public class SideEffectAnalyzer
{
    // Methods with these prefixes are expected to be pure (read-only)
    private static readonly HashSet<string> PureMethodPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Get", "Is", "Has", "Can", "Should", "Find", "Calculate", "Compute",
        "Check", "Validate", "Equals", "Compare", "Contains", "Try"
    };

    // Methods with these prefixes are expected to modify state
    private static readonly HashSet<string> MutatingMethodPrefixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Set", "Add", "Remove", "Delete", "Update", "Clear", "Reset",
        "Insert", "Append", "Push", "Pop", "Enqueue", "Dequeue",
        "Create", "Initialize", "Dispose", "Close", "Open", "Start", "Stop"
    };

    // I/O operations that indicate side effects
    private static readonly HashSet<string> IOOperations = new(StringComparer.OrdinalIgnoreCase)
    {
        "File.Write", "File.Read", "File.Delete", "File.Create", "File.Open",
        "Console.Write", "Console.Read", "Debug.Write", "Trace.Write",
        "HttpClient", "WebClient", "Socket", "Stream",
        "Database", "DbContext", "SqlCommand", "DbCommand",
        "Log", "Logger", "Logging"
    };

    /// <summary>
    /// Analyze methods for side effects.
    /// </summary>
    public (List<SideEffectIssue> Issues, List<MethodPurityInfo> PurityAnalysis) Analyze(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<SideEffectIssue>();
        var purityAnalysis = new List<MethodPurityInfo>();

        var classes = root.DescendantNodes().OfType<ClassDeclarationSyntax>();

        foreach (var classDecl in classes)
        {
            var className = classDecl.Identifier.Text;

            // Get all instance fields for tracking modifications
            var instanceFields = GetInstanceFields(classDecl);
            var instanceProperties = GetInstanceProperties(classDecl);

            foreach (var method in classDecl.Members.OfType<MethodDeclarationSyntax>())
            {
                var methodName = method.Identifier.Text;
                var body = (SyntaxNode?)method.Body ?? method.ExpressionBody;
                if (body == null) continue;

                // Analyze purity
                var purityInfo = AnalyzeMethodPurity(
                    method, body, semanticModel, className, filePath,
                    instanceFields, instanceProperties);

                purityAnalysis.Add(purityInfo);

                // Check for unexpected side effects
                var expectedPurity = GetExpectedPurity(methodName);
                if (expectedPurity == MethodPurity.Pure || expectedPurity == MethodPurity.ReadsState)
                {
                    if (purityInfo.Purity == MethodPurity.ModifiesState ||
                        purityInfo.Purity == MethodPurity.HasIO)
                    {
                        var issue = CreateSideEffectIssue(method, purityInfo, expectedPurity, filePath, className);
                        issues.Add(issue);
                    }
                }
            }

            // Also analyze properties
            foreach (var property in classDecl.Members.OfType<PropertyDeclarationSyntax>())
            {
                var getter = property.AccessorList?.Accessors
                    .FirstOrDefault(a => a.IsKind(SyntaxKind.GetAccessorDeclaration));

                if (getter?.Body != null || getter?.ExpressionBody != null)
                {
                    var body = (SyntaxNode?)getter.Body ?? getter.ExpressionBody;
                    if (body != null)
                    {
                        var purityInfo = AnalyzeAccessorPurity(
                            getter, body, semanticModel, className, filePath,
                            property.Identifier.Text, instanceFields, instanceProperties);

                        // Getters should never modify state
                        if (purityInfo.Purity == MethodPurity.ModifiesState)
                        {
                            var lineSpan = getter.GetLocation().GetLineSpan();
                            issues.Add(new SideEffectIssue
                            {
                                Type = ContractType.SideEffect,
                                Severity = ContractSeverity.Error,
                                FilePath = filePath,
                                Line = lineSpan.StartLinePosition.Line + 1,
                                Column = lineSpan.StartLinePosition.Character + 1,
                                ClassName = className,
                                MethodName = $"{property.Identifier.Text}.get",
                                Description = "Property getter modifies state - this is unexpected behavior",
                                Suggestion = "Property getters should be pure. Move state modification to a separate method.",
                                CodeSnippet = getter.ToString(),
                                SuggestedFix = "// Consider: public T Property { get { return _field; } } // No modifications",
                                Purity = purityInfo.Purity,
                                ExpectedPurity = MethodPurity.ReadsState,
                                ModifiedFields = purityInfo.WritesFields,
                                ModifiedProperties = purityInfo.WritesProperties,
                                Confidence = 0.95
                            });
                        }
                    }
                }
            }
        }

        return (issues, purityAnalysis);
    }

    private MethodPurityInfo AnalyzeMethodPurity(
        MethodDeclarationSyntax method,
        SyntaxNode body,
        SemanticModel semanticModel,
        string className,
        string filePath,
        HashSet<string> instanceFields,
        HashSet<string> instanceProperties)
    {
        var methodName = method.Identifier.Text;
        var lineSpan = method.GetLocation().GetLineSpan();

        var readsFields = new List<string>();
        var writesFields = new List<string>();
        var readsProperties = new List<string>();
        var writesProperties = new List<string>();
        var ioOperations = new List<string>();

        // Analyze field accesses
        AnalyzeFieldAccesses(body, instanceFields, readsFields, writesFields);

        // Analyze property accesses
        AnalyzePropertyAccesses(body, semanticModel, instanceProperties, readsProperties, writesProperties);

        // Analyze I/O operations
        AnalyzeIOOperations(body, semanticModel, ioOperations);

        // Analyze method calls that might have side effects
        AnalyzeMethodCalls(body, semanticModel, writesFields, ioOperations);

        // Determine purity level
        MethodPurity purity;
        if (ioOperations.Any())
        {
            purity = MethodPurity.HasIO;
        }
        else if (writesFields.Any() || writesProperties.Any())
        {
            purity = MethodPurity.ModifiesState;
        }
        else if (readsFields.Any() || readsProperties.Any())
        {
            purity = MethodPurity.ReadsState;
        }
        else
        {
            purity = MethodPurity.Pure;
        }

        return new MethodPurityInfo
        {
            MethodName = methodName,
            ClassName = className,
            FilePath = filePath,
            Line = lineSpan.StartLinePosition.Line + 1,
            Purity = purity,
            ReadsFields = readsFields.Distinct().ToList(),
            WritesFields = writesFields.Distinct().ToList(),
            ReadsProperties = readsProperties.Distinct().ToList(),
            WritesProperties = writesProperties.Distinct().ToList(),
            IOOperations = ioOperations.Distinct().ToList(),
            NameSuggestsPurity = IsPureName(methodName)
        };
    }

    private MethodPurityInfo AnalyzeAccessorPurity(
        AccessorDeclarationSyntax accessor,
        SyntaxNode body,
        SemanticModel semanticModel,
        string className,
        string filePath,
        string propertyName,
        HashSet<string> instanceFields,
        HashSet<string> instanceProperties)
    {
        var lineSpan = accessor.GetLocation().GetLineSpan();

        var readsFields = new List<string>();
        var writesFields = new List<string>();
        var readsProperties = new List<string>();
        var writesProperties = new List<string>();
        var ioOperations = new List<string>();

        AnalyzeFieldAccesses(body, instanceFields, readsFields, writesFields);
        AnalyzePropertyAccesses(body, semanticModel, instanceProperties, readsProperties, writesProperties);
        AnalyzeIOOperations(body, semanticModel, ioOperations);

        MethodPurity purity;
        if (ioOperations.Any())
        {
            purity = MethodPurity.HasIO;
        }
        else if (writesFields.Any() || writesProperties.Any())
        {
            purity = MethodPurity.ModifiesState;
        }
        else if (readsFields.Any() || readsProperties.Any())
        {
            purity = MethodPurity.ReadsState;
        }
        else
        {
            purity = MethodPurity.Pure;
        }

        return new MethodPurityInfo
        {
            MethodName = $"{propertyName}.get",
            ClassName = className,
            FilePath = filePath,
            Line = lineSpan.StartLinePosition.Line + 1,
            Purity = purity,
            ReadsFields = readsFields.Distinct().ToList(),
            WritesFields = writesFields.Distinct().ToList(),
            ReadsProperties = readsProperties.Distinct().ToList(),
            WritesProperties = writesProperties.Distinct().ToList(),
            IOOperations = ioOperations.Distinct().ToList(),
            NameSuggestsPurity = true // Getters should always be pure
        };
    }

    private void AnalyzeFieldAccesses(
        SyntaxNode body,
        HashSet<string> instanceFields,
        List<string> readsFields,
        List<string> writesFields)
    {
        // Find field reads
        var identifiers = body.DescendantNodes().OfType<IdentifierNameSyntax>();
        foreach (var id in identifiers)
        {
            var name = id.Identifier.Text;
            if (instanceFields.Contains(name) || instanceFields.Contains($"_{name}"))
            {
                // Check if this is a write (left side of assignment)
                if (IsWriteAccess(id))
                {
                    writesFields.Add(name);
                }
                else
                {
                    readsFields.Add(name);
                }
            }
        }

        // Find this.field accesses
        var memberAccesses = body.DescendantNodes().OfType<MemberAccessExpressionSyntax>()
            .Where(m => m.Expression is ThisExpressionSyntax);

        foreach (var access in memberAccesses)
        {
            var memberName = access.Name.Identifier.Text;
            if (IsWriteAccess(access))
            {
                writesFields.Add(memberName);
            }
            else
            {
                readsFields.Add(memberName);
            }
        }

        // Find increment/decrement operations on fields
        var prefixUnary = body.DescendantNodes().OfType<PrefixUnaryExpressionSyntax>()
            .Where(p => p.IsKind(SyntaxKind.PreIncrementExpression) ||
                       p.IsKind(SyntaxKind.PreDecrementExpression));

        var postfixUnary = body.DescendantNodes().OfType<PostfixUnaryExpressionSyntax>()
            .Where(p => p.IsKind(SyntaxKind.PostIncrementExpression) ||
                       p.IsKind(SyntaxKind.PostDecrementExpression));

        foreach (var unary in prefixUnary)
        {
            if (unary.Operand is IdentifierNameSyntax id && instanceFields.Contains(id.Identifier.Text))
            {
                writesFields.Add(id.Identifier.Text);
            }
        }

        foreach (var unary in postfixUnary)
        {
            if (unary.Operand is IdentifierNameSyntax id && instanceFields.Contains(id.Identifier.Text))
            {
                writesFields.Add(id.Identifier.Text);
            }
        }
    }

    private void AnalyzePropertyAccesses(
        SyntaxNode body,
        SemanticModel semanticModel,
        HashSet<string> instanceProperties,
        List<string> readsProperties,
        List<string> writesProperties)
    {
        var memberAccesses = body.DescendantNodes().OfType<MemberAccessExpressionSyntax>()
            .Where(m => m.Expression is ThisExpressionSyntax);

        foreach (var access in memberAccesses)
        {
            var memberName = access.Name.Identifier.Text;
            if (instanceProperties.Contains(memberName))
            {
                if (IsWriteAccess(access))
                {
                    writesProperties.Add(memberName);
                }
                else
                {
                    readsProperties.Add(memberName);
                }
            }
        }
    }

    private void AnalyzeIOOperations(
        SyntaxNode body,
        SemanticModel semanticModel,
        List<string> ioOperations)
    {
        var invocations = body.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in invocations)
        {
            var invocationText = invocation.ToString();

            foreach (var ioOp in IOOperations)
            {
                if (invocationText.Contains(ioOp))
                {
                    ioOperations.Add(ioOp);
                }
            }

            // Check for async/await patterns that typically indicate I/O
            if (invocationText.EndsWith("Async") ||
                body.DescendantNodes().OfType<AwaitExpressionSyntax>().Any())
            {
                var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                if (symbol != null)
                {
                    var ns = symbol.ContainingNamespace?.ToDisplayString() ?? "";
                    if (ns.Contains("System.IO") || ns.Contains("System.Net") ||
                        ns.Contains("System.Data") || ns.Contains("Microsoft.EntityFramework"))
                    {
                        ioOperations.Add(symbol.ToDisplayString());
                    }
                }
            }
        }
    }

    private void AnalyzeMethodCalls(
        SyntaxNode body,
        SemanticModel semanticModel,
        List<string> writesFields,
        List<string> ioOperations)
    {
        var invocations = body.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in invocations)
        {
            // Check for collection-modifying method calls
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var methodName = memberAccess.Name.Identifier.Text;

                // Collection modification methods
                var mutatingMethods = new[] { "Add", "Remove", "Clear", "Insert", "RemoveAt",
                    "Push", "Pop", "Enqueue", "Dequeue", "Sort", "Reverse" };

                if (mutatingMethods.Contains(methodName))
                {
                    // Check if called on a field
                    var target = memberAccess.Expression;
                    if (target is IdentifierNameSyntax id)
                    {
                        writesFields.Add(id.Identifier.Text);
                    }
                    else if (target is MemberAccessExpressionSyntax ma &&
                             ma.Expression is ThisExpressionSyntax)
                    {
                        writesFields.Add(ma.Name.Identifier.Text);
                    }
                }
            }
        }
    }

    private bool IsWriteAccess(SyntaxNode node)
    {
        var parent = node.Parent;

        // Direct assignment
        if (parent is AssignmentExpressionSyntax assignment &&
            assignment.Left == node)
        {
            return true;
        }

        // Compound assignment (+=, -=, etc.)
        if (parent is AssignmentExpressionSyntax compound &&
            (compound.IsKind(SyntaxKind.AddAssignmentExpression) ||
             compound.IsKind(SyntaxKind.SubtractAssignmentExpression) ||
             compound.IsKind(SyntaxKind.MultiplyAssignmentExpression) ||
             compound.IsKind(SyntaxKind.DivideAssignmentExpression)) &&
            compound.Left == node)
        {
            return true;
        }

        // out/ref parameter
        if (parent is ArgumentSyntax arg &&
            (arg.RefOrOutKeyword.IsKind(SyntaxKind.OutKeyword) ||
             arg.RefOrOutKeyword.IsKind(SyntaxKind.RefKeyword)))
        {
            return true;
        }

        return false;
    }

    private HashSet<string> GetInstanceFields(ClassDeclarationSyntax classDecl)
    {
        var fields = new HashSet<string>();

        foreach (var field in classDecl.Members.OfType<FieldDeclarationSyntax>())
        {
            if (field.Modifiers.Any(SyntaxKind.StaticKeyword))
                continue;

            foreach (var variable in field.Declaration.Variables)
            {
                fields.Add(variable.Identifier.Text);
            }
        }

        return fields;
    }

    private HashSet<string> GetInstanceProperties(ClassDeclarationSyntax classDecl)
    {
        var properties = new HashSet<string>();

        foreach (var prop in classDecl.Members.OfType<PropertyDeclarationSyntax>())
        {
            if (prop.Modifiers.Any(SyntaxKind.StaticKeyword))
                continue;

            properties.Add(prop.Identifier.Text);
        }

        return properties;
    }

    private MethodPurity GetExpectedPurity(string methodName)
    {
        foreach (var prefix in PureMethodPrefixes)
        {
            if (methodName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                // Get/Is/Has methods should be read-only at most
                if (prefix == "Get" || prefix == "Is" || prefix == "Has" || prefix == "Can")
                    return MethodPurity.ReadsState;

                return MethodPurity.Pure;
            }
        }

        foreach (var prefix in MutatingMethodPrefixes)
        {
            if (methodName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return MethodPurity.ModifiesState;
            }
        }

        // Unknown - no expectation
        return MethodPurity.ModifiesState; // Assume methods can modify state by default
    }

    private bool IsPureName(string methodName)
    {
        return PureMethodPrefixes.Any(p =>
            methodName.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }

    private SideEffectIssue CreateSideEffectIssue(
        MethodDeclarationSyntax method,
        MethodPurityInfo purityInfo,
        MethodPurity expectedPurity,
        string filePath,
        string className)
    {
        var lineSpan = method.GetLocation().GetLineSpan();
        var methodName = method.Identifier.Text;

        var description = purityInfo.Purity == MethodPurity.HasIO
            ? $"Method '{methodName}' performs I/O operations but name suggests it should be pure"
            : $"Method '{methodName}' modifies state but name suggests it should be pure/read-only";

        var suggestion = purityInfo.Purity == MethodPurity.HasIO
            ? $"Rename method to indicate I/O (e.g., 'Load{methodName.TrimStart("Get".ToCharArray())}Async') or extract I/O to separate method"
            : $"Rename method to indicate mutation (e.g., 'Set', 'Update', 'Apply') or remove side effects";

        var modifiedMembers = purityInfo.WritesFields.Concat(purityInfo.WritesProperties).ToList();
        var suggestedFix = modifiedMembers.Any()
            ? $"// Modified members: {string.Join(", ", modifiedMembers)}\n// Consider renaming to: Update{methodName.TrimStart("Get".ToCharArray())}"
            : $"// Consider extracting side effects to a separate method";

        return new SideEffectIssue
        {
            Type = ContractType.SideEffect,
            Severity = purityInfo.Purity == MethodPurity.HasIO ? ContractSeverity.Warning : ContractSeverity.Error,
            FilePath = filePath,
            Line = lineSpan.StartLinePosition.Line + 1,
            Column = lineSpan.StartLinePosition.Character + 1,
            ClassName = className,
            MethodName = methodName,
            Description = description,
            Suggestion = suggestion,
            CodeSnippet = method.ToString().Split('\n').FirstOrDefault() ?? method.Identifier.Text,
            SuggestedFix = suggestedFix,
            Purity = purityInfo.Purity,
            ExpectedPurity = expectedPurity,
            ModifiedFields = purityInfo.WritesFields,
            ModifiedProperties = purityInfo.WritesProperties,
            SideEffectCalls = purityInfo.IOOperations,
            Confidence = 0.85
        };
    }
}
