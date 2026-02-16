using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Contracts.Models;

namespace BaseScanner.Analyzers.Contracts;

/// <summary>
/// Detects class invariants - conditions that should always be true for an object's state.
/// Identifies consistency rules between fields and properties.
/// </summary>
public class InvariantDetector
{
    /// <summary>
    /// Detect class invariants in a syntax tree.
    /// </summary>
    public List<InvariantIssue> Detect(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<InvariantIssue>();

        var classes = root.DescendantNodes().OfType<ClassDeclarationSyntax>();

        foreach (var classDecl in classes)
        {
            var className = classDecl.Identifier.Text;

            // Detect various types of invariants
            issues.AddRange(DetectNullabilityInvariants(classDecl, semanticModel, filePath, className));
            issues.AddRange(DetectCollectionInvariants(classDecl, semanticModel, filePath, className));
            issues.AddRange(DetectRelationalInvariants(classDecl, semanticModel, filePath, className));
            issues.AddRange(DetectStateInvariants(classDecl, semanticModel, filePath, className));
            issues.AddRange(DetectDisposalInvariants(classDecl, semanticModel, filePath, className));
        }

        return issues;
    }

    private IEnumerable<InvariantIssue> DetectNullabilityInvariants(
        ClassDeclarationSyntax classDecl,
        SemanticModel semanticModel,
        string filePath,
        string className)
    {
        var issues = new List<InvariantIssue>();

        // Find required fields/properties that are never null after construction
        var members = GetNonNullableReferenceMembers(classDecl, semanticModel);
        var constructors = classDecl.Members.OfType<ConstructorDeclarationSyntax>().ToList();
        var methods = classDecl.Members.OfType<MethodDeclarationSyntax>().ToList();

        foreach (var member in members)
        {
            var memberName = member.Name;

            // Check if set to non-null in all constructors
            bool initializedInAllConstructors = constructors.All(ctor =>
            {
                var body = (SyntaxNode?)ctor.Body ?? ctor.Initializer;
                if (body == null) return false;
                return IsAssignedNonNull(body, memberName);
            });

            // Check if any method sets it to null
            var methodsSettingNull = methods.Where(m =>
            {
                var body = (SyntaxNode?)m.Body ?? m.ExpressionBody;
                return body != null && SetsToNull(body, memberName);
            }).Select(m => m.Identifier.Text).ToList();

            if (initializedInAllConstructors && constructors.Count > 0)
            {
                if (methodsSettingNull.Count > 0)
                {
                    var lineSpan = member.Syntax.GetLocation().GetLineSpan();
                    issues.Add(new InvariantIssue
                    {
                        Type = ContractType.Invariant,
                        Severity = ContractSeverity.Warning,
                        FilePath = filePath,
                        Line = lineSpan.StartLinePosition.Line + 1,
                        Column = lineSpan.StartLinePosition.Character + 1,
                        ClassName = className,
                        MethodName = "",
                        Description = $"Member '{memberName}' is always initialized to non-null but may be set to null later",
                        Suggestion = $"Consider making '{memberName}' nullable or preventing null assignment",
                        CodeSnippet = member.Syntax.ToString(),
                        SuggestedFix = $"// Add validation in setter or mark as nullable",
                        InvolvedMembers = [memberName],
                        InvariantCondition = $"{memberName} != null",
                        PotentiallyViolatingMethods = methodsSettingNull,
                        Confidence = 0.8
                    });
                }
                else
                {
                    // Good invariant - member is always non-null
                    var lineSpan = member.Syntax.GetLocation().GetLineSpan();
                    issues.Add(new InvariantIssue
                    {
                        Type = ContractType.Invariant,
                        Severity = ContractSeverity.Info,
                        FilePath = filePath,
                        Line = lineSpan.StartLinePosition.Line + 1,
                        Column = lineSpan.StartLinePosition.Character + 1,
                        ClassName = className,
                        MethodName = "",
                        Description = $"Member '{memberName}' is always non-null (class invariant)",
                        Suggestion = "Document this invariant for maintainability",
                        CodeSnippet = member.Syntax.ToString(),
                        SuggestedFix = $"/// <remarks>Invariant: {memberName} is never null after construction.</remarks>",
                        InvolvedMembers = [memberName],
                        InvariantCondition = $"{memberName} != null",
                        Confidence = 0.9
                    });
                }
            }
        }

        return issues;
    }

    private IEnumerable<InvariantIssue> DetectCollectionInvariants(
        ClassDeclarationSyntax classDecl,
        SemanticModel semanticModel,
        string filePath,
        string className)
    {
        var issues = new List<InvariantIssue>();

        // Find collection fields
        var fields = classDecl.Members.OfType<FieldDeclarationSyntax>()
            .Where(f => IsCollectionType(f.Declaration.Type.ToString()));

        foreach (var field in fields)
        {
            foreach (var variable in field.Declaration.Variables)
            {
                var fieldName = variable.Identifier.Text;
                var methods = classDecl.Members.OfType<MethodDeclarationSyntax>().ToList();

                // Check if collection is exposed directly
                var exposingProperties = classDecl.Members.OfType<PropertyDeclarationSyntax>()
                    .Where(p => p.ExpressionBody?.Expression.ToString() == fieldName ||
                                (p.AccessorList?.Accessors.Any(a =>
                                    a.ExpressionBody?.Expression.ToString() == fieldName ||
                                    a.Body?.ToString().Contains($"return {fieldName}") == true) ?? false))
                    .ToList();

                if (exposingProperties.Any())
                {
                    var lineSpan = field.GetLocation().GetLineSpan();
                    issues.Add(new InvariantIssue
                    {
                        Type = ContractType.Invariant,
                        Severity = ContractSeverity.Warning,
                        FilePath = filePath,
                        Line = lineSpan.StartLinePosition.Line + 1,
                        Column = lineSpan.StartLinePosition.Character + 1,
                        ClassName = className,
                        MethodName = "",
                        Description = $"Collection '{fieldName}' is exposed, breaking encapsulation invariant",
                        Suggestion = "Return a copy or use IReadOnlyCollection",
                        CodeSnippet = field.ToString(),
                        SuggestedFix = $"public IReadOnlyCollection<T> {exposingProperties.First().Identifier.Text} => {fieldName}.AsReadOnly();",
                        InvolvedMembers = [fieldName, .. exposingProperties.Select(p => p.Identifier.Text)],
                        InvariantCondition = $"External code cannot modify {fieldName}",
                        Confidence = 0.85
                    });
                }

                // Check for synchronized access patterns
                var accessingMethods = methods.Where(m =>
                {
                    var body = (SyntaxNode?)m.Body ?? m.ExpressionBody;
                    return body?.ToString().Contains(fieldName) == true;
                }).ToList();

                var lockedMethods = accessingMethods.Where(m =>
                {
                    var body = (SyntaxNode?)m.Body ?? m.ExpressionBody;
                    return body?.DescendantNodes().OfType<LockStatementSyntax>().Any() == true;
                }).ToList();

                if (lockedMethods.Any() && lockedMethods.Count < accessingMethods.Count)
                {
                    var unlockedMethods = accessingMethods.Except(lockedMethods)
                        .Select(m => m.Identifier.Text).ToList();

                    var lineSpan = field.GetLocation().GetLineSpan();
                    issues.Add(new InvariantIssue
                    {
                        Type = ContractType.Invariant,
                        Severity = ContractSeverity.Error,
                        FilePath = filePath,
                        Line = lineSpan.StartLinePosition.Line + 1,
                        Column = lineSpan.StartLinePosition.Character + 1,
                        ClassName = className,
                        MethodName = "",
                        Description = $"Collection '{fieldName}' has inconsistent synchronization",
                        Suggestion = "Ensure all accesses are synchronized or use ConcurrentCollection",
                        CodeSnippet = field.ToString(),
                        SuggestedFix = $"// Use ConcurrentBag<T> or add lock() to all methods accessing {fieldName}",
                        InvolvedMembers = [fieldName, .. unlockedMethods],
                        InvariantCondition = $"All access to {fieldName} is synchronized",
                        PotentiallyViolatingMethods = unlockedMethods,
                        Confidence = 0.9
                    });
                }
            }
        }

        return issues;
    }

    private IEnumerable<InvariantIssue> DetectRelationalInvariants(
        ClassDeclarationSyntax classDecl,
        SemanticModel semanticModel,
        string filePath,
        string className)
    {
        var issues = new List<InvariantIssue>();

        // Find related fields (e.g., min/max, start/end, count/items)
        var fields = classDecl.Members.OfType<FieldDeclarationSyntax>()
            .SelectMany(f => f.Declaration.Variables.Select(v => v.Identifier.Text))
            .ToList();

        var properties = classDecl.Members.OfType<PropertyDeclarationSyntax>()
            .Select(p => p.Identifier.Text)
            .ToList();

        var allMembers = fields.Concat(properties).ToList();

        // Detect min/max pairs
        var minMaxPairs = FindRelatedPairs(allMembers, "Min", "Max");
        foreach (var (min, max) in minMaxPairs)
        {
            var violatingMethods = FindMethodsViolatingInvariant(classDecl, min, max, (a, b) => $"{a} <= {b}");

            if (violatingMethods.Any())
            {
                var lineSpan = classDecl.Identifier.GetLocation().GetLineSpan();
                issues.Add(new InvariantIssue
                {
                    Type = ContractType.Invariant,
                    Severity = ContractSeverity.Warning,
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    ClassName = className,
                    MethodName = "",
                    Description = $"Relational invariant '{min} <= {max}' may be violated",
                    Suggestion = "Add validation when setting these properties",
                    CodeSnippet = $"{min}, {max}",
                    SuggestedFix = $"if ({min} > {max}) throw new InvalidOperationException(\"{min} cannot exceed {max}\");",
                    InvolvedMembers = [min, max],
                    InvariantCondition = $"{min} <= {max}",
                    PotentiallyViolatingMethods = violatingMethods,
                    Confidence = 0.7
                });
            }
        }

        // Detect start/end pairs
        var startEndPairs = FindRelatedPairs(allMembers, "Start", "End");
        foreach (var (start, end) in startEndPairs)
        {
            var violatingMethods = FindMethodsViolatingInvariant(classDecl, start, end, (a, b) => $"{a} <= {b}");

            if (violatingMethods.Any())
            {
                var lineSpan = classDecl.Identifier.GetLocation().GetLineSpan();
                issues.Add(new InvariantIssue
                {
                    Type = ContractType.Invariant,
                    Severity = ContractSeverity.Warning,
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    ClassName = className,
                    MethodName = "",
                    Description = $"Relational invariant '{start} <= {end}' may be violated",
                    Suggestion = "Add validation when setting these properties",
                    CodeSnippet = $"{start}, {end}",
                    SuggestedFix = $"if ({start} > {end}) throw new ArgumentOutOfRangeException();",
                    InvolvedMembers = [start, end],
                    InvariantCondition = $"{start} <= {end}",
                    PotentiallyViolatingMethods = violatingMethods,
                    Confidence = 0.7
                });
            }
        }

        // Detect count/capacity relationships
        var countCapacityPairs = new List<(string, string)>();
        foreach (var count in allMembers.Where(m => m.ToLower().Contains("count") || m.ToLower().Contains("size")))
        {
            foreach (var capacity in allMembers.Where(m => m.ToLower().Contains("capacity") || m.ToLower().Contains("max")))
            {
                if (count != capacity)
                    countCapacityPairs.Add((count, capacity));
            }
        }

        foreach (var (count, capacity) in countCapacityPairs)
        {
            var lineSpan = classDecl.Identifier.GetLocation().GetLineSpan();
            issues.Add(new InvariantIssue
            {
                Type = ContractType.Invariant,
                Severity = ContractSeverity.Info,
                FilePath = filePath,
                Line = lineSpan.StartLinePosition.Line + 1,
                Column = lineSpan.StartLinePosition.Character + 1,
                ClassName = className,
                MethodName = "",
                Description = $"Potential invariant: '{count} <= {capacity}'",
                Suggestion = "Verify and document this relationship if it's an invariant",
                CodeSnippet = $"{count}, {capacity}",
                SuggestedFix = $"/// <invariant>{count} is always less than or equal to {capacity}</invariant>",
                InvolvedMembers = [count, capacity],
                InvariantCondition = $"{count} <= {capacity}",
                Confidence = 0.5
            });
        }

        return issues;
    }

    private IEnumerable<InvariantIssue> DetectStateInvariants(
        ClassDeclarationSyntax classDecl,
        SemanticModel semanticModel,
        string filePath,
        string className)
    {
        var issues = new List<InvariantIssue>();

        // Find state-related fields (IsX, HasX, etc.)
        var stateFields = classDecl.Members.OfType<FieldDeclarationSyntax>()
            .SelectMany(f => f.Declaration.Variables)
            .Where(v => v.Identifier.Text.StartsWith("_is") ||
                       v.Identifier.Text.StartsWith("_has") ||
                       v.Identifier.Text.StartsWith("is") ||
                       v.Identifier.Text.StartsWith("has"))
            .ToList();

        var stateProperties = classDecl.Members.OfType<PropertyDeclarationSyntax>()
            .Where(p => p.Identifier.Text.StartsWith("Is") ||
                       p.Identifier.Text.StartsWith("Has") ||
                       p.Identifier.Text.StartsWith("Can"))
            .ToList();

        // Find methods that check state before operating
        var methods = classDecl.Members.OfType<MethodDeclarationSyntax>().ToList();

        foreach (var prop in stateProperties)
        {
            var propName = prop.Identifier.Text;
            var methodsRequiringState = methods.Where(m =>
            {
                var body = (SyntaxNode?)m.Body ?? m.ExpressionBody;
                if (body == null) return false;

                // Check if method has a guard checking this property
                var ifStatements = body.DescendantNodes().OfType<IfStatementSyntax>();
                return ifStatements.Any(ifs =>
                    ifs.Condition.ToString().Contains(propName) &&
                    ifs.Statement.ToString().Contains("throw"));
            }).ToList();

            if (methodsRequiringState.Count >= 2)
            {
                var lineSpan = prop.GetLocation().GetLineSpan();
                issues.Add(new InvariantIssue
                {
                    Type = ContractType.Invariant,
                    Severity = ContractSeverity.Info,
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    ClassName = className,
                    MethodName = "",
                    Description = $"State property '{propName}' is checked by multiple methods",
                    Suggestion = "Consider documenting this as a state invariant",
                    CodeSnippet = prop.ToString(),
                    SuggestedFix = $"/// <remarks>Methods require {propName} == true before calling.</remarks>",
                    InvolvedMembers = [propName, .. methodsRequiringState.Select(m => m.Identifier.Text)],
                    InvariantCondition = $"{propName} == true for certain operations",
                    Confidence = 0.75
                });
            }
        }

        return issues;
    }

    private IEnumerable<InvariantIssue> DetectDisposalInvariants(
        ClassDeclarationSyntax classDecl,
        SemanticModel semanticModel,
        string filePath,
        string className)
    {
        var issues = new List<InvariantIssue>();

        // Check if class implements IDisposable
        bool implementsDisposable = classDecl.BaseList?.Types
            .Any(t => t.ToString().Contains("IDisposable") || t.ToString().Contains("IAsyncDisposable")) ?? false;

        if (!implementsDisposable)
            return issues;

        // Find the disposed flag
        var disposedFields = classDecl.Members.OfType<FieldDeclarationSyntax>()
            .SelectMany(f => f.Declaration.Variables)
            .Where(v => v.Identifier.Text.ToLower().Contains("disposed") ||
                       v.Identifier.Text.ToLower().Contains("isdisposed"))
            .ToList();

        if (!disposedFields.Any())
        {
            var lineSpan = classDecl.Identifier.GetLocation().GetLineSpan();
            issues.Add(new InvariantIssue
            {
                Type = ContractType.Invariant,
                Severity = ContractSeverity.Warning,
                FilePath = filePath,
                Line = lineSpan.StartLinePosition.Line + 1,
                Column = lineSpan.StartLinePosition.Character + 1,
                ClassName = className,
                MethodName = "",
                Description = "IDisposable class lacks disposed tracking field",
                Suggestion = "Add a _disposed field to track disposal state",
                CodeSnippet = classDecl.Identifier.Text,
                SuggestedFix = "private bool _disposed;\n\nprivate void ThrowIfDisposed() { if (_disposed) throw new ObjectDisposedException(nameof(" + className + ")); }",
                InvolvedMembers = ["IDisposable"],
                InvariantCondition = "Methods check disposal state before operating",
                Confidence = 0.8
            });
            return issues;
        }

        // Find methods that should check disposed state
        var publicMethods = classDecl.Members.OfType<MethodDeclarationSyntax>()
            .Where(m => m.Modifiers.Any(SyntaxKind.PublicKeyword))
            .Where(m => m.Identifier.Text != "Dispose" && m.Identifier.Text != "DisposeAsync")
            .ToList();

        var disposedFieldName = disposedFields.First().Identifier.Text;
        var methodsWithoutCheck = publicMethods.Where(m =>
        {
            var body = (SyntaxNode?)m.Body ?? m.ExpressionBody;
            if (body == null) return false;

            var bodyText = body.ToString();
            return !bodyText.Contains(disposedFieldName) &&
                   !bodyText.Contains("ThrowIfDisposed") &&
                   !bodyText.Contains("ObjectDisposedException");
        }).Select(m => m.Identifier.Text).ToList();

        if (methodsWithoutCheck.Any())
        {
            var lineSpan = disposedFields.First().GetLocation().GetLineSpan();
            issues.Add(new InvariantIssue
            {
                Type = ContractType.Invariant,
                Severity = ContractSeverity.Warning,
                FilePath = filePath,
                Line = lineSpan.StartLinePosition.Line + 1,
                Column = lineSpan.StartLinePosition.Character + 1,
                ClassName = className,
                MethodName = "",
                Description = "Some public methods don't check disposal state",
                Suggestion = "Add disposal check at the start of public methods",
                CodeSnippet = disposedFieldName,
                SuggestedFix = $"if ({disposedFieldName}) throw new ObjectDisposedException(nameof({className}));",
                InvolvedMembers = [disposedFieldName, .. methodsWithoutCheck],
                InvariantCondition = "All public methods check _disposed before operating",
                PotentiallyViolatingMethods = methodsWithoutCheck,
                Confidence = 0.85
            });
        }

        return issues;
    }

    private List<(string Name, SyntaxNode Syntax)> GetNonNullableReferenceMembers(
        ClassDeclarationSyntax classDecl,
        SemanticModel semanticModel)
    {
        var members = new List<(string Name, SyntaxNode Syntax)>();

        // Fields
        foreach (var field in classDecl.Members.OfType<FieldDeclarationSyntax>())
        {
            var typeName = field.Declaration.Type.ToString();
            if (IsReferenceType(typeName) && !typeName.EndsWith("?"))
            {
                foreach (var variable in field.Declaration.Variables)
                {
                    members.Add((variable.Identifier.Text, field));
                }
            }
        }

        // Properties
        foreach (var prop in classDecl.Members.OfType<PropertyDeclarationSyntax>())
        {
            var typeName = prop.Type.ToString();
            if (IsReferenceType(typeName) && !typeName.EndsWith("?"))
            {
                members.Add((prop.Identifier.Text, prop));
            }
        }

        return members;
    }

    private bool IsReferenceType(string typeName)
    {
        var valueTypes = new[] { "int", "long", "short", "byte", "bool", "float", "double", "decimal",
            "char", "DateTime", "Guid", "TimeSpan", "DateOnly", "TimeOnly" };
        return !valueTypes.Contains(typeName) && !typeName.StartsWith("Nullable<");
    }

    private bool IsCollectionType(string typeName)
    {
        return typeName.StartsWith("List<") || typeName.StartsWith("Dictionary<") ||
               typeName.StartsWith("HashSet<") || typeName.Contains("Collection") ||
               typeName.EndsWith("[]");
    }

    private bool IsAssignedNonNull(SyntaxNode body, string memberName)
    {
        var assignments = body.DescendantNodes().OfType<AssignmentExpressionSyntax>()
            .Where(a => a.Left.ToString() == memberName ||
                       a.Left.ToString() == $"this.{memberName}" ||
                       a.Left.ToString() == $"_{memberName}" ||
                       a.Left.ToString() == $"this._{memberName}");

        return assignments.Any(a =>
            a.Right is not LiteralExpressionSyntax lit ||
            !lit.IsKind(SyntaxKind.NullLiteralExpression));
    }

    private bool SetsToNull(SyntaxNode body, string memberName)
    {
        var assignments = body.DescendantNodes().OfType<AssignmentExpressionSyntax>()
            .Where(a => a.Left.ToString() == memberName ||
                       a.Left.ToString() == $"this.{memberName}" ||
                       a.Left.ToString() == $"_{memberName}");

        return assignments.Any(a =>
            a.Right is LiteralExpressionSyntax lit &&
            lit.IsKind(SyntaxKind.NullLiteralExpression));
    }

    private List<(string, string)> FindRelatedPairs(List<string> members, string suffix1, string suffix2)
    {
        var pairs = new List<(string, string)>();

        foreach (var m1 in members.Where(m => m.Contains(suffix1)))
        {
            var baseName = m1.Replace(suffix1, "");
            var m2Candidates = members.Where(m => m.Contains(suffix2) && m.Replace(suffix2, "") == baseName);

            foreach (var m2 in m2Candidates)
            {
                pairs.Add((m1, m2));
            }
        }

        return pairs;
    }

    private List<string> FindMethodsViolatingInvariant(
        ClassDeclarationSyntax classDecl,
        string member1,
        string member2,
        Func<string, string, string> invariantExpr)
    {
        var violatingMethods = new List<string>();

        foreach (var method in classDecl.Members.OfType<MethodDeclarationSyntax>())
        {
            var body = (SyntaxNode?)method.Body ?? method.ExpressionBody;
            if (body == null) continue;

            // Check if method modifies both members without validation
            var modifiesMember1 = body.DescendantNodes().OfType<AssignmentExpressionSyntax>()
                .Any(a => a.Left.ToString().Contains(member1));
            var modifiesMember2 = body.DescendantNodes().OfType<AssignmentExpressionSyntax>()
                .Any(a => a.Left.ToString().Contains(member2));

            if (modifiesMember1 || modifiesMember2)
            {
                // Check if there's a validation check
                var hasValidation = body.DescendantNodes().OfType<IfStatementSyntax>()
                    .Any(ifs => ifs.Condition.ToString().Contains(member1) &&
                               ifs.Condition.ToString().Contains(member2));

                if (!hasValidation)
                {
                    violatingMethods.Add(method.Identifier.Text);
                }
            }
        }

        return violatingMethods;
    }
}
