using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Contracts.Models;

namespace BaseScanner.Analyzers.Contracts;

/// <summary>
/// Detects implicit preconditions in method implementations.
/// Identifies parameters that are used without proper validation.
/// </summary>
public class PreconditionDetector
{
    private static readonly HashSet<string> ReferenceTypes = new()
    {
        "string", "String", "object", "Object", "dynamic"
    };

    private static readonly HashSet<string> CollectionTypes = new()
    {
        "IEnumerable", "ICollection", "IList", "List", "Array",
        "Dictionary", "HashSet", "Queue", "Stack", "LinkedList"
    };

    /// <summary>
    /// Detect implicit preconditions in a syntax tree.
    /// </summary>
    public List<PreconditionIssue> Detect(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<PreconditionIssue>();

        var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>();

        foreach (var method in methods)
        {
            var className = GetClassName(method);
            var body = (SyntaxNode?)method.Body ?? method.ExpressionBody;
            if (body == null) continue;

            // Detect null preconditions
            issues.AddRange(DetectNullPreconditions(method, body, semanticModel, filePath, className));

            // Detect range preconditions
            issues.AddRange(DetectRangePreconditions(method, body, semanticModel, filePath, className));

            // Detect state preconditions
            issues.AddRange(DetectStatePreconditions(method, body, semanticModel, filePath, className));
        }

        return issues;
    }

    private IEnumerable<PreconditionIssue> DetectNullPreconditions(
        MethodDeclarationSyntax method,
        SyntaxNode body,
        SemanticModel semanticModel,
        string filePath,
        string className)
    {
        var issues = new List<PreconditionIssue>();
        var checkedParameters = GetNullCheckedParameters(body);

        foreach (var parameter in method.ParameterList.Parameters)
        {
            var paramName = parameter.Identifier.Text;
            var paramType = parameter.Type?.ToString() ?? "";

            // Skip if already checked, is value type, or has default value
            if (checkedParameters.Contains(paramName))
                continue;

            if (IsValueType(paramType, semanticModel, parameter.Type))
                continue;

            if (parameter.Default != null)
                continue;

            // Check if parameter is dereferenced
            var dereferences = FindDereferences(body, paramName);
            if (!dereferences.Any())
                continue;

            var firstDeref = dereferences.First();
            var lineSpan = firstDeref.GetLocation().GetLineSpan();

            // Determine severity based on usage
            var usageCount = dereferences.Count();
            var severity = usageCount > 3 ? ContractSeverity.Warning : ContractSeverity.Info;

            // Check if it's used in a critical context
            if (IsUsedInCriticalContext(firstDeref, semanticModel))
            {
                severity = ContractSeverity.Error;
            }

            issues.Add(new PreconditionIssue
            {
                Type = ContractType.NullPrecondition,
                Severity = severity,
                FilePath = filePath,
                Line = lineSpan.StartLinePosition.Line + 1,
                Column = lineSpan.StartLinePosition.Character + 1,
                ClassName = className,
                MethodName = method.Identifier.Text,
                Description = $"Parameter '{paramName}' is used without null check",
                Suggestion = $"Add null check at method entry for parameter '{paramName}'",
                CodeSnippet = firstDeref.Parent?.ToString() ?? firstDeref.ToString(),
                SuggestedFix = GenerateNullGuard(paramName, paramType),
                TargetExpression = paramName,
                ExpectedCondition = $"{paramName} != null",
                ExceptionType = "ArgumentNullException",
                Confidence = 0.85
            });
        }

        return issues;
    }

    private IEnumerable<PreconditionIssue> DetectRangePreconditions(
        MethodDeclarationSyntax method,
        SyntaxNode body,
        SemanticModel semanticModel,
        string filePath,
        string className)
    {
        var issues = new List<PreconditionIssue>();
        var checkedParameters = GetRangeCheckedParameters(body, method);

        foreach (var parameter in method.ParameterList.Parameters)
        {
            var paramName = parameter.Identifier.Text;
            var paramType = parameter.Type?.ToString() ?? "";

            // Look for index-like parameters
            if (!IsIndexType(paramType, paramName))
                continue;

            if (checkedParameters.Contains(paramName))
                continue;

            // Check if used as array/collection index
            var indexUsages = FindIndexUsages(body, paramName);
            if (!indexUsages.Any())
                continue;

            var firstUsage = indexUsages.First();
            var lineSpan = firstUsage.GetLocation().GetLineSpan();

            issues.Add(new PreconditionIssue
            {
                Type = ContractType.RangePrecondition,
                Severity = ContractSeverity.Warning,
                FilePath = filePath,
                Line = lineSpan.StartLinePosition.Line + 1,
                Column = lineSpan.StartLinePosition.Character + 1,
                ClassName = className,
                MethodName = method.Identifier.Text,
                Description = $"Index parameter '{paramName}' used without bounds check",
                Suggestion = $"Add bounds check for index parameter '{paramName}'",
                CodeSnippet = firstUsage.Parent?.ToString() ?? firstUsage.ToString(),
                SuggestedFix = GenerateRangeGuard(paramName, firstUsage),
                TargetExpression = paramName,
                ExpectedCondition = $"{paramName} >= 0 && {paramName} < collection.Length",
                ExceptionType = "ArgumentOutOfRangeException",
                Confidence = 0.8
            });
        }

        return issues;
    }

    private IEnumerable<PreconditionIssue> DetectStatePreconditions(
        MethodDeclarationSyntax method,
        SyntaxNode body,
        SemanticModel semanticModel,
        string filePath,
        string className)
    {
        var issues = new List<PreconditionIssue>();

        // Look for field/property accesses that imply state requirements
        var memberAccesses = body.DescendantNodes().OfType<MemberAccessExpressionSyntax>()
            .Where(m => m.Expression is ThisExpressionSyntax ||
                        m.Expression is IdentifierNameSyntax id &&
                        IsFieldOrProperty(id, semanticModel));

        var stateChecks = new Dictionary<string, List<MemberAccessExpressionSyntax>>();

        foreach (var access in memberAccesses)
        {
            var memberName = access.Name.Identifier.Text;
            var symbol = semanticModel.GetSymbolInfo(access).Symbol;

            if (symbol == null) continue;

            // Check if this member access is inside a null check for the member
            if (IsInsideNullCheck(access, memberName))
                continue;

            // Look for patterns suggesting state requirements
            if (memberName.Contains("Initialized") ||
                memberName.Contains("Connected") ||
                memberName.Contains("Open") ||
                memberName.Contains("Ready") ||
                memberName.Contains("Disposed"))
            {
                if (!stateChecks.ContainsKey(memberName))
                    stateChecks[memberName] = new List<MemberAccessExpressionSyntax>();
                stateChecks[memberName].Add(access);
            }
        }

        // Detect usage of state-dependent members without checks
        var conditionalAccesses = body.DescendantNodes().OfType<IfStatementSyntax>();
        var guardedMembers = new HashSet<string>();

        foreach (var ifStmt in conditionalAccesses)
        {
            var condition = ifStmt.Condition.ToString();
            foreach (var stateMember in stateChecks.Keys)
            {
                if (condition.Contains(stateMember))
                {
                    guardedMembers.Add(stateMember);
                }
            }
        }

        // Report unguarded state accesses
        foreach (var (memberName, accesses) in stateChecks)
        {
            if (guardedMembers.Contains(memberName))
                continue;

            var firstAccess = accesses.First();
            var lineSpan = firstAccess.GetLocation().GetLineSpan();

            issues.Add(new PreconditionIssue
            {
                Type = ContractType.StatePrecondition,
                Severity = ContractSeverity.Warning,
                FilePath = filePath,
                Line = lineSpan.StartLinePosition.Line + 1,
                Column = lineSpan.StartLinePosition.Character + 1,
                ClassName = className,
                MethodName = method.Identifier.Text,
                Description = $"Method may require object to be in specific state (uses '{memberName}')",
                Suggestion = $"Add state check for '{memberName}' before use",
                CodeSnippet = firstAccess.Parent?.ToString() ?? firstAccess.ToString(),
                SuggestedFix = GenerateStateGuard(memberName),
                TargetExpression = $"this.{memberName}",
                ExpectedCondition = $"{memberName} is in expected state",
                ExceptionType = "InvalidOperationException",
                Confidence = 0.6
            });
        }

        return issues;
    }

    private HashSet<string> GetNullCheckedParameters(SyntaxNode body)
    {
        var checkedParams = new HashSet<string>();

        // Check for null checks in if statements
        var ifStatements = body.DescendantNodes().OfType<IfStatementSyntax>();
        foreach (var ifStmt in ifStatements)
        {
            var condition = ifStmt.Condition.ToString();

            // Pattern: if (param == null) or if (param is null)
            ExtractNullCheckParams(condition, checkedParams);
        }

        // Check for ArgumentNullException.ThrowIfNull
        var invocations = body.DescendantNodes().OfType<InvocationExpressionSyntax>();
        foreach (var inv in invocations)
        {
            var text = inv.ToString();
            if (text.Contains("ThrowIfNull") || text.Contains("ArgumentNullException"))
            {
                // Extract parameter name from the invocation
                foreach (var arg in inv.ArgumentList.Arguments)
                {
                    if (arg.Expression is IdentifierNameSyntax id)
                    {
                        checkedParams.Add(id.Identifier.Text);
                    }
                    else if (arg.Expression is InvocationExpressionSyntax nameofInv &&
                             nameofInv.ToString().StartsWith("nameof"))
                    {
                        var nameofArg = nameofInv.ArgumentList.Arguments.FirstOrDefault();
                        if (nameofArg?.Expression is IdentifierNameSyntax nameofId)
                        {
                            checkedParams.Add(nameofId.Identifier.Text);
                        }
                    }
                }
            }
        }

        // Check for null-coalescing operators (?? throw)
        var nullCoalescing = body.DescendantNodes().OfType<BinaryExpressionSyntax>()
            .Where(b => b.IsKind(SyntaxKind.CoalesceExpression));
        foreach (var coalesce in nullCoalescing)
        {
            if (coalesce.Left is IdentifierNameSyntax id)
            {
                checkedParams.Add(id.Identifier.Text);
            }
        }

        // Check for Guard clauses and contract libraries
        foreach (var inv in invocations)
        {
            var text = inv.ToString().ToLower();
            if (text.Contains("guard.") || text.Contains("contract.requires") ||
                text.Contains("check.") || text.Contains("ensure."))
            {
                foreach (var arg in inv.ArgumentList.Arguments)
                {
                    if (arg.Expression is IdentifierNameSyntax id)
                    {
                        checkedParams.Add(id.Identifier.Text);
                    }
                }
            }
        }

        return checkedParams;
    }

    private void ExtractNullCheckParams(string condition, HashSet<string> checkedParams)
    {
        // Simple patterns for null checks
        var patterns = new[]
        {
            @"(\w+)\s*==\s*null",
            @"(\w+)\s*!=\s*null",
            @"(\w+)\s+is\s+null",
            @"(\w+)\s+is\s+not\s+null",
            @"(\w+)\s*\?\.",
            @"(\w+)\s*\?\?"
        };

        foreach (var pattern in patterns)
        {
            var regex = new System.Text.RegularExpressions.Regex(pattern);
            var matches = regex.Matches(condition);
            foreach (System.Text.RegularExpressions.Match match in matches)
            {
                if (match.Groups.Count > 1)
                {
                    checkedParams.Add(match.Groups[1].Value);
                }
            }
        }
    }

    private HashSet<string> GetRangeCheckedParameters(SyntaxNode body, MethodDeclarationSyntax method)
    {
        var checkedParams = new HashSet<string>();

        var ifStatements = body.DescendantNodes().OfType<IfStatementSyntax>();
        foreach (var ifStmt in ifStatements)
        {
            var condition = ifStmt.Condition.ToString();

            // Patterns for range checks
            foreach (var param in method.ParameterList.Parameters)
            {
                var paramName = param.Identifier.Text;

                if (condition.Contains($"{paramName} < 0") ||
                    condition.Contains($"{paramName} >= 0") ||
                    condition.Contains($"{paramName} > ") ||
                    condition.Contains($"{paramName} <= ") ||
                    condition.Contains($"0 <= {paramName}") ||
                    condition.Contains($"0 > {paramName}"))
                {
                    checkedParams.Add(paramName);
                }
            }
        }

        // Check for ArgumentOutOfRangeException
        var invocations = body.DescendantNodes().OfType<InvocationExpressionSyntax>();
        foreach (var inv in invocations)
        {
            var text = inv.ToString();
            if (text.Contains("ThrowIfNegative") || text.Contains("ThrowIfGreaterThan") ||
                text.Contains("ThrowIfLessThan") || text.Contains("ArgumentOutOfRangeException"))
            {
                foreach (var arg in inv.ArgumentList.Arguments)
                {
                    if (arg.Expression is IdentifierNameSyntax id)
                    {
                        checkedParams.Add(id.Identifier.Text);
                    }
                }
            }
        }

        return checkedParams;
    }

    private bool IsValueType(string typeName, SemanticModel semanticModel, TypeSyntax? typeSyntax)
    {
        if (typeSyntax == null)
            return false;

        var typeInfo = semanticModel.GetTypeInfo(typeSyntax);
        if (typeInfo.Type?.IsValueType == true)
            return true;

        // Check for nullable value types
        if (typeName.EndsWith("?"))
            return false; // Nullable types can be null

        // Common value types
        return typeName is "int" or "long" or "short" or "byte" or "bool" or "float" or "double" or "decimal" or
            "char" or "Int32" or "Int64" or "Boolean" or "DateTime" or "Guid" or "TimeSpan" or
            "uint" or "ulong" or "ushort" or "sbyte" or "DateOnly" or "TimeOnly";
    }

    private bool IsIndexType(string typeName, string paramName)
    {
        var indexTypes = new[] { "int", "Int32", "long", "Int64", "uint", "UInt32" };
        if (!indexTypes.Contains(typeName))
            return false;

        var indexNames = new[] { "index", "idx", "i", "j", "k", "pos", "position", "offset", "start", "end", "count", "length" };
        return indexNames.Any(n => paramName.ToLower().Contains(n));
    }

    private IEnumerable<SyntaxNode> FindDereferences(SyntaxNode body, string paramName)
    {
        var dereferences = new List<SyntaxNode>();

        // Member access: param.Something
        var memberAccesses = body.DescendantNodes().OfType<MemberAccessExpressionSyntax>()
            .Where(m => m.Expression is IdentifierNameSyntax id && id.Identifier.Text == paramName);
        dereferences.AddRange(memberAccesses);

        // Indexer access: param[x]
        var elementAccesses = body.DescendantNodes().OfType<ElementAccessExpressionSyntax>()
            .Where(e => e.Expression is IdentifierNameSyntax id && id.Identifier.Text == paramName);
        dereferences.AddRange(elementAccesses);

        // Method invocation on the parameter: param.Method()
        var invocations = body.DescendantNodes().OfType<InvocationExpressionSyntax>()
            .Where(inv => inv.Expression is MemberAccessExpressionSyntax ma &&
                          ma.Expression is IdentifierNameSyntax id &&
                          id.Identifier.Text == paramName);
        dereferences.AddRange(invocations);

        return dereferences.OrderBy(d => d.SpanStart);
    }

    private IEnumerable<ElementAccessExpressionSyntax> FindIndexUsages(SyntaxNode body, string paramName)
    {
        return body.DescendantNodes().OfType<ElementAccessExpressionSyntax>()
            .Where(e => e.ArgumentList.Arguments.Any(a =>
                a.Expression is IdentifierNameSyntax id && id.Identifier.Text == paramName));
    }

    private bool IsUsedInCriticalContext(SyntaxNode node, SemanticModel semanticModel)
    {
        // Check if used in security-sensitive operations
        var parent = node.Parent;
        while (parent != null)
        {
            if (parent is InvocationExpressionSyntax inv)
            {
                var text = inv.ToString().ToLower();
                if (text.Contains("execute") || text.Contains("command") ||
                    text.Contains("query") || text.Contains("sql") ||
                    text.Contains("process") || text.Contains("file"))
                {
                    return true;
                }
            }
            parent = parent.Parent;
        }

        return false;
    }

    private bool IsInsideNullCheck(SyntaxNode node, string memberName)
    {
        var parent = node.Parent;
        while (parent != null)
        {
            if (parent is IfStatementSyntax ifStmt)
            {
                var condition = ifStmt.Condition.ToString();
                if (condition.Contains($"{memberName} != null") ||
                    condition.Contains($"{memberName} is not null"))
                {
                    return true;
                }
            }
            parent = parent.Parent;
        }
        return false;
    }

    private bool IsFieldOrProperty(IdentifierNameSyntax id, SemanticModel semanticModel)
    {
        var symbol = semanticModel.GetSymbolInfo(id).Symbol;
        return symbol is IFieldSymbol or IPropertySymbol;
    }

    private string GenerateNullGuard(string paramName, string paramType)
    {
        return $"ArgumentNullException.ThrowIfNull({paramName});";
    }

    private string GenerateRangeGuard(string paramName, ElementAccessExpressionSyntax usage)
    {
        var collection = usage.Expression.ToString();
        return $"ArgumentOutOfRangeException.ThrowIfNegative({paramName});\n" +
               $"ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual({paramName}, {collection}.Length);";
    }

    private string GenerateStateGuard(string memberName)
    {
        var stateName = memberName.Replace("Is", "").Replace("_", "");
        return $"if (!{memberName})\n" +
               $"    throw new InvalidOperationException(\"Object must be {stateName} before calling this method.\");";
    }

    private string GetClassName(MethodDeclarationSyntax method)
    {
        return method.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault()?.Identifier.Text ?? "Unknown";
    }
}
