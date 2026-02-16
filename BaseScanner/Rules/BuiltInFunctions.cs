using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace BaseScanner.Rules;

/// <summary>
/// Built-in functions for the rule DSL.
/// These functions can be used in rule conditions to perform complex checks.
/// </summary>
public class BuiltInFunctions
{
    private readonly Dictionary<string, Func<SyntaxNode, SemanticModel?, string[], bool>> _functions;

    public BuiltInFunctions()
    {
        _functions = new Dictionary<string, Func<SyntaxNode, SemanticModel?, string[], bool>>(StringComparer.OrdinalIgnoreCase)
        {
            { "isPublic", IsPublic },
            { "isPrivate", IsPrivate },
            { "isProtected", IsProtected },
            { "isInternal", IsInternal },
            { "isStatic", IsStatic },
            { "isAsync", IsAsync },
            { "isVirtual", IsVirtual },
            { "isOverride", IsOverride },
            { "isAbstract", IsAbstract },
            { "hasAttribute", HasAttribute },
            { "inNamespace", InNamespace },
            { "inheritsFrom", InheritsFrom },
            { "implements", ImplementsInterface },
            { "hasParameter", HasParameter },
            { "parameterCount", ParameterCount },
            { "lineCount", LineCount },
            { "complexity", Complexity },
            { "inTryCatch", InTryCatch },
            { "inLoop", InLoop },
            { "inConditional", InConditional },
            { "isTestMethod", IsTestMethod },
            { "isConstructor", IsConstructor },
            { "isProperty", IsProperty },
            { "isField", IsField },
            { "hasDocComment", HasDocComment },
            { "returnType", ReturnType },
            { "containsCall", ContainsCall },
            { "usesType", UsesType },
            { "isGeneric", IsGeneric },
            { "hasTypeParameter", HasTypeParameter },
            { "isExtensionMethod", IsExtensionMethod },
            { "isDisposable", IsDisposable },
            { "accessesField", AccessesField },
            { "modifiesState", ModifiesState }
        };
    }

    /// <summary>
    /// Creates a validator function from a condition string.
    /// Format: functionName(arg1, arg2, ...)
    /// </summary>
    public Func<SyntaxNode, SemanticModel?, bool>? CreateConditionValidator(string condition)
    {
        var match = Regex.Match(condition.Trim(), @"^(\w+)\s*\(([^)]*)\)$");

        if (!match.Success)
        {
            // Simple condition without arguments
            if (_functions.TryGetValue(condition.Trim(), out var simpleFunc))
            {
                return (node, model) => simpleFunc(node, model, Array.Empty<string>());
            }
            return null;
        }

        var functionName = match.Groups[1].Value;
        var argsString = match.Groups[2].Value;
        var args = string.IsNullOrWhiteSpace(argsString)
            ? Array.Empty<string>()
            : argsString.Split(',').Select(a => a.Trim().Trim('"', '\'')).ToArray();

        // Check for negation
        var isNegated = functionName.StartsWith("not", StringComparison.OrdinalIgnoreCase);
        if (isNegated)
        {
            functionName = functionName.Substring(3);
        }

        if (!_functions.TryGetValue(functionName, out var func))
        {
            return null;
        }

        if (isNegated)
        {
            return (node, model) => !func(node, model, args);
        }

        return (node, model) => func(node, model, args);
    }

    /// <summary>
    /// Gets all available function names.
    /// </summary>
    public IEnumerable<string> GetAvailableFunctions() => _functions.Keys;

    #region Modifier Checks

    private bool IsPublic(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return GetModifiers(node).Any(SyntaxKind.PublicKeyword);
    }

    private bool IsPrivate(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return GetModifiers(node).Any(SyntaxKind.PrivateKeyword);
    }

    private bool IsProtected(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return GetModifiers(node).Any(SyntaxKind.ProtectedKeyword);
    }

    private bool IsInternal(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return GetModifiers(node).Any(SyntaxKind.InternalKeyword);
    }

    private bool IsStatic(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return GetModifiers(node).Any(SyntaxKind.StaticKeyword);
    }

    private bool IsAsync(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return GetModifiers(node).Any(SyntaxKind.AsyncKeyword);
    }

    private bool IsVirtual(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return GetModifiers(node).Any(SyntaxKind.VirtualKeyword);
    }

    private bool IsOverride(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return GetModifiers(node).Any(SyntaxKind.OverrideKeyword);
    }

    private bool IsAbstract(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return GetModifiers(node).Any(SyntaxKind.AbstractKeyword);
    }

    private SyntaxTokenList GetModifiers(SyntaxNode node)
    {
        return node switch
        {
            MethodDeclarationSyntax m => m.Modifiers,
            PropertyDeclarationSyntax p => p.Modifiers,
            FieldDeclarationSyntax f => f.Modifiers,
            ClassDeclarationSyntax c => c.Modifiers,
            StructDeclarationSyntax s => s.Modifiers,
            InterfaceDeclarationSyntax i => i.Modifiers,
            EventDeclarationSyntax e => e.Modifiers,
            _ => node.Ancestors().OfType<MemberDeclarationSyntax>().FirstOrDefault() switch
            {
                MethodDeclarationSyntax m => m.Modifiers,
                PropertyDeclarationSyntax p => p.Modifiers,
                FieldDeclarationSyntax f => f.Modifiers,
                _ => default
            }
        };
    }

    #endregion

    #region Type and Attribute Checks

    private bool HasAttribute(SyntaxNode node, SemanticModel? model, string[] args)
    {
        if (args.Length == 0) return false;

        var attributeName = args[0];
        var attributes = GetAttributes(node);

        return attributes.SelectMany(al => al.Attributes).Any(a =>
        {
            var name = a.Name.ToString();
            return name.Equals(attributeName, StringComparison.OrdinalIgnoreCase) ||
                   name.Equals(attributeName + "Attribute", StringComparison.OrdinalIgnoreCase);
        });
    }

    private SyntaxList<AttributeListSyntax> GetAttributes(SyntaxNode node)
    {
        return node switch
        {
            MethodDeclarationSyntax m => m.AttributeLists,
            PropertyDeclarationSyntax p => p.AttributeLists,
            FieldDeclarationSyntax f => f.AttributeLists,
            ClassDeclarationSyntax c => c.AttributeLists,
            ParameterSyntax param => param.AttributeLists,
            _ => node.Ancestors().OfType<MemberDeclarationSyntax>().FirstOrDefault() switch
            {
                MethodDeclarationSyntax m => m.AttributeLists,
                _ => default
            }
        };
    }

    private bool InNamespace(SyntaxNode node, SemanticModel? model, string[] args)
    {
        if (args.Length == 0) return false;

        var pattern = args[0];
        var ns = node.Ancestors().OfType<BaseNamespaceDeclarationSyntax>().FirstOrDefault();

        if (ns == null) return false;

        var nsName = ns.Name.ToString();
        return WildcardMatch(nsName, pattern);
    }

    private bool InheritsFrom(SyntaxNode node, SemanticModel? model, string[] args)
    {
        if (args.Length == 0 || model == null) return false;

        var baseTypeName = args[0];
        var classDecl = node.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();

        if (classDecl == null) return false;

        var symbol = model.GetDeclaredSymbol(classDecl);
        if (symbol == null) return false;

        var baseType = symbol.BaseType;
        while (baseType != null)
        {
            if (WildcardMatch(baseType.Name, baseTypeName) ||
                WildcardMatch(baseType.ToDisplayString(), baseTypeName))
            {
                return true;
            }
            baseType = baseType.BaseType;
        }

        return false;
    }

    private bool ImplementsInterface(SyntaxNode node, SemanticModel? model, string[] args)
    {
        if (args.Length == 0 || model == null) return false;

        var interfaceName = args[0];
        var typeDecl = node.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault();

        if (typeDecl == null) return false;

        var symbol = model.GetDeclaredSymbol(typeDecl) as INamedTypeSymbol;
        if (symbol == null) return false;

        return symbol.AllInterfaces.Any(i =>
            WildcardMatch(i.Name, interfaceName) ||
            WildcardMatch(i.ToDisplayString(), interfaceName));
    }

    #endregion

    #region Method Checks

    private bool HasParameter(SyntaxNode node, SemanticModel? model, string[] args)
    {
        if (args.Length == 0) return false;

        var paramName = args[0];
        var method = node as MethodDeclarationSyntax ??
                     node.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

        if (method == null) return false;

        return method.ParameterList.Parameters.Any(p =>
            WildcardMatch(p.Identifier.Text, paramName) ||
            (args.Length > 1 && WildcardMatch(p.Type?.ToString() ?? "", args[1])));
    }

    private bool ParameterCount(SyntaxNode node, SemanticModel? model, string[] args)
    {
        if (args.Length == 0) return false;

        var method = node as MethodDeclarationSyntax ??
                     node.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

        if (method == null) return false;

        var count = method.ParameterList.Parameters.Count;
        var comparison = args[0];

        return ParseComparison(count, comparison);
    }

    private bool LineCount(SyntaxNode node, SemanticModel? model, string[] args)
    {
        if (args.Length == 0) return false;

        var span = node.GetLocation().GetLineSpan();
        var lines = span.EndLinePosition.Line - span.StartLinePosition.Line + 1;

        return ParseComparison(lines, args[0]);
    }

    private bool Complexity(SyntaxNode node, SemanticModel? model, string[] args)
    {
        if (args.Length == 0) return false;

        var method = node as MethodDeclarationSyntax ??
                     node.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

        if (method == null) return false;

        var complexity = CalculateCyclomaticComplexity(method);
        return ParseComparison(complexity, args[0]);
    }

    private bool ReturnType(SyntaxNode node, SemanticModel? model, string[] args)
    {
        if (args.Length == 0) return false;

        var method = node as MethodDeclarationSyntax ??
                     node.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

        if (method == null) return false;

        return WildcardMatch(method.ReturnType.ToString(), args[0]);
    }

    private bool IsTestMethod(SyntaxNode node, SemanticModel? model, string[] args)
    {
        var method = node as MethodDeclarationSyntax ??
                     node.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

        if (method == null) return false;

        var testAttributes = new[] { "Test", "TestMethod", "Fact", "Theory", "TestCase" };
        return method.AttributeLists
            .SelectMany(al => al.Attributes)
            .Any(a => testAttributes.Any(ta =>
                a.Name.ToString().Equals(ta, StringComparison.OrdinalIgnoreCase)));
    }

    private bool IsConstructor(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return node is ConstructorDeclarationSyntax ||
               node.Ancestors().Any(a => a is ConstructorDeclarationSyntax);
    }

    private bool IsProperty(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return node is PropertyDeclarationSyntax ||
               node.Ancestors().Any(a => a is PropertyDeclarationSyntax);
    }

    private bool IsField(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return node is FieldDeclarationSyntax ||
               node.Ancestors().Any(a => a is FieldDeclarationSyntax);
    }

    private bool IsGeneric(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return node switch
        {
            MethodDeclarationSyntax m => m.TypeParameterList?.Parameters.Count > 0,
            TypeDeclarationSyntax t => t.TypeParameterList?.Parameters.Count > 0,
            _ => false
        };
    }

    private bool HasTypeParameter(SyntaxNode node, SemanticModel? model, string[] args)
    {
        if (args.Length == 0) return false;

        var typeParamName = args[0];

        TypeParameterListSyntax? typeParams = node switch
        {
            MethodDeclarationSyntax m => m.TypeParameterList,
            TypeDeclarationSyntax t => t.TypeParameterList,
            _ => null
        };

        if (typeParams == null) return false;

        return typeParams.Parameters.Any(p =>
            WildcardMatch(p.Identifier.Text, typeParamName));
    }

    private bool IsExtensionMethod(SyntaxNode node, SemanticModel? model, string[] args)
    {
        var method = node as MethodDeclarationSyntax ??
                     node.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();

        if (method == null) return false;

        return method.ParameterList.Parameters.FirstOrDefault()?.Modifiers.Any(SyntaxKind.ThisKeyword) ?? false;
    }

    private bool IsDisposable(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return ImplementsInterface(node, model, new[] { "IDisposable" }) ||
               ImplementsInterface(node, model, new[] { "IAsyncDisposable" });
    }

    #endregion

    #region Context Checks

    private bool InTryCatch(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return node.Ancestors().Any(a => a is TryStatementSyntax);
    }

    private bool InLoop(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return node.Ancestors().Any(a =>
            a is ForStatementSyntax or
                ForEachStatementSyntax or
                WhileStatementSyntax or
                DoStatementSyntax);
    }

    private bool InConditional(SyntaxNode node, SemanticModel? model, string[] args)
    {
        return node.Ancestors().Any(a =>
            a is IfStatementSyntax or
                SwitchStatementSyntax or
                ConditionalExpressionSyntax);
    }

    private bool HasDocComment(SyntaxNode node, SemanticModel? model, string[] args)
    {
        var trivia = node.GetLeadingTrivia();
        return trivia.Any(t =>
            t.IsKind(SyntaxKind.SingleLineDocumentationCommentTrivia) ||
            t.IsKind(SyntaxKind.MultiLineDocumentationCommentTrivia));
    }

    private bool ContainsCall(SyntaxNode node, SemanticModel? model, string[] args)
    {
        if (args.Length == 0) return false;

        var pattern = args[0];
        var invocations = node.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in invocations)
        {
            var methodName = invocation.Expression switch
            {
                MemberAccessExpressionSyntax ma => $"{ma.Expression}.{ma.Name}",
                IdentifierNameSyntax id => id.Identifier.Text,
                _ => invocation.Expression.ToString()
            };

            if (WildcardMatch(methodName, pattern))
                return true;
        }

        return false;
    }

    private bool UsesType(SyntaxNode node, SemanticModel? model, string[] args)
    {
        if (args.Length == 0) return false;

        var pattern = args[0];
        var types = node.DescendantNodes()
            .OfType<TypeSyntax>()
            .Select(t => t.ToString());

        return types.Any(t => WildcardMatch(t, pattern));
    }

    private bool AccessesField(SyntaxNode node, SemanticModel? model, string[] args)
    {
        if (args.Length == 0) return false;

        var pattern = args[0];
        var identifiers = node.DescendantNodes().OfType<IdentifierNameSyntax>();

        foreach (var id in identifiers)
        {
            if (WildcardMatch(id.Identifier.Text, pattern))
            {
                if (model != null)
                {
                    var symbol = model.GetSymbolInfo(id).Symbol;
                    if (symbol is IFieldSymbol)
                        return true;
                }
                else
                {
                    // Without semantic model, assume it's a field access
                    return true;
                }
            }
        }

        return false;
    }

    private bool ModifiesState(SyntaxNode node, SemanticModel? model, string[] args)
    {
        // Check for assignments
        var hasAssignment = node.DescendantNodes().Any(n =>
            n is AssignmentExpressionSyntax ||
            n is PostfixUnaryExpressionSyntax post && (post.IsKind(SyntaxKind.PostIncrementExpression) || post.IsKind(SyntaxKind.PostDecrementExpression)) ||
            n is PrefixUnaryExpressionSyntax pre && (pre.IsKind(SyntaxKind.PreIncrementExpression) || pre.IsKind(SyntaxKind.PreDecrementExpression)));

        return hasAssignment;
    }

    #endregion

    #region Helper Methods

    private bool WildcardMatch(string text, string pattern)
    {
        var regexPattern = "^" + Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
        return Regex.IsMatch(text, regexPattern, RegexOptions.IgnoreCase);
    }

    private bool ParseComparison(int value, string comparison)
    {
        comparison = comparison.Trim();

        if (comparison.StartsWith(">="))
            return value >= int.Parse(comparison[2..].Trim());
        if (comparison.StartsWith("<="))
            return value <= int.Parse(comparison[2..].Trim());
        if (comparison.StartsWith(">"))
            return value > int.Parse(comparison[1..].Trim());
        if (comparison.StartsWith("<"))
            return value < int.Parse(comparison[1..].Trim());
        if (comparison.StartsWith("==") || comparison.StartsWith("="))
            return value == int.Parse(comparison.TrimStart('=').Trim());
        if (comparison.StartsWith("!="))
            return value != int.Parse(comparison[2..].Trim());

        // Just a number means equals
        if (int.TryParse(comparison, out var num))
            return value == num;

        return false;
    }

    private int CalculateCyclomaticComplexity(SyntaxNode node)
    {
        int complexity = 1;

        foreach (var descendant in node.DescendantNodes())
        {
            complexity += descendant switch
            {
                IfStatementSyntax => 1,
                ConditionalExpressionSyntax => 1,
                CaseSwitchLabelSyntax => 1,
                CasePatternSwitchLabelSyntax => 1,
                ForStatementSyntax => 1,
                ForEachStatementSyntax => 1,
                WhileStatementSyntax => 1,
                DoStatementSyntax => 1,
                CatchClauseSyntax => 1,
                BinaryExpressionSyntax b when b.IsKind(SyntaxKind.LogicalAndExpression) => 1,
                BinaryExpressionSyntax b when b.IsKind(SyntaxKind.LogicalOrExpression) => 1,
                BinaryExpressionSyntax b when b.IsKind(SyntaxKind.CoalesceExpression) => 1,
                _ => 0
            };
        }

        return complexity;
    }

    #endregion
}
