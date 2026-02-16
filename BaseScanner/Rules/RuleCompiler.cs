using System.Text.RegularExpressions;
using BaseScanner.Rules.Models;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace BaseScanner.Rules;

/// <summary>
/// Compiles rule patterns into executable Roslyn matchers.
/// </summary>
public class RuleCompiler
{
    private readonly BuiltInFunctions _builtInFunctions;

    public RuleCompiler()
    {
        _builtInFunctions = new BuiltInFunctions();
    }

    /// <summary>
    /// Compiles a custom rule into an executable compiled rule.
    /// </summary>
    public CompiledRule Compile(CustomRule rule)
    {
        var matcher = CreateMatcher(rule);
        var validators = CreateValidators(rule);

        return new CompiledRule
        {
            Rule = rule,
            Matcher = matcher,
            Validators = validators
        };
    }

    /// <summary>
    /// Compiles multiple rules.
    /// </summary>
    public List<CompiledRule> CompileAll(IEnumerable<CustomRule> rules)
    {
        return rules.Select(Compile).ToList();
    }

    private Func<SyntaxNode, SemanticModel?, MatchResult?> CreateMatcher(CustomRule rule)
    {
        return rule.Pattern.Type switch
        {
            PatternType.MethodInvocation => CreateMethodInvocationMatcher(rule),
            PatternType.MethodDeclaration => CreateMethodDeclarationMatcher(rule),
            PatternType.TypeUsage => CreateTypeUsageMatcher(rule),
            PatternType.NumericLiteral => CreateNumericLiteralMatcher(rule),
            PatternType.StringLiteral => CreateStringLiteralMatcher(rule),
            PatternType.Attribute => CreateAttributeMatcher(rule),
            _ => (_, _) => null
        };
    }

    private List<Func<SyntaxNode, SemanticModel?, bool>> CreateValidators(CustomRule rule)
    {
        var validators = new List<Func<SyntaxNode, SemanticModel?, bool>>();

        // Add NotIn validator
        if (rule.Pattern.NotIn.Count > 0)
        {
            validators.Add((node, model) => !IsInExcludedContext(node, rule.Pattern.NotIn));
        }

        // Add In validator
        if (rule.Pattern.In.Count > 0)
        {
            validators.Add((node, model) => IsInRequiredContext(node, rule.Pattern.In));
        }

        // Add condition validators
        foreach (var condition in rule.Pattern.Conditions)
        {
            var conditionValidator = _builtInFunctions.CreateConditionValidator(condition);
            if (conditionValidator != null)
            {
                validators.Add(conditionValidator);
            }
        }

        return validators;
    }

    #region Pattern Matchers

    private Func<SyntaxNode, SemanticModel?, MatchResult?> CreateMethodInvocationMatcher(CustomRule rule)
    {
        var pattern = rule.Pattern.Match ?? "*";
        var regex = WildcardToRegex(pattern);

        return (node, model) =>
        {
            if (node is not InvocationExpressionSyntax invocation)
                return null;

            string methodName;
            string? typeName = null;

            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                methodName = memberAccess.Name.Identifier.Text;

                // Try to get type info from semantic model
                if (model != null)
                {
                    var typeInfo = model.GetTypeInfo(memberAccess.Expression);
                    typeName = typeInfo.Type?.Name ?? memberAccess.Expression.ToString();
                }
                else
                {
                    typeName = memberAccess.Expression.ToString();
                }
            }
            else if (invocation.Expression is IdentifierNameSyntax identifier)
            {
                methodName = identifier.Identifier.Text;
            }
            else
            {
                return null;
            }

            var fullName = typeName != null ? $"{typeName}.{methodName}" : methodName;

            if (regex.IsMatch(fullName))
            {
                return new MatchResult
                {
                    IsMatch = true,
                    Node = node,
                    Captures = new Dictionary<string, string>
                    {
                        { "method", methodName },
                        { "type", typeName ?? "" },
                        { "fullName", fullName }
                    }
                };
            }

            return null;
        };
    }

    private Func<SyntaxNode, SemanticModel?, MatchResult?> CreateMethodDeclarationMatcher(CustomRule rule)
    {
        var namePattern = rule.Pattern.NamePattern != null
            ? new Regex(rule.Pattern.NamePattern, RegexOptions.Compiled)
            : null;

        var returnPattern = rule.Pattern.Returns != null
            ? WildcardToRegex(rule.Pattern.Returns)
            : null;

        return (node, model) =>
        {
            if (node is not MethodDeclarationSyntax method)
                return null;

            var methodName = method.Identifier.Text;
            var returnType = method.ReturnType.ToString();
            var paramCount = method.ParameterList.Parameters.Count;

            // Check name pattern
            if (namePattern != null && !namePattern.IsMatch(methodName))
                return null;

            // Check return type pattern
            if (returnPattern != null && !returnPattern.IsMatch(returnType))
                return null;

            // Check parameter count constraints
            if (rule.Pattern.MinParameters.HasValue && paramCount < rule.Pattern.MinParameters.Value)
                return null;

            if (rule.Pattern.MaxParameters.HasValue && paramCount > rule.Pattern.MaxParameters.Value)
                return null;

            // Check match pattern if specified
            if (!string.IsNullOrEmpty(rule.Pattern.Match))
            {
                var matchRegex = WildcardToRegex(rule.Pattern.Match);
                if (!matchRegex.IsMatch(methodName))
                    return null;
            }

            var className = method.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault()?.Identifier.Text ?? "";

            return new MatchResult
            {
                IsMatch = true,
                Node = node,
                Captures = new Dictionary<string, string>
                {
                    { "method", methodName },
                    { "class", className },
                    { "returnType", returnType },
                    { "parameterCount", paramCount.ToString() }
                }
            };
        };
    }

    private Func<SyntaxNode, SemanticModel?, MatchResult?> CreateTypeUsageMatcher(CustomRule rule)
    {
        var pattern = rule.Pattern.Match ?? "*";
        var regex = WildcardToRegex(pattern);

        return (node, model) =>
        {
            string? typeName = null;

            if (node is TypeSyntax typeSyntax)
            {
                typeName = typeSyntax.ToString();
            }
            else if (node is ObjectCreationExpressionSyntax objectCreation)
            {
                typeName = objectCreation.Type.ToString();
            }
            else if (node is IdentifierNameSyntax identifier && model != null)
            {
                var symbolInfo = model.GetSymbolInfo(identifier);
                if (symbolInfo.Symbol is INamedTypeSymbol typeSymbol)
                {
                    typeName = typeSymbol.Name;
                }
            }

            if (typeName == null)
                return null;

            if (regex.IsMatch(typeName))
            {
                return new MatchResult
                {
                    IsMatch = true,
                    Node = node,
                    Captures = new Dictionary<string, string>
                    {
                        { "type", typeName }
                    }
                };
            }

            return null;
        };
    }

    private Func<SyntaxNode, SemanticModel?, MatchResult?> CreateNumericLiteralMatcher(CustomRule rule)
    {
        var pattern = rule.Pattern.Match != null ? WildcardToRegex(rule.Pattern.Match) : null;

        return (node, model) =>
        {
            if (node is not LiteralExpressionSyntax literal ||
                !literal.IsKind(SyntaxKind.NumericLiteralExpression))
                return null;

            var valueText = literal.Token.ValueText;

            // Check pattern if specified
            if (pattern != null && !pattern.IsMatch(valueText))
                return null;

            // Check value constraints
            if (double.TryParse(valueText, out var value))
            {
                if (rule.Pattern.MinValue.HasValue && value < rule.Pattern.MinValue.Value)
                    return null;

                if (rule.Pattern.MaxValue.HasValue && value > rule.Pattern.MaxValue.Value)
                    return null;
            }

            return new MatchResult
            {
                IsMatch = true,
                Node = node,
                Captures = new Dictionary<string, string>
                {
                    { "value", valueText }
                }
            };
        };
    }

    private Func<SyntaxNode, SemanticModel?, MatchResult?> CreateStringLiteralMatcher(CustomRule rule)
    {
        var pattern = rule.Pattern.Match ?? "*";
        Regex regex;

        if (rule.Pattern.UseRegex)
        {
            regex = new Regex(pattern, RegexOptions.Compiled);
        }
        else
        {
            regex = WildcardToRegex(pattern);
        }

        return (node, model) =>
        {
            if (node is not LiteralExpressionSyntax literal ||
                !literal.IsKind(SyntaxKind.StringLiteralExpression))
                return null;

            var value = literal.Token.ValueText;

            if (regex.IsMatch(value))
            {
                return new MatchResult
                {
                    IsMatch = true,
                    Node = node,
                    Captures = new Dictionary<string, string>
                    {
                        { "value", value }
                    }
                };
            }

            return null;
        };
    }

    private Func<SyntaxNode, SemanticModel?, MatchResult?> CreateAttributeMatcher(CustomRule rule)
    {
        var pattern = rule.Pattern.Match ?? "*";
        var regex = WildcardToRegex(pattern);

        return (node, model) =>
        {
            if (node is not AttributeSyntax attribute)
                return null;

            var attributeName = attribute.Name.ToString();

            // Remove "Attribute" suffix for matching
            var shortName = attributeName.EndsWith("Attribute")
                ? attributeName[..^9]
                : attributeName;

            if (!regex.IsMatch(attributeName) && !regex.IsMatch(shortName))
                return null;

            // Check required arguments
            if (rule.Pattern.RequiredArguments.Count > 0)
            {
                var arguments = attribute.ArgumentList?.Arguments
                    .Select(a => a.ToString())
                    .ToList() ?? new List<string>();

                foreach (var requiredArg in rule.Pattern.RequiredArguments)
                {
                    if (!arguments.Any(a => a.Contains(requiredArg)))
                        return null;
                }
            }

            return new MatchResult
            {
                IsMatch = true,
                Node = node,
                Captures = new Dictionary<string, string>
                {
                    { "attribute", attributeName }
                }
            };
        };
    }

    #endregion

    #region Helper Methods

    private bool IsInExcludedContext(SyntaxNode node, List<string> excludePatterns)
    {
        // Get the containing class and method names
        var containingClass = node.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault()?.Identifier.Text ?? "";
        var containingMethod = node.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault()?.Identifier.Text ?? "";
        var filePath = node.SyntaxTree.FilePath ?? "";

        foreach (var pattern in excludePatterns)
        {
            var regex = WildcardToRegex(pattern);

            if (regex.IsMatch(containingClass) ||
                regex.IsMatch(containingMethod) ||
                regex.IsMatch(filePath) ||
                regex.IsMatch(Path.GetFileName(filePath)))
            {
                return true;
            }
        }

        return false;
    }

    private bool IsInRequiredContext(SyntaxNode node, List<string> includePatterns)
    {
        var containingClass = node.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault()?.Identifier.Text ?? "";
        var containingMethod = node.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault()?.Identifier.Text ?? "";
        var filePath = node.SyntaxTree.FilePath ?? "";

        foreach (var pattern in includePatterns)
        {
            var regex = WildcardToRegex(pattern);

            if (regex.IsMatch(containingClass) ||
                regex.IsMatch(containingMethod) ||
                regex.IsMatch(filePath) ||
                regex.IsMatch(Path.GetFileName(filePath)))
            {
                return true;
            }
        }

        return false;
    }

    private Regex WildcardToRegex(string pattern)
    {
        // Escape special regex characters except * and ?
        var escaped = Regex.Escape(pattern)
            .Replace("\\*", ".*")
            .Replace("\\?", ".");

        return new Regex($"^{escaped}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    }

    #endregion
}
