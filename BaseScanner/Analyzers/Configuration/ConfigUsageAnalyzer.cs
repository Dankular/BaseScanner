using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Configuration.Models;

namespace BaseScanner.Analyzers.Configuration;

/// <summary>
/// Analyzes how configuration is accessed throughout the codebase:
/// - IConfiguration usage patterns (indexer, GetValue, GetSection, GetConnectionString)
/// - ConfigurationManager patterns (AppSettings, ConnectionStrings)
/// - Environment.GetEnvironmentVariable usage
/// - IOptions<T> pattern usage
/// </summary>
public class ConfigUsageAnalyzer
{
    /// <summary>
    /// Analyze configuration access patterns in the document.
    /// </summary>
    public Task<List<ConfigurationAccess>> AnalyzeAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root)
    {
        var accesses = new List<ConfigurationAccess>();
        var filePath = document.FilePath ?? "";

        // Analyze IConfiguration indexer access: config["key"]
        AnalyzeIConfigurationIndexer(root, semanticModel, filePath, accesses);

        // Analyze IConfiguration.GetValue<T>("key")
        AnalyzeIConfigurationGetValue(root, semanticModel, filePath, accesses);

        // Analyze IConfiguration.GetSection("key")
        AnalyzeIConfigurationGetSection(root, semanticModel, filePath, accesses);

        // Analyze IConfiguration.GetConnectionString("name")
        AnalyzeGetConnectionString(root, semanticModel, filePath, accesses);

        // Analyze ConfigurationManager.AppSettings["key"]
        AnalyzeConfigurationManagerAppSettings(root, semanticModel, filePath, accesses);

        // Analyze ConfigurationManager.ConnectionStrings["name"]
        AnalyzeConfigurationManagerConnectionStrings(root, semanticModel, filePath, accesses);

        // Analyze Environment.GetEnvironmentVariable("name")
        AnalyzeEnvironmentVariables(root, semanticModel, filePath, accesses);

        // Analyze IOptions<T> pattern
        AnalyzeOptionsPattern(root, semanticModel, filePath, accesses);

        return Task.FromResult(accesses);
    }

    private void AnalyzeIConfigurationIndexer(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<ConfigurationAccess> accesses)
    {
        var elementAccesses = root.DescendantNodes().OfType<ElementAccessExpressionSyntax>();

        foreach (var access in elementAccesses)
        {
            // Check if this is IConfiguration access
            var expressionType = semanticModel.GetTypeInfo(access.Expression).Type;
            if (!IsConfigurationType(expressionType))
                continue;

            // Get the key being accessed
            if (access.ArgumentList.Arguments.Count == 1)
            {
                var keyArg = access.ArgumentList.Arguments[0].Expression;
                var key = GetStringValue(keyArg, semanticModel);

                if (!string.IsNullOrEmpty(key))
                {
                    var (containingType, containingMethod) = GetContainingContext(access);
                    var lineSpan = access.GetLocation().GetLineSpan();

                    accesses.Add(new ConfigurationAccess
                    {
                        Key = key,
                        AccessType = ConfigurationAccessType.IConfigurationIndexer,
                        FilePath = filePath,
                        Line = lineSpan.StartLinePosition.Line + 1,
                        ContainingType = containingType,
                        ContainingMethod = containingMethod,
                        HasDefaultValue = false,
                        ExpectedType = "string"
                    });
                }
            }
        }
    }

    private void AnalyzeIConfigurationGetValue(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<ConfigurationAccess> accesses)
    {
        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in invocations)
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                if (memberAccess.Name.Identifier.Text != "GetValue")
                    continue;

                // Check if this is IConfiguration or IConfigurationSection
                var expressionType = semanticModel.GetTypeInfo(memberAccess.Expression).Type;
                if (!IsConfigurationType(expressionType))
                    continue;

                // Get the key argument
                if (invocation.ArgumentList.Arguments.Count >= 1)
                {
                    var keyArg = invocation.ArgumentList.Arguments[0].Expression;
                    var key = GetStringValue(keyArg, semanticModel);

                    if (!string.IsNullOrEmpty(key))
                    {
                        var hasDefault = invocation.ArgumentList.Arguments.Count >= 2;
                        var defaultValue = hasDefault
                            ? invocation.ArgumentList.Arguments[1].Expression.ToString()
                            : null;

                        // Try to get the type argument
                        var expectedType = "object";
                        if (memberAccess.Name is GenericNameSyntax genericName)
                        {
                            expectedType = genericName.TypeArgumentList.Arguments.FirstOrDefault()?.ToString() ?? "object";
                        }

                        var (containingType, containingMethod) = GetContainingContext(invocation);
                        var lineSpan = invocation.GetLocation().GetLineSpan();

                        accesses.Add(new ConfigurationAccess
                        {
                            Key = key,
                            AccessType = ConfigurationAccessType.IConfigurationGetValue,
                            FilePath = filePath,
                            Line = lineSpan.StartLinePosition.Line + 1,
                            ContainingType = containingType,
                            ContainingMethod = containingMethod,
                            HasDefaultValue = hasDefault,
                            DefaultValue = defaultValue,
                            ExpectedType = expectedType
                        });
                    }
                }
            }
        }
    }

    private void AnalyzeIConfigurationGetSection(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<ConfigurationAccess> accesses)
    {
        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in invocations)
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                if (memberAccess.Name.Identifier.Text != "GetSection")
                    continue;

                var expressionType = semanticModel.GetTypeInfo(memberAccess.Expression).Type;
                if (!IsConfigurationType(expressionType))
                    continue;

                if (invocation.ArgumentList.Arguments.Count >= 1)
                {
                    var keyArg = invocation.ArgumentList.Arguments[0].Expression;
                    var key = GetStringValue(keyArg, semanticModel);

                    if (!string.IsNullOrEmpty(key))
                    {
                        var (containingType, containingMethod) = GetContainingContext(invocation);
                        var lineSpan = invocation.GetLocation().GetLineSpan();

                        accesses.Add(new ConfigurationAccess
                        {
                            Key = key,
                            AccessType = ConfigurationAccessType.IConfigurationGetSection,
                            FilePath = filePath,
                            Line = lineSpan.StartLinePosition.Line + 1,
                            ContainingType = containingType,
                            ContainingMethod = containingMethod,
                            HasDefaultValue = false,
                            ExpectedType = "IConfigurationSection"
                        });
                    }
                }
            }
        }
    }

    private void AnalyzeGetConnectionString(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<ConfigurationAccess> accesses)
    {
        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in invocations)
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                if (memberAccess.Name.Identifier.Text != "GetConnectionString")
                    continue;

                // Can be extension method on IConfiguration
                if (invocation.ArgumentList.Arguments.Count >= 1)
                {
                    var nameArg = invocation.ArgumentList.Arguments[0].Expression;
                    var name = GetStringValue(nameArg, semanticModel);

                    if (!string.IsNullOrEmpty(name))
                    {
                        var (containingType, containingMethod) = GetContainingContext(invocation);
                        var lineSpan = invocation.GetLocation().GetLineSpan();

                        // Key is ConnectionStrings:Name
                        accesses.Add(new ConfigurationAccess
                        {
                            Key = $"ConnectionStrings:{name}",
                            AccessType = ConfigurationAccessType.IConfigurationGetConnectionString,
                            FilePath = filePath,
                            Line = lineSpan.StartLinePosition.Line + 1,
                            ContainingType = containingType,
                            ContainingMethod = containingMethod,
                            HasDefaultValue = false,
                            ExpectedType = "string"
                        });
                    }
                }
            }
        }
    }

    private void AnalyzeConfigurationManagerAppSettings(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<ConfigurationAccess> accesses)
    {
        var elementAccesses = root.DescendantNodes().OfType<ElementAccessExpressionSyntax>();

        foreach (var access in elementAccesses)
        {
            if (access.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                if (memberAccess.Name.Identifier.Text != "AppSettings")
                    continue;

                // Check if this is ConfigurationManager
                if (memberAccess.Expression is IdentifierNameSyntax identifier)
                {
                    if (identifier.Identifier.Text != "ConfigurationManager")
                        continue;
                }
                else if (memberAccess.Expression is MemberAccessExpressionSyntax innerMember)
                {
                    if (innerMember.Name.Identifier.Text != "ConfigurationManager")
                        continue;
                }
                else
                {
                    continue;
                }

                if (access.ArgumentList.Arguments.Count == 1)
                {
                    var keyArg = access.ArgumentList.Arguments[0].Expression;
                    var key = GetStringValue(keyArg, semanticModel);

                    if (!string.IsNullOrEmpty(key))
                    {
                        var (containingType, containingMethod) = GetContainingContext(access);
                        var lineSpan = access.GetLocation().GetLineSpan();

                        accesses.Add(new ConfigurationAccess
                        {
                            Key = key,
                            AccessType = ConfigurationAccessType.ConfigurationManagerAppSettings,
                            FilePath = filePath,
                            Line = lineSpan.StartLinePosition.Line + 1,
                            ContainingType = containingType,
                            ContainingMethod = containingMethod,
                            HasDefaultValue = false,
                            ExpectedType = "string"
                        });
                    }
                }
            }
        }
    }

    private void AnalyzeConfigurationManagerConnectionStrings(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<ConfigurationAccess> accesses)
    {
        var elementAccesses = root.DescendantNodes().OfType<ElementAccessExpressionSyntax>();

        foreach (var access in elementAccesses)
        {
            if (access.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                if (memberAccess.Name.Identifier.Text != "ConnectionStrings")
                    continue;

                // Check if this is ConfigurationManager
                var isConfigManager = false;
                if (memberAccess.Expression is IdentifierNameSyntax identifier)
                {
                    isConfigManager = identifier.Identifier.Text == "ConfigurationManager";
                }
                else if (memberAccess.Expression is MemberAccessExpressionSyntax innerMember)
                {
                    isConfigManager = innerMember.Name.Identifier.Text == "ConfigurationManager";
                }

                if (!isConfigManager)
                    continue;

                if (access.ArgumentList.Arguments.Count == 1)
                {
                    var nameArg = access.ArgumentList.Arguments[0].Expression;
                    var name = GetStringValue(nameArg, semanticModel);

                    if (!string.IsNullOrEmpty(name))
                    {
                        var (containingType, containingMethod) = GetContainingContext(access);
                        var lineSpan = access.GetLocation().GetLineSpan();

                        accesses.Add(new ConfigurationAccess
                        {
                            Key = $"ConnectionStrings:{name}",
                            AccessType = ConfigurationAccessType.ConfigurationManagerConnectionStrings,
                            FilePath = filePath,
                            Line = lineSpan.StartLinePosition.Line + 1,
                            ContainingType = containingType,
                            ContainingMethod = containingMethod,
                            HasDefaultValue = false,
                            ExpectedType = "string"
                        });
                    }
                }
            }
        }
    }

    private void AnalyzeEnvironmentVariables(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<ConfigurationAccess> accesses)
    {
        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in invocations)
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                if (memberAccess.Name.Identifier.Text != "GetEnvironmentVariable")
                    continue;

                // Verify it's System.Environment
                var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                if (symbol?.ContainingType?.ToDisplayString() != "System.Environment")
                    continue;

                if (invocation.ArgumentList.Arguments.Count >= 1)
                {
                    var varArg = invocation.ArgumentList.Arguments[0].Expression;
                    var varName = GetStringValue(varArg, semanticModel);

                    if (!string.IsNullOrEmpty(varName))
                    {
                        var (containingType, containingMethod) = GetContainingContext(invocation);
                        var lineSpan = invocation.GetLocation().GetLineSpan();

                        accesses.Add(new ConfigurationAccess
                        {
                            Key = varName,
                            AccessType = ConfigurationAccessType.EnvironmentVariable,
                            FilePath = filePath,
                            Line = lineSpan.StartLinePosition.Line + 1,
                            ContainingType = containingType,
                            ContainingMethod = containingMethod,
                            HasDefaultValue = false,
                            ExpectedType = "string"
                        });
                    }
                }
            }
        }
    }

    private void AnalyzeOptionsPattern(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<ConfigurationAccess> accesses)
    {
        // Look for IOptions<T>, IOptionsSnapshot<T>, IOptionsMonitor<T> usage
        var memberAccesses = root.DescendantNodes().OfType<MemberAccessExpressionSyntax>();

        foreach (var memberAccess in memberAccesses)
        {
            if (memberAccess.Name.Identifier.Text != "Value" &&
                memberAccess.Name.Identifier.Text != "CurrentValue")
                continue;

            var expressionType = semanticModel.GetTypeInfo(memberAccess.Expression).Type;
            if (expressionType == null)
                continue;

            var typeName = expressionType.ToDisplayString();
            if (!typeName.Contains("IOptions") && !typeName.Contains("IOptionsSnapshot") &&
                !typeName.Contains("IOptionsMonitor"))
                continue;

            // Extract the options type
            if (expressionType is INamedTypeSymbol namedType && namedType.IsGenericType)
            {
                var optionsType = namedType.TypeArguments.FirstOrDefault();
                if (optionsType != null)
                {
                    var (containingType, containingMethod) = GetContainingContext(memberAccess);
                    var lineSpan = memberAccess.GetLocation().GetLineSpan();

                    // The key is typically the type name (by convention)
                    accesses.Add(new ConfigurationAccess
                    {
                        Key = optionsType.Name,
                        AccessType = ConfigurationAccessType.OptionsPattern,
                        FilePath = filePath,
                        Line = lineSpan.StartLinePosition.Line + 1,
                        ContainingType = containingType,
                        ContainingMethod = containingMethod,
                        HasDefaultValue = false,
                        ExpectedType = optionsType.ToDisplayString()
                    });
                }
            }
        }

        // Also look for Configure<T> calls to understand what sections are being bound
        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in invocations)
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccessExpr)
            {
                var methodName = memberAccessExpr.Name.Identifier.Text;
                if (methodName != "Configure" && methodName != "Bind")
                    continue;

                // Check for GetSection call in arguments
                foreach (var arg in invocation.ArgumentList.Arguments)
                {
                    if (arg.Expression is InvocationExpressionSyntax innerInvocation)
                    {
                        if (innerInvocation.Expression is MemberAccessExpressionSyntax innerMemberAccess)
                        {
                            if (innerMemberAccess.Name.Identifier.Text == "GetSection")
                            {
                                if (innerInvocation.ArgumentList.Arguments.Count > 0)
                                {
                                    var sectionArg = innerInvocation.ArgumentList.Arguments[0].Expression;
                                    var sectionName = GetStringValue(sectionArg, semanticModel);

                                    if (!string.IsNullOrEmpty(sectionName))
                                    {
                                        var (containingType, containingMethod) = GetContainingContext(invocation);
                                        var lineSpan = invocation.GetLocation().GetLineSpan();

                                        accesses.Add(new ConfigurationAccess
                                        {
                                            Key = sectionName,
                                            AccessType = ConfigurationAccessType.OptionsPattern,
                                            FilePath = filePath,
                                            Line = lineSpan.StartLinePosition.Line + 1,
                                            ContainingType = containingType,
                                            ContainingMethod = containingMethod,
                                            HasDefaultValue = false,
                                            ExpectedType = "Options Section"
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private static bool IsConfigurationType(ITypeSymbol? type)
    {
        if (type == null) return false;

        var typeName = type.ToDisplayString();
        return typeName.Contains("IConfiguration") ||
               typeName.Contains("IConfigurationSection") ||
               typeName.Contains("IConfigurationRoot");
    }

    private static string? GetStringValue(ExpressionSyntax expression, SemanticModel semanticModel)
    {
        // Direct string literal
        if (expression is LiteralExpressionSyntax literal &&
            literal.IsKind(SyntaxKind.StringLiteralExpression))
        {
            return literal.Token.ValueText;
        }

        // String interpolation (try to get the literal parts)
        if (expression is InterpolatedStringExpressionSyntax interpolated)
        {
            var parts = interpolated.Contents
                .OfType<InterpolatedStringTextSyntax>()
                .Select(t => t.TextToken.ValueText);
            return string.Concat(parts);
        }

        // Try to get constant value
        var constant = semanticModel.GetConstantValue(expression);
        if (constant.HasValue && constant.Value is string str)
        {
            return str;
        }

        // nameof expression
        if (expression is InvocationExpressionSyntax invocation &&
            invocation.Expression is IdentifierNameSyntax identifier &&
            identifier.Identifier.Text == "nameof")
        {
            if (invocation.ArgumentList.Arguments.Count > 0)
            {
                return invocation.ArgumentList.Arguments[0].Expression.ToString();
            }
        }

        return null;
    }

    private static (string? ContainingType, string? ContainingMethod) GetContainingContext(SyntaxNode node)
    {
        string? containingType = null;
        string? containingMethod = null;

        var parent = node.Parent;
        while (parent != null)
        {
            if (parent is MethodDeclarationSyntax method && containingMethod == null)
            {
                containingMethod = method.Identifier.Text;
            }
            else if (parent is ConstructorDeclarationSyntax constructor && containingMethod == null)
            {
                containingMethod = constructor.Identifier.Text;
            }
            else if (parent is PropertyDeclarationSyntax property && containingMethod == null)
            {
                containingMethod = property.Identifier.Text;
            }
            else if (parent is TypeDeclarationSyntax type && containingType == null)
            {
                containingType = type.Identifier.Text;
            }

            if (containingType != null && containingMethod != null)
                break;

            parent = parent.Parent;
        }

        return (containingType, containingMethod);
    }
}
