using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Configuration.Models;
using System.Text.RegularExpressions;

namespace BaseScanner.Analyzers.Configuration;

/// <summary>
/// Detects environment-specific code patterns that may cause issues across deployments:
/// - String comparisons with environment names (if env == "Production")
/// - IHostEnvironment checks (IsProduction(), IsDevelopment())
/// - Preprocessor directives (#if DEBUG)
/// - Environment variable checks for environment names
/// </summary>
public class EnvironmentCodeDetector
{
    // Known environment names to detect
    private static readonly HashSet<string> EnvironmentNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Production", "Prod",
        "Development", "Dev",
        "Staging", "Stage",
        "Testing", "Test",
        "QA", "UAT",
        "Local", "Debug",
        "Release", "Live"
    };

    // IHostEnvironment method patterns
    private static readonly HashSet<string> HostEnvironmentMethods = new()
    {
        "IsProduction",
        "IsDevelopment",
        "IsStaging",
        "IsEnvironment"
    };

    // Environment variable names that typically hold environment info
    private static readonly HashSet<string> EnvironmentVariables = new(StringComparer.OrdinalIgnoreCase)
    {
        "ASPNETCORE_ENVIRONMENT",
        "DOTNET_ENVIRONMENT",
        "ENVIRONMENT",
        "ENV",
        "NODE_ENV",
        "APP_ENVIRONMENT"
    };

    /// <summary>
    /// Detect environment-specific code patterns.
    /// </summary>
    public Task<List<EnvironmentCodePattern>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root)
    {
        var patterns = new List<EnvironmentCodePattern>();
        var filePath = document.FilePath ?? "";

        // Detect string comparisons with environment names
        DetectStringComparisons(root, semanticModel, filePath, patterns);

        // Detect IHostEnvironment checks
        DetectHostEnvironmentChecks(root, semanticModel, filePath, patterns);

        // Detect preprocessor directives
        DetectPreprocessorDirectives(root, filePath, patterns);

        // Detect environment variable checks
        DetectEnvironmentVariableChecks(root, semanticModel, filePath, patterns);

        // Detect configuration-based environment checks
        DetectConfigurationEnvironmentChecks(root, semanticModel, filePath, patterns);

        return Task.FromResult(patterns);
    }

    /// <summary>
    /// Create configuration issues from detected patterns.
    /// </summary>
    public List<ConfigurationIssue> CreateIssuesFromPatterns(List<EnvironmentCodePattern> patterns)
    {
        return patterns.Select(p => new ConfigurationIssue
        {
            IssueType = ConfigurationIssueType.EnvironmentBranch,
            Severity = GetSeverityForPattern(p),
            FilePath = p.FilePath,
            StartLine = p.Line,
            EndLine = p.Line,
            CodeSnippet = p.CodeSnippet,
            Description = p.Description,
            Recommendation = GetRecommendation(p),
            DetectedValue = p.EnvironmentName,
            SuggestedFix = GetSuggestedFix(p),
            Confidence = GetConfidence(p)
        }).ToList();
    }

    private void DetectStringComparisons(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<EnvironmentCodePattern> patterns)
    {
        // Find binary expressions (== comparisons)
        var binaryExpressions = root.DescendantNodes()
            .OfType<BinaryExpressionSyntax>()
            .Where(b => b.IsKind(SyntaxKind.EqualsExpression) || b.IsKind(SyntaxKind.NotEqualsExpression));

        foreach (var binary in binaryExpressions)
        {
            var leftText = GetStringValue(binary.Left, semanticModel);
            var rightText = GetStringValue(binary.Right, semanticModel);

            var envName = EnvironmentNames.FirstOrDefault(e =>
                e.Equals(leftText, StringComparison.OrdinalIgnoreCase) ||
                e.Equals(rightText, StringComparison.OrdinalIgnoreCase));

            if (envName != null)
            {
                // Check if this is likely an environment comparison
                var context = binary.Parent?.Parent?.ToString() ?? "";
                var isLikelyEnvCheck = IsLikelyEnvironmentCheck(binary, semanticModel);

                if (isLikelyEnvCheck)
                {
                    var lineSpan = binary.GetLocation().GetLineSpan();
                    patterns.Add(new EnvironmentCodePattern
                    {
                        EnvironmentName = envName,
                        PatternType = EnvironmentPatternType.StringComparison,
                        FilePath = filePath,
                        Line = lineSpan.StartLinePosition.Line + 1,
                        CodeSnippet = GetContainingStatement(binary),
                        Description = $"Environment-specific code branching based on '{envName}' environment check. This can lead to environment-specific bugs and deployment issues."
                    });
                }
            }
        }

        // Find string.Equals calls
        var equalsInvocations = root.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(i => i.Expression is MemberAccessExpressionSyntax ma &&
                       ma.Name.Identifier.Text == "Equals");

        foreach (var invocation in equalsInvocations)
        {
            foreach (var arg in invocation.ArgumentList.Arguments)
            {
                var argValue = GetStringValue(arg.Expression, semanticModel);
                var envName = EnvironmentNames.FirstOrDefault(e =>
                    e.Equals(argValue, StringComparison.OrdinalIgnoreCase));

                if (envName != null && IsLikelyEnvironmentCheck(invocation, semanticModel))
                {
                    var lineSpan = invocation.GetLocation().GetLineSpan();
                    patterns.Add(new EnvironmentCodePattern
                    {
                        EnvironmentName = envName,
                        PatternType = EnvironmentPatternType.StringComparison,
                        FilePath = filePath,
                        Line = lineSpan.StartLinePosition.Line + 1,
                        CodeSnippet = GetContainingStatement(invocation),
                        Description = $"Environment-specific code branching detected using string comparison with '{envName}'."
                    });
                }
            }
        }
    }

    private void DetectHostEnvironmentChecks(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<EnvironmentCodePattern> patterns)
    {
        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in invocations)
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var methodName = memberAccess.Name.Identifier.Text;

                if (HostEnvironmentMethods.Contains(methodName))
                {
                    var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                    var containingType = symbol?.ContainingType?.ToDisplayString() ?? "";

                    // Check if it's from hosting/environment extensions
                    if (containingType.Contains("HostEnvironment") ||
                        containingType.Contains("WebHostEnvironment") ||
                        containingType.Contains("HostingEnvironmentExtensions"))
                    {
                        var envName = methodName switch
                        {
                            "IsProduction" => "Production",
                            "IsDevelopment" => "Development",
                            "IsStaging" => "Staging",
                            _ => "Custom"
                        };

                        // Check if used in conditional
                        if (IsUsedInConditional(invocation))
                        {
                            var lineSpan = invocation.GetLocation().GetLineSpan();
                            patterns.Add(new EnvironmentCodePattern
                            {
                                EnvironmentName = envName,
                                PatternType = EnvironmentPatternType.HostEnvironmentCheck,
                                FilePath = filePath,
                                Line = lineSpan.StartLinePosition.Line + 1,
                                CodeSnippet = GetContainingStatement(invocation),
                                Description = $"Environment check using {methodName}(). Consider using environment-specific configuration instead of code branching."
                            });
                        }
                    }
                }
            }
        }
    }

    private void DetectPreprocessorDirectives(
        SyntaxNode root,
        string filePath,
        List<EnvironmentCodePattern> patterns)
    {
        // Find #if directives in the syntax tree's trivia
        foreach (var trivia in root.DescendantTrivia())
        {
            if (trivia.IsKind(SyntaxKind.IfDirectiveTrivia))
            {
                var directive = trivia.GetStructure() as IfDirectiveTriviaSyntax;
                if (directive != null)
                {
                    var condition = directive.Condition.ToString();

                    // Check for DEBUG, RELEASE, or other environment-related symbols
                    if (condition.Contains("DEBUG") || condition.Contains("RELEASE") ||
                        condition.Contains("TRACE") || condition.Contains("PRODUCTION"))
                    {
                        var lineSpan = directive.GetLocation().GetLineSpan();
                        var envName = condition.Contains("DEBUG") ? "Debug" :
                                     condition.Contains("RELEASE") ? "Release" :
                                     condition.Contains("PRODUCTION") ? "Production" : condition;

                        patterns.Add(new EnvironmentCodePattern
                        {
                            EnvironmentName = envName,
                            PatternType = EnvironmentPatternType.PreprocessorDirective,
                            FilePath = filePath,
                            Line = lineSpan.StartLinePosition.Line + 1,
                            CodeSnippet = directive.ToString().Trim(),
                            Description = $"Preprocessor directive creates compile-time environment-specific code paths. Code behaves differently based on build configuration."
                        });
                    }
                }
            }
        }
    }

    private void DetectEnvironmentVariableChecks(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<EnvironmentCodePattern> patterns)
    {
        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in invocations)
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                if (memberAccess.Name.Identifier.Text == "GetEnvironmentVariable")
                {
                    var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                    if (symbol?.ContainingType?.ToDisplayString() == "System.Environment")
                    {
                        // Check what environment variable is being accessed
                        if (invocation.ArgumentList.Arguments.Count > 0)
                        {
                            var arg = invocation.ArgumentList.Arguments[0].Expression;
                            var varName = GetStringValue(arg, semanticModel);

                            if (varName != null && EnvironmentVariables.Contains(varName))
                            {
                                // Check if the result is compared to an environment name
                                var parent = invocation.Parent;
                                while (parent != null)
                                {
                                    if (parent is BinaryExpressionSyntax binary)
                                    {
                                        var otherSide = binary.Left == invocation ? binary.Right : binary.Left;
                                        var otherValue = GetStringValue(otherSide, semanticModel);

                                        if (otherValue != null && EnvironmentNames.Contains(otherValue))
                                        {
                                            var lineSpan = binary.GetLocation().GetLineSpan();
                                            patterns.Add(new EnvironmentCodePattern
                                            {
                                                EnvironmentName = otherValue,
                                                PatternType = EnvironmentPatternType.EnvironmentVariableCheck,
                                                FilePath = filePath,
                                                Line = lineSpan.StartLinePosition.Line + 1,
                                                CodeSnippet = GetContainingStatement(binary),
                                                Description = $"Environment check using {varName} environment variable. Consider using IConfiguration or IHostEnvironment for consistency."
                                            });
                                            break;
                                        }
                                    }
                                    parent = parent.Parent;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private void DetectConfigurationEnvironmentChecks(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<EnvironmentCodePattern> patterns)
    {
        // Look for configuration access to "Environment" or similar keys
        var elementAccesses = root.DescendantNodes().OfType<ElementAccessExpressionSyntax>();

        foreach (var access in elementAccesses)
        {
            if (access.ArgumentList.Arguments.Count == 1)
            {
                var argValue = GetStringValue(access.ArgumentList.Arguments[0].Expression, semanticModel);

                if (argValue != null && argValue.Contains("Environment", StringComparison.OrdinalIgnoreCase))
                {
                    // Check if this is IConfiguration access
                    var expressionType = semanticModel.GetTypeInfo(access.Expression).Type;
                    if (expressionType?.Name == "IConfiguration" || expressionType?.ToDisplayString().Contains("IConfiguration") == true)
                    {
                        // Check if compared to environment name
                        var parent = access.Parent;
                        while (parent != null)
                        {
                            if (parent is BinaryExpressionSyntax binary)
                            {
                                var otherSide = binary.Left.ToString().Contains(access.ToString()) ? binary.Right : binary.Left;
                                var otherValue = GetStringValue(otherSide as ExpressionSyntax, semanticModel);

                                if (otherValue != null && EnvironmentNames.Contains(otherValue))
                                {
                                    var lineSpan = binary.GetLocation().GetLineSpan();
                                    patterns.Add(new EnvironmentCodePattern
                                    {
                                        EnvironmentName = otherValue,
                                        PatternType = EnvironmentPatternType.ConfigurationCheck,
                                        FilePath = filePath,
                                        Line = lineSpan.StartLinePosition.Line + 1,
                                        CodeSnippet = GetContainingStatement(binary),
                                        Description = $"Environment-based code branching using configuration. Consider using environment-specific configuration files instead."
                                    });
                                    break;
                                }
                            }
                            parent = parent.Parent;
                        }
                    }
                }
            }
        }
    }

    private static string? GetStringValue(ExpressionSyntax? expression, SemanticModel semanticModel)
    {
        if (expression == null) return null;

        // Direct string literal
        if (expression is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression))
        {
            return literal.Token.ValueText;
        }

        // Try constant value
        var constant = semanticModel.GetConstantValue(expression);
        if (constant.HasValue && constant.Value is string str)
        {
            return str;
        }

        return null;
    }

    private static bool IsLikelyEnvironmentCheck(SyntaxNode node, SemanticModel semanticModel)
    {
        var parent = node.Parent;
        var context = node.ToString().ToLowerInvariant();

        // Check for environment-related variable names in context
        var envRelatedNames = new[] { "env", "environment", "hosting", "aspnetcore" };
        if (envRelatedNames.Any(n => context.Contains(n)))
            return true;

        // Check if inside an if statement
        while (parent != null)
        {
            if (parent is IfStatementSyntax || parent is ConditionalExpressionSyntax)
                return true;
            if (parent is MethodDeclarationSyntax || parent is ClassDeclarationSyntax)
                break;
            parent = parent.Parent;
        }

        return false;
    }

    private static bool IsUsedInConditional(SyntaxNode node)
    {
        var parent = node.Parent;
        while (parent != null)
        {
            if (parent is IfStatementSyntax || parent is ConditionalExpressionSyntax ||
                parent is SwitchStatementSyntax || parent is WhenClauseSyntax)
                return true;
            if (parent is MethodDeclarationSyntax || parent is ClassDeclarationSyntax)
                break;
            parent = parent.Parent;
        }
        return false;
    }

    private static string GetContainingStatement(SyntaxNode node)
    {
        var parent = node.Parent;
        while (parent != null)
        {
            if (parent is StatementSyntax statement)
            {
                var text = statement.ToString().Trim();
                return text.Length > 200 ? text[..200] + "..." : text;
            }
            parent = parent.Parent;
        }
        return node.ToString().Trim();
    }

    private static ConfigurationSeverity GetSeverityForPattern(EnvironmentCodePattern pattern)
    {
        return pattern.PatternType switch
        {
            EnvironmentPatternType.PreprocessorDirective => ConfigurationSeverity.Low, // Common and often intentional
            EnvironmentPatternType.HostEnvironmentCheck => ConfigurationSeverity.Medium,
            EnvironmentPatternType.StringComparison => ConfigurationSeverity.High,
            EnvironmentPatternType.EnvironmentVariableCheck => ConfigurationSeverity.Medium,
            EnvironmentPatternType.ConfigurationCheck => ConfigurationSeverity.Medium,
            _ => ConfigurationSeverity.Low
        };
    }

    private static string GetRecommendation(EnvironmentCodePattern pattern)
    {
        return pattern.PatternType switch
        {
            EnvironmentPatternType.PreprocessorDirective =>
                "Consider if compile-time differences are truly necessary. Use configuration-based feature flags for runtime flexibility.",
            EnvironmentPatternType.HostEnvironmentCheck =>
                "Use environment-specific configuration files (appsettings.{Environment}.json) or feature flags instead of code branching.",
            EnvironmentPatternType.StringComparison =>
                "Replace string comparisons with strongly-typed configuration. Use IOptions<T> pattern for environment-specific behavior.",
            EnvironmentPatternType.EnvironmentVariableCheck =>
                "Use IConfiguration and IHostEnvironment for consistent environment handling across the application.",
            EnvironmentPatternType.ConfigurationCheck =>
                "Use IHostEnvironment for environment checks. Move environment-specific settings to appsettings.{Environment}.json.",
            _ => "Consider using configuration-based approaches instead of environment-specific code branches."
        };
    }

    private static string GetSuggestedFix(EnvironmentCodePattern pattern)
    {
        return pattern.PatternType switch
        {
            EnvironmentPatternType.PreprocessorDirective =>
                "// Use feature flags:\n_featureFlags.IsEnabled(\"MyFeature\")",
            EnvironmentPatternType.HostEnvironmentCheck =>
                "// Use configuration instead:\nvar setting = _configuration[\"MySetting\"];",
            EnvironmentPatternType.StringComparison =>
                "// Use environment-specific config:\n// appsettings.Production.json: { \"MySetting\": \"value\" }",
            EnvironmentPatternType.EnvironmentVariableCheck =>
                "// Use IHostEnvironment:\n_hostEnvironment.EnvironmentName",
            EnvironmentPatternType.ConfigurationCheck =>
                "// Use IHostEnvironment:\nif (_hostEnvironment.IsProduction()) { }",
            _ => "// Use configuration-based approach"
        };
    }

    private static string GetConfidence(EnvironmentCodePattern pattern)
    {
        return pattern.PatternType switch
        {
            EnvironmentPatternType.PreprocessorDirective => "High",
            EnvironmentPatternType.HostEnvironmentCheck => "High",
            EnvironmentPatternType.StringComparison => "Medium",
            _ => "Medium"
        };
    }
}
