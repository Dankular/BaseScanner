using System.Diagnostics;
using System.Text.RegularExpressions;
using BaseScanner.Rules.Models;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace BaseScanner.Rules;

/// <summary>
/// Executes custom rules against C# code using Roslyn.
/// </summary>
public class RuleEngine
{
    private readonly RuleParser _parser;
    private readonly RuleCompiler _compiler;
    private readonly string _rulesDirectory;

    public RuleEngine(string? rulesDirectory = null)
    {
        _rulesDirectory = rulesDirectory ?? Path.Combine(".basescanner", "rules");
        _parser = new RuleParser(_rulesDirectory);
        _compiler = new RuleCompiler();
    }

    /// <summary>
    /// Loads and executes all rules against a project.
    /// </summary>
    public async Task<RuleExecutionResult> ExecuteAsync(Project project)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = new RuleExecutionResult { Success = true };

        try
        {
            // Load and compile rules
            var rules = await _parser.LoadAllRulesAsync();
            if (rules.Count == 0)
            {
                result.Errors.Add("No rules found in rules directory");
                return result;
            }

            var compiledRules = _compiler.CompileAll(rules);
            result.RulesExecuted = compiledRules.Count;

            // Execute rules against each document
            foreach (var document in project.Documents)
            {
                if (document.FilePath == null) continue;
                if (ShouldSkipFile(document.FilePath)) continue;

                try
                {
                    var violations = await ExecuteRulesOnDocumentAsync(document, compiledRules);
                    result.Violations.AddRange(violations);
                    result.FilesAnalyzed++;
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"Error analyzing '{document.FilePath}': {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Errors.Add($"Rule execution failed: {ex.Message}");
        }

        stopwatch.Stop();
        result.ExecutionTime = stopwatch.Elapsed;

        return result;
    }

    /// <summary>
    /// Executes specific rules against a project.
    /// </summary>
    public async Task<RuleExecutionResult> ExecuteRulesAsync(Project project, IEnumerable<CustomRule> rules)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = new RuleExecutionResult { Success = true };

        try
        {
            var compiledRules = _compiler.CompileAll(rules);
            result.RulesExecuted = compiledRules.Count;

            foreach (var document in project.Documents)
            {
                if (document.FilePath == null) continue;
                if (ShouldSkipFile(document.FilePath)) continue;

                try
                {
                    var violations = await ExecuteRulesOnDocumentAsync(document, compiledRules);
                    result.Violations.AddRange(violations);
                    result.FilesAnalyzed++;
                }
                catch (Exception ex)
                {
                    result.Errors.Add($"Error analyzing '{document.FilePath}': {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Errors.Add($"Rule execution failed: {ex.Message}");
        }

        stopwatch.Stop();
        result.ExecutionTime = stopwatch.Elapsed;

        return result;
    }

    /// <summary>
    /// Executes rules against a single syntax tree.
    /// </summary>
    public async Task<List<RuleViolation>> ExecuteRulesOnSyntaxTreeAsync(
        SyntaxTree syntaxTree,
        SemanticModel? semanticModel,
        IEnumerable<CompiledRule> compiledRules)
    {
        var violations = new List<RuleViolation>();
        var root = await syntaxTree.GetRootAsync();
        var filePath = syntaxTree.FilePath ?? "unknown";

        foreach (var compiledRule in compiledRules)
        {
            var ruleViolations = ExecuteRuleOnTree(root, semanticModel, compiledRule, filePath);
            violations.AddRange(ruleViolations);
        }

        return violations;
    }

    /// <summary>
    /// Validates a YAML rule definition.
    /// </summary>
    public (bool IsValid, List<string> Errors) ValidateRule(string yamlContent)
    {
        try
        {
            var rules = _parser.ParseYaml(yamlContent);
            var allErrors = new List<string>();

            foreach (var rule in rules)
            {
                var (isValid, errors) = _parser.ValidateRule(rule);
                if (!isValid)
                {
                    allErrors.AddRange(errors.Select(e => $"{rule.Name}: {e}"));
                }
            }

            return (allErrors.Count == 0, allErrors);
        }
        catch (Exception ex)
        {
            return (false, new List<string> { $"Parse error: {ex.Message}" });
        }
    }

    /// <summary>
    /// Creates sample rule files in the rules directory.
    /// </summary>
    public async Task CreateSampleRulesAsync()
    {
        Directory.CreateDirectory(_rulesDirectory);

        var sampleRules = GetSampleRulesYaml();
        var samplePath = Path.Combine(_rulesDirectory, "sample-rules.yaml");

        await File.WriteAllTextAsync(samplePath, sampleRules);
    }

    private async Task<List<RuleViolation>> ExecuteRulesOnDocumentAsync(
        Document document,
        List<CompiledRule> compiledRules)
    {
        var syntaxTree = await document.GetSyntaxTreeAsync();
        if (syntaxTree == null) return new List<RuleViolation>();

        var semanticModel = await document.GetSemanticModelAsync();
        return await ExecuteRulesOnSyntaxTreeAsync(syntaxTree, semanticModel, compiledRules);
    }

    private List<RuleViolation> ExecuteRuleOnTree(
        SyntaxNode root,
        SemanticModel? semanticModel,
        CompiledRule compiledRule,
        string filePath)
    {
        var violations = new List<RuleViolation>();

        // Get the nodes to check based on pattern type
        var nodesToCheck = GetNodesForPatternType(root, compiledRule.Rule.Pattern.Type);

        foreach (var node in nodesToCheck)
        {
            try
            {
                // Run the matcher
                var matchResult = compiledRule.Matcher(node, semanticModel);

                if (matchResult == null || !matchResult.IsMatch)
                    continue;

                // Run validators
                var passesValidation = compiledRule.Validators.All(v => v(node, semanticModel));
                if (!passesValidation)
                    continue;

                // Create violation
                var violation = CreateViolation(compiledRule.Rule, node, filePath, matchResult);
                violations.Add(violation);
            }
            catch
            {
                // Skip nodes that cause errors
            }
        }

        return violations;
    }

    private IEnumerable<SyntaxNode> GetNodesForPatternType(SyntaxNode root, PatternType patternType)
    {
        return patternType switch
        {
            PatternType.MethodInvocation => root.DescendantNodes().OfType<InvocationExpressionSyntax>(),
            PatternType.MethodDeclaration => root.DescendantNodes().OfType<MethodDeclarationSyntax>(),
            PatternType.TypeUsage => root.DescendantNodes().Where(n =>
                n is TypeSyntax or ObjectCreationExpressionSyntax or IdentifierNameSyntax),
            PatternType.NumericLiteral => root.DescendantNodes().OfType<LiteralExpressionSyntax>()
                .Where(l => l.IsKind(SyntaxKind.NumericLiteralExpression)),
            PatternType.StringLiteral => root.DescendantNodes().OfType<LiteralExpressionSyntax>()
                .Where(l => l.IsKind(SyntaxKind.StringLiteralExpression)),
            PatternType.Attribute => root.DescendantNodes().OfType<AttributeSyntax>(),
            _ => root.DescendantNodes()
        };
    }

    private RuleViolation CreateViolation(
        CustomRule rule,
        SyntaxNode node,
        string filePath,
        MatchResult matchResult)
    {
        var location = node.GetLocation();
        var lineSpan = location.GetLineSpan();
        var line = lineSpan.StartLinePosition.Line + 1;
        var column = lineSpan.StartLinePosition.Character + 1;

        // Interpolate message
        var message = InterpolateMessage(rule.Message, node, filePath, line, matchResult);

        // Get code snippet
        var codeSnippet = GetCodeSnippet(node);

        return new RuleViolation
        {
            Rule = rule,
            FilePath = filePath,
            Line = line,
            Column = column,
            Message = message,
            CodeSnippet = codeSnippet,
            Context = matchResult.Captures,
            Node = node
        };
    }

    private string InterpolateMessage(
        string template,
        SyntaxNode node,
        string filePath,
        int line,
        MatchResult matchResult)
    {
        var message = template;

        // Standard interpolations
        message = message.Replace("{file}", Path.GetFileName(filePath));
        message = message.Replace("{filePath}", filePath);
        message = message.Replace("{line}", line.ToString());

        // Get class and method context
        var className = node.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault()?.Identifier.Text ?? "";
        var methodName = node.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault()?.Identifier.Text ?? "";

        message = message.Replace("{class}", className);
        message = message.Replace("{method}", methodName);

        // Captured values
        foreach (var (key, value) in matchResult.Captures)
        {
            message = message.Replace($"{{{key}}}", value);
        }

        // Node text
        var nodeText = node.ToString();
        if (nodeText.Length > 50)
            nodeText = nodeText.Substring(0, 47) + "...";
        message = message.Replace("{node}", nodeText);

        return message;
    }

    private string GetCodeSnippet(SyntaxNode node)
    {
        var text = node.ToString();

        // Get the containing statement for better context
        var statement = node.Ancestors().OfType<StatementSyntax>().FirstOrDefault();
        if (statement != null)
        {
            text = statement.ToString();
        }

        // Truncate if too long
        if (text.Length > 100)
        {
            text = text.Substring(0, 97) + "...";
        }

        // Clean up whitespace
        text = Regex.Replace(text, @"\s+", " ").Trim();

        return text;
    }

    private bool ShouldSkipFile(string filePath)
    {
        // Skip designer files
        if (filePath.Contains(".Designer.cs"))
            return true;

        // Skip generated files
        if (filePath.Contains(".g.cs") || filePath.Contains(".generated.cs"))
            return true;

        // Skip obj/bin folders
        var normalized = filePath.Replace('\\', '/').ToLowerInvariant();
        if (normalized.Contains("/obj/") || normalized.Contains("/bin/"))
            return true;

        return false;
    }

    private string GetSampleRulesYaml()
    {
        return @"# BaseScanner Custom Rules
# Place this file in .basescanner/rules/ directory

version: ""1.0""

rules:
  # Ensure data access goes through repository layer
  - name: NoDirectDbAccess
    description: ""Data access should go through repository pattern""
    severity: Warning
    pattern:
      type: MethodInvocation
      match: ""*.DbContext.*""
      notIn: [""*Repository*"", ""*DataAccess*"", ""*Migration*""]
    message: ""Direct DbContext access outside repository layer in {class}.{method}""
    suggestion: ""Move database access to a repository class""
    tags: [""architecture"", ""data-access""]

  # Async methods should have Async suffix
  - name: RequireAsyncSuffix
    description: ""Async methods should end with 'Async'""
    severity: Info
    pattern:
      type: MethodDeclaration
      returns: ""Task*""
      namePattern: ""^(?!.*Async$).*$""
    message: ""Async method '{method}' should end with 'Async' suffix""
    suggestion: ""Rename method to {method}Async""
    tags: [""naming"", ""async""]

  # Avoid magic numbers
  - name: NoMagicNumbers
    description: ""Magic numbers should be named constants""
    severity: Info
    pattern:
      type: NumericLiteral
      minValue: 2
      maxValue: 999999
      notIn: [""*Test*"", ""*Spec*""]
    message: ""Consider extracting magic number {value} to a named constant""
    tags: [""maintainability""]

  # Require authorization attribute on controllers
  - name: RequireAuthorization
    description: ""Controller actions should have authorization""
    severity: Warning
    pattern:
      type: MethodDeclaration
      match: ""*""
      conditions:
        - ""isPublic""
        - ""hasAttribute(HttpGet)""
        - ""notHasAttribute(Authorize)""
        - ""notHasAttribute(AllowAnonymous)""
    message: ""Public action '{method}' should have [Authorize] or [AllowAnonymous] attribute""
    tags: [""security""]

  # Avoid empty catch blocks
  - name: NoEmptyCatch
    description: ""Catch blocks should not be empty""
    severity: Warning
    pattern:
      type: MethodInvocation
      match: ""*""
      conditions:
        - ""inTryCatch""
    message: ""Empty catch block - consider logging or rethrowing""
    tags: [""error-handling""]

  # Flag hardcoded connection strings
  - name: NoHardcodedConnectionStrings
    description: ""Connection strings should be in configuration""
    severity: Error
    pattern:
      type: StringLiteral
      match: ""*Data Source*""
      useRegex: false
    message: ""Hardcoded connection string detected - move to configuration""
    tags: [""security"", ""configuration""]

  # Methods with too many parameters
  - name: TooManyParameters
    description: ""Methods should not have more than 5 parameters""
    severity: Info
    pattern:
      type: MethodDeclaration
      minParameters: 6
    message: ""Method '{method}' has {parameterCount} parameters - consider using a parameter object""
    suggestion: ""Create a request/options class to group parameters""
    tags: [""maintainability"", ""refactoring""]

  # Require XML documentation on public members
  - name: RequireDocumentation
    description: ""Public methods should have XML documentation""
    severity: Info
    pattern:
      type: MethodDeclaration
      conditions:
        - ""isPublic""
        - ""notHasDocComment""
        - ""notIsTestMethod""
    message: ""Public method '{method}' should have XML documentation""
    tags: [""documentation""]
";
    }
}
