using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Naming.Models;

namespace BaseScanner.Analyzers.Naming;

/// <summary>
/// Analyzes semantic quality of names including:
/// - Boolean predicate patterns (IsX, HasX, CanX)
/// - Method naming semantics (GetX, CreateX, etc.)
/// - Async method conventions
/// - Event handler patterns
/// </summary>
public class NameAnalyzer
{
    private readonly ConventionRules _rules;

    // Semantic pattern definitions
    private static readonly Regex BooleanPredicatePattern = new(@"^(Is|Has|Can|Should|Will|Was|Are|Does|Did|Must|Allows?|Supports?|Contains?|Includes?|Enables?|Requires?)[A-Z]", RegexOptions.Compiled);
    private static readonly Regex GetterPattern = new(@"^(Get|Fetch|Retrieve|Read|Load|Find|Lookup|Query)[A-Z]", RegexOptions.Compiled);
    private static readonly Regex SetterPattern = new(@"^(Set|Update|Write|Save|Store|Put|Assign)[A-Z]", RegexOptions.Compiled);
    private static readonly Regex CreatorPattern = new(@"^(Create|Build|Make|New|Construct|Generate|Produce|Initialize|Instantiate)[A-Z]", RegexOptions.Compiled);
    private static readonly Regex AsyncPattern = new(@"Async$", RegexOptions.Compiled);
    private static readonly Regex EventHandlerPattern = new(@"^(On|Handle)[A-Z]", RegexOptions.Compiled);
    private static readonly Regex ValidatorPattern = new(@"^(Validate|Check|Verify|Ensure|Assert|Confirm)[A-Z]", RegexOptions.Compiled);
    private static readonly Regex ParserPattern = new(@"^(Parse|TryParse|Deserialize|Decode|Extract)[A-Z]", RegexOptions.Compiled);
    private static readonly Regex ConverterPattern = new(@"^(To|Convert|As|Transform|Map)[A-Z]", RegexOptions.Compiled);
    private static readonly Regex FinderPattern = new(@"^(Find|Search|Lookup|Locate|Seek)[A-Z]", RegexOptions.Compiled);
    private static readonly Regex ComparerPattern = new(@"^(Compare|Equals|Match|Diff)[A-Z]?", RegexOptions.Compiled);
    private static readonly Regex AggregatorPattern = new(@"^(Sum|Count|Average|Max|Min|Total|Aggregate)[A-Z]?", RegexOptions.Compiled);
    private static readonly Regex DisposerPattern = new(@"^(Dispose|Close|Cleanup|Release|Free|Shutdown|Terminate)", RegexOptions.Compiled);
    private static readonly Regex InitializerPattern = new(@"^(Initialize|Init|Setup|Configure|Bootstrap|Start)[A-Z]?", RegexOptions.Compiled);

    // Common side effect indicators
    private static readonly HashSet<string> SideEffectIndicators = new(StringComparer.OrdinalIgnoreCase)
    {
        "save", "write", "update", "delete", "remove", "insert", "create", "add",
        "send", "post", "put", "publish", "dispatch", "emit", "notify", "log",
        "set", "assign", "modify", "change", "alter", "mutate", "transform",
        "start", "stop", "begin", "end", "open", "close", "connect", "disconnect"
    };

    public NameAnalyzer() : this(new ConventionRules())
    {
    }

    public NameAnalyzer(ConventionRules rules)
    {
        _rules = rules;
    }

    /// <summary>
    /// Infers the semantic purpose of a method from its name.
    /// </summary>
    public SemanticPurpose InferPurpose(string methodName)
    {
        if (string.IsNullOrEmpty(methodName))
            return SemanticPurpose.Unknown;

        if (BooleanPredicatePattern.IsMatch(methodName))
            return SemanticPurpose.BooleanPredicate;

        if (GetterPattern.IsMatch(methodName))
            return SemanticPurpose.Getter;

        if (SetterPattern.IsMatch(methodName))
            return SemanticPurpose.Setter;

        if (CreatorPattern.IsMatch(methodName))
            return SemanticPurpose.Creator;

        if (EventHandlerPattern.IsMatch(methodName))
            return SemanticPurpose.EventHandler;

        if (ValidatorPattern.IsMatch(methodName))
            return SemanticPurpose.Validator;

        if (ParserPattern.IsMatch(methodName))
            return SemanticPurpose.Parser;

        if (ConverterPattern.IsMatch(methodName))
            return SemanticPurpose.Converter;

        if (FinderPattern.IsMatch(methodName))
            return SemanticPurpose.Finder;

        if (ComparerPattern.IsMatch(methodName))
            return SemanticPurpose.Comparer;

        if (AggregatorPattern.IsMatch(methodName))
            return SemanticPurpose.Aggregator;

        if (DisposerPattern.IsMatch(methodName))
            return SemanticPurpose.Disposer;

        if (InitializerPattern.IsMatch(methodName))
            return SemanticPurpose.Initializer;

        return SemanticPurpose.Unknown;
    }

    /// <summary>
    /// Analyzes a method for semantic naming issues.
    /// </summary>
    public SemanticNameAnalysis AnalyzeMethod(
        MethodDeclarationSyntax method,
        SemanticModel semanticModel,
        string filePath)
    {
        var methodName = method.Identifier.Text;
        var symbol = semanticModel.GetDeclaredSymbol(method);
        var returnType = symbol?.ReturnType.ToDisplayString() ?? method.ReturnType.ToString();
        var isAsync = method.Modifiers.Any(SyntaxKind.AsyncKeyword);
        var lineSpan = method.Identifier.GetLocation().GetLineSpan();
        var purpose = InferPurpose(methodName);

        var issues = new List<SemanticIssue>();

        // Check for potential side effects based on method body
        var hasPotentialSideEffects = DetectPotentialSideEffects(method, semanticModel);

        // Check: IsX should return bool
        if (BooleanPredicatePattern.IsMatch(methodName))
        {
            if (!IsBooleanType(returnType))
            {
                issues.Add(new SemanticIssue
                {
                    IssueType = "BooleanPredicateReturnType",
                    Message = $"Method '{methodName}' appears to be a boolean predicate but returns '{returnType}' instead of 'bool'",
                    Severity = NamingViolationSeverity.Warning,
                    Suggestion = returnType == "void"
                        ? $"Change return type to 'bool' or rename to a verb form"
                        : $"Consider renaming or changing return type to 'bool'",
                    Explanation = "Methods with names like IsX, HasX, CanX should return boolean values for clarity"
                });
            }
        }

        // Check: GetX shouldn't have side effects (warning if it does)
        if (GetterPattern.IsMatch(methodName) && hasPotentialSideEffects)
        {
            issues.Add(new SemanticIssue
            {
                IssueType = "GetterWithSideEffects",
                Message = $"Method '{methodName}' is named as a getter but may have side effects",
                Severity = NamingViolationSeverity.Suggestion,
                Suggestion = "Consider renaming to reflect the side effects (e.g., FetchAndCacheX, LoadX)",
                Explanation = "GetX methods should be pure getters without side effects for predictability"
            });
        }

        // Check: CreateX should return new instance
        if (CreatorPattern.IsMatch(methodName))
        {
            if (returnType == "void" || returnType == "System.Void")
            {
                issues.Add(new SemanticIssue
                {
                    IssueType = "CreatorReturnsVoid",
                    Message = $"Method '{methodName}' is named as a creator but returns void",
                    Severity = NamingViolationSeverity.Warning,
                    Suggestion = "Return the created instance or rename to InitializeX, SetupX",
                    Explanation = "CreateX, BuildX methods should return the created object"
                });
            }
        }

        // Check: Async methods should end with Async
        if (isAsync && !AsyncPattern.IsMatch(methodName))
        {
            issues.Add(new SemanticIssue
            {
                IssueType = "AsyncMethodWithoutSuffix",
                Message = $"Async method '{methodName}' should end with 'Async' suffix",
                Severity = NamingViolationSeverity.Warning,
                Suggestion = $"Rename to '{methodName}Async'",
                Explanation = "Async methods should have the 'Async' suffix to indicate their asynchronous nature"
            });
        }

        // Check: Method ends with Async but isn't async
        if (AsyncPattern.IsMatch(methodName) && !isAsync && !ReturnsTaskType(returnType))
        {
            issues.Add(new SemanticIssue
            {
                IssueType = "AsyncSuffixNotAsync",
                Message = $"Method '{methodName}' has 'Async' suffix but is not async and doesn't return Task",
                Severity = NamingViolationSeverity.Warning,
                Suggestion = $"Make the method async or remove the 'Async' suffix",
                Explanation = "Methods with 'Async' suffix should be async or return Task/Task<T>"
            });
        }

        // Check: Event handlers should match pattern
        if (IsEventHandler(method, semanticModel))
        {
            if (!EventHandlerPattern.IsMatch(methodName))
            {
                issues.Add(new SemanticIssue
                {
                    IssueType = "EventHandlerNaming",
                    Message = $"Event handler '{methodName}' should follow OnEventName or HandleEventName pattern",
                    Severity = NamingViolationSeverity.Suggestion,
                    Suggestion = GetEventHandlerSuggestion(method),
                    Explanation = "Event handlers conventionally start with 'On' or 'Handle'"
                });
            }
        }

        // Check: Validator should return bool or throw
        if (ValidatorPattern.IsMatch(methodName))
        {
            if (!IsBooleanType(returnType) && returnType != "void")
            {
                issues.Add(new SemanticIssue
                {
                    IssueType = "ValidatorReturnType",
                    Message = $"Validator method '{methodName}' should return bool or void (throwing on failure)",
                    Severity = NamingViolationSeverity.Suggestion,
                    Suggestion = "Return bool for success/failure or void with exceptions",
                    Explanation = "Validators typically return bool or throw exceptions on invalid input"
                });
            }
        }

        // Check for meaningless names
        var qualityIssues = CheckNameQuality(methodName);
        issues.AddRange(qualityIssues);

        return new SemanticNameAnalysis
        {
            SymbolName = methodName,
            SymbolCategory = SymbolCategory.Method,
            FilePath = filePath,
            Line = lineSpan.StartLinePosition.Line + 1,
            InferredPurpose = purpose,
            ReturnType = returnType,
            IsAsync = isAsync,
            HasPotentialSideEffects = hasPotentialSideEffects,
            Issues = issues
        };
    }

    /// <summary>
    /// Analyzes a property for semantic naming issues.
    /// </summary>
    public SemanticNameAnalysis AnalyzeProperty(
        PropertyDeclarationSyntax property,
        SemanticModel semanticModel,
        string filePath)
    {
        var propertyName = property.Identifier.Text;
        var propertyType = property.Type.ToString();
        var lineSpan = property.Identifier.GetLocation().GetLineSpan();

        var issues = new List<SemanticIssue>();

        // Check: Boolean properties should use Is/Has/Can prefix
        if (IsBooleanType(propertyType))
        {
            if (!BooleanPredicatePattern.IsMatch(propertyName) &&
                !propertyName.Equals("Enabled", StringComparison.OrdinalIgnoreCase) &&
                !propertyName.Equals("Visible", StringComparison.OrdinalIgnoreCase) &&
                !propertyName.Equals("Active", StringComparison.OrdinalIgnoreCase) &&
                !propertyName.Equals("Valid", StringComparison.OrdinalIgnoreCase) &&
                !propertyName.Equals("Empty", StringComparison.OrdinalIgnoreCase) &&
                !propertyName.Equals("Readonly", StringComparison.OrdinalIgnoreCase) &&
                !propertyName.EndsWith("ed", StringComparison.OrdinalIgnoreCase) &&
                !propertyName.EndsWith("able", StringComparison.OrdinalIgnoreCase))
            {
                issues.Add(new SemanticIssue
                {
                    IssueType = "BooleanPropertyNaming",
                    Message = $"Boolean property '{propertyName}' should use Is/Has/Can prefix or be an adjective",
                    Severity = NamingViolationSeverity.Suggestion,
                    Suggestion = $"Consider renaming to 'Is{propertyName}' or 'Has{propertyName}'",
                    Explanation = "Boolean properties are clearer when named as predicates"
                });
            }
        }

        // Check for collection properties that don't indicate plurality
        if (IsCollectionType(propertyType) && !IsPluralOrCollectionNamed(propertyName))
        {
            issues.Add(new SemanticIssue
            {
                IssueType = "CollectionPropertyNaming",
                Message = $"Collection property '{propertyName}' should use plural form",
                Severity = NamingViolationSeverity.Suggestion,
                Suggestion = $"Consider renaming to '{Pluralize(propertyName)}'",
                Explanation = "Collection properties should indicate plurality for clarity"
            });
        }

        return new SemanticNameAnalysis
        {
            SymbolName = propertyName,
            SymbolCategory = SymbolCategory.Property,
            FilePath = filePath,
            Line = lineSpan.StartLinePosition.Line + 1,
            InferredPurpose = SemanticPurpose.Unknown,
            ReturnType = propertyType,
            IsAsync = false,
            HasPotentialSideEffects = false,
            Issues = issues
        };
    }

    /// <summary>
    /// Analyzes a name for general quality issues.
    /// </summary>
    public NameQualityAnalysis AnalyzeNameQuality(string name, SymbolCategory category)
    {
        var issues = new List<string>();
        var strengths = new List<string>();
        var words = _rules.SplitIntoWords(name);
        var convention = _rules.DetectNamingConvention(name);
        var containsAbbreviation = _rules.ContainsAbbreviation(name, out var abbreviations);
        var containsNumber = Regex.IsMatch(name, @"\d");
        var qualityScore = 100.0;

        // Length checks
        if (name.Length < 2)
        {
            issues.Add("Name is too short - consider a more descriptive name");
            qualityScore -= 20;
        }
        else if (name.Length < 4 && category != SymbolCategory.TypeParameter && category != SymbolCategory.LocalVariable)
        {
            issues.Add("Name might be too short for this context");
            qualityScore -= 10;
        }

        if (name.Length > 50)
        {
            issues.Add("Name is excessively long - consider a shorter name");
            qualityScore -= 15;
        }
        else if (name.Length > 35)
        {
            issues.Add("Name is quite long");
            qualityScore -= 5;
        }

        // Word count
        if (words.Count > 5)
        {
            issues.Add("Name has many words - consider simplifying");
            qualityScore -= 10;
        }
        else if (words.Count >= 3)
        {
            strengths.Add("Descriptive multi-word name");
        }

        // Numbers in names
        if (containsNumber && !IsAcceptableNumberedName(name))
        {
            issues.Add("Contains numbers - consider using a more descriptive name");
            qualityScore -= 10;
        }

        // Abbreviation usage
        if (containsAbbreviation)
        {
            var allowed = abbreviations.Where(a =>
                _rules.GetConfiguration().AllowedAbbreviations.Contains(a, StringComparer.OrdinalIgnoreCase)).ToList();
            var notAllowed = abbreviations.Except(allowed, StringComparer.OrdinalIgnoreCase).ToList();

            if (allowed.Any())
            {
                strengths.Add($"Uses common abbreviation(s): {string.Join(", ", allowed)}");
            }

            if (notAllowed.Any())
            {
                issues.Add($"Uses uncommon abbreviation(s): {string.Join(", ", notAllowed)}");
                qualityScore -= 5 * notAllowed.Count;
            }
        }

        // Meaningless name detection
        var meaninglessNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "data", "info", "item", "obj", "object", "thing", "stuff",
            "temp", "tmp", "x", "y", "z", "foo", "bar", "baz",
            "result", "value", "val", "ret", "retval"
        };

        var cleanName = name.TrimStart('_');
        if (meaninglessNames.Contains(cleanName.ToLowerInvariant()))
        {
            issues.Add("Name is too generic - use a more specific name");
            qualityScore -= 25;
        }

        // Positive indicators
        if (words.All(w => w.Length >= 3))
        {
            strengths.Add("Uses full words instead of abbreviations");
        }

        if (category == SymbolCategory.Method && words.Count >= 2 && IsVerb(words[0]))
        {
            strengths.Add("Method name starts with verb");
        }

        // Convention appropriateness
        var rule = _rules.GetRule(category);
        if (rule != null && _rules.IsValidForConvention(name, rule.Convention, rule.RequiredPrefix, rule.RequiredSuffix))
        {
            strengths.Add($"Follows {FormatConvention(rule.Convention)} convention");
        }
        else if (rule != null)
        {
            qualityScore -= 15;
        }

        // Build suggested improvement
        string? suggestion = null;
        if (issues.Any())
        {
            suggestion = BuildImprovementSuggestion(name, category, issues);
        }

        return new NameQualityAnalysis
        {
            Name = name,
            Category = category,
            IsValid = qualityScore >= 50,
            QualityScore = Math.Max(0, Math.Min(100, qualityScore)),
            Issues = issues,
            Strengths = strengths,
            SuggestedImprovement = suggestion,
            Words = words,
            ContainsAbbreviation = containsAbbreviation,
            ContainsNumber = containsNumber,
            Length = name.Length,
            DetectedConvention = convention
        };
    }

    private List<SemanticIssue> CheckNameQuality(string name)
    {
        var issues = new List<SemanticIssue>();

        // Check for meaningless method names
        var genericMethodNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Do", "Run", "Execute", "Process", "Handle",
            "DoIt", "DoWork", "DoStuff", "DoSomething",
            "Main", "Helper", "Utility", "Work"
        };

        if (genericMethodNames.Contains(name))
        {
            issues.Add(new SemanticIssue
            {
                IssueType = "GenericMethodName",
                Message = $"Method name '{name}' is too generic",
                Severity = NamingViolationSeverity.Suggestion,
                Suggestion = "Use a name that describes what the method does",
                Explanation = "Method names should clearly indicate their purpose"
            });
        }

        // Check for numbered method names
        if (Regex.IsMatch(name, @"^[A-Za-z]+\d+$") && !IsAcceptableNumberedName(name))
        {
            issues.Add(new SemanticIssue
            {
                IssueType = "NumberedMethodName",
                Message = $"Method name '{name}' contains a number suffix",
                Severity = NamingViolationSeverity.Suggestion,
                Suggestion = "Use descriptive names instead of numbered variants",
                Explanation = "Numbered names often indicate code duplication or poor abstraction"
            });
        }

        return issues;
    }

    private bool DetectPotentialSideEffects(MethodDeclarationSyntax method, SemanticModel semanticModel)
    {
        var body = (SyntaxNode?)method.Body ?? method.ExpressionBody;
        if (body == null)
            return false;

        // Check for assignments to fields/properties
        foreach (var assignment in body.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is MemberAccessExpressionSyntax or IdentifierNameSyntax)
            {
                var symbol = semanticModel.GetSymbolInfo(assignment.Left).Symbol;
                if (symbol is IFieldSymbol or IPropertySymbol)
                    return true;
            }
        }

        // Check for invocations with side effect indicators
        foreach (var invocation in body.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var methodName = invocation.Expression switch
            {
                IdentifierNameSyntax id => id.Identifier.Text,
                MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
                _ => null
            };

            if (methodName != null)
            {
                foreach (var indicator in SideEffectIndicators)
                {
                    if (methodName.Contains(indicator, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
        }

        // Check for object creation (might indicate side effects)
        if (body.DescendantNodes().OfType<ObjectCreationExpressionSyntax>().Any())
        {
            // Only count as side effect if it's related to I/O or external services
            foreach (var creation in body.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
            {
                var typeName = creation.Type.ToString();
                if (typeName.Contains("Stream") || typeName.Contains("Client") ||
                    typeName.Contains("Connection") || typeName.Contains("Writer"))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private bool IsEventHandler(MethodDeclarationSyntax method, SemanticModel semanticModel)
    {
        // Check for typical event handler signature
        var parameters = method.ParameterList.Parameters;
        if (parameters.Count == 2)
        {
            var firstParam = parameters[0].Type?.ToString() ?? "";
            var secondParam = parameters[1].Type?.ToString() ?? "";

            if (firstParam == "object" && (secondParam.EndsWith("EventArgs") || secondParam == "EventArgs"))
                return true;
        }

        return false;
    }

    private string? GetEventHandlerSuggestion(MethodDeclarationSyntax method)
    {
        var name = method.Identifier.Text;

        // Try to extract event name
        if (name.Contains("_"))
        {
            var parts = name.Split('_');
            if (parts.Length >= 2)
            {
                var eventName = parts[parts.Length - 1];
                return $"Consider renaming to 'On{eventName}' or 'Handle{eventName}'";
            }
        }

        return "Consider using 'OnEventName' or 'HandleEventName' pattern";
    }

    private static bool IsBooleanType(string typeName) =>
        typeName == "bool" || typeName == "Boolean" || typeName == "System.Boolean";

    private static bool ReturnsTaskType(string typeName) =>
        typeName.StartsWith("Task") || typeName.StartsWith("ValueTask") ||
        typeName.StartsWith("System.Threading.Tasks.Task");

    private static bool IsCollectionType(string typeName) =>
        typeName.Contains("List") || typeName.Contains("Collection") ||
        typeName.Contains("Enumerable") || typeName.Contains("Array") ||
        typeName.Contains("Dictionary") || typeName.Contains("Set") ||
        typeName.EndsWith("[]");

    private static bool IsPluralOrCollectionNamed(string name) =>
        name.EndsWith("s", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith("es", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith("ies", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("List", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("Collection", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("Array", StringComparison.OrdinalIgnoreCase) ||
        name.Contains("Items", StringComparison.OrdinalIgnoreCase);

    private static string Pluralize(string name)
    {
        if (string.IsNullOrEmpty(name))
            return name;

        if (name.EndsWith("y", StringComparison.OrdinalIgnoreCase) &&
            !name.EndsWith("ay", StringComparison.OrdinalIgnoreCase) &&
            !name.EndsWith("ey", StringComparison.OrdinalIgnoreCase) &&
            !name.EndsWith("oy", StringComparison.OrdinalIgnoreCase) &&
            !name.EndsWith("uy", StringComparison.OrdinalIgnoreCase))
        {
            return name.Substring(0, name.Length - 1) + "ies";
        }

        if (name.EndsWith("s", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith("x", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith("ch", StringComparison.OrdinalIgnoreCase) ||
            name.EndsWith("sh", StringComparison.OrdinalIgnoreCase))
        {
            return name + "es";
        }

        return name + "s";
    }

    private static bool IsAcceptableNumberedName(string name)
    {
        // Some numbered names are acceptable (e.g., Vector3, Base64, Md5)
        var acceptablePatterns = new[]
        {
            @"Vector\d", @"Matrix\d", @"Point\d",
            @"Base\d+", @"Utf\d+", @"Md\d", @"Sha\d+",
            @"Http\d", @"Version\d", @"Level\d"
        };

        return acceptablePatterns.Any(p => Regex.IsMatch(name, p, RegexOptions.IgnoreCase));
    }

    private static bool IsVerb(string word)
    {
        var commonVerbs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "get", "set", "add", "remove", "create", "build", "delete", "update",
            "find", "search", "load", "save", "read", "write", "send", "receive",
            "start", "stop", "begin", "end", "open", "close", "run", "execute",
            "validate", "check", "verify", "parse", "convert", "transform",
            "calculate", "compute", "process", "handle", "initialize", "configure",
            "enable", "disable", "show", "hide", "apply", "reset", "clear"
        };

        return commonVerbs.Contains(word);
    }

    private static string FormatConvention(NamingConvention convention) => convention switch
    {
        NamingConvention.PascalCase => "PascalCase",
        NamingConvention.CamelCase => "camelCase",
        NamingConvention.UpperSnakeCase => "UPPER_SNAKE_CASE",
        NamingConvention.LowerSnakeCase => "lower_snake_case",
        NamingConvention.IPrefixed => "I-prefixed PascalCase",
        NamingConvention.UnderscorePrefixed => "underscore-prefixed camelCase",
        _ => convention.ToString()
    };

    private string? BuildImprovementSuggestion(string name, SymbolCategory category, List<string> issues)
    {
        if (issues.Contains("Name is too short - consider a more descriptive name"))
        {
            return category switch
            {
                SymbolCategory.Method => "Use a verb-noun combination like 'ProcessData' or 'ValidateInput'",
                SymbolCategory.Property => "Use a descriptive noun like 'CurrentValue' or 'IsEnabled'",
                SymbolCategory.LocalVariable => "Consider a more descriptive name based on usage",
                _ => "Consider a more descriptive name"
            };
        }

        if (issues.Any(i => i.Contains("too generic")))
        {
            return category switch
            {
                SymbolCategory.Method => "Describe what the method does (e.g., 'CalculateTotalPrice' instead of 'Process')",
                SymbolCategory.Parameter => "Describe the parameter's purpose (e.g., 'customerName' instead of 'data')",
                SymbolCategory.LocalVariable => "Describe what the variable holds (e.g., 'activeUsers' instead of 'items')",
                _ => "Use a name that reflects the purpose"
            };
        }

        return null;
    }
}
