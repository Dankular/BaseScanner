using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;
using BaseScanner.Analyzers.Documentation.Models;
using System.Text.RegularExpressions;

namespace BaseScanner.Analyzers.Documentation.Detectors;

/// <summary>
/// Detects naming quality issues including misleading names, abbreviation overuse,
/// and mismatches between names and actual behavior.
/// </summary>
public class NamingQualityDetector : DocDetectorBase
{
    public override DocIssueCategory Category => DocIssueCategory.NamingQuality;
    public override string Name => "Naming Quality Detector";
    public override string Description => "Detects misleading names, abbreviation overuse, and naming convention violations.";

    // Common abbreviations that are acceptable
    private static readonly HashSet<string> AcceptableAbbreviations = new(StringComparer.OrdinalIgnoreCase)
    {
        "Id", "Url", "Uri", "Xml", "Html", "Json", "Css", "Js",
        "Db", "Sql", "Api", "Dto", "Io", "Ui", "Guid", "Http", "Https",
        "Cpu", "Gpu", "Ram", "Ssd", "Hdd", "Usb", "Ip", "Tcp", "Udp",
        "Async", "Sync", "Config", "Init", "Auth", "Admin", "App",
        "Max", "Min", "Avg", "Num", "Idx", "Len", "Src", "Dst", "Tmp",
        "Btn", "Lbl", "Txt", "Img", "Div", "Nav", "Ref", "Ptr"
    };

    // Abbreviation pattern
    private static readonly Regex AbbreviationPattern = new(@"([A-Z]{2,}|[a-z]{1,3})(?=[A-Z]|$)", RegexOptions.Compiled);
    private static readonly Regex ConsecutiveUppercasePattern = new(@"[A-Z]{3,}", RegexOptions.Compiled);

    // Name prefix patterns
    private static readonly Regex IsPrefixPattern = new(@"^[Ii]s[A-Z]", RegexOptions.Compiled);
    private static readonly Regex HasPrefixPattern = new(@"^[Hh]as[A-Z]", RegexOptions.Compiled);
    private static readonly Regex CanPrefixPattern = new(@"^[Cc]an[A-Z]", RegexOptions.Compiled);
    private static readonly Regex ShouldPrefixPattern = new(@"^[Ss]hould[A-Z]", RegexOptions.Compiled);
    private static readonly Regex GetPrefixPattern = new(@"^[Gg]et[A-Z]", RegexOptions.Compiled);
    private static readonly Regex SetPrefixPattern = new(@"^[Ss]et[A-Z]", RegexOptions.Compiled);
    private static readonly Regex FindPrefixPattern = new(@"^[Ff]ind[A-Z]", RegexOptions.Compiled);
    private static readonly Regex ComputePrefixPattern = new(@"^([Cc]ompute|[Cc]alculate|[Cc]alc)[A-Z]", RegexOptions.Compiled);

    // List of name suggestions accumulated during analysis
    private readonly List<NameSuggestion> _nameSuggestions = [];

    public List<NameSuggestion> GetNameSuggestions() => [.. _nameSuggestions];

    public override async Task<List<DocumentationIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext? context = null)
    {
        _nameSuggestions.Clear();
        var issues = new List<DocumentationIssue>();
        var filePath = document.FilePath ?? "";

        // Check method naming
        issues.AddRange(await CheckMethodNamingAsync(root, semanticModel, filePath));

        // Check property naming
        issues.AddRange(await CheckPropertyNamingAsync(root, semanticModel, filePath));

        // Check variable naming
        issues.AddRange(CheckVariableNaming(root, filePath));

        // Check type naming
        issues.AddRange(await CheckTypeNamingAsync(root, semanticModel, filePath));

        // Check for abbreviation overuse
        issues.AddRange(CheckAbbreviationOveruse(root, filePath));

        return issues;
    }

    private Task<List<DocumentationIssue>> CheckMethodNamingAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(method);
            if (symbol == null) continue;

            var (startLine, endLine) = GetLineSpan(method.Identifier);
            var methodName = method.Identifier.Text;

            // Check Is/Has/Can/Should prefix returns bool
            if (IsBooleanPrefixMethod(methodName))
            {
                var returnType = symbol.ReturnType;
                var isActuallyBool = returnType.SpecialType == SpecialType.System_Boolean ||
                                    (returnType is INamedTypeSymbol namedType &&
                                     namedType.Name == "Task" &&
                                     namedType.TypeArguments.Length == 1 &&
                                     namedType.TypeArguments[0].SpecialType == SpecialType.System_Boolean);

                if (!isActuallyBool)
                {
                    var prefix = GetBooleanPrefix(methodName);
                    var suggestedName = SuggestNonBooleanMethodName(methodName, symbol.ReturnType.Name);

                    issues.Add(CreateIssue(
                        DocumentationIssueType.MisleadingName,
                        DocIssueSeverity.Major,
                        filePath,
                        startLine,
                        endLine,
                        methodName,
                        "Method",
                        $"Method '{methodName}' uses '{prefix}' prefix but returns '{symbol.ReturnType.Name}' instead of bool",
                        $"Rename to '{suggestedName}' or change return type to bool",
                        currentCode: $"public {method.ReturnType} {methodName}",
                        suggestedCode: $"public {method.ReturnType} {suggestedName}",
                        confidence: 95));

                    _nameSuggestions.Add(new NameSuggestion
                    {
                        OriginalName = methodName,
                        SuggestedName = suggestedName,
                        Reason = $"'{prefix}' prefix implies boolean return type",
                        Confidence = 85
                    });
                }
            }

            // Check Get prefix for side effects
            if (GetPrefixPattern.IsMatch(methodName))
            {
                var hasSideEffects = DetectSideEffects(method, semanticModel);
                if (hasSideEffects.HasSideEffects)
                {
                    var suggestedName = SuggestNameForSideEffectGetter(methodName, hasSideEffects.SideEffectType);

                    issues.Add(CreateIssue(
                        DocumentationIssueType.MisleadingName,
                        DocIssueSeverity.Major,
                        filePath,
                        startLine,
                        endLine,
                        methodName,
                        "Method",
                        $"Method '{methodName}' uses 'Get' prefix but has side effects ({hasSideEffects.SideEffectType})",
                        $"Rename to '{suggestedName}' to indicate side effects, or remove the side effects",
                        currentCode: $"public {method.ReturnType} {methodName}",
                        suggestedCode: $"public {method.ReturnType} {suggestedName}",
                        confidence: 85));

                    _nameSuggestions.Add(new NameSuggestion
                    {
                        OriginalName = methodName,
                        SuggestedName = suggestedName,
                        Reason = $"'Get' prefix implies no side effects but method {hasSideEffects.SideEffectType}",
                        Confidence = 75
                    });
                }
            }

            // Check Find prefix doesn't return single item when collection expected
            if (FindPrefixPattern.IsMatch(methodName))
            {
                var returnsCollection = IsCollectionType(symbol.ReturnType);
                var hasPluralSuffix = methodName.EndsWith("s") || methodName.EndsWith("All") || methodName.EndsWith("Many");

                if (!returnsCollection && hasPluralSuffix)
                {
                    var suggestedName = methodName.TrimEnd('s');
                    if (suggestedName.EndsWith("ie")) suggestedName = suggestedName[..^2] + "y";

                    issues.Add(CreateIssue(
                        DocumentationIssueType.MisleadingName,
                        DocIssueSeverity.Minor,
                        filePath,
                        startLine,
                        endLine,
                        methodName,
                        "Method",
                        $"Method '{methodName}' suggests returning multiple items but returns single '{symbol.ReturnType.Name}'",
                        $"Rename to singular form like '{suggestedName}'",
                        confidence: 70));
                }
            }

            // Check Compute/Calculate implies pure function
            if (ComputePrefixPattern.IsMatch(methodName))
            {
                var hasSideEffects = DetectSideEffects(method, semanticModel);
                if (hasSideEffects.HasSideEffects)
                {
                    var prefix = methodName.StartsWith("Calc", StringComparison.OrdinalIgnoreCase) ? "Calculate" : "Compute";
                    issues.Add(CreateIssue(
                        DocumentationIssueType.MisleadingName,
                        DocIssueSeverity.Minor,
                        filePath,
                        startLine,
                        endLine,
                        methodName,
                        "Method",
                        $"Method '{methodName}' uses '{prefix}' prefix implying pure function but has side effects",
                        "Consider renaming or extracting side effects into separate method",
                        confidence: 70));
                }
            }

            // Check for verb-noun consistency
            if (IsPublicMethod(method))
            {
                var verbIssue = CheckVerbNounConsistency(methodName, symbol);
                if (verbIssue != null)
                {
                    issues.Add(CreateIssue(
                        DocumentationIssueType.VerbNounMismatch,
                        DocIssueSeverity.Info,
                        filePath,
                        startLine,
                        endLine,
                        methodName,
                        "Method",
                        verbIssue,
                        "Consider renaming for clarity",
                        confidence: 50));
                }
            }
        }

        return Task.FromResult(issues);
    }

    private Task<List<DocumentationIssue>> CheckPropertyNamingAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        foreach (var property in root.DescendantNodes().OfType<PropertyDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(property);
            if (symbol == null) continue;

            var (startLine, endLine) = GetLineSpan(property.Identifier);
            var propName = property.Identifier.Text;

            // Check boolean properties
            if (IsBooleanPrefixName(propName))
            {
                var isBool = symbol.Type.SpecialType == SpecialType.System_Boolean;
                if (!isBool)
                {
                    var prefix = GetBooleanPrefix(propName);
                    issues.Add(CreateIssue(
                        DocumentationIssueType.MisleadingName,
                        DocIssueSeverity.Major,
                        filePath,
                        startLine,
                        endLine,
                        propName,
                        "Property",
                        $"Property '{propName}' uses '{prefix}' prefix but is type '{symbol.Type.Name}' not bool",
                        $"Rename property or change type to bool",
                        confidence: 90));
                }
            }

            // Check collection properties for plural naming
            if (IsCollectionType(symbol.Type))
            {
                if (!propName.EndsWith("s") && !propName.EndsWith("List") && !propName.EndsWith("Collection") &&
                    !propName.EndsWith("Array") && !propName.EndsWith("Set") && !propName.EndsWith("Items"))
                {
                    var suggestedName = MakePlural(propName);
                    issues.Add(CreateIssue(
                        DocumentationIssueType.MisleadingName,
                        DocIssueSeverity.Info,
                        filePath,
                        startLine,
                        endLine,
                        propName,
                        "Property",
                        $"Collection property '{propName}' should use plural naming",
                        $"Consider renaming to '{suggestedName}'",
                        confidence: 60));

                    _nameSuggestions.Add(new NameSuggestion
                    {
                        OriginalName = propName,
                        SuggestedName = suggestedName,
                        Reason = "Collection properties should use plural naming",
                        Confidence = 60
                    });
                }
            }

            // Check for Get prefix on properties (properties shouldn't have Get prefix)
            if (GetPrefixPattern.IsMatch(propName))
            {
                var suggestedName = propName.Substring(3);
                issues.Add(CreateIssue(
                    DocumentationIssueType.MisleadingName,
                    DocIssueSeverity.Minor,
                    filePath,
                    startLine,
                    endLine,
                    propName,
                    "Property",
                    $"Property '{propName}' uses 'Get' prefix - properties don't need Get prefix",
                    $"Rename to '{suggestedName}'",
                    confidence: 85));

                _nameSuggestions.Add(new NameSuggestion
                {
                    OriginalName = propName,
                    SuggestedName = suggestedName,
                    Reason = "Properties implicitly 'get' values, prefix is redundant",
                    Confidence = 85
                });
            }
        }

        return Task.FromResult(issues);
    }

    private List<DocumentationIssue> CheckVariableNaming(SyntaxNode root, string filePath)
    {
        var issues = new List<DocumentationIssue>();

        // Check local variables
        foreach (var local in root.DescendantNodes().OfType<LocalDeclarationStatementSyntax>())
        {
            foreach (var variable in local.Declaration.Variables)
            {
                var varName = variable.Identifier.Text;
                var (startLine, endLine) = GetLineSpan(variable.Identifier);

                // Check for single-letter names (except in loops)
                if (varName.Length == 1 && !IsLoopVariable(variable))
                {
                    issues.Add(CreateIssue(
                        DocumentationIssueType.MisleadingName,
                        DocIssueSeverity.Info,
                        filePath,
                        startLine,
                        endLine,
                        varName,
                        "Variable",
                        $"Single-letter variable name '{varName}' is not descriptive",
                        "Use a more descriptive name",
                        confidence: 70));
                }

                // Check for very short non-descriptive names
                if (varName.Length <= 2 && !IsAcceptableShortName(varName))
                {
                    issues.Add(CreateIssue(
                        DocumentationIssueType.MisleadingName,
                        DocIssueSeverity.Info,
                        filePath,
                        startLine,
                        endLine,
                        varName,
                        "Variable",
                        $"Variable name '{varName}' may not be descriptive enough",
                        "Consider using a more meaningful name",
                        confidence: 50));
                }
            }
        }

        // Check parameters
        foreach (var parameter in root.DescendantNodes().OfType<ParameterSyntax>())
        {
            var paramName = parameter.Identifier.Text;
            var (startLine, endLine) = GetLineSpan(parameter.Identifier);

            if (paramName.Length == 1)
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MisleadingName,
                    DocIssueSeverity.Warning,
                    filePath,
                    startLine,
                    endLine,
                    paramName,
                    "Parameter",
                    $"Single-letter parameter name '{paramName}' lacks meaning",
                    "Use a descriptive name that explains the parameter's purpose",
                    confidence: 80));
            }
        }

        return issues;
    }

    private Task<List<DocumentationIssue>> CheckTypeNamingAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        foreach (var classDecl in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
        {
            var className = classDecl.Identifier.Text;
            var (startLine, endLine) = GetLineSpan(classDecl.Identifier);

            // Check for "Manager" or "Handler" without clear responsibility
            if (className.EndsWith("Manager") || className.EndsWith("Handler") || className.EndsWith("Processor"))
            {
                var memberCount = classDecl.Members.OfType<MethodDeclarationSyntax>().Count();
                if (memberCount > 10)
                {
                    issues.Add(CreateIssue(
                        DocumentationIssueType.MisleadingName,
                        DocIssueSeverity.Info,
                        filePath,
                        startLine,
                        endLine,
                        className,
                        "Class",
                        $"Class '{className}' has generic suffix and {memberCount} methods - may have too many responsibilities",
                        "Consider splitting into more focused classes with specific names",
                        confidence: 50));
                }
            }

            // Check for "Data" or "Info" suffix without being a DTO/record
            if ((className.EndsWith("Data") || className.EndsWith("Info")) &&
                !classDecl.Modifiers.Any(SyntaxKind.SealedKeyword) &&
                classDecl.Members.OfType<MethodDeclarationSyntax>().Count() > 3)
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.MisleadingName,
                    DocIssueSeverity.Info,
                    filePath,
                    startLine,
                    endLine,
                    className,
                    "Class",
                    $"Class '{className}' uses Data/Info suffix but has significant behavior",
                    "Consider renaming to reflect its responsibility or extracting behavior",
                    confidence: 40));
            }
        }

        // Check interfaces
        foreach (var interfaceDecl in root.DescendantNodes().OfType<InterfaceDeclarationSyntax>())
        {
            var interfaceName = interfaceDecl.Identifier.Text;
            var (startLine, endLine) = GetLineSpan(interfaceDecl.Identifier);

            // Check for I prefix
            if (!interfaceName.StartsWith("I") || (interfaceName.Length > 1 && char.IsLower(interfaceName[1])))
            {
                var suggestedName = "I" + interfaceName;
                issues.Add(CreateIssue(
                    DocumentationIssueType.InconsistentNaming,
                    DocIssueSeverity.Minor,
                    filePath,
                    startLine,
                    endLine,
                    interfaceName,
                    "Interface",
                    $"Interface '{interfaceName}' should follow 'I' prefix convention",
                    $"Rename to '{suggestedName}'",
                    confidence: 95));

                _nameSuggestions.Add(new NameSuggestion
                {
                    OriginalName = interfaceName,
                    SuggestedName = suggestedName,
                    Reason = "Interface naming convention requires 'I' prefix",
                    Confidence = 95
                });
            }
        }

        return Task.FromResult(issues);
    }

    private List<DocumentationIssue> CheckAbbreviationOveruse(SyntaxNode root, string filePath)
    {
        var issues = new List<DocumentationIssue>();

        var allIdentifiers = root.DescendantTokens()
            .Where(t => t.IsKind(SyntaxKind.IdentifierToken))
            .GroupBy(t => t.Text)
            .Select(g => g.First())
            .ToList();

        foreach (var identifier in allIdentifiers)
        {
            var name = identifier.Text;
            var (startLine, endLine) = GetLineSpan(identifier);

            // Find potential abbreviations
            var abbreviations = FindAbbreviations(name);
            var unacceptableAbbreviations = abbreviations
                .Where(a => !AcceptableAbbreviations.Contains(a) && a.Length >= 2)
                .ToList();

            if (unacceptableAbbreviations.Count >= 2)
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.AbbreviationOveruse,
                    DocIssueSeverity.Info,
                    filePath,
                    startLine,
                    endLine,
                    name,
                    "Identifier",
                    $"Identifier '{name}' contains multiple abbreviations: {string.Join(", ", unacceptableAbbreviations)}",
                    "Consider using full words for better readability",
                    confidence: 60,
                    metadata: new Dictionary<string, object>
                    {
                        ["Abbreviations"] = unacceptableAbbreviations
                    }));
            }

            // Check for consecutive uppercase (like HTTP, XML inside words)
            var consecutiveMatches = ConsecutiveUppercasePattern.Matches(name);
            foreach (Match match in consecutiveMatches)
            {
                var abbr = match.Value;
                if (!AcceptableAbbreviations.Contains(abbr) && abbr.Length > 3)
                {
                    issues.Add(CreateIssue(
                        DocumentationIssueType.AbbreviationOveruse,
                        DocIssueSeverity.Info,
                        filePath,
                        startLine,
                        endLine,
                        name,
                        "Identifier",
                        $"Identifier '{name}' contains unclear abbreviation '{abbr}'",
                        "Consider using camelCase or spelling out the abbreviation",
                        confidence: 50));
                }
            }
        }

        return issues;
    }

    // Helper methods
    private static bool IsBooleanPrefixMethod(string name)
    {
        return IsPrefixPattern.IsMatch(name) ||
               HasPrefixPattern.IsMatch(name) ||
               CanPrefixPattern.IsMatch(name) ||
               ShouldPrefixPattern.IsMatch(name);
    }

    private static bool IsBooleanPrefixName(string name)
    {
        return IsPrefixPattern.IsMatch(name) ||
               HasPrefixPattern.IsMatch(name) ||
               CanPrefixPattern.IsMatch(name) ||
               ShouldPrefixPattern.IsMatch(name);
    }

    private static string GetBooleanPrefix(string name)
    {
        if (IsPrefixPattern.IsMatch(name)) return "Is";
        if (HasPrefixPattern.IsMatch(name)) return "Has";
        if (CanPrefixPattern.IsMatch(name)) return "Can";
        if (ShouldPrefixPattern.IsMatch(name)) return "Should";
        return "";
    }

    private static string SuggestNonBooleanMethodName(string name, string returnType)
    {
        var withoutPrefix = name;
        if (name.StartsWith("Is", StringComparison.OrdinalIgnoreCase))
            withoutPrefix = name.Substring(2);
        else if (name.StartsWith("Has", StringComparison.OrdinalIgnoreCase))
            withoutPrefix = name.Substring(3);
        else if (name.StartsWith("Can", StringComparison.OrdinalIgnoreCase))
            withoutPrefix = name.Substring(3);
        else if (name.StartsWith("Should", StringComparison.OrdinalIgnoreCase))
            withoutPrefix = name.Substring(6);

        // Suggest based on return type
        if (returnType.Contains("List") || returnType.Contains("IEnumerable") || returnType.Contains("Collection"))
            return "Get" + withoutPrefix + "s";
        if (returnType == "int" || returnType == "Int32" || returnType == "long")
            return "Get" + withoutPrefix + "Count";

        return "Get" + withoutPrefix;
    }

    private static (bool HasSideEffects, string SideEffectType) DetectSideEffects(
        MethodDeclarationSyntax method,
        SemanticModel semanticModel)
    {
        // Check for assignments to fields or properties
        foreach (var assignment in method.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is MemberAccessExpressionSyntax memberAccess)
            {
                if (memberAccess.Expression is ThisExpressionSyntax)
                {
                    return (true, "modifies instance state");
                }
            }
            else if (assignment.Left is IdentifierNameSyntax identifier)
            {
                var symbol = semanticModel.GetSymbolInfo(identifier).Symbol;
                if (symbol is IFieldSymbol or IPropertySymbol)
                {
                    return (true, "modifies field/property");
                }
            }
        }

        // Check for method calls that might have side effects
        foreach (var invocation in method.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax ma)
            {
                var methodName = ma.Name.Identifier.Text;
                var sideEffectMethods = new[] { "Add", "Remove", "Clear", "Set", "Update", "Delete", "Insert", "Save", "Write", "Post", "Put" };

                if (sideEffectMethods.Any(s => methodName.StartsWith(s, StringComparison.OrdinalIgnoreCase)))
                {
                    return (true, $"calls {methodName}");
                }
            }
        }

        // Check for database/file/network operations
        foreach (var invocation in method.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var text = invocation.ToString();
            if (text.Contains("SaveChanges") || text.Contains("ExecuteNonQuery") ||
                text.Contains("File.Write") || text.Contains("Stream.Write"))
            {
                return (true, "performs I/O operation");
            }
        }

        return (false, "");
    }

    private static string SuggestNameForSideEffectGetter(string name, string sideEffectType)
    {
        var withoutGet = name.Substring(3);

        if (sideEffectType.Contains("modifies"))
            return "GetOrCreate" + withoutGet;
        if (sideEffectType.Contains("Add") || sideEffectType.Contains("Insert"))
            return "GetOrAdd" + withoutGet;
        if (sideEffectType.Contains("Save") || sideEffectType.Contains("Write"))
            return "FetchAnd" + withoutGet;

        return "Load" + withoutGet;
    }

    private static bool IsCollectionType(ITypeSymbol type)
    {
        var typeName = type.Name;
        return typeName.Contains("List") ||
               typeName.Contains("Collection") ||
               typeName.Contains("Enumerable") ||
               typeName.Contains("Array") ||
               typeName.Contains("Set") ||
               typeName.Contains("Dictionary") ||
               type.AllInterfaces.Any(i => i.Name == "IEnumerable");
    }

    private static bool IsPublicMethod(MethodDeclarationSyntax method)
    {
        return method.Modifiers.Any(m => m.IsKind(SyntaxKind.PublicKeyword));
    }

    private static string? CheckVerbNounConsistency(string methodName, IMethodSymbol symbol)
    {
        // Check if method starts with verb
        var commonVerbs = new[] { "Get", "Set", "Create", "Delete", "Update", "Find", "Search", "Load", "Save", "Process", "Handle", "Execute", "Run", "Start", "Stop" };

        var startsWithVerb = commonVerbs.Any(v => methodName.StartsWith(v, StringComparison.OrdinalIgnoreCase));

        if (!startsWithVerb && !methodName.Contains("On") && methodName.Length > 3)
        {
            // Doesn't start with verb - might be problematic for methods
            var firstWord = Regex.Match(methodName, @"^([A-Z][a-z]+)").Groups[1].Value;
            if (!string.IsNullOrEmpty(firstWord) && !IsNoun(firstWord))
            {
                return $"Method '{methodName}' should start with a verb";
            }
        }

        return null;
    }

    private static bool IsNoun(string word)
    {
        // Simple heuristic - in practice you'd use a more sophisticated check
        var commonNouns = new[] { "Data", "Info", "Result", "Response", "Request", "Event", "Handler", "Manager", "Service", "Provider" };
        return commonNouns.Any(n => word.Equals(n, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsLoopVariable(VariableDeclaratorSyntax variable)
    {
        return variable.Parent?.Parent?.Parent is ForStatementSyntax or ForEachStatementSyntax;
    }

    private static bool IsAcceptableShortName(string name)
    {
        var acceptable = new[] { "id", "db", "io", "ui", "ex", "sb" };
        return acceptable.Contains(name.ToLower());
    }

    private static string MakePlural(string name)
    {
        if (name.EndsWith("y") && !name.EndsWith("ay") && !name.EndsWith("ey") && !name.EndsWith("oy") && !name.EndsWith("uy"))
            return name[..^1] + "ies";
        if (name.EndsWith("s") || name.EndsWith("x") || name.EndsWith("ch") || name.EndsWith("sh"))
            return name + "es";
        return name + "s";
    }

    private static List<string> FindAbbreviations(string name)
    {
        var abbreviations = new List<string>();
        var matches = AbbreviationPattern.Matches(name);

        foreach (Match match in matches)
        {
            var value = match.Value;
            // Check if it looks like an abbreviation (short and all caps or no vowels)
            if (value.Length <= 4 && (value.All(char.IsUpper) || !ContainsVowel(value)))
            {
                abbreviations.Add(value);
            }
        }

        return abbreviations;
    }

    private static bool ContainsVowel(string s)
    {
        return s.Any(c => "aeiouAEIOU".Contains(c));
    }
}
