using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Memory.Detectors;

/// <summary>
/// Detects unbounded caches and dictionaries used for caching that lack:
/// - Size limits
/// - Expiration policies
/// - Weak references
/// </summary>
public class CacheLeakDetector : IMemoryLeakDetector
{
    public string Category => "CacheUnbounded";

    // Patterns that suggest caching intent
    private static readonly HashSet<string> CachePatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        "cache", "cached", "caching", "memo", "memoize", "memoized",
        "lookup", "registry", "store", "pool", "buffer", "index"
    };

    // Collection types commonly used for caching
    private static readonly HashSet<string> CacheableTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Dictionary", "ConcurrentDictionary", "SortedDictionary",
        "Hashtable", "SortedList", "HashSet", "SortedSet"
    };

    // Types that indicate proper cache management
    private static readonly HashSet<string> ProperCacheTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "MemoryCache", "IMemoryCache", "ObjectCache", "ConcurrentLru",
        "LazyCache", "CacheManager", "EasyCaching", "FusionCache",
        "WeakReference", "ConditionalWeakTable"
    };

    public Task<List<MemoryLeak>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context)
    {
        var leaks = new List<MemoryLeak>();
        var filePath = document.FilePath ?? "";

        // Find fields that look like caches
        var cacheFields = FindCacheFields(root, semanticModel);

        foreach (var cacheField in cacheFields)
        {
            var analysis = AnalyzeCacheUsage(cacheField, root, semanticModel);

            if (!analysis.HasSizeLimit &&
                !analysis.HasExpiration &&
                !analysis.UsesWeakReferences &&
                !analysis.HasEvictionPolicy)
            {
                var lineSpan = cacheField.Location.GetLineSpan();
                var severity = DetermineSeverity(cacheField, analysis);

                leaks.Add(new MemoryLeak
                {
                    LeakType = Category,
                    Severity = severity,
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = GenerateDescription(cacheField, analysis),
                    Recommendation = GenerateRecommendation(cacheField, analysis),
                    ProblematicCode = cacheField.DeclarationCode,
                    SuggestedFix = GenerateSuggestedFix(cacheField),
                    Confidence = cacheField.IsCacheByName ? "High" : "Medium",
                    CweId = "CWE-401",
                    IsInHotPath = analysis.AddInHotPath,
                    Details = BuildDetails(cacheField, analysis)
                });
            }
        }

        return Task.FromResult(leaks);
    }

    private record CacheFieldInfo(
        string Name,
        string TypeName,
        string KeyType,
        string ValueType,
        bool IsStatic,
        bool IsCacheByName,
        Location Location,
        string DeclarationCode,
        ISymbol Symbol);

    private record CacheAnalysis(
        int AddOperations,
        int RemoveOperations,
        bool HasSizeLimit,
        bool HasExpiration,
        bool UsesWeakReferences,
        bool HasEvictionPolicy,
        bool AddInHotPath,
        List<string> AddMethodLocations);

    private List<CacheFieldInfo> FindCacheFields(SyntaxNode root, SemanticModel semanticModel)
    {
        var caches = new List<CacheFieldInfo>();

        // Check fields
        foreach (var field in root.DescendantNodes().OfType<FieldDeclarationSyntax>())
        {
            foreach (var variable in field.Declaration.Variables)
            {
                var symbol = semanticModel.GetDeclaredSymbol(variable) as IFieldSymbol;
                if (symbol == null)
                    continue;

                if (IsCacheType(symbol.Type, out var keyType, out var valueType))
                {
                    var isCacheByName = IsCacheByNaming(variable.Identifier.Text);
                    var isStatic = field.Modifiers.Any(SyntaxKind.StaticKeyword);

                    // Skip if it's a proper cache implementation
                    if (IsProperCacheType(symbol.Type))
                        continue;

                    caches.Add(new CacheFieldInfo(
                        Name: variable.Identifier.Text,
                        TypeName: symbol.Type.Name,
                        KeyType: keyType,
                        ValueType: valueType,
                        IsStatic: isStatic,
                        IsCacheByName: isCacheByName,
                        Location: variable.GetLocation(),
                        DeclarationCode: field.ToString().Trim(),
                        Symbol: symbol
                    ));
                }
            }
        }

        // Check properties
        foreach (var property in root.DescendantNodes().OfType<PropertyDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(property) as IPropertySymbol;
            if (symbol == null)
                continue;

            if (IsCacheType(symbol.Type, out var keyType, out var valueType))
            {
                var isCacheByName = IsCacheByNaming(property.Identifier.Text);
                var isStatic = property.Modifiers.Any(SyntaxKind.StaticKeyword);

                if (IsProperCacheType(symbol.Type))
                    continue;

                caches.Add(new CacheFieldInfo(
                    Name: property.Identifier.Text,
                    TypeName: symbol.Type.Name,
                    KeyType: keyType,
                    ValueType: valueType,
                    IsStatic: isStatic,
                    IsCacheByName: isCacheByName,
                    Location: property.GetLocation(),
                    DeclarationCode: TruncateCode(property.ToString()),
                    Symbol: symbol
                ));
            }
        }

        return caches;
    }

    private bool IsCacheType(ITypeSymbol type, out string keyType, out string valueType)
    {
        keyType = "";
        valueType = "";

        if (type is INamedTypeSymbol namedType)
        {
            if (CacheableTypes.Contains(namedType.Name))
            {
                if (namedType.IsGenericType && namedType.TypeArguments.Length >= 1)
                {
                    keyType = namedType.TypeArguments[0].ToDisplayString();
                    if (namedType.TypeArguments.Length >= 2)
                        valueType = namedType.TypeArguments[1].ToDisplayString();
                }
                return true;
            }
        }

        return false;
    }

    private bool IsProperCacheType(ITypeSymbol type)
    {
        if (ProperCacheTypes.Contains(type.Name))
            return true;

        // Check if it implements proper cache interfaces
        return type.AllInterfaces.Any(i => ProperCacheTypes.Contains(i.Name));
    }

    private bool IsCacheByNaming(string name)
    {
        var lowerName = name.ToLower();
        return CachePatterns.Any(pattern => lowerName.Contains(pattern));
    }

    private CacheAnalysis AnalyzeCacheUsage(
        CacheFieldInfo cacheField,
        SyntaxNode root,
        SemanticModel semanticModel)
    {
        var addOperations = 0;
        var removeOperations = 0;
        var hasSizeLimit = false;
        var hasExpiration = false;
        var usesWeakReferences = false;
        var hasEvictionPolicy = false;
        var addInHotPath = false;
        var addLocations = new List<string>();

        // Analyze all invocations
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
                continue;

            var targetSymbol = semanticModel.GetSymbolInfo(memberAccess.Expression).Symbol;
            if (!SymbolEqualityComparer.Default.Equals(targetSymbol, cacheField.Symbol))
                continue;

            var methodName = memberAccess.Name.Identifier.Text;

            // Check for add operations
            if (IsAddMethod(methodName))
            {
                addOperations++;
                addInHotPath = addInHotPath || IsInLoop(invocation);
                var lineSpan = invocation.GetLocation().GetLineSpan();
                addLocations.Add($"Line {lineSpan.StartLinePosition.Line + 1}");
            }

            // Check for remove operations
            if (IsRemoveMethod(methodName))
            {
                removeOperations++;
            }

            // Check for size-limiting patterns
            if (methodName == "TryAdd" || methodName == "AddOrUpdate")
            {
                // Check if there's a size check before
                hasSizeLimit = hasSizeLimit || HasSizeCheckBefore(invocation, cacheField, root, semanticModel);
            }
        }

        // Check for indexer assignments (dict[key] = value)
        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is ElementAccessExpressionSyntax elementAccess)
            {
                var targetSymbol = semanticModel.GetSymbolInfo(elementAccess.Expression).Symbol;
                if (SymbolEqualityComparer.Default.Equals(targetSymbol, cacheField.Symbol))
                {
                    addOperations++;
                    addInHotPath = addInHotPath || IsInLoop(assignment);
                }
            }
        }

        // Check for expiration-related code
        hasExpiration = CheckForExpirationLogic(cacheField, root, semanticModel);

        // Check for weak reference usage
        usesWeakReferences = cacheField.ValueType.Contains("WeakReference") ||
                            cacheField.TypeName.Contains("Weak");

        // Check for eviction policy
        hasEvictionPolicy = CheckForEvictionPolicy(cacheField, root, semanticModel);

        return new CacheAnalysis(
            AddOperations: addOperations,
            RemoveOperations: removeOperations,
            HasSizeLimit: hasSizeLimit,
            HasExpiration: hasExpiration,
            UsesWeakReferences: usesWeakReferences,
            HasEvictionPolicy: hasEvictionPolicy,
            AddInHotPath: addInHotPath,
            AddMethodLocations: addLocations
        );
    }

    private bool IsAddMethod(string methodName)
    {
        return methodName is "Add" or "TryAdd" or "AddOrUpdate" or "GetOrAdd" or "Set";
    }

    private bool IsRemoveMethod(string methodName)
    {
        return methodName is "Remove" or "TryRemove" or "Clear";
    }

    private bool IsInLoop(SyntaxNode node)
    {
        return node.Ancestors().Any(a =>
            a is ForStatementSyntax or
                ForEachStatementSyntax or
                WhileStatementSyntax or
                DoStatementSyntax);
    }

    private bool HasSizeCheckBefore(
        InvocationExpressionSyntax invocation,
        CacheFieldInfo cacheField,
        SyntaxNode root,
        SemanticModel semanticModel)
    {
        // Look for if (cache.Count > limit) patterns before this invocation
        var containingBlock = invocation.Ancestors().OfType<BlockSyntax>().FirstOrDefault();
        if (containingBlock == null)
            return false;

        foreach (var ifStatement in containingBlock.DescendantNodes().OfType<IfStatementSyntax>())
        {
            var condition = ifStatement.Condition.ToString();
            if (condition.Contains(cacheField.Name) &&
                (condition.Contains("Count") || condition.Contains("Length")) &&
                (condition.Contains("<") || condition.Contains("<=")))
            {
                return true;
            }
        }

        return false;
    }

    private bool CheckForExpirationLogic(
        CacheFieldInfo cacheField,
        SyntaxNode root,
        SemanticModel semanticModel)
    {
        var sourceText = root.ToString().ToLower();

        // Check for common expiration patterns
        var expirationKeywords = new[] { "expire", "expiration", "ttl", "timeout", "lifetime", "stale" };
        var hasExpirationKeyword = expirationKeywords.Any(k => sourceText.Contains(k));

        if (!hasExpirationKeyword)
            return false;

        // Check if expiration logic is associated with this cache
        var cacheNameLower = cacheField.Name.ToLower();
        return sourceText.Contains(cacheNameLower) && hasExpirationKeyword;
    }

    private bool CheckForEvictionPolicy(
        CacheFieldInfo cacheField,
        SyntaxNode root,
        SemanticModel semanticModel)
    {
        var sourceText = root.ToString().ToLower();

        // Check for LRU, LFU, or other eviction patterns
        var evictionKeywords = new[] { "evict", "lru", "lfu", "fifo", "oldest", "priority" };
        return evictionKeywords.Any(k => sourceText.Contains(k));
    }

    private string DetermineSeverity(CacheFieldInfo cacheField, CacheAnalysis analysis)
    {
        // Critical: Static cache with adds in hot path and no cleanup
        if (cacheField.IsStatic && analysis.AddInHotPath && analysis.RemoveOperations == 0)
            return "Critical";

        // High: Static cache with many add operations
        if (cacheField.IsStatic && analysis.AddOperations > 3)
            return "High";

        // High: Cache by name with no cleanup
        if (cacheField.IsCacheByName && analysis.RemoveOperations == 0)
            return "High";

        // Medium: Instance cache with potential growth
        if (analysis.AddOperations > analysis.RemoveOperations)
            return "Medium";

        return "Low";
    }

    private string TruncateCode(string code)
    {
        var lines = code.Split('\n');
        if (lines.Length > 3)
            return string.Join("\n", lines.Take(3)) + "\n// ...";
        return code.Length > 150 ? code.Substring(0, 150) + "..." : code;
    }

    private string GenerateDescription(CacheFieldInfo cacheField, CacheAnalysis analysis)
    {
        var issues = new List<string>();

        if (!analysis.HasSizeLimit)
            issues.Add("no size limit");
        if (!analysis.HasExpiration)
            issues.Add("no expiration policy");
        if (!analysis.UsesWeakReferences)
            issues.Add("uses strong references");
        if (!analysis.HasEvictionPolicy)
            issues.Add("no eviction policy");

        var staticNote = cacheField.IsStatic ? "Static " : "";
        var issueList = string.Join(", ", issues);

        return $"{staticNote}cache '{cacheField.Name}' ({cacheField.TypeName}<{cacheField.KeyType}, {cacheField.ValueType}>) " +
               $"has {issueList}. Found {analysis.AddOperations} add operation(s) and {analysis.RemoveOperations} remove operation(s).";
    }

    private string GenerateRecommendation(CacheFieldInfo cacheField, CacheAnalysis analysis)
    {
        var recommendations = new List<string>();

        if (!analysis.HasSizeLimit)
            recommendations.Add("Add a maximum size limit");

        if (!analysis.HasExpiration)
            recommendations.Add("Implement time-based expiration");

        if (!analysis.UsesWeakReferences && !analysis.HasEvictionPolicy)
            recommendations.Add("Consider using weak references or an eviction policy");

        recommendations.Add("Consider using MemoryCache or a dedicated caching library");

        return string.Join(". ", recommendations) + ".";
    }

    private List<string> BuildDetails(CacheFieldInfo cacheField, CacheAnalysis analysis)
    {
        var details = new List<string>
        {
            $"Cache name: {cacheField.Name}",
            $"Type: {cacheField.TypeName}<{cacheField.KeyType}, {cacheField.ValueType}>",
            $"Is static: {cacheField.IsStatic}",
            $"Add operations: {analysis.AddOperations}",
            $"Remove operations: {analysis.RemoveOperations}",
            $"Has size limit: {analysis.HasSizeLimit}",
            $"Has expiration: {analysis.HasExpiration}",
            $"Uses weak references: {analysis.UsesWeakReferences}",
            $"Has eviction policy: {analysis.HasEvictionPolicy}",
            $"Adds in hot path: {analysis.AddInHotPath}"
        };

        if (analysis.AddMethodLocations.Count > 0)
            details.Add($"Add locations: {string.Join(", ", analysis.AddMethodLocations.Take(5))}");

        return details;
    }

    private string GenerateSuggestedFix(CacheFieldInfo cacheField)
    {
        return $@"// Option 1: Use MemoryCache with size limit and expiration
private static readonly MemoryCache _{cacheField.Name} = new(new MemoryCacheOptions
{{
    SizeLimit = 1000, // Maximum number of entries
    ExpirationScanFrequency = TimeSpan.FromMinutes(5)
}});

public {cacheField.ValueType}? Get({cacheField.KeyType} key)
{{
    return _{cacheField.Name}.Get<{cacheField.ValueType}>(key);
}}

public void Set({cacheField.KeyType} key, {cacheField.ValueType} value)
{{
    var options = new MemoryCacheEntryOptions
    {{
        Size = 1,
        AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30),
        SlidingExpiration = TimeSpan.FromMinutes(10)
    }};
    _{cacheField.Name}.Set(key, value, options);
}}

// Option 2: Use ConditionalWeakTable for automatic cleanup
private static readonly ConditionalWeakTable<{cacheField.KeyType}, {cacheField.ValueType}> _{cacheField.Name} = new();

// Option 3: Implement manual size limiting
private const int MaxCacheSize = 1000;
private static readonly Dictionary<{cacheField.KeyType}, {cacheField.ValueType}> _{cacheField.Name} = new();
private static readonly Queue<{cacheField.KeyType}> _cacheOrder = new();

public static void AddToCache({cacheField.KeyType} key, {cacheField.ValueType} value)
{{
    lock (_{cacheField.Name})
    {{
        // Evict oldest if at capacity
        while (_{cacheField.Name}.Count >= MaxCacheSize && _cacheOrder.Count > 0)
        {{
            var oldestKey = _cacheOrder.Dequeue();
            _{cacheField.Name}.Remove(oldestKey);
        }}

        _{cacheField.Name}[key] = value;
        _cacheOrder.Enqueue(key);
    }}
}}";
    }
}
