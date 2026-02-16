using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Memory.Detectors;

/// <summary>
/// Detects static collections that have Add operations but no Remove/Clear operations,
/// which can lead to unbounded memory growth over the application lifetime.
/// </summary>
public class StaticCollectionDetector : IMemoryLeakDetector
{
    public string Category => "StaticGrowth";

    private static readonly HashSet<string> CollectionTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "List", "HashSet", "Dictionary", "SortedSet", "SortedList", "SortedDictionary",
        "LinkedList", "Queue", "Stack", "ConcurrentDictionary", "ConcurrentQueue",
        "ConcurrentStack", "ConcurrentBag", "BlockingCollection", "ObservableCollection",
        "Collection", "ArrayList", "Hashtable"
    };

    private static readonly HashSet<string> AddMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "Add", "AddRange", "Insert", "InsertRange", "Enqueue", "Push",
        "TryAdd", "AddOrUpdate", "GetOrAdd", "Set"
    };

    private static readonly HashSet<string> RemoveMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "Remove", "RemoveAt", "RemoveRange", "RemoveAll", "Clear",
        "Dequeue", "Pop", "TryRemove", "TryDequeue", "TryPop",
        "TryTake", "Take"
    };

    public Task<List<MemoryLeak>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context)
    {
        var leaks = new List<MemoryLeak>();
        var filePath = document.FilePath ?? "";

        // Find all static collection fields
        var staticCollections = FindStaticCollections(root, semanticModel);

        foreach (var collection in staticCollections)
        {
            var operations = AnalyzeCollectionOperations(collection, root, semanticModel);

            // Check for unbounded growth pattern
            if (operations.AddOperations > 0 && operations.RemoveOperations == 0)
            {
                if (!operations.HasSizeLimit && !operations.UsesWeakReferences)
                {
                    var lineSpan = collection.Location.GetLineSpan();
                    var severity = DetermineSeverity(operations.AddOperations);

                    leaks.Add(new MemoryLeak
                    {
                        LeakType = Category,
                        Severity = severity,
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = $"Static collection '{collection.Name}' has {operations.AddOperations} Add operation(s) " +
                                     $"but no Remove/Clear operations. This can cause unbounded memory growth.",
                        Recommendation = "Add a mechanism to limit the collection size, use weak references, " +
                                        "or implement a cleanup strategy.",
                        ProblematicCode = collection.DeclarationCode,
                        SuggestedFix = GenerateSuggestedFix(collection),
                        Confidence = operations.AddOperations > 1 ? "High" : "Medium",
                        CweId = "CWE-401",
                        IsInHotPath = operations.AddInLoop,
                        Details = new List<string>
                        {
                            $"Collection type: {collection.CollectionType}",
                            $"Add operations: {operations.AddOperations}",
                            $"Remove operations: {operations.RemoveOperations}",
                            $"Add in loop: {operations.AddInLoop}",
                            operations.HasSizeLimit ? "Has size limit check" : "No size limit detected"
                        }
                    });
                }
            }
        }

        return Task.FromResult(leaks);
    }

    private record StaticCollectionField(
        string Name,
        string CollectionType,
        string ElementType,
        Location Location,
        string DeclarationCode,
        ISymbol Symbol);

    private List<StaticCollectionField> FindStaticCollections(SyntaxNode root, SemanticModel semanticModel)
    {
        var collections = new List<StaticCollectionField>();

        // Check static fields
        foreach (var field in root.DescendantNodes().OfType<FieldDeclarationSyntax>())
        {
            if (!field.Modifiers.Any(SyntaxKind.StaticKeyword))
                continue;

            foreach (var variable in field.Declaration.Variables)
            {
                var symbol = semanticModel.GetDeclaredSymbol(variable) as IFieldSymbol;
                if (symbol == null)
                    continue;

                if (IsCollectionType(symbol.Type))
                {
                    var elementType = GetElementType(symbol.Type);
                    collections.Add(new StaticCollectionField(
                        Name: variable.Identifier.Text,
                        CollectionType: symbol.Type.Name,
                        ElementType: elementType,
                        Location: variable.GetLocation(),
                        DeclarationCode: field.ToString().Trim(),
                        Symbol: symbol
                    ));
                }
            }
        }

        // Check static properties with backing collections
        foreach (var property in root.DescendantNodes().OfType<PropertyDeclarationSyntax>())
        {
            if (!property.Modifiers.Any(SyntaxKind.StaticKeyword))
                continue;

            var symbol = semanticModel.GetDeclaredSymbol(property) as IPropertySymbol;
            if (symbol == null)
                continue;

            if (IsCollectionType(symbol.Type))
            {
                var elementType = GetElementType(symbol.Type);
                collections.Add(new StaticCollectionField(
                    Name: property.Identifier.Text,
                    CollectionType: symbol.Type.Name,
                    ElementType: elementType,
                    Location: property.GetLocation(),
                    DeclarationCode: TruncateCode(property.ToString()),
                    Symbol: symbol
                ));
            }
        }

        return collections;
    }

    private bool IsCollectionType(ITypeSymbol type)
    {
        // Check if the type is a known collection type
        if (CollectionTypes.Contains(type.Name))
            return true;

        // Check if it implements ICollection<T> or ICollection
        return type.AllInterfaces.Any(i =>
            i.Name is "ICollection" or "IList" or "IDictionary" ||
            (i.IsGenericType && i.OriginalDefinition.Name is "ICollection" or "IList" or "IDictionary"));
    }

    private string GetElementType(ITypeSymbol type)
    {
        if (type is INamedTypeSymbol namedType && namedType.IsGenericType)
        {
            var typeArgs = namedType.TypeArguments;
            if (typeArgs.Length == 1)
                return typeArgs[0].ToDisplayString();
            if (typeArgs.Length == 2)
                return $"{typeArgs[0].ToDisplayString()}, {typeArgs[1].ToDisplayString()}";
        }
        return "object";
    }

    private StaticCollectionInfo AnalyzeCollectionOperations(
        StaticCollectionField collection,
        SyntaxNode root,
        SemanticModel semanticModel)
    {
        var addCount = 0;
        var removeCount = 0;
        var addInLoop = false;
        var hasSizeLimit = false;
        var usesWeakReferences = false;

        // Find all member access expressions that reference this collection
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess)
                continue;

            // Check if it's accessing our collection
            var targetSymbol = semanticModel.GetSymbolInfo(memberAccess.Expression).Symbol;
            if (!SymbolEqualityComparer.Default.Equals(targetSymbol, collection.Symbol))
                continue;

            var methodName = memberAccess.Name.Identifier.Text;

            if (AddMethods.Contains(methodName))
            {
                addCount++;
                addInLoop = IsInLoop(invocation);
            }
            else if (RemoveMethods.Contains(methodName))
            {
                removeCount++;
            }
        }

        // Check for indexer assignments (dictionary[key] = value)
        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is ElementAccessExpressionSyntax elementAccess)
            {
                var targetSymbol = semanticModel.GetSymbolInfo(elementAccess.Expression).Symbol;
                if (SymbolEqualityComparer.Default.Equals(targetSymbol, collection.Symbol))
                {
                    addCount++;
                    addInLoop = addInLoop || IsInLoop(assignment);
                }
            }
        }

        // Check for size limiting patterns
        hasSizeLimit = HasSizeLimitingPattern(collection, root, semanticModel);

        // Check for weak references in collection type
        usesWeakReferences = collection.ElementType.Contains("WeakReference") ||
                            collection.CollectionType.Contains("Weak");

        return new StaticCollectionInfo
        {
            Name = collection.Name,
            CollectionType = collection.CollectionType,
            AddOperations = addCount,
            RemoveOperations = removeCount,
            HasSizeLimit = hasSizeLimit,
            UsesWeakReferences = usesWeakReferences
        };
    }

    private bool IsInLoop(SyntaxNode node)
    {
        return node.Ancestors().Any(a =>
            a is ForStatementSyntax or
                ForEachStatementSyntax or
                WhileStatementSyntax or
                DoStatementSyntax);
    }

    private bool HasSizeLimitingPattern(
        StaticCollectionField collection,
        SyntaxNode root,
        SemanticModel semanticModel)
    {
        // Look for patterns like: if (collection.Count > limit) collection.Remove...
        foreach (var ifStatement in root.DescendantNodes().OfType<IfStatementSyntax>())
        {
            var condition = ifStatement.Condition.ToString();
            if (condition.Contains(collection.Name) &&
                (condition.Contains("Count") || condition.Contains("Length")) &&
                (condition.Contains(">") || condition.Contains(">=")))
            {
                // Check if the body contains a remove operation
                var body = ifStatement.Statement.ToString();
                if (RemoveMethods.Any(m => body.Contains(m)))
                    return true;
            }
        }

        // Look for LRU cache patterns
        var typeString = collection.CollectionType.ToLower();
        if (typeString.Contains("lru") || typeString.Contains("cache"))
            return true;

        return false;
    }

    private string DetermineSeverity(int addOperations)
    {
        if (addOperations > 5)
            return "Critical";
        if (addOperations > 2)
            return "High";
        if (addOperations > 1)
            return "Medium";
        return "Low";
    }

    private string TruncateCode(string code)
    {
        var lines = code.Split('\n');
        if (lines.Length > 3)
        {
            return string.Join("\n", lines.Take(3)) + "\n// ...";
        }
        return code.Length > 150 ? code.Substring(0, 150) + "..." : code;
    }

    private string GenerateSuggestedFix(StaticCollectionField collection)
    {
        return $@"// Option 1: Use a bounded collection with automatic eviction
private static readonly MemoryCache<{collection.ElementType}> {collection.Name} =
    new MemoryCache<{collection.ElementType}>(new MemoryCacheOptions
    {{
        SizeLimit = 1000,
        ExpirationScanFrequency = TimeSpan.FromMinutes(5)
    }});

// Option 2: Use weak references
private static readonly ConditionalWeakTable<Key, Value> {collection.Name} = new();

// Option 3: Implement manual size limiting
private const int MaxSize = 1000;
public static void Add(TItem item)
{{
    lock ({collection.Name})
    {{
        if ({collection.Name}.Count >= MaxSize)
        {{
            // Remove oldest items
            {collection.Name}.RemoveAt(0);
        }}
        {collection.Name}.Add(item);
    }}
}}

// Option 4: Implement periodic cleanup
private static readonly Timer _cleanupTimer = new(CleanupCallback, null,
    TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));

private static void CleanupCallback(object? state)
{{
    lock ({collection.Name})
    {{
        // Remove stale items
        {collection.Name}.RemoveAll(item => IsStale(item));
    }}
}}";
    }
}
