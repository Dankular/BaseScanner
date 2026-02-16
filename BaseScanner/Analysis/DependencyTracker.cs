using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analysis.Models;

namespace BaseScanner.Analysis;

/// <summary>
/// Tracks dependencies between files by analyzing symbol references.
/// Used to determine which files need re-analysis when a file changes.
/// </summary>
public class DependencyTracker
{
    private readonly Dictionary<string, HashSet<string>> _dependencies = [];
    private readonly Dictionary<string, HashSet<string>> _dependents = [];
    private readonly Dictionary<string, string> _typeToFile = [];
    private readonly Dictionary<string, List<SymbolDefinition>> _fileSymbols = [];
    private readonly Dictionary<string, List<SymbolReference>> _fileReferences = [];

    /// <summary>
    /// Builds a dependency graph from a Roslyn project.
    /// </summary>
    public async Task<DependencyGraph> BuildDependencyGraphAsync(Project project)
    {
        _dependencies.Clear();
        _dependents.Clear();
        _typeToFile.Clear();
        _fileSymbols.Clear();
        _fileReferences.Clear();

        var compilation = await project.GetCompilationAsync();
        if (compilation == null)
            return CreateGraph();

        // First pass: collect all type definitions and their file locations
        foreach (var document in project.Documents)
        {
            if (document.FilePath == null)
                continue;

            var syntaxTree = await document.GetSyntaxTreeAsync();
            if (syntaxTree == null)
                continue;

            var semanticModel = compilation.GetSemanticModel(syntaxTree);
            var root = await syntaxTree.GetRootAsync();
            var normalizedPath = NormalizePath(document.FilePath);

            CollectDefinitions(root, semanticModel, normalizedPath);
        }

        // Second pass: collect all type references
        foreach (var document in project.Documents)
        {
            if (document.FilePath == null)
                continue;

            var syntaxTree = await document.GetSyntaxTreeAsync();
            if (syntaxTree == null)
                continue;

            var semanticModel = compilation.GetSemanticModel(syntaxTree);
            var root = await syntaxTree.GetRootAsync();
            var normalizedPath = NormalizePath(document.FilePath);

            await CollectReferencesAsync(root, semanticModel, normalizedPath);
        }

        return CreateGraph();
    }

    /// <summary>
    /// Gets files that depend on the specified file (will need re-analysis if file changes).
    /// </summary>
    public List<string> GetDependents(string filePath)
    {
        var normalizedPath = NormalizePath(filePath);
        if (_dependents.TryGetValue(normalizedPath, out var deps))
            return deps.ToList();
        return [];
    }

    /// <summary>
    /// Gets files that the specified file depends on.
    /// </summary>
    public List<string> GetDependencies(string filePath)
    {
        var normalizedPath = NormalizePath(filePath);
        if (_dependencies.TryGetValue(normalizedPath, out var deps))
            return deps.ToList();
        return [];
    }

    /// <summary>
    /// Gets all files affected by changes to the specified files (transitive closure).
    /// </summary>
    public HashSet<string> GetAffectedFiles(IEnumerable<string> changedFiles)
    {
        var affected = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var toProcess = new Queue<string>(changedFiles.Select(NormalizePath));

        while (toProcess.Count > 0)
        {
            var file = toProcess.Dequeue();
            if (affected.Contains(file))
                continue;

            affected.Add(file);

            // Add all files that depend on this file
            if (_dependents.TryGetValue(file, out var deps))
            {
                foreach (var dep in deps)
                {
                    if (!affected.Contains(dep))
                        toProcess.Enqueue(dep);
                }
            }
        }

        return affected;
    }

    /// <summary>
    /// Gets symbol definitions for a file.
    /// </summary>
    public List<SymbolDefinition> GetDefinitions(string filePath)
    {
        var normalizedPath = NormalizePath(filePath);
        if (_fileSymbols.TryGetValue(normalizedPath, out var symbols))
            return symbols;
        return [];
    }

    /// <summary>
    /// Gets symbol references from a file.
    /// </summary>
    public List<SymbolReference> GetReferences(string filePath)
    {
        var normalizedPath = NormalizePath(filePath);
        if (_fileReferences.TryGetValue(normalizedPath, out var refs))
            return refs;
        return [];
    }

    /// <summary>
    /// Loads a dependency graph from cache.
    /// </summary>
    public void LoadFromGraph(DependencyGraph graph)
    {
        _dependencies.Clear();
        _dependents.Clear();
        _typeToFile.Clear();

        foreach (var kvp in graph.Dependencies)
        {
            _dependencies[kvp.Key] = new HashSet<string>(kvp.Value, StringComparer.OrdinalIgnoreCase);
        }

        foreach (var kvp in graph.Dependents)
        {
            _dependents[kvp.Key] = new HashSet<string>(kvp.Value, StringComparer.OrdinalIgnoreCase);
        }

        foreach (var kvp in graph.TypeToFile)
        {
            _typeToFile[kvp.Key] = kvp.Value;
        }
    }

    /// <summary>
    /// Updates the graph for a single file.
    /// </summary>
    public async Task UpdateFileAsync(Document document, SemanticModel semanticModel)
    {
        if (document.FilePath == null)
            return;

        var normalizedPath = NormalizePath(document.FilePath);
        var syntaxTree = await document.GetSyntaxTreeAsync();
        if (syntaxTree == null)
            return;

        var root = await syntaxTree.GetRootAsync();

        // Remove old entries for this file
        RemoveFile(normalizedPath);

        // Recollect definitions and references
        CollectDefinitions(root, semanticModel, normalizedPath);
        await CollectReferencesAsync(root, semanticModel, normalizedPath);
    }

    /// <summary>
    /// Removes a file from the dependency graph.
    /// </summary>
    public void RemoveFile(string filePath)
    {
        var normalizedPath = NormalizePath(filePath);

        // Remove from dependencies
        _dependencies.Remove(normalizedPath);

        // Remove from dependents lists
        foreach (var deps in _dependents.Values)
        {
            deps.Remove(normalizedPath);
        }

        // Remove as dependent
        _dependents.Remove(normalizedPath);

        // Remove type mappings for this file
        var typesToRemove = _typeToFile
            .Where(kvp => kvp.Value.Equals(normalizedPath, StringComparison.OrdinalIgnoreCase))
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var type in typesToRemove)
        {
            _typeToFile.Remove(type);
        }

        _fileSymbols.Remove(normalizedPath);
        _fileReferences.Remove(normalizedPath);
    }

    private void CollectDefinitions(SyntaxNode root, SemanticModel semanticModel, string filePath)
    {
        var definitions = new List<SymbolDefinition>();

        // Collect type declarations
        var typeDeclarations = root.DescendantNodes()
            .OfType<BaseTypeDeclarationSyntax>();

        foreach (var typeDecl in typeDeclarations)
        {
            var symbol = semanticModel.GetDeclaredSymbol(typeDecl);
            if (symbol == null)
                continue;

            var fullyQualifiedName = symbol.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);
            _typeToFile[fullyQualifiedName] = filePath;

            var lineSpan = typeDecl.GetLocation().GetLineSpan();
            definitions.Add(new SymbolDefinition
            {
                FullyQualifiedName = fullyQualifiedName,
                Kind = GetSymbolKind(typeDecl),
                Line = lineSpan.StartLinePosition.Line + 1,
                Accessibility = symbol.DeclaredAccessibility.ToString()
            });

            // Also collect members
            CollectMemberDefinitions(typeDecl, semanticModel, definitions);
        }

        _fileSymbols[filePath] = definitions;
    }

    private void CollectMemberDefinitions(
        BaseTypeDeclarationSyntax typeDecl,
        SemanticModel semanticModel,
        List<SymbolDefinition> definitions)
    {
        var members = typeDecl.DescendantNodes()
            .Where(n => n is MethodDeclarationSyntax or PropertyDeclarationSyntax or FieldDeclarationSyntax);

        foreach (var member in members)
        {
            ISymbol? symbol = member switch
            {
                MethodDeclarationSyntax method => semanticModel.GetDeclaredSymbol(method),
                PropertyDeclarationSyntax prop => semanticModel.GetDeclaredSymbol(prop),
                FieldDeclarationSyntax field => field.Declaration.Variables.FirstOrDefault() is { } variable
                    ? semanticModel.GetDeclaredSymbol(variable)
                    : null,
                _ => null
            };

            if (symbol == null)
                continue;

            var lineSpan = member.GetLocation().GetLineSpan();
            definitions.Add(new SymbolDefinition
            {
                FullyQualifiedName = symbol.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat),
                Kind = symbol.Kind.ToString(),
                Line = lineSpan.StartLinePosition.Line + 1,
                Accessibility = symbol.DeclaredAccessibility.ToString()
            });
        }
    }

    private async Task CollectReferencesAsync(SyntaxNode root, SemanticModel semanticModel, string filePath)
    {
        var references = new Dictionary<string, List<int>>();
        var symbolRefs = new List<SymbolReference>();

        // Collect all identifier references
        var identifiers = root.DescendantNodes()
            .OfType<IdentifierNameSyntax>()
            .ToList();

        foreach (var identifier in identifiers)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(identifier);
            var symbol = symbolInfo.Symbol;

            if (symbol == null)
                continue;

            // Get the containing type
            var containingType = symbol.ContainingType ?? symbol as INamedTypeSymbol;
            if (containingType == null)
                continue;

            var fullyQualifiedName = containingType.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

            // Find which file defines this type
            if (_typeToFile.TryGetValue(fullyQualifiedName, out var definingFile))
            {
                // Skip self-references
                if (definingFile.Equals(filePath, StringComparison.OrdinalIgnoreCase))
                    continue;

                // Add dependency
                if (!_dependencies.ContainsKey(filePath))
                    _dependencies[filePath] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                _dependencies[filePath].Add(definingFile);

                // Add reverse dependency (dependent)
                if (!_dependents.ContainsKey(definingFile))
                    _dependents[definingFile] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                _dependents[definingFile].Add(filePath);

                // Track reference location
                var lineSpan = identifier.GetLocation().GetLineSpan();
                var line = lineSpan.StartLinePosition.Line + 1;

                if (!references.ContainsKey(fullyQualifiedName))
                    references[fullyQualifiedName] = [];
                references[fullyQualifiedName].Add(line);
            }
        }

        // Also check type syntax nodes (for base types, generic arguments, etc.)
        var typeNodes = root.DescendantNodes()
            .OfType<TypeSyntax>()
            .ToList();

        foreach (var typeNode in typeNodes)
        {
            var typeInfo = semanticModel.GetTypeInfo(typeNode);
            var typeSymbol = typeInfo.Type as INamedTypeSymbol;

            if (typeSymbol == null)
                continue;

            var fullyQualifiedName = typeSymbol.ToDisplayString(SymbolDisplayFormat.FullyQualifiedFormat);

            if (_typeToFile.TryGetValue(fullyQualifiedName, out var definingFile))
            {
                if (definingFile.Equals(filePath, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!_dependencies.ContainsKey(filePath))
                    _dependencies[filePath] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                _dependencies[filePath].Add(definingFile);

                if (!_dependents.ContainsKey(definingFile))
                    _dependents[definingFile] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                _dependents[definingFile].Add(filePath);

                var lineSpan = typeNode.GetLocation().GetLineSpan();
                var line = lineSpan.StartLinePosition.Line + 1;

                if (!references.ContainsKey(fullyQualifiedName))
                    references[fullyQualifiedName] = [];
                references[fullyQualifiedName].Add(line);
            }
        }

        // Convert to SymbolReference list
        foreach (var kvp in references)
        {
            symbolRefs.Add(new SymbolReference
            {
                FullyQualifiedName = kvp.Key,
                Kind = "Type",
                ReferenceLines = kvp.Value.Distinct().OrderBy(x => x).ToList()
            });
        }

        _fileReferences[filePath] = symbolRefs;
    }

    private DependencyGraph CreateGraph()
    {
        return new DependencyGraph
        {
            Dependencies = _dependencies.ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value.ToList()),
            Dependents = _dependents.ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value.ToList()),
            TypeToFile = new Dictionary<string, string>(_typeToFile)
        };
    }

    private static string GetSymbolKind(BaseTypeDeclarationSyntax typeDecl)
    {
        return typeDecl switch
        {
            ClassDeclarationSyntax => "Class",
            InterfaceDeclarationSyntax => "Interface",
            StructDeclarationSyntax => "Struct",
            EnumDeclarationSyntax => "Enum",
            RecordDeclarationSyntax record => record.ClassOrStructKeyword.IsKind(SyntaxKind.StructKeyword)
                ? "RecordStruct"
                : "RecordClass",
            _ => "Type"
        };
    }

    private static string NormalizePath(string path)
    {
        return Path.GetFullPath(path).Replace('/', Path.DirectorySeparatorChar);
    }
}

/// <summary>
/// Extension methods for dependency tracking.
/// </summary>
public static class DependencyTrackerExtensions
{
    /// <summary>
    /// Gets a visualization of the dependency graph in DOT format.
    /// </summary>
    public static string ToDotFormat(this DependencyGraph graph, string projectDirectory)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("digraph Dependencies {");
        sb.AppendLine("    rankdir=LR;");
        sb.AppendLine("    node [shape=box];");

        foreach (var (file, deps) in graph.Dependencies)
        {
            var fromName = Path.GetFileName(file);
            foreach (var dep in deps)
            {
                var toName = Path.GetFileName(dep);
                sb.AppendLine($"    \"{fromName}\" -> \"{toName}\";");
            }
        }

        sb.AppendLine("}");
        return sb.ToString();
    }

    /// <summary>
    /// Finds circular dependencies in the graph.
    /// </summary>
    public static List<List<string>> FindCircularDependencies(this DependencyGraph graph)
    {
        var cycles = new List<List<string>>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var recursionStack = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var path = new List<string>();

        foreach (var file in graph.Dependencies.Keys)
        {
            if (!visited.Contains(file))
            {
                FindCyclesDfs(file, graph.Dependencies, visited, recursionStack, path, cycles);
            }
        }

        return cycles;
    }

    private static void FindCyclesDfs(
        string node,
        Dictionary<string, List<string>> dependencies,
        HashSet<string> visited,
        HashSet<string> recursionStack,
        List<string> path,
        List<List<string>> cycles)
    {
        visited.Add(node);
        recursionStack.Add(node);
        path.Add(node);

        if (dependencies.TryGetValue(node, out var deps))
        {
            foreach (var neighbor in deps)
            {
                if (!visited.Contains(neighbor))
                {
                    FindCyclesDfs(neighbor, dependencies, visited, recursionStack, path, cycles);
                }
                else if (recursionStack.Contains(neighbor))
                {
                    // Found a cycle
                    var cycleStart = path.IndexOf(neighbor);
                    var cycle = path.Skip(cycleStart).ToList();
                    cycle.Add(neighbor); // Close the cycle
                    cycles.Add(cycle);
                }
            }
        }

        path.RemoveAt(path.Count - 1);
        recursionStack.Remove(node);
    }
}
