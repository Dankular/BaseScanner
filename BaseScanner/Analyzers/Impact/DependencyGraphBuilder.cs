using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Impact.Models;
using ImpactSymbolKind = BaseScanner.Analyzers.Impact.Models.SymbolKind;

namespace BaseScanner.Analyzers.Impact;

/// <summary>
/// Builds a comprehensive dependency graph from a Roslyn project or solution.
/// Tracks all types of dependencies: calls, type usage, inheritance, field access, and events.
/// </summary>
public class DependencyGraphBuilder
{
    private readonly ImpactAnalysisOptions _options;
    private readonly Dictionary<string, DependencyNode> _nodes = new();
    private readonly Dictionary<string, List<DependencyEdge>> _outgoingEdges = new();
    private readonly Dictionary<string, List<DependencyEdge>> _incomingEdges = new();

    public DependencyGraphBuilder(ImpactAnalysisOptions? options = null)
    {
        _options = options ?? new ImpactAnalysisOptions();
    }

    /// <summary>
    /// Builds a dependency graph from a project.
    /// </summary>
    public async Task<DependencyGraph> BuildFromProjectAsync(Project project)
    {
        _nodes.Clear();
        _outgoingEdges.Clear();
        _incomingEdges.Clear();

        // First pass: collect all symbols (nodes)
        foreach (var document in project.Documents)
        {
            if (ShouldExcludeDocument(document)) continue;
            await CollectSymbolsAsync(document);
        }

        // Second pass: collect all dependencies (edges)
        foreach (var document in project.Documents)
        {
            if (ShouldExcludeDocument(document)) continue;
            await CollectDependenciesAsync(document);
        }

        return BuildGraph(project.FilePath ?? project.Name);
    }

    /// <summary>
    /// Builds a dependency graph from a solution.
    /// </summary>
    public async Task<DependencyGraph> BuildFromSolutionAsync(Solution solution)
    {
        _nodes.Clear();
        _outgoingEdges.Clear();
        _incomingEdges.Clear();

        foreach (var project in solution.Projects)
        {
            if (ShouldExcludeProject(project)) continue;

            foreach (var document in project.Documents)
            {
                if (ShouldExcludeDocument(document)) continue;
                await CollectSymbolsAsync(document);
            }
        }

        foreach (var project in solution.Projects)
        {
            if (ShouldExcludeProject(project)) continue;

            foreach (var document in project.Documents)
            {
                if (ShouldExcludeDocument(document)) continue;
                await CollectDependenciesAsync(document);
            }
        }

        return BuildGraph(solution.FilePath ?? "Solution");
    }

    /// <summary>
    /// Gets statistics about the built graph.
    /// </summary>
    public DependencyGraphStats GetStats(DependencyGraph graph)
    {
        var edgesByType = graph.OutgoingEdges.Values
            .SelectMany(e => e)
            .GroupBy(e => e.Type)
            .ToDictionary(g => g.Key, g => g.Count());

        var incomingCounts = graph.IncomingEdges
            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Count);

        var outgoingCounts = graph.OutgoingEdges
            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Count);

        var mostDependedUpon = incomingCounts.Count > 0
            ? incomingCounts.MaxBy(kvp => kvp.Value)
            : default;

        var mostDependent = outgoingCounts.Count > 0
            ? outgoingCounts.MaxBy(kvp => kvp.Value)
            : default;

        return new DependencyGraphStats
        {
            TypeCount = graph.Nodes.Values.Count(n => n.Kind == ImpactSymbolKind.Type),
            MethodCount = graph.Nodes.Values.Count(n => n.Kind == ImpactSymbolKind.Method),
            PropertyCount = graph.Nodes.Values.Count(n => n.Kind == ImpactSymbolKind.Property),
            FieldCount = graph.Nodes.Values.Count(n => n.Kind == ImpactSymbolKind.Field),
            EventCount = graph.Nodes.Values.Count(n => n.Kind == ImpactSymbolKind.Event),
            EdgeCount = graph.EdgeCount,
            EdgesByType = edgesByType,
            AverageDependencies = graph.NodeCount > 0
                ? (double)graph.EdgeCount / graph.NodeCount
                : 0,
            MaxIncomingDependencies = incomingCounts.Count > 0 ? incomingCounts.Values.Max() : 0,
            MostDependedUponSymbol = mostDependedUpon.Key,
            MaxOutgoingDependencies = outgoingCounts.Count > 0 ? outgoingCounts.Values.Max() : 0,
            MostDependentSymbol = mostDependent.Key
        };
    }

    private bool ShouldExcludeDocument(Document document)
    {
        if (document.FilePath == null) return true;

        foreach (var pattern in _options.ExcludePatterns)
        {
            if (document.FilePath.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private bool ShouldExcludeProject(Project project)
    {
        if (!_options.IncludeTestProjects)
        {
            var name = project.Name.ToLowerInvariant();
            if (name.Contains("test") || name.Contains("spec"))
                return true;
        }

        return false;
    }

    private async Task CollectSymbolsAsync(Document document)
    {
        var syntaxRoot = await document.GetSyntaxRootAsync();
        var semanticModel = await document.GetSemanticModelAsync();
        if (syntaxRoot == null || semanticModel == null) return;

        var filePath = document.FilePath ?? "";

        // Collect types
        foreach (var typeDecl in syntaxRoot.DescendantNodes().OfType<TypeDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(typeDecl);
            if (symbol == null) continue;

            var node = CreateNode(symbol, filePath, typeDecl.GetLocation());
            _nodes[node.FullyQualifiedName] = node;

            // Collect members
            CollectTypeMembers(typeDecl, semanticModel, symbol.ToDisplayString(), filePath);
        }

        // Collect delegates
        foreach (var delegateDecl in syntaxRoot.DescendantNodes().OfType<DelegateDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(delegateDecl);
            if (symbol == null) continue;

            var node = CreateNode(symbol, filePath, delegateDecl.GetLocation());
            _nodes[node.FullyQualifiedName] = node;
        }

        // Collect enums
        foreach (var enumDecl in syntaxRoot.DescendantNodes().OfType<EnumDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(enumDecl);
            if (symbol == null) continue;

            var node = CreateNode(symbol, filePath, enumDecl.GetLocation());
            _nodes[node.FullyQualifiedName] = node;
        }
    }

    private void CollectTypeMembers(TypeDeclarationSyntax typeDecl, SemanticModel semanticModel,
        string containingType, string filePath)
    {
        // Methods
        foreach (var method in typeDecl.Members.OfType<MethodDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(method);
            if (symbol == null) continue;

            var node = CreateNode(symbol, filePath, method.GetLocation(), containingType);
            _nodes[node.FullyQualifiedName] = node;
        }

        // Constructors
        foreach (var ctor in typeDecl.Members.OfType<ConstructorDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(ctor);
            if (symbol == null) continue;

            var node = CreateNode(symbol, filePath, ctor.GetLocation(), containingType);
            _nodes[node.FullyQualifiedName] = node;
        }

        // Properties
        foreach (var prop in typeDecl.Members.OfType<PropertyDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(prop);
            if (symbol == null) continue;

            var node = CreateNode(symbol, filePath, prop.GetLocation(), containingType);
            _nodes[node.FullyQualifiedName] = node;
        }

        // Fields
        foreach (var field in typeDecl.Members.OfType<FieldDeclarationSyntax>())
        {
            foreach (var variable in field.Declaration.Variables)
            {
                var symbol = semanticModel.GetDeclaredSymbol(variable);
                if (symbol == null) continue;

                var node = CreateNode(symbol, filePath, variable.GetLocation(), containingType);
                _nodes[node.FullyQualifiedName] = node;
            }
        }

        // Events
        foreach (var eventDecl in typeDecl.Members.OfType<EventDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(eventDecl);
            if (symbol == null) continue;

            var node = CreateNode(symbol, filePath, eventDecl.GetLocation(), containingType);
            _nodes[node.FullyQualifiedName] = node;
        }

        foreach (var eventField in typeDecl.Members.OfType<EventFieldDeclarationSyntax>())
        {
            foreach (var variable in eventField.Declaration.Variables)
            {
                var symbol = semanticModel.GetDeclaredSymbol(variable);
                if (symbol == null) continue;

                var node = CreateNode(symbol, filePath, variable.GetLocation(), containingType);
                _nodes[node.FullyQualifiedName] = node;
            }
        }

        // Indexers
        foreach (var indexer in typeDecl.Members.OfType<IndexerDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(indexer);
            if (symbol == null) continue;

            var node = CreateNode(symbol, filePath, indexer.GetLocation(), containingType);
            _nodes[node.FullyQualifiedName] = node;
        }

        // Operators
        foreach (var op in typeDecl.Members.OfType<OperatorDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(op);
            if (symbol == null) continue;

            var node = CreateNode(symbol, filePath, op.GetLocation(), containingType);
            _nodes[node.FullyQualifiedName] = node;
        }

        // Nested types
        foreach (var nestedType in typeDecl.Members.OfType<TypeDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(nestedType);
            if (symbol == null) continue;

            var node = CreateNode(symbol, filePath, nestedType.GetLocation(), containingType);
            _nodes[node.FullyQualifiedName] = node;

            CollectTypeMembers(nestedType, semanticModel, node.FullyQualifiedName, filePath);
        }
    }

    private async Task CollectDependenciesAsync(Document document)
    {
        var syntaxRoot = await document.GetSyntaxRootAsync();
        var semanticModel = await document.GetSemanticModelAsync();
        if (syntaxRoot == null || semanticModel == null) return;

        var filePath = document.FilePath ?? "";

        foreach (var typeDecl in syntaxRoot.DescendantNodes().OfType<TypeDeclarationSyntax>())
        {
            var typeSymbol = semanticModel.GetDeclaredSymbol(typeDecl);
            if (typeSymbol == null) continue;

            var sourceKey = typeSymbol.ToDisplayString();

            // Inheritance dependencies
            if (_options.DependencyTypes.Contains(DependencyType.Inheritance))
            {
                CollectInheritanceDependencies(typeDecl, semanticModel, sourceKey, filePath);
            }

            // Collect dependencies from members
            CollectMemberDependencies(typeDecl, semanticModel, filePath);
        }
    }

    private void CollectInheritanceDependencies(TypeDeclarationSyntax typeDecl, SemanticModel semanticModel,
        string sourceKey, string filePath)
    {
        if (typeDecl.BaseList == null) return;

        foreach (var baseType in typeDecl.BaseList.Types)
        {
            var typeInfo = semanticModel.GetTypeInfo(baseType.Type);
            if (typeInfo.Type is INamedTypeSymbol namedType && !namedType.IsImplicitlyDeclared)
            {
                var targetKey = namedType.ToDisplayString();
                var line = baseType.GetLocation().GetLineSpan().StartLinePosition.Line + 1;

                var dependencyType = namedType.TypeKind == TypeKind.Interface
                    ? DependencyType.InterfaceImplementation
                    : DependencyType.Inheritance;

                AddEdge(sourceKey, targetKey, dependencyType, filePath, line);
            }
        }
    }

    private void CollectMemberDependencies(TypeDeclarationSyntax typeDecl, SemanticModel semanticModel,
        string filePath)
    {
        // Process methods
        foreach (var method in typeDecl.Members.OfType<MethodDeclarationSyntax>())
        {
            var methodSymbol = semanticModel.GetDeclaredSymbol(method);
            if (methodSymbol == null) continue;

            var sourceKey = methodSymbol.ToDisplayString();

            // Check for override
            if (methodSymbol.IsOverride && methodSymbol.OverriddenMethod != null)
            {
                var targetKey = methodSymbol.OverriddenMethod.ToDisplayString();
                var line = method.Identifier.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                AddEdge(sourceKey, targetKey, DependencyType.Override, filePath, line);
            }

            // Collect dependencies within method body
            if (method.Body != null)
            {
                CollectBlockDependencies(method.Body, semanticModel, sourceKey, filePath);
            }
            else if (method.ExpressionBody != null)
            {
                CollectExpressionDependencies(method.ExpressionBody.Expression, semanticModel, sourceKey, filePath);
            }

            // Collect type usage from parameters and return type
            CollectTypeUsageDependencies(method.ReturnType, semanticModel, sourceKey, filePath);
            foreach (var param in method.ParameterList.Parameters)
            {
                if (param.Type != null)
                {
                    CollectTypeUsageDependencies(param.Type, semanticModel, sourceKey, filePath);
                }
            }
        }

        // Process constructors
        foreach (var ctor in typeDecl.Members.OfType<ConstructorDeclarationSyntax>())
        {
            var ctorSymbol = semanticModel.GetDeclaredSymbol(ctor);
            if (ctorSymbol == null) continue;

            var sourceKey = ctorSymbol.ToDisplayString();

            if (ctor.Body != null)
            {
                CollectBlockDependencies(ctor.Body, semanticModel, sourceKey, filePath);
            }
            else if (ctor.ExpressionBody != null)
            {
                CollectExpressionDependencies(ctor.ExpressionBody.Expression, semanticModel, sourceKey, filePath);
            }

            // Constructor initializer
            if (ctor.Initializer != null)
            {
                var initSymbol = semanticModel.GetSymbolInfo(ctor.Initializer).Symbol;
                if (initSymbol != null)
                {
                    var targetKey = initSymbol.ToDisplayString();
                    var line = ctor.Initializer.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    AddEdge(sourceKey, targetKey, DependencyType.DirectCall, filePath, line);
                }
            }
        }

        // Process properties
        foreach (var prop in typeDecl.Members.OfType<PropertyDeclarationSyntax>())
        {
            var propSymbol = semanticModel.GetDeclaredSymbol(prop);
            if (propSymbol == null) continue;

            var sourceKey = propSymbol.ToDisplayString();

            // Type usage
            CollectTypeUsageDependencies(prop.Type, semanticModel, sourceKey, filePath);

            // Accessors
            if (prop.AccessorList != null)
            {
                foreach (var accessor in prop.AccessorList.Accessors)
                {
                    if (accessor.Body != null)
                    {
                        CollectBlockDependencies(accessor.Body, semanticModel, sourceKey, filePath);
                    }
                    else if (accessor.ExpressionBody != null)
                    {
                        CollectExpressionDependencies(accessor.ExpressionBody.Expression, semanticModel, sourceKey, filePath);
                    }
                }
            }
            else if (prop.ExpressionBody != null)
            {
                CollectExpressionDependencies(prop.ExpressionBody.Expression, semanticModel, sourceKey, filePath);
            }
        }

        // Process fields
        foreach (var field in typeDecl.Members.OfType<FieldDeclarationSyntax>())
        {
            CollectTypeUsageDependencies(field.Declaration.Type, semanticModel,
                semanticModel.GetDeclaredSymbol(typeDecl)?.ToDisplayString() ?? "", filePath);

            foreach (var variable in field.Declaration.Variables)
            {
                var fieldSymbol = semanticModel.GetDeclaredSymbol(variable);
                if (fieldSymbol == null) continue;

                var sourceKey = fieldSymbol.ToDisplayString();

                if (variable.Initializer != null)
                {
                    CollectExpressionDependencies(variable.Initializer.Value, semanticModel, sourceKey, filePath);
                }
            }
        }
    }

    private void CollectBlockDependencies(BlockSyntax block, SemanticModel semanticModel,
        string sourceKey, string filePath)
    {
        // Method invocations (DirectCall)
        if (_options.DependencyTypes.Contains(DependencyType.DirectCall))
        {
            foreach (var invocation in block.DescendantNodes().OfType<InvocationExpressionSyntax>())
            {
                var symbol = semanticModel.GetSymbolInfo(invocation).Symbol;
                if (symbol is IMethodSymbol methodSymbol && !methodSymbol.IsImplicitlyDeclared)
                {
                    var targetKey = methodSymbol.ToDisplayString();
                    var line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    AddEdge(sourceKey, targetKey, DependencyType.DirectCall, filePath, line);
                }
            }
        }

        // Object creations (TypeUsage)
        if (_options.DependencyTypes.Contains(DependencyType.TypeUsage))
        {
            foreach (var creation in block.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
            {
                var typeInfo = semanticModel.GetTypeInfo(creation);
                if (typeInfo.Type is INamedTypeSymbol namedType && !namedType.IsImplicitlyDeclared)
                {
                    var targetKey = namedType.ToDisplayString();
                    var line = creation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    AddEdge(sourceKey, targetKey, DependencyType.TypeUsage, filePath, line);
                }

                // Also track constructor call
                var ctorSymbol = semanticModel.GetSymbolInfo(creation).Symbol;
                if (ctorSymbol != null)
                {
                    var ctorKey = ctorSymbol.ToDisplayString();
                    var line = creation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    AddEdge(sourceKey, ctorKey, DependencyType.DirectCall, filePath, line);
                }
            }
        }

        // Field accesses
        if (_options.DependencyTypes.Contains(DependencyType.FieldAccess))
        {
            foreach (var memberAccess in block.DescendantNodes().OfType<MemberAccessExpressionSyntax>())
            {
                var symbol = semanticModel.GetSymbolInfo(memberAccess).Symbol;
                if (symbol is IFieldSymbol fieldSymbol && !fieldSymbol.IsImplicitlyDeclared)
                {
                    var targetKey = fieldSymbol.ToDisplayString();
                    var line = memberAccess.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    AddEdge(sourceKey, targetKey, DependencyType.FieldAccess, filePath, line);
                }
            }
        }

        // Property accesses
        if (_options.DependencyTypes.Contains(DependencyType.PropertyAccess))
        {
            foreach (var memberAccess in block.DescendantNodes().OfType<MemberAccessExpressionSyntax>())
            {
                var symbol = semanticModel.GetSymbolInfo(memberAccess).Symbol;
                if (symbol is IPropertySymbol propertySymbol && !propertySymbol.IsImplicitlyDeclared)
                {
                    var targetKey = propertySymbol.ToDisplayString();
                    var line = memberAccess.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    AddEdge(sourceKey, targetKey, DependencyType.PropertyAccess, filePath, line);
                }
            }
        }

        // Event subscriptions
        if (_options.DependencyTypes.Contains(DependencyType.EventSubscription))
        {
            foreach (var assignment in block.DescendantNodes().OfType<AssignmentExpressionSyntax>())
            {
                if (assignment.IsKind(SyntaxKind.AddAssignmentExpression) ||
                    assignment.IsKind(SyntaxKind.SubtractAssignmentExpression))
                {
                    var symbol = semanticModel.GetSymbolInfo(assignment.Left).Symbol;
                    if (symbol is IEventSymbol eventSymbol)
                    {
                        var targetKey = eventSymbol.ToDisplayString();
                        var line = assignment.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                        AddEdge(sourceKey, targetKey, DependencyType.EventSubscription, filePath, line);
                    }
                }
            }
        }
    }

    private void CollectExpressionDependencies(ExpressionSyntax expression, SemanticModel semanticModel,
        string sourceKey, string filePath)
    {
        // Method invocations
        if (_options.DependencyTypes.Contains(DependencyType.DirectCall))
        {
            foreach (var invocation in expression.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>())
            {
                var symbol = semanticModel.GetSymbolInfo(invocation).Symbol;
                if (symbol is IMethodSymbol methodSymbol && !methodSymbol.IsImplicitlyDeclared)
                {
                    var targetKey = methodSymbol.ToDisplayString();
                    var line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                    AddEdge(sourceKey, targetKey, DependencyType.DirectCall, filePath, line);
                }
            }
        }

        // Member accesses
        foreach (var memberAccess in expression.DescendantNodesAndSelf().OfType<MemberAccessExpressionSyntax>())
        {
            var symbol = semanticModel.GetSymbolInfo(memberAccess).Symbol;

            if (_options.DependencyTypes.Contains(DependencyType.FieldAccess) && symbol is IFieldSymbol fieldSymbol)
            {
                var targetKey = fieldSymbol.ToDisplayString();
                var line = memberAccess.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                AddEdge(sourceKey, targetKey, DependencyType.FieldAccess, filePath, line);
            }

            if (_options.DependencyTypes.Contains(DependencyType.PropertyAccess) && symbol is IPropertySymbol propSymbol)
            {
                var targetKey = propSymbol.ToDisplayString();
                var line = memberAccess.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
                AddEdge(sourceKey, targetKey, DependencyType.PropertyAccess, filePath, line);
            }
        }
    }

    private void CollectTypeUsageDependencies(TypeSyntax typeSyntax, SemanticModel semanticModel,
        string sourceKey, string filePath)
    {
        if (!_options.DependencyTypes.Contains(DependencyType.TypeUsage)) return;

        var typeInfo = semanticModel.GetTypeInfo(typeSyntax);
        AddTypeUsage(typeInfo.Type, sourceKey, filePath, typeSyntax.GetLocation());
    }

    private void AddTypeUsage(ITypeSymbol? type, string sourceKey, string filePath, Location location)
    {
        if (type == null) return;

        // Handle generic types
        if (type is INamedTypeSymbol namedType)
        {
            if (!namedType.IsImplicitlyDeclared && !IsSystemType(namedType))
            {
                var targetKey = namedType.ToDisplayString();
                var line = location.GetLineSpan().StartLinePosition.Line + 1;
                AddEdge(sourceKey, targetKey, DependencyType.TypeUsage, filePath, line);
            }

            // Process type arguments
            foreach (var typeArg in namedType.TypeArguments)
            {
                AddTypeUsage(typeArg, sourceKey, filePath, location);
            }
        }

        // Handle arrays
        if (type is IArrayTypeSymbol arrayType)
        {
            AddTypeUsage(arrayType.ElementType, sourceKey, filePath, location);
        }
    }

    private static bool IsSystemType(INamedTypeSymbol type)
    {
        var ns = type.ContainingNamespace?.ToDisplayString() ?? "";
        return ns.StartsWith("System") || ns.StartsWith("Microsoft");
    }

    private DependencyNode CreateNode(ISymbol symbol, string filePath, Location location,
        string? containingType = null)
    {
        var kind = symbol switch
        {
            INamedTypeSymbol => ImpactSymbolKind.Type,
            IMethodSymbol m => m.MethodKind == MethodKind.Constructor
                ? ImpactSymbolKind.Constructor
                : m.MethodKind == MethodKind.UserDefinedOperator
                    ? ImpactSymbolKind.Operator
                    : ImpactSymbolKind.Method,
            IPropertySymbol p => p.IsIndexer ? ImpactSymbolKind.Indexer : ImpactSymbolKind.Property,
            IFieldSymbol => ImpactSymbolKind.Field,
            IEventSymbol => ImpactSymbolKind.Event,
            _ => ImpactSymbolKind.Type
        };

        var accessibility = symbol.DeclaredAccessibility switch
        {
            Accessibility.Public => AccessibilityLevel.Public,
            Accessibility.Internal => AccessibilityLevel.Internal,
            Accessibility.Protected => AccessibilityLevel.Protected,
            Accessibility.ProtectedOrInternal => AccessibilityLevel.ProtectedInternal,
            Accessibility.Private => AccessibilityLevel.Private,
            Accessibility.ProtectedAndInternal => AccessibilityLevel.PrivateProtected,
            _ => AccessibilityLevel.Private
        };

        var isPublicApi = symbol.DeclaredAccessibility == Accessibility.Public ||
                          symbol.DeclaredAccessibility == Accessibility.Protected ||
                          symbol.DeclaredAccessibility == Accessibility.ProtectedOrInternal;

        var isCritical = _options.CriticalSymbols.Contains(symbol.ToDisplayString());

        return new DependencyNode
        {
            FullyQualifiedName = symbol.ToDisplayString(),
            Name = symbol.Name,
            Kind = kind,
            ContainingType = containingType,
            FilePath = filePath,
            Line = location.GetLineSpan().StartLinePosition.Line + 1,
            Accessibility = accessibility,
            IsPublicApi = isPublicApi,
            IsCritical = isCritical,
            CriticalityWeight = isCritical ? 5 : 1
        };
    }

    private void AddEdge(string source, string target, DependencyType type, string filePath, int line)
    {
        // Skip self-references
        if (source == target) return;

        // Skip edges to system types
        if (target.StartsWith("System.") || target.StartsWith("Microsoft.")) return;

        var edge = new DependencyEdge
        {
            Source = source,
            Target = target,
            Type = type,
            FilePath = filePath,
            Line = line
        };

        if (!_outgoingEdges.ContainsKey(source))
            _outgoingEdges[source] = new List<DependencyEdge>();

        // Avoid duplicate edges
        if (!_outgoingEdges[source].Any(e => e.Target == target && e.Type == type))
        {
            _outgoingEdges[source].Add(edge);

            if (!_incomingEdges.ContainsKey(target))
                _incomingEdges[target] = new List<DependencyEdge>();

            _incomingEdges[target].Add(edge);
        }
    }

    private DependencyGraph BuildGraph(string projectPath)
    {
        return new DependencyGraph
        {
            Nodes = _nodes.ToImmutableDictionary(),
            OutgoingEdges = _outgoingEdges
                .ToImmutableDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.ToImmutableList()),
            IncomingEdges = _incomingEdges
                .ToImmutableDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value.ToImmutableList()),
            ProjectPath = projectPath,
            BuiltAt = DateTime.UtcNow
        };
    }
}
