using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers;
using BaseScanner.Analyzers.Security;
using BaseScanner.Server.Models;
using System.Collections.Concurrent;

namespace BaseScanner.Server;

/// <summary>
/// Provides real-time diagnostics for LSP integration.
/// Runs analyzers on document changes with debouncing to avoid excessive analysis.
/// </summary>
public class DiagnosticsProvider
{
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _pendingAnalyses = new();
    private readonly ConcurrentDictionary<string, DocumentState> _documentStates = new();
    private readonly LspServerOptions _options;
    private readonly object _projectLock = new();
    private Project? _currentProject;
    private Compilation? _currentCompilation;

    public DiagnosticsProvider(LspServerOptions options)
    {
        _options = options;
    }

    /// <summary>
    /// Event raised when diagnostics are updated for a document.
    /// </summary>
    public event Action<string, List<LspDiagnostic>>? DiagnosticsUpdated;

    /// <summary>
    /// Initialize with a project for analysis context.
    /// </summary>
    public async Task InitializeAsync(Project project)
    {
        lock (_projectLock)
        {
            _currentProject = project;
        }

        _currentCompilation = await project.GetCompilationAsync();
    }

    /// <summary>
    /// Queue analysis for a document with debouncing.
    /// </summary>
    public void QueueAnalysis(string documentUri, string content, int version)
    {
        // Cancel any pending analysis for this document
        if (_pendingAnalyses.TryRemove(documentUri, out var existingCts))
        {
            existingCts.Cancel();
            existingCts.Dispose();
        }

        var cts = new CancellationTokenSource();
        _pendingAnalyses[documentUri] = cts;

        // Update document state
        _documentStates[documentUri] = new DocumentState
        {
            Uri = documentUri,
            Content = content,
            Version = version,
            LastAnalyzed = DateTime.MinValue
        };

        // Schedule debounced analysis
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(_options.AnalysisDebounceMs, cts.Token);
                await AnalyzeDocumentAsync(documentUri, content, cts.Token);
            }
            catch (OperationCanceledException)
            {
                // Analysis was cancelled, ignore
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Analysis error for {documentUri}: {ex.Message}");
            }
            finally
            {
                _pendingAnalyses.TryRemove(documentUri, out _);
            }
        });
    }

    /// <summary>
    /// Analyze a document and produce diagnostics.
    /// </summary>
    public async Task<List<LspDiagnostic>> AnalyzeDocumentAsync(
        string documentUri,
        string content,
        CancellationToken cancellationToken = default)
    {
        var diagnostics = new List<LspDiagnostic>();
        var filePath = UriToPath(documentUri);

        try
        {
            // Parse the document
            var syntaxTree = CSharpSyntaxTree.ParseText(content, path: filePath, cancellationToken: cancellationToken);
            var root = await syntaxTree.GetRootAsync(cancellationToken);

            // Get or create compilation
            var compilation = GetOrCreateCompilation(syntaxTree);
            var semanticModel = compilation?.GetSemanticModel(syntaxTree);

            // Run syntax-level analysis
            diagnostics.AddRange(AnalyzeSyntax(root, filePath));

            // Run semantic analysis if available
            if (semanticModel != null)
            {
                diagnostics.AddRange(await AnalyzeSemanticAsync(root, semanticModel, filePath, cancellationToken));
            }

            // Run pattern-based analyzers
            diagnostics.AddRange(await RunAnalyzersAsync(root, semanticModel, filePath, cancellationToken));

            // Limit diagnostics per file
            diagnostics = diagnostics
                .OrderBy(d => d.Severity)
                .ThenBy(d => d.Range.Start.Line)
                .Take(_options.MaxDiagnosticsPerFile)
                .ToList();

            // Update document state
            if (_documentStates.TryGetValue(documentUri, out var state))
            {
                _documentStates[documentUri] = state with
                {
                    Diagnostics = diagnostics,
                    LastAnalyzed = DateTime.UtcNow
                };
            }

            // Raise event
            DiagnosticsUpdated?.Invoke(documentUri, diagnostics);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Add error diagnostic
            diagnostics.Add(new LspDiagnostic
            {
                Range = LspRange.FromLine(0),
                Severity = LspDiagnosticSeverity.Error,
                Code = "BS0000",
                Message = $"Analysis failed: {ex.Message}"
            });
        }

        return diagnostics;
    }

    /// <summary>
    /// Get diagnostics for a workspace (all open documents).
    /// </summary>
    public async Task<Dictionary<string, List<LspDiagnostic>>> AnalyzeWorkspaceAsync(
        CancellationToken cancellationToken = default)
    {
        var results = new Dictionary<string, List<LspDiagnostic>>();

        foreach (var kvp in _documentStates)
        {
            if (cancellationToken.IsCancellationRequested) break;

            var diagnostics = await AnalyzeDocumentAsync(kvp.Key, kvp.Value.Content, cancellationToken);
            results[kvp.Key] = diagnostics;
        }

        return results;
    }

    /// <summary>
    /// Clear diagnostics for a document.
    /// </summary>
    public void ClearDiagnostics(string documentUri)
    {
        if (_pendingAnalyses.TryRemove(documentUri, out var cts))
        {
            cts.Cancel();
            cts.Dispose();
        }

        _documentStates.TryRemove(documentUri, out _);
        DiagnosticsUpdated?.Invoke(documentUri, []);
    }

    /// <summary>
    /// Get current diagnostics for a document.
    /// </summary>
    public List<LspDiagnostic> GetDiagnostics(string documentUri)
    {
        return _documentStates.TryGetValue(documentUri, out var state)
            ? state.Diagnostics
            : [];
    }

    private Compilation? GetOrCreateCompilation(SyntaxTree syntaxTree)
    {
        lock (_projectLock)
        {
            if (_currentCompilation == null)
            {
                // Create a standalone compilation for analysis
                return CSharpCompilation.Create(
                    "Analysis",
                    [syntaxTree],
                    Basic.Reference.Assemblies.Net90.References.All,
                    new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
            }

            // Add or replace syntax tree in existing compilation
            var existingTree = _currentCompilation.SyntaxTrees
                .FirstOrDefault(t => t.FilePath == syntaxTree.FilePath);

            if (existingTree != null)
            {
                return _currentCompilation.ReplaceSyntaxTree(existingTree, syntaxTree);
            }

            return _currentCompilation.AddSyntaxTrees(syntaxTree);
        }
    }

    private List<LspDiagnostic> AnalyzeSyntax(SyntaxNode root, string filePath)
    {
        var diagnostics = new List<LspDiagnostic>();

        // Check for syntax errors
        foreach (var diagnostic in root.GetDiagnostics())
        {
            if (diagnostic.Severity == DiagnosticSeverity.Error ||
                diagnostic.Severity == DiagnosticSeverity.Warning)
            {
                var lineSpan = diagnostic.Location.GetLineSpan();
                diagnostics.Add(new LspDiagnostic
                {
                    Range = LspRange.FromLineSpan(lineSpan),
                    Severity = diagnostic.Severity == DiagnosticSeverity.Error
                        ? LspDiagnosticSeverity.Error
                        : LspDiagnosticSeverity.Warning,
                    Code = diagnostic.Id,
                    Message = diagnostic.GetMessage()
                });
            }
        }

        return diagnostics;
    }

    private async Task<List<LspDiagnostic>> AnalyzeSemanticAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        CancellationToken cancellationToken)
    {
        var diagnostics = new List<LspDiagnostic>();

        // Check compilation diagnostics
        foreach (var diagnostic in semanticModel.GetDiagnostics(cancellationToken: cancellationToken))
        {
            if (diagnostic.Severity == DiagnosticSeverity.Error ||
                diagnostic.Severity == DiagnosticSeverity.Warning)
            {
                var lineSpan = diagnostic.Location.GetLineSpan();
                diagnostics.Add(new LspDiagnostic
                {
                    Range = LspRange.FromLineSpan(lineSpan),
                    Severity = diagnostic.Severity == DiagnosticSeverity.Error
                        ? LspDiagnosticSeverity.Error
                        : LspDiagnosticSeverity.Warning,
                    Code = diagnostic.Id,
                    Message = diagnostic.GetMessage()
                });
            }
        }

        return diagnostics;
    }

    private async Task<List<LspDiagnostic>> RunAnalyzersAsync(
        SyntaxNode root,
        SemanticModel? semanticModel,
        string filePath,
        CancellationToken cancellationToken)
    {
        var diagnostics = new List<LspDiagnostic>();

        // Run method complexity analysis
        if (_options.Analyzers.CodeQuality)
        {
            diagnostics.AddRange(AnalyzeComplexity(root, filePath));
        }

        // Run async pattern analysis
        if (_options.Analyzers.Performance && semanticModel != null)
        {
            diagnostics.AddRange(AnalyzeAsyncPatterns(root, semanticModel, filePath));
        }

        // Run exception handling analysis
        if (_options.Analyzers.ExceptionHandling)
        {
            diagnostics.AddRange(AnalyzeExceptionHandling(root, filePath));
        }

        // Run resource leak analysis
        if (_options.Analyzers.ResourceLeaks && semanticModel != null)
        {
            diagnostics.AddRange(AnalyzeResourceLeaks(root, semanticModel, filePath));
        }

        // Run optimization analysis
        if (_options.Analyzers.Optimization && semanticModel != null)
        {
            diagnostics.AddRange(AnalyzeOptimizations(root, semanticModel, filePath));
        }

        // Run security analysis
        if (_options.Analyzers.Security && semanticModel != null)
        {
            diagnostics.AddRange(AnalyzeSecurityIssues(root, semanticModel, filePath));
        }

        return diagnostics;
    }

    private List<LspDiagnostic> AnalyzeComplexity(SyntaxNode root, string filePath)
    {
        var diagnostics = new List<LspDiagnostic>();

        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            var complexity = CalculateCyclomaticComplexity(method);
            var lineSpan = method.GetLocation().GetLineSpan();
            var lineCount = lineSpan.EndLinePosition.Line - lineSpan.StartLinePosition.Line + 1;

            if (complexity > 15)
            {
                diagnostics.Add(new LspDiagnostic
                {
                    Range = LspRange.FromLine(lineSpan.StartLinePosition.Line),
                    Severity = complexity > 25 ? LspDiagnosticSeverity.Warning : LspDiagnosticSeverity.Information,
                    Code = "BS1001",
                    Message = $"Method '{method.Identifier.Text}' has high cyclomatic complexity ({complexity}). Consider refactoring.",
                    Data = new LspDiagnosticData
                    {
                        IssueType = "HighComplexity",
                        Category = "CodeQuality",
                        HasQuickFix = false
                    }
                });
            }

            if (lineCount > 50)
            {
                diagnostics.Add(new LspDiagnostic
                {
                    Range = LspRange.FromLine(lineSpan.StartLinePosition.Line),
                    Severity = lineCount > 100 ? LspDiagnosticSeverity.Warning : LspDiagnosticSeverity.Information,
                    Code = "BS1002",
                    Message = $"Method '{method.Identifier.Text}' is too long ({lineCount} lines). Consider extracting methods.",
                    Data = new LspDiagnosticData
                    {
                        IssueType = "LongMethod",
                        Category = "Refactoring",
                        HasQuickFix = false
                    }
                });
            }

            var paramCount = method.ParameterList.Parameters.Count;
            if (paramCount > 5)
            {
                diagnostics.Add(new LspDiagnostic
                {
                    Range = LspRange.FromLine(lineSpan.StartLinePosition.Line),
                    Severity = LspDiagnosticSeverity.Information,
                    Code = "BS1003",
                    Message = $"Method '{method.Identifier.Text}' has too many parameters ({paramCount}). Consider using a parameter object.",
                    Data = new LspDiagnosticData
                    {
                        IssueType = "TooManyParameters",
                        Category = "Refactoring",
                        HasQuickFix = false
                    }
                });
            }
        }

        // Check for god classes
        foreach (var classDecl in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
        {
            var methodCount = classDecl.Members.OfType<MethodDeclarationSyntax>().Count();
            var fieldCount = classDecl.Members.OfType<FieldDeclarationSyntax>().Sum(f => f.Declaration.Variables.Count);
            var propertyCount = classDecl.Members.OfType<PropertyDeclarationSyntax>().Count();

            if (methodCount > 20 || (fieldCount + propertyCount) > 15)
            {
                var lineSpan = classDecl.GetLocation().GetLineSpan();
                diagnostics.Add(new LspDiagnostic
                {
                    Range = LspRange.FromLine(lineSpan.StartLinePosition.Line),
                    Severity = LspDiagnosticSeverity.Warning,
                    Code = "BS1004",
                    Message = $"Class '{classDecl.Identifier.Text}' may be a God Class ({methodCount} methods, {fieldCount + propertyCount} fields/properties). Consider splitting responsibilities.",
                    Data = new LspDiagnosticData
                    {
                        IssueType = "GodClass",
                        Category = "Refactoring",
                        HasQuickFix = false
                    }
                });
            }
        }

        return diagnostics;
    }

    private List<LspDiagnostic> AnalyzeAsyncPatterns(SyntaxNode root, SemanticModel semanticModel, string filePath)
    {
        var diagnostics = new List<LspDiagnostic>();

        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            // Check for async void (except event handlers)
            if (method.Modifiers.Any(SyntaxKind.AsyncKeyword))
            {
                var returnType = method.ReturnType.ToString();
                if (returnType == "void" && !method.Identifier.Text.Contains("Handler") && !method.Identifier.Text.StartsWith("On"))
                {
                    var lineSpan = method.GetLocation().GetLineSpan();
                    diagnostics.Add(new LspDiagnostic
                    {
                        Range = LspRange.FromLine(lineSpan.StartLinePosition.Line),
                        Severity = LspDiagnosticSeverity.Warning,
                        Code = "BS2001",
                        Message = $"Async method '{method.Identifier.Text}' returns void. Use Task instead to allow exception propagation.",
                        Data = new LspDiagnosticData
                        {
                            IssueType = "AsyncVoid",
                            Category = "Performance",
                            HasQuickFix = true,
                            SuggestedCode = method.ReturnType.ToString().Replace("void", "Task")
                        }
                    });
                }
            }

            // Check for missing ConfigureAwait
            foreach (var await in method.DescendantNodes().OfType<AwaitExpressionSyntax>())
            {
                var expr = await.Expression;
                if (expr is InvocationExpressionSyntax invocation)
                {
                    var memberAccess = invocation.Expression as MemberAccessExpressionSyntax;
                    if (memberAccess?.Name.Identifier.Text != "ConfigureAwait")
                    {
                        // Check if the awaited expression returns a Task
                        var typeInfo = semanticModel.GetTypeInfo(expr);
                        if (typeInfo.Type?.Name == "Task" || typeInfo.Type?.Name == "ValueTask")
                        {
                            var lineSpan = await.GetLocation().GetLineSpan();
                            diagnostics.Add(new LspDiagnostic
                            {
                                Range = LspRange.FromLineSpan(lineSpan),
                                Severity = LspDiagnosticSeverity.Hint,
                                Code = "BS2002",
                                Message = "Consider using ConfigureAwait(false) for library code.",
                                Data = new LspDiagnosticData
                                {
                                    IssueType = "MissingConfigureAwait",
                                    Category = "Performance",
                                    HasQuickFix = true,
                                    OriginalCode = await.ToString(),
                                    SuggestedCode = await.ToString() + ".ConfigureAwait(false)"
                                }
                            });
                        }
                    }
                }
            }
        }

        return diagnostics;
    }

    private List<LspDiagnostic> AnalyzeExceptionHandling(SyntaxNode root, string filePath)
    {
        var diagnostics = new List<LspDiagnostic>();

        foreach (var catchClause in root.DescendantNodes().OfType<CatchClauseSyntax>())
        {
            // Check for empty catch blocks
            if (catchClause.Block.Statements.Count == 0)
            {
                var lineSpan = catchClause.GetLocation().GetLineSpan();
                diagnostics.Add(new LspDiagnostic
                {
                    Range = LspRange.FromLineSpan(lineSpan),
                    Severity = LspDiagnosticSeverity.Warning,
                    Code = "BS3001",
                    Message = "Empty catch block swallows exceptions silently. Add logging or rethrow.",
                    Data = new LspDiagnosticData
                    {
                        IssueType = "EmptyCatch",
                        Category = "ExceptionHandling",
                        HasQuickFix = true
                    }
                });
            }

            // Check for catching Exception without filtering
            if (catchClause.Declaration?.Type.ToString() == "Exception" && catchClause.Filter == null)
            {
                // Check if it just rethrows
                var throwStatements = catchClause.Block.DescendantNodes().OfType<ThrowStatementSyntax>().ToList();
                var onlyRethrows = throwStatements.Count == 1 && throwStatements[0].Expression == null;

                if (!onlyRethrows)
                {
                    var lineSpan = catchClause.GetLocation().GetLineSpan();
                    diagnostics.Add(new LspDiagnostic
                    {
                        Range = LspRange.FromLineSpan(lineSpan),
                        Severity = LspDiagnosticSeverity.Information,
                        Code = "BS3002",
                        Message = "Catching generic Exception. Consider catching specific exception types.",
                        Data = new LspDiagnosticData
                        {
                            IssueType = "GenericCatch",
                            Category = "ExceptionHandling",
                            HasQuickFix = false
                        }
                    });
                }
            }
        }

        return diagnostics;
    }

    private List<LspDiagnostic> AnalyzeResourceLeaks(SyntaxNode root, SemanticModel semanticModel, string filePath)
    {
        var diagnostics = new List<LspDiagnostic>();

        // Check for disposable objects not in using statements
        foreach (var localDecl in root.DescendantNodes().OfType<LocalDeclarationStatementSyntax>())
        {
            if (localDecl.UsingKeyword.IsKind(SyntaxKind.None))
            {
                foreach (var variable in localDecl.Declaration.Variables)
                {
                    if (variable.Initializer?.Value != null)
                    {
                        var typeInfo = semanticModel.GetTypeInfo(variable.Initializer.Value);
                        if (typeInfo.Type != null && ImplementsIDisposable(typeInfo.Type))
                        {
                            // Check if it's disposed or returned
                            var method = localDecl.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
                            if (method != null)
                            {
                                var varName = variable.Identifier.Text;
                                var hasDispose = method.DescendantNodes()
                                    .OfType<InvocationExpressionSyntax>()
                                    .Any(i => i.Expression.ToString().Contains($"{varName}.Dispose"));
                                var hasUsing = method.DescendantNodes()
                                    .OfType<UsingStatementSyntax>()
                                    .Any();

                                if (!hasDispose && !hasUsing)
                                {
                                    var lineSpan = localDecl.GetLocation().GetLineSpan();
                                    diagnostics.Add(new LspDiagnostic
                                    {
                                        Range = LspRange.FromLineSpan(lineSpan),
                                        Severity = LspDiagnosticSeverity.Warning,
                                        Code = "BS4001",
                                        Message = $"Disposable resource '{varName}' may not be disposed. Use 'using' statement.",
                                        Data = new LspDiagnosticData
                                        {
                                            IssueType = "MissingUsing",
                                            Category = "ResourceLeak",
                                            HasQuickFix = true,
                                            OriginalCode = localDecl.ToString(),
                                            SuggestedCode = $"using {localDecl.Declaration}"
                                        }
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        return diagnostics;
    }

    private List<LspDiagnostic> AnalyzeOptimizations(SyntaxNode root, SemanticModel semanticModel, string filePath)
    {
        var diagnostics = new List<LspDiagnostic>();

        // Check for string concatenation in loops
        foreach (var loop in root.DescendantNodes().Where(n => n is ForStatementSyntax or ForEachStatementSyntax or WhileStatementSyntax))
        {
            var stringConcats = loop.DescendantNodes()
                .OfType<AssignmentExpressionSyntax>()
                .Where(a => a.IsKind(SyntaxKind.AddAssignmentExpression))
                .Where(a =>
                {
                    var typeInfo = semanticModel.GetTypeInfo(a.Left);
                    return typeInfo.Type?.SpecialType == SpecialType.System_String;
                })
                .ToList();

            foreach (var concat in stringConcats)
            {
                var lineSpan = concat.GetLocation().GetLineSpan();
                diagnostics.Add(new LspDiagnostic
                {
                    Range = LspRange.FromLineSpan(lineSpan),
                    Severity = LspDiagnosticSeverity.Warning,
                    Code = "BS5001",
                    Message = "String concatenation in loop. Use StringBuilder for better performance.",
                    Data = new LspDiagnosticData
                    {
                        IssueType = "StringConcatInLoop",
                        Category = "Performance",
                        HasQuickFix = true
                    }
                });
            }
        }

        // Check for multiple LINQ enumerations
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var methodName = memberAccess.Name.Identifier.Text;
                if (methodName == "Count" || methodName == "Any" || methodName == "First" || methodName == "Last")
                {
                    var receiverType = semanticModel.GetTypeInfo(memberAccess.Expression);
                    if (receiverType.Type?.Name == "IEnumerable")
                    {
                        // Check if the same enumerable is enumerated multiple times
                        var lineSpan = invocation.GetLocation().GetLineSpan();
                        diagnostics.Add(new LspDiagnostic
                        {
                            Range = LspRange.FromLineSpan(lineSpan),
                            Severity = LspDiagnosticSeverity.Hint,
                            Code = "BS5002",
                            Message = $"Consider materializing enumerable before calling '{methodName}' if enumerated multiple times.",
                            Data = new LspDiagnosticData
                            {
                                IssueType = "MultipleEnumeration",
                                Category = "Performance",
                                HasQuickFix = false
                            }
                        });
                    }
                }
            }
        }

        return diagnostics;
    }

    private List<LspDiagnostic> AnalyzeSecurityIssues(SyntaxNode root, SemanticModel semanticModel, string filePath)
    {
        var diagnostics = new List<LspDiagnostic>();

        // Check for SQL injection vulnerabilities
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var methodName = invocation.Expression.ToString();
            if (methodName.Contains("ExecuteSql") || methodName.Contains("FromSqlRaw"))
            {
                foreach (var arg in invocation.ArgumentList.Arguments)
                {
                    if (arg.Expression is InterpolatedStringExpressionSyntax ||
                        (arg.Expression is BinaryExpressionSyntax binary && binary.IsKind(SyntaxKind.AddExpression)))
                    {
                        var lineSpan = invocation.GetLocation().GetLineSpan();
                        diagnostics.Add(new LspDiagnostic
                        {
                            Range = LspRange.FromLineSpan(lineSpan),
                            Severity = LspDiagnosticSeverity.Error,
                            Code = "BS6001",
                            Message = "Potential SQL injection vulnerability. Use parameterized queries.",
                            Data = new LspDiagnosticData
                            {
                                IssueType = "SqlInjection",
                                Category = "Security",
                                HasQuickFix = false,
                                Confidence = "High"
                            }
                        });
                        break;
                    }
                }
            }
        }

        // Check for hardcoded secrets
        foreach (var literal in root.DescendantNodes().OfType<LiteralExpressionSyntax>())
        {
            if (literal.IsKind(SyntaxKind.StringLiteralExpression))
            {
                var value = literal.Token.ValueText;
                var parent = literal.Parent;

                // Check variable/parameter names for secret indicators
                var varName = parent switch
                {
                    EqualsValueClauseSyntax evs => evs.Parent switch
                    {
                        VariableDeclaratorSyntax vd => vd.Identifier.Text,
                        PropertyDeclarationSyntax pd => pd.Identifier.Text,
                        _ => ""
                    },
                    AssignmentExpressionSyntax aes => aes.Left.ToString(),
                    _ => ""
                };

                var secretPatterns = new[] { "password", "secret", "apikey", "api_key", "connectionstring", "token" };
                if (secretPatterns.Any(p => varName.Contains(p, StringComparison.OrdinalIgnoreCase)) && value.Length > 0)
                {
                    var lineSpan = literal.GetLocation().GetLineSpan();
                    diagnostics.Add(new LspDiagnostic
                    {
                        Range = LspRange.FromLineSpan(lineSpan),
                        Severity = LspDiagnosticSeverity.Error,
                        Code = "BS6002",
                        Message = "Potential hardcoded secret detected. Use secure configuration management.",
                        Data = new LspDiagnosticData
                        {
                            IssueType = "HardcodedSecret",
                            Category = "Security",
                            HasQuickFix = false,
                            Confidence = "High"
                        }
                    });
                }
            }
        }

        return diagnostics;
    }

    private static int CalculateCyclomaticComplexity(MethodDeclarationSyntax method)
    {
        var complexity = 1;
        var body = (SyntaxNode?)method.Body ?? method.ExpressionBody;
        if (body == null) return complexity;

        foreach (var node in body.DescendantNodes())
        {
            switch (node)
            {
                case IfStatementSyntax:
                case ConditionalExpressionSyntax:
                case CaseSwitchLabelSyntax:
                case CasePatternSwitchLabelSyntax:
                case ForStatementSyntax:
                case ForEachStatementSyntax:
                case WhileStatementSyntax:
                case DoStatementSyntax:
                case CatchClauseSyntax:
                    complexity++;
                    break;
                case BinaryExpressionSyntax binary when
                    binary.IsKind(SyntaxKind.LogicalAndExpression) ||
                    binary.IsKind(SyntaxKind.LogicalOrExpression) ||
                    binary.IsKind(SyntaxKind.CoalesceExpression):
                    complexity++;
                    break;
            }
        }

        return complexity;
    }

    private static bool ImplementsIDisposable(ITypeSymbol type)
    {
        if (type.AllInterfaces.Any(i => i.Name == "IDisposable")) return true;
        if (type.Name == "IDisposable") return true;
        return type.BaseType != null && ImplementsIDisposable(type.BaseType);
    }

    private static string UriToPath(string uri)
    {
        if (uri.StartsWith("file:///"))
        {
            var path = Uri.UnescapeDataString(uri.Substring(8));
            if (Path.DirectorySeparatorChar == '\\')
            {
                path = path.Replace('/', '\\');
            }
            return path;
        }
        return uri;
    }
}
