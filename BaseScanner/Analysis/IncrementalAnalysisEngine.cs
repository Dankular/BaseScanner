using System.Diagnostics;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analysis.Models;
using BaseScanner.Analyzers;
using BaseScanner.Analyzers.Security;

namespace BaseScanner.Analysis;

/// <summary>
/// Main engine for incremental code analysis.
/// Coordinates caching, change detection, dependency tracking, and analysis.
/// </summary>
public class IncrementalAnalysisEngine
{
    private readonly AnalysisCache _cache;
    private readonly DependencyTracker _dependencyTracker;
    private readonly ChangeDetector _changeDetector;
    private readonly IncrementalAnalysisOptions _options;

    /// <summary>
    /// Creates a new incremental analysis engine.
    /// </summary>
    /// <param name="projectPath">Path to the project.</param>
    /// <param name="options">Incremental analysis options.</param>
    public IncrementalAnalysisEngine(string projectPath, IncrementalAnalysisOptions? options = null)
    {
        _options = options ?? new IncrementalAnalysisOptions();
        _cache = new AnalysisCache(projectPath);
        _dependencyTracker = new DependencyTracker();
        _changeDetector = new ChangeDetector(_cache, _dependencyTracker);
    }

    /// <summary>
    /// Gets the analysis cache.
    /// </summary>
    public AnalysisCache Cache => _cache;

    /// <summary>
    /// Gets the dependency tracker.
    /// </summary>
    public DependencyTracker DependencyTracker => _dependencyTracker;

    /// <summary>
    /// Gets the change detector.
    /// </summary>
    public ChangeDetector ChangeDetector => _changeDetector;

    /// <summary>
    /// Performs incremental analysis on a project.
    /// </summary>
    public async Task<IncrementalAnalysisResult> AnalyzeAsync(Project project)
    {
        var stopwatch = Stopwatch.StartNew();

        // Handle clear cache option
        if (_options.ClearCache)
        {
            await _cache.ClearAsync();
            Console.WriteLine("Cache cleared.");
        }

        // Handle no-cache option (force full analysis)
        if (_options.NoCache || !_options.UseIncremental)
        {
            return await PerformFullAnalysisAsync(project, stopwatch);
        }

        // Load existing cache
        await _cache.LoadAsync();

        // Load dependency graph from cache
        _dependencyTracker.LoadFromGraph(_cache.GetDependencyGraph());

        // Get all source files
        var sourceFiles = project.Documents
            .Where(d => d.FilePath != null && d.FilePath.EndsWith(".cs"))
            .Select(d => d.FilePath!)
            .ToList();

        // Detect changes
        var changes = _changeDetector.DetectChanges(sourceFiles);
        var changeSummary = _changeDetector.GetChangeSummary(changes);

        Console.WriteLine($"Incremental analysis: {changeSummary.Summary}");

        // If no changes, return cached results
        if (!changes.HasChanges && changes.AffectedFiles.Count == 0)
        {
            Console.WriteLine("No changes detected. Using cached results.");
            return CreateResultFromCache(project, changes, stopwatch);
        }

        // Update dependency graph if needed
        if (_options.UpdateDependencyGraph && (changes.NewFiles.Count > 0 || changes.ChangedFiles.Count > 0))
        {
            Console.WriteLine("Updating dependency graph...");
            var graph = await _dependencyTracker.BuildDependencyGraphAsync(project);
            _cache.UpdateDependencyGraph(graph);
        }

        // Analyze changed files
        var filesToAnalyze = changes.FilesToAnalyze;
        Console.WriteLine($"Analyzing {filesToAnalyze.Count} files...");

        var compilation = await project.GetCompilationAsync();
        if (compilation == null)
        {
            throw new InvalidOperationException("Failed to get compilation");
        }

        // Analyze each file
        var analyzedResults = new Dictionary<string, FileAnalysisResult>();
        foreach (var filePath in filesToAnalyze)
        {
            var document = project.Documents.FirstOrDefault(d =>
                d.FilePath != null &&
                d.FilePath.Equals(filePath, StringComparison.OrdinalIgnoreCase));

            if (document == null)
                continue;

            var result = await AnalyzeFileAsync(document, compilation);
            if (result != null)
            {
                analyzedResults[filePath] = result;

                // Update cache entry
                var fileInfo = new FileInfo(filePath);
                var cacheEntry = new FileCacheEntry
                {
                    FilePath = filePath,
                    ContentHash = AnalysisCache.ComputeFileHash(filePath),
                    LastAnalyzedAt = DateTime.UtcNow,
                    FileSize = fileInfo.Length,
                    Results = result,
                    DefinedSymbols = _dependencyTracker.GetDefinitions(filePath),
                    ReferencedSymbols = _dependencyTracker.GetReferences(filePath)
                };
                _cache.SetFileEntry(cacheEntry);
            }
        }

        // Remove deleted files from cache
        foreach (var deletedFile in changes.DeletedFiles)
        {
            _cache.RemoveFileEntry(deletedFile);
            _dependencyTracker.RemoveFile(deletedFile);
        }

        // Merge results with cached results
        var mergedResults = MergeResults(analyzedResults, changes.UnchangedFiles);

        // Save updated cache
        await _cache.SaveAsync();

        stopwatch.Stop();

        // Estimate time saved
        var estimatedFullAnalysisTime = TimeSpan.FromMilliseconds(
            sourceFiles.Count * 50); // Rough estimate: 50ms per file
        var timeSaved = estimatedFullAnalysisTime - stopwatch.Elapsed;
        if (timeSaved < TimeSpan.Zero)
            timeSaved = TimeSpan.Zero;

        return new IncrementalAnalysisResult
        {
            IsIncremental = true,
            FilesAnalyzed = filesToAnalyze.Count,
            FilesCached = changes.UnchangedFiles.Count,
            TotalFiles = sourceFiles.Count,
            TimeSaved = timeSaved,
            Changes = changes,
            Results = mergedResults
        };
    }

    /// <summary>
    /// Performs full analysis without using cache.
    /// </summary>
    private async Task<IncrementalAnalysisResult> PerformFullAnalysisAsync(
        Project project,
        Stopwatch stopwatch)
    {
        Console.WriteLine("Performing full analysis (cache disabled)...");

        var sourceFiles = project.Documents
            .Where(d => d.FilePath != null && d.FilePath.EndsWith(".cs"))
            .Select(d => d.FilePath!)
            .ToList();

        var compilation = await project.GetCompilationAsync();
        if (compilation == null)
        {
            throw new InvalidOperationException("Failed to get compilation");
        }

        // Build dependency graph
        Console.WriteLine("Building dependency graph...");
        var graph = await _dependencyTracker.BuildDependencyGraphAsync(project);
        _cache.UpdateDependencyGraph(graph);

        // Analyze all files
        Console.WriteLine($"Analyzing {sourceFiles.Count} files...");
        var analyzedResults = new Dictionary<string, FileAnalysisResult>();

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null || !document.FilePath.EndsWith(".cs"))
                continue;

            var result = await AnalyzeFileAsync(document, compilation);
            if (result != null)
            {
                analyzedResults[document.FilePath] = result;

                // Update cache entry
                var fileInfo = new FileInfo(document.FilePath);
                var cacheEntry = new FileCacheEntry
                {
                    FilePath = document.FilePath,
                    ContentHash = AnalysisCache.ComputeFileHash(document.FilePath),
                    LastAnalyzedAt = DateTime.UtcNow,
                    FileSize = fileInfo.Length,
                    Results = result,
                    DefinedSymbols = _dependencyTracker.GetDefinitions(document.FilePath),
                    ReferencedSymbols = _dependencyTracker.GetReferences(document.FilePath)
                };
                _cache.SetFileEntry(cacheEntry);
            }
        }

        // Save cache
        await _cache.SaveAsync();

        stopwatch.Stop();

        var mergedResults = MergeResults(analyzedResults, []);

        return new IncrementalAnalysisResult
        {
            IsIncremental = false,
            FilesAnalyzed = sourceFiles.Count,
            FilesCached = 0,
            TotalFiles = sourceFiles.Count,
            TimeSaved = null,
            Changes = null,
            Results = mergedResults
        };
    }

    /// <summary>
    /// Analyzes a single file.
    /// </summary>
    private async Task<FileAnalysisResult?> AnalyzeFileAsync(Document document, Compilation compilation)
    {
        if (document.FilePath == null)
            return null;

        try
        {
            var syntaxTree = await document.GetSyntaxTreeAsync();
            if (syntaxTree == null)
                return null;

            var semanticModel = compilation.GetSemanticModel(syntaxTree);
            var root = await syntaxTree.GetRootAsync();

            var result = new FileAnalysisResult();

            // Performance issues
            result = result with
            {
                PerformanceIssues = await AnalyzePerformanceIssuesAsync(root, semanticModel, document.FilePath)
            };

            // Exception handling issues
            result = result with
            {
                ExceptionIssues = AnalyzeExceptionHandling(root, semanticModel, document.FilePath)
            };

            // Resource leak issues
            result = result with
            {
                ResourceIssues = AnalyzeResourceLeaks(root, semanticModel, document.FilePath)
            };

            // Security issues
            result = result with
            {
                SecurityIssues = await AnalyzeSecurityAsync(root, semanticModel, document.FilePath)
            };

            // Optimization opportunities
            result = result with
            {
                Optimizations = AnalyzeOptimizations(root, semanticModel, document.FilePath)
            };

            // File metrics
            result = result with
            {
                Metrics = CalculateFileMetrics(root)
            };

            // Refactoring opportunities
            result = result with
            {
                Refactoring = AnalyzeRefactoring(root, semanticModel, document.FilePath)
            };

            return result;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Failed to analyze {Path.GetFileName(document.FilePath)}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Analyzes performance issues in a file.
    /// </summary>
    private async Task<List<CachedIssue>> AnalyzePerformanceIssuesAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<CachedIssue>();

        // Check for async void methods
        var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>();
        foreach (var method in methods)
        {
            if (method.Modifiers.Any(SyntaxKind.AsyncKeyword) &&
                method.ReturnType.ToString() == "void")
            {
                var lineSpan = method.GetLocation().GetLineSpan();
                issues.Add(new CachedIssue
                {
                    Type = "AsyncVoid",
                    Severity = "Warning",
                    Message = $"Async method '{method.Identifier.Text}' returns void. Consider returning Task.",
                    Line = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    CodeSnippet = method.Identifier.Text
                });
            }
        }

        // Check for .Result or .Wait() on tasks
        var memberAccesses = root.DescendantNodes().OfType<MemberAccessExpressionSyntax>();
        foreach (var access in memberAccesses)
        {
            var name = access.Name.Identifier.Text;
            if (name == "Result" || name == "Wait")
            {
                var symbol = semanticModel.GetSymbolInfo(access.Expression).Symbol;
                if (symbol?.ContainingType?.Name == "Task" ||
                    symbol?.ContainingType?.Name == "ValueTask")
                {
                    var lineSpan = access.GetLocation().GetLineSpan();
                    issues.Add(new CachedIssue
                    {
                        Type = "BlockingAsyncCall",
                        Severity = "Warning",
                        Message = $"Blocking call to {name} on Task. Use await instead.",
                        Line = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        CodeSnippet = access.ToString()
                    });
                }
            }
        }

        return issues;
    }

    /// <summary>
    /// Analyzes exception handling issues.
    /// </summary>
    private List<CachedIssue> AnalyzeExceptionHandling(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<CachedIssue>();

        var catchClauses = root.DescendantNodes().OfType<CatchClauseSyntax>();
        foreach (var catchClause in catchClauses)
        {
            // Empty catch block
            if (catchClause.Block.Statements.Count == 0)
            {
                var lineSpan = catchClause.GetLocation().GetLineSpan();
                issues.Add(new CachedIssue
                {
                    Type = "EmptyCatchBlock",
                    Severity = "Warning",
                    Message = "Empty catch block swallows exceptions silently.",
                    Line = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1
                });
            }

            // Catch without type (catch all)
            if (catchClause.Declaration == null)
            {
                var lineSpan = catchClause.GetLocation().GetLineSpan();
                issues.Add(new CachedIssue
                {
                    Type = "CatchAll",
                    Severity = "Info",
                    Message = "Catch-all block catches all exceptions. Consider catching specific exceptions.",
                    Line = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1
                });
            }
        }

        return issues;
    }

    /// <summary>
    /// Analyzes resource leak issues.
    /// </summary>
    private List<CachedIssue> AnalyzeResourceLeaks(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<CachedIssue>();

        // Check for IDisposable objects not in using statements
        var objectCreations = root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
        foreach (var creation in objectCreations)
        {
            var typeInfo = semanticModel.GetTypeInfo(creation);
            if (typeInfo.Type == null)
                continue;

            var isDisposable = typeInfo.Type.AllInterfaces
                .Any(i => i.Name == "IDisposable" || i.Name == "IAsyncDisposable");

            if (!isDisposable)
                continue;

            // Check if it's in a using statement or using declaration (C# 8.0+)
            var parent = creation.Parent;
            var inUsing = false;
            while (parent != null)
            {
                if (parent is UsingStatementSyntax)
                {
                    inUsing = true;
                    break;
                }
                // Check for C# 8.0 using declarations (LocalDeclarationStatement with using modifier)
                if (parent is LocalDeclarationStatementSyntax localDecl &&
                    localDecl.UsingKeyword != default)
                {
                    inUsing = true;
                    break;
                }
                parent = parent.Parent;
            }

            if (!inUsing)
            {
                var lineSpan = creation.GetLocation().GetLineSpan();
                issues.Add(new CachedIssue
                {
                    Type = "PotentialResourceLeak",
                    Severity = "Warning",
                    Message = $"IDisposable object '{typeInfo.Type.Name}' may not be disposed. Consider using a using statement.",
                    Line = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    CodeSnippet = creation.ToString()
                });
            }
        }

        return issues;
    }

    /// <summary>
    /// Analyzes security issues.
    /// </summary>
    private async Task<List<CachedSecurityIssue>> AnalyzeSecurityAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<CachedSecurityIssue>();

        // Check for SQL injection vulnerabilities
        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();
        foreach (var invocation in invocations)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(invocation);
            var method = symbolInfo.Symbol as IMethodSymbol;

            if (method == null)
                continue;

            // Check for ExecuteNonQuery, ExecuteReader, ExecuteScalar with string concatenation
            if (method.Name.StartsWith("Execute") &&
                method.ContainingType?.Name.Contains("Command") == true)
            {
                // Check if the command text uses string concatenation
                var arguments = invocation.ArgumentList?.Arguments;
                if (arguments != null)
                {
                    foreach (var arg in arguments)
                    {
                        if (arg.Expression is BinaryExpressionSyntax binary &&
                            binary.IsKind(SyntaxKind.AddExpression))
                        {
                            var lineSpan = invocation.GetLocation().GetLineSpan();
                            issues.Add(new CachedSecurityIssue
                            {
                                VulnerabilityType = "SQL Injection",
                                Severity = "High",
                                CweId = "CWE-89",
                                StartLine = lineSpan.StartLinePosition.Line + 1,
                                EndLine = lineSpan.EndLinePosition.Line + 1,
                                Description = "Potential SQL injection vulnerability due to string concatenation in SQL command.",
                                Confidence = "Medium"
                            });
                        }
                    }
                }
            }
        }

        return issues;
    }

    /// <summary>
    /// Analyzes optimization opportunities.
    /// </summary>
    private List<CachedOptimization> AnalyzeOptimizations(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var optimizations = new List<CachedOptimization>();

        // Check for LINQ .Count() > 0 instead of .Any()
        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();
        foreach (var invocation in invocations)
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
                memberAccess.Name.Identifier.Text == "Count")
            {
                var parent = invocation.Parent;
                if (parent is BinaryExpressionSyntax binary &&
                    (binary.IsKind(SyntaxKind.GreaterThanExpression) ||
                     binary.IsKind(SyntaxKind.NotEqualsExpression)))
                {
                    if (binary.Right is LiteralExpressionSyntax literal &&
                        literal.Token.ValueText == "0")
                    {
                        var lineSpan = binary.GetLocation().GetLineSpan();
                        optimizations.Add(new CachedOptimization
                        {
                            Category = "Performance",
                            Type = "UseAnyInsteadOfCount",
                            StartLine = lineSpan.StartLinePosition.Line + 1,
                            EndLine = lineSpan.EndLinePosition.Line + 1,
                            Description = "Use .Any() instead of .Count() > 0 for better performance.",
                            Confidence = "High"
                        });
                    }
                }
            }
        }

        // Check for string concatenation in loops
        var loops = root.DescendantNodes()
            .Where(n => n is ForStatementSyntax or ForEachStatementSyntax or WhileStatementSyntax);

        foreach (var loop in loops)
        {
            var assignments = loop.DescendantNodes().OfType<AssignmentExpressionSyntax>()
                .Where(a => a.IsKind(SyntaxKind.AddAssignmentExpression));

            foreach (var assignment in assignments)
            {
                var typeInfo = semanticModel.GetTypeInfo(assignment.Left);
                if (typeInfo.Type?.SpecialType == SpecialType.System_String)
                {
                    var lineSpan = assignment.GetLocation().GetLineSpan();
                    optimizations.Add(new CachedOptimization
                    {
                        Category = "Performance",
                        Type = "UseStringBuilder",
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = "String concatenation in loop. Consider using StringBuilder.",
                        Confidence = "High"
                    });
                }
            }
        }

        return optimizations;
    }

    /// <summary>
    /// Calculates file-level metrics.
    /// </summary>
    private CachedFileMetrics CalculateFileMetrics(SyntaxNode root)
    {
        var text = root.GetText();
        var lines = text.Lines;
        var totalLines = lines.Count;

        var commentLines = 0;
        var codeLines = 0;

        foreach (var line in lines)
        {
            var lineText = line.ToString().Trim();
            if (string.IsNullOrEmpty(lineText))
                continue;

            if (lineText.StartsWith("//") || lineText.StartsWith("/*") || lineText.StartsWith("*"))
                commentLines++;
            else
                codeLines++;
        }

        var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>().ToList();
        var classes = root.DescendantNodes().OfType<ClassDeclarationSyntax>().Count() +
                      root.DescendantNodes().OfType<RecordDeclarationSyntax>().Count() +
                      root.DescendantNodes().OfType<StructDeclarationSyntax>().Count();

        var complexities = methods.Select(m => CalculateCyclomaticComplexity(m)).ToList();

        return new CachedFileMetrics
        {
            TotalLines = totalLines,
            CodeLines = codeLines,
            CommentLines = commentLines,
            MethodCount = methods.Count,
            ClassCount = classes,
            AverageComplexity = complexities.Count > 0 ? complexities.Average() : 0,
            MaxComplexity = complexities.Count > 0 ? complexities.Max() : 0
        };
    }

    /// <summary>
    /// Calculates cyclomatic complexity for a method.
    /// </summary>
    private int CalculateCyclomaticComplexity(MethodDeclarationSyntax method)
    {
        var complexity = 1; // Base complexity

        var nodes = method.DescendantNodes();

        // Count decision points
        complexity += nodes.OfType<IfStatementSyntax>().Count();
        complexity += nodes.OfType<ElseClauseSyntax>().Count();
        complexity += nodes.OfType<SwitchStatementSyntax>().Count();
        complexity += nodes.OfType<CaseSwitchLabelSyntax>().Count();
        complexity += nodes.OfType<ForStatementSyntax>().Count();
        complexity += nodes.OfType<ForEachStatementSyntax>().Count();
        complexity += nodes.OfType<WhileStatementSyntax>().Count();
        complexity += nodes.OfType<DoStatementSyntax>().Count();
        complexity += nodes.OfType<CatchClauseSyntax>().Count();
        complexity += nodes.OfType<ConditionalExpressionSyntax>().Count();
        complexity += nodes.OfType<BinaryExpressionSyntax>()
            .Count(b => b.IsKind(SyntaxKind.LogicalAndExpression) ||
                        b.IsKind(SyntaxKind.LogicalOrExpression) ||
                        b.IsKind(SyntaxKind.CoalesceExpression));

        return complexity;
    }

    /// <summary>
    /// Analyzes refactoring opportunities.
    /// </summary>
    private CachedRefactoringResult AnalyzeRefactoring(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var result = new CachedRefactoringResult();
        var longMethods = new List<CachedLongMethod>();
        var godClasses = new List<CachedGodClass>();

        // Long methods
        var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>();
        foreach (var method in methods)
        {
            var lineSpan = method.GetLocation().GetLineSpan();
            var lineCount = lineSpan.EndLinePosition.Line - lineSpan.StartLinePosition.Line + 1;
            var complexity = CalculateCyclomaticComplexity(method);

            if (lineCount > 50 || complexity > 10)
            {
                var containingType = method.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault();
                longMethods.Add(new CachedLongMethod
                {
                    Line = lineSpan.StartLinePosition.Line + 1,
                    ClassName = containingType?.Identifier.Text ?? "Unknown",
                    MethodName = method.Identifier.Text,
                    LineCount = lineCount,
                    Complexity = complexity
                });
            }
        }

        // God classes
        var classes = root.DescendantNodes().OfType<ClassDeclarationSyntax>();
        foreach (var cls in classes)
        {
            var methodCount = cls.Members.OfType<MethodDeclarationSyntax>().Count();
            var fieldCount = cls.Members.OfType<FieldDeclarationSyntax>()
                .SelectMany(f => f.Declaration.Variables).Count();

            if (methodCount > 20 || fieldCount > 15)
            {
                var lineSpan = cls.GetLocation().GetLineSpan();
                godClasses.Add(new CachedGodClass
                {
                    Line = lineSpan.StartLinePosition.Line + 1,
                    ClassName = cls.Identifier.Text,
                    MethodCount = methodCount,
                    FieldCount = fieldCount,
                    LCOM = CalculateLCOM(cls)
                });
            }
        }

        return result with
        {
            LongMethods = longMethods,
            GodClasses = godClasses
        };
    }

    /// <summary>
    /// Calculates LCOM (Lack of Cohesion of Methods) for a class.
    /// </summary>
    private double CalculateLCOM(ClassDeclarationSyntax cls)
    {
        var methods = cls.Members.OfType<MethodDeclarationSyntax>().ToList();
        var fields = cls.Members.OfType<FieldDeclarationSyntax>()
            .SelectMany(f => f.Declaration.Variables)
            .Select(v => v.Identifier.Text)
            .ToHashSet();

        if (methods.Count <= 1 || fields.Count == 0)
            return 0;

        var methodFieldSets = new List<HashSet<string>>();
        foreach (var method in methods)
        {
            var usedFields = method.DescendantNodes()
                .OfType<IdentifierNameSyntax>()
                .Select(id => id.Identifier.Text)
                .Where(name => fields.Contains(name))
                .ToHashSet();
            methodFieldSets.Add(usedFields);
        }

        // Calculate LCOM4 (number of connected components in method-field graph)
        var pairs = methodFieldSets.Count * (methodFieldSets.Count - 1) / 2;
        var sharedPairs = 0;

        for (int i = 0; i < methodFieldSets.Count; i++)
        {
            for (int j = i + 1; j < methodFieldSets.Count; j++)
            {
                if (methodFieldSets[i].Intersect(methodFieldSets[j]).Any())
                    sharedPairs++;
            }
        }

        return pairs > 0 ? (double)(pairs - sharedPairs) / pairs : 0;
    }

    /// <summary>
    /// Creates result from cached data when no changes detected.
    /// </summary>
    private IncrementalAnalysisResult CreateResultFromCache(
        Project project,
        ChangeDetectionResult changes,
        Stopwatch stopwatch)
    {
        var mergedResults = MergeResults(
            new Dictionary<string, FileAnalysisResult>(),
            changes.UnchangedFiles);

        stopwatch.Stop();

        var totalFiles = project.Documents
            .Count(d => d.FilePath != null && d.FilePath.EndsWith(".cs"));

        return new IncrementalAnalysisResult
        {
            IsIncremental = true,
            FilesAnalyzed = 0,
            FilesCached = changes.UnchangedFiles.Count,
            TotalFiles = totalFiles,
            TimeSaved = TimeSpan.FromMilliseconds(totalFiles * 50), // Estimated
            Changes = changes,
            Results = mergedResults
        };
    }

    /// <summary>
    /// Merges fresh analysis results with cached results.
    /// </summary>
    private MergedAnalysisResults MergeResults(
        Dictionary<string, FileAnalysisResult> freshResults,
        List<string> unchangedFiles)
    {
        var allPerformanceIssues = new List<CachedIssue>();
        var allExceptionIssues = new List<CachedIssue>();
        var allResourceIssues = new List<CachedIssue>();
        var allSecurityIssues = new List<CachedSecurityIssue>();
        var allOptimizations = new List<CachedOptimization>();
        var allLongMethods = new List<CachedLongMethod>();
        var allGodClasses = new List<CachedGodClass>();

        var totalLines = 0;
        var totalMethods = 0;
        var totalClasses = 0;
        var complexities = new List<double>();
        var maxComplexity = 0;

        // Add fresh results
        foreach (var (filePath, result) in freshResults)
        {
            AddFileResultsToMerged(
                result,
                allPerformanceIssues,
                allExceptionIssues,
                allResourceIssues,
                allSecurityIssues,
                allOptimizations,
                allLongMethods,
                allGodClasses,
                ref totalLines,
                ref totalMethods,
                ref totalClasses,
                complexities,
                ref maxComplexity);
        }

        // Add cached results for unchanged files
        foreach (var filePath in unchangedFiles)
        {
            var cached = _cache.GetFileEntry(filePath);
            if (cached?.Results != null)
            {
                AddFileResultsToMerged(
                    cached.Results,
                    allPerformanceIssues,
                    allExceptionIssues,
                    allResourceIssues,
                    allSecurityIssues,
                    allOptimizations,
                    allLongMethods,
                    allGodClasses,
                    ref totalLines,
                    ref totalMethods,
                    ref totalClasses,
                    complexities,
                    ref maxComplexity);
            }
        }

        var averageComplexity = complexities.Count > 0 ? complexities.Average() : 0;
        var methodsAboveThreshold = complexities.Count(c => c > 10);

        return new MergedAnalysisResults
        {
            PerformanceIssues = allPerformanceIssues,
            ExceptionIssues = allExceptionIssues,
            ResourceIssues = allResourceIssues,
            SecurityIssues = allSecurityIssues,
            Optimizations = allOptimizations,
            Refactoring = new CachedRefactoringResult
            {
                LongMethods = allLongMethods,
                GodClasses = allGodClasses
            },
            Metrics = new AggregatedMetrics
            {
                TotalFiles = freshResults.Count + unchangedFiles.Count,
                TotalLines = totalLines,
                TotalMethods = totalMethods,
                TotalClasses = totalClasses,
                AverageComplexity = averageComplexity,
                MaxComplexity = maxComplexity,
                MethodsAboveComplexityThreshold = methodsAboveThreshold
            }
        };
    }

    private void AddFileResultsToMerged(
        FileAnalysisResult result,
        List<CachedIssue> allPerformanceIssues,
        List<CachedIssue> allExceptionIssues,
        List<CachedIssue> allResourceIssues,
        List<CachedSecurityIssue> allSecurityIssues,
        List<CachedOptimization> allOptimizations,
        List<CachedLongMethod> allLongMethods,
        List<CachedGodClass> allGodClasses,
        ref int totalLines,
        ref int totalMethods,
        ref int totalClasses,
        List<double> complexities,
        ref int maxComplexity)
    {
        allPerformanceIssues.AddRange(result.PerformanceIssues);
        allExceptionIssues.AddRange(result.ExceptionIssues);
        allResourceIssues.AddRange(result.ResourceIssues);
        allSecurityIssues.AddRange(result.SecurityIssues);
        allOptimizations.AddRange(result.Optimizations);

        if (result.Refactoring != null)
        {
            allLongMethods.AddRange(result.Refactoring.LongMethods);
            allGodClasses.AddRange(result.Refactoring.GodClasses);
        }

        if (result.Metrics != null)
        {
            totalLines += result.Metrics.TotalLines;
            totalMethods += result.Metrics.MethodCount;
            totalClasses += result.Metrics.ClassCount;
            complexities.Add(result.Metrics.AverageComplexity);
            if (result.Metrics.MaxComplexity > maxComplexity)
                maxComplexity = result.Metrics.MaxComplexity;
        }
    }
}
