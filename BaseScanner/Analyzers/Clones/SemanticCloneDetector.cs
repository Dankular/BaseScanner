using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using BaseScanner.Analyzers.Clones.Models;
using System.Diagnostics;

namespace BaseScanner.Analyzers.Clones;

/// <summary>
/// Main coordinator for semantic code clone detection.
/// Orchestrates the analysis pipeline: extraction, indexing, detection, classification, and reporting.
/// </summary>
public class SemanticCloneDetector
{
    private readonly CloneDetectionOptions _options;
    private CloneAnalysisEngine? _engine;

    public SemanticCloneDetector() : this(new CloneDetectionOptions()) { }

    public SemanticCloneDetector(CloneDetectionOptions options)
    {
        _options = options;
    }

    /// <summary>
    /// Analyze a project for code clones.
    /// </summary>
    public async Task<CloneDetectionResult> AnalyzeProjectAsync(Project project)
    {
        var stopwatch = Stopwatch.StartNew();
        var warnings = new List<string>();

        _engine = new CloneAnalysisEngine(_options);

        try
        {
            // Phase 1: Extract fragments from all documents
            var allFragments = new List<CodeFragment>();
            var totalLines = 0;
            var filesAnalyzed = 0;

            foreach (var document in project.Documents)
            {
                if (document.FilePath == null) continue;

                try
                {
                    var semanticModel = await document.GetSemanticModelAsync();
                    if (semanticModel == null) continue;

                    var fragments = await _engine.ExtractFragmentsAsync(document, semanticModel);
                    allFragments.AddRange(fragments);

                    // Count lines
                    var root = await document.GetSyntaxRootAsync();
                    if (root != null)
                    {
                        totalLines += root.GetText().Lines.Count;
                        filesAnalyzed++;
                    }
                }
                catch (Exception ex)
                {
                    warnings.Add($"Error analyzing {document.FilePath}: {ex.Message}");
                }
            }

            // Phase 2: Index fragments
            _engine.IndexFragments(allFragments);

            // Phase 3: Detect clone pairs
            var clonePairs = _engine.DetectClonePairs();

            // Phase 4: Form clone classes
            var cloneClasses = _engine.FormCloneClasses(clonePairs);

            // Phase 5: Suggest extractions
            var extractionOpportunities = _engine.SuggestExtractions(cloneClasses);

            // Compute metrics
            var metrics = _engine.ComputeMetrics(clonePairs, cloneClasses, totalLines);
            var byType = _engine.ComputeStatisticsByType(clonePairs, cloneClasses);

            stopwatch.Stop();

            return new CloneDetectionResult
            {
                AnalyzedPath = project.FilePath ?? project.Name,
                AnalyzedAt = DateTime.UtcNow,
                FilesAnalyzed = filesAnalyzed,
                TotalLinesAnalyzed = totalLines,
                ClonePairs = clonePairs,
                CloneClasses = cloneClasses,
                ExtractionOpportunities = extractionOpportunities,
                Metrics = metrics,
                ByType = byType,
                Warnings = warnings,
                Duration = stopwatch.Elapsed
            };
        }
        finally
        {
            _engine.ClearIndexes();
        }
    }

    /// <summary>
    /// Analyze a solution for code clones across all projects.
    /// </summary>
    public async Task<CloneDetectionResult> AnalyzeSolutionAsync(Solution solution)
    {
        var stopwatch = Stopwatch.StartNew();
        var warnings = new List<string>();

        _engine = new CloneAnalysisEngine(_options);

        try
        {
            var allFragments = new List<CodeFragment>();
            var totalLines = 0;
            var filesAnalyzed = 0;

            foreach (var project in solution.Projects)
            {
                foreach (var document in project.Documents)
                {
                    if (document.FilePath == null) continue;

                    try
                    {
                        var semanticModel = await document.GetSemanticModelAsync();
                        if (semanticModel == null) continue;

                        var fragments = await _engine.ExtractFragmentsAsync(document, semanticModel);
                        allFragments.AddRange(fragments);

                        var root = await document.GetSyntaxRootAsync();
                        if (root != null)
                        {
                            totalLines += root.GetText().Lines.Count;
                            filesAnalyzed++;
                        }
                    }
                    catch (Exception ex)
                    {
                        warnings.Add($"Error analyzing {document.FilePath}: {ex.Message}");
                    }
                }
            }

            _engine.IndexFragments(allFragments);
            var clonePairs = _engine.DetectClonePairs();
            var cloneClasses = _engine.FormCloneClasses(clonePairs);
            var extractionOpportunities = _engine.SuggestExtractions(cloneClasses);
            var metrics = _engine.ComputeMetrics(clonePairs, cloneClasses, totalLines);
            var byType = _engine.ComputeStatisticsByType(clonePairs, cloneClasses);

            stopwatch.Stop();

            return new CloneDetectionResult
            {
                AnalyzedPath = solution.FilePath ?? "Solution",
                AnalyzedAt = DateTime.UtcNow,
                FilesAnalyzed = filesAnalyzed,
                TotalLinesAnalyzed = totalLines,
                ClonePairs = clonePairs,
                CloneClasses = cloneClasses,
                ExtractionOpportunities = extractionOpportunities,
                Metrics = metrics,
                ByType = byType,
                Warnings = warnings,
                Duration = stopwatch.Elapsed
            };
        }
        finally
        {
            _engine.ClearIndexes();
        }
    }

    /// <summary>
    /// Analyze source code from text for clones (for testing or single-file analysis).
    /// </summary>
    public CloneDetectionResult AnalyzeSourceCode(string sourceCode, string fileName = "source.cs")
    {
        var stopwatch = Stopwatch.StartNew();

        var tree = CSharpSyntaxTree.ParseText(sourceCode, path: fileName);
        var compilation = CSharpCompilation.Create("Analysis")
            .AddReferences(MetadataReference.CreateFromFile(typeof(object).Assembly.Location))
            .AddSyntaxTrees(tree);

        var semanticModel = compilation.GetSemanticModel(tree);
        var root = tree.GetRoot();

        _engine = new CloneAnalysisEngine(_options);

        var fragments = ExtractFragmentsFromSyntaxTree(root, fileName, semanticModel);
        _engine.IndexFragments(fragments);

        var clonePairs = _engine.DetectClonePairs();
        var cloneClasses = _engine.FormCloneClasses(clonePairs);
        var extractionOpportunities = _engine.SuggestExtractions(cloneClasses);

        var totalLines = root.GetText().Lines.Count;
        var metrics = _engine.ComputeMetrics(clonePairs, cloneClasses, totalLines);
        var byType = _engine.ComputeStatisticsByType(clonePairs, cloneClasses);

        stopwatch.Stop();

        return new CloneDetectionResult
        {
            AnalyzedPath = fileName,
            AnalyzedAt = DateTime.UtcNow,
            FilesAnalyzed = 1,
            TotalLinesAnalyzed = totalLines,
            ClonePairs = clonePairs,
            CloneClasses = cloneClasses,
            ExtractionOpportunities = extractionOpportunities,
            Metrics = metrics,
            ByType = byType,
            Warnings = [],
            Duration = stopwatch.Elapsed
        };
    }

    /// <summary>
    /// Analyze multiple source files for clones.
    /// </summary>
    public CloneDetectionResult AnalyzeSourceFiles(Dictionary<string, string> sourceFiles)
    {
        var stopwatch = Stopwatch.StartNew();

        var trees = sourceFiles.Select(kv =>
            CSharpSyntaxTree.ParseText(kv.Value, path: kv.Key)).ToList();

        var compilation = CSharpCompilation.Create("Analysis")
            .AddReferences(MetadataReference.CreateFromFile(typeof(object).Assembly.Location))
            .AddSyntaxTrees(trees);

        _engine = new CloneAnalysisEngine(_options);

        var allFragments = new List<CodeFragment>();
        var totalLines = 0;

        foreach (var tree in trees)
        {
            var semanticModel = compilation.GetSemanticModel(tree);
            var root = tree.GetRoot();
            var fileName = tree.FilePath;

            var fragments = ExtractFragmentsFromSyntaxTree(root, fileName, semanticModel);
            allFragments.AddRange(fragments);
            totalLines += root.GetText().Lines.Count;
        }

        _engine.IndexFragments(allFragments);

        var clonePairs = _engine.DetectClonePairs();
        var cloneClasses = _engine.FormCloneClasses(clonePairs);
        var extractionOpportunities = _engine.SuggestExtractions(cloneClasses);
        var metrics = _engine.ComputeMetrics(clonePairs, cloneClasses, totalLines);
        var byType = _engine.ComputeStatisticsByType(clonePairs, cloneClasses);

        stopwatch.Stop();

        return new CloneDetectionResult
        {
            AnalyzedPath = $"[{sourceFiles.Count} files]",
            AnalyzedAt = DateTime.UtcNow,
            FilesAnalyzed = sourceFiles.Count,
            TotalLinesAnalyzed = totalLines,
            ClonePairs = clonePairs,
            CloneClasses = cloneClasses,
            ExtractionOpportunities = extractionOpportunities,
            Metrics = metrics,
            ByType = byType,
            Warnings = [],
            Duration = stopwatch.Elapsed
        };
    }

    private List<CodeFragment> ExtractFragmentsFromSyntaxTree(
        SyntaxNode root,
        string filePath,
        SemanticModel semanticModel)
    {
        var fragments = new List<CodeFragment>();
        var hasher = new SemanticHasher(_options.NGramSize, _options.MinHashFunctions);
        var normalizer = new SyntaxNormalizer();

        if (_options.MethodLevelOnly)
        {
            foreach (var method in root.DescendantNodes().OfType<Microsoft.CodeAnalysis.CSharp.Syntax.MethodDeclarationSyntax>())
            {
                var fragment = CreateFragment(method, filePath, semanticModel, hasher, normalizer);
                if (fragment != null)
                    fragments.Add(fragment);
            }
        }
        else
        {
            foreach (var method in root.DescendantNodes().OfType<Microsoft.CodeAnalysis.CSharp.Syntax.MethodDeclarationSyntax>())
            {
                var body = method.Body ?? (SyntaxNode?)method.ExpressionBody;
                if (body != null)
                {
                    var fragment = CreateFragment(body, filePath, semanticModel, hasher, normalizer, method);
                    if (fragment != null)
                        fragments.Add(fragment);
                }
            }
        }

        return fragments;
    }

    private CodeFragment? CreateFragment(
        SyntaxNode node,
        string filePath,
        SemanticModel semanticModel,
        SemanticHasher hasher,
        SyntaxNormalizer normalizer,
        Microsoft.CodeAnalysis.CSharp.Syntax.MethodDeclarationSyntax? containingMethod = null)
    {
        var lineSpan = node.GetLocation().GetLineSpan();
        var lineCount = lineSpan.EndLinePosition.Line - lineSpan.StartLinePosition.Line + 1;

        if (lineCount < _options.MinLines || lineCount > _options.MaxLines)
            return null;

        var tokenCount = node.DescendantTokens().Count();
        if (tokenCount < _options.MinTokens)
            return null;

        var sourceCode = node.ToFullString();

        normalizer.Reset();
        var normalizedTokens = normalizer.NormalizeTokens(node);
        var normalizedCode = string.Join(" ", normalizedTokens);

        var exactHash = hasher.ComputeExactHash(node);
        var normalizedHash = hasher.ComputeStringHash(normalizedCode);
        var tokenFingerprints = hasher.ComputeNormalizedFingerprints(normalizedTokens);
        var astHashes = hasher.ComputeAstHashes(node);
        var controlFlowSignature = hasher.ComputeControlFlowSignature(node);

        var containingClass = node.Ancestors()
            .OfType<Microsoft.CodeAnalysis.CSharp.Syntax.ClassDeclarationSyntax>()
            .FirstOrDefault();

        var fragmentId = $"{filePath}:{lineSpan.StartLinePosition.Line}:{lineSpan.EndLinePosition.Line}";

        return new CodeFragment
        {
            Id = fragmentId,
            FilePath = filePath,
            StartLine = lineSpan.StartLinePosition.Line + 1,
            EndLine = lineSpan.EndLinePosition.Line + 1,
            StartPosition = node.SpanStart,
            EndPosition = node.Span.End,
            SourceCode = sourceCode,
            NormalizedCode = normalizedCode,
            ContainingMethod = containingMethod?.Identifier.Text,
            ContainingClass = containingClass?.Identifier.Text,
            TokenCount = tokenCount,
            SemanticHash = exactHash,
            NormalizedHash = normalizedHash,
            TokenFingerprints = tokenFingerprints,
            AstHashes = astHashes,
            ControlFlowSignature = controlFlowSignature
        };
    }

    /// <summary>
    /// Find clones for a specific code snippet.
    /// </summary>
    public async Task<List<ClonePair>> FindClonesForSnippetAsync(
        Project project,
        string snippet)
    {
        // First, analyze the project to build the index
        await AnalyzeProjectAsync(project);

        if (_engine == null)
            return [];

        // Create a fragment for the snippet
        var tree = CSharpSyntaxTree.ParseText(snippet);
        var compilation = CSharpCompilation.Create("Snippet")
            .AddReferences(MetadataReference.CreateFromFile(typeof(object).Assembly.Location))
            .AddSyntaxTrees(tree);

        var semanticModel = compilation.GetSemanticModel(tree);
        var root = tree.GetRoot();

        var hasher = new SemanticHasher(_options.NGramSize, _options.MinHashFunctions);
        var normalizer = new SyntaxNormalizer();

        var snippetFragment = CreateFragment(root, "snippet.cs", semanticModel, hasher, normalizer);

        if (snippetFragment == null)
            return [];

        // Find candidates
        var candidates = _engine.FindCandidates(snippetFragment);

        // Classify each pair
        var classifier = new CloneClassifier(hasher, normalizer, _options);
        var pairs = new List<ClonePair>();

        foreach (var candidate in candidates)
        {
            var pair = classifier.ClassifyClonePair(snippetFragment, candidate);
            if (pair.Similarity >= _options.MinSimilarity)
            {
                pairs.Add(pair);
            }
        }

        return pairs.OrderByDescending(p => p.Similarity).ToList();
    }

    /// <summary>
    /// Generate a summary report of clone detection results.
    /// </summary>
    public static string GenerateReport(CloneDetectionResult result)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("===========================================");
        sb.AppendLine("        CLONE DETECTION REPORT");
        sb.AppendLine("===========================================");
        sb.AppendLine();

        sb.AppendLine($"Analyzed: {result.AnalyzedPath}");
        sb.AppendLine($"Date: {result.AnalyzedAt:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Duration: {result.Duration.TotalSeconds:F2} seconds");
        sb.AppendLine();

        sb.AppendLine("--- SUMMARY ---");
        sb.AppendLine($"Files analyzed: {result.FilesAnalyzed}");
        sb.AppendLine($"Total lines: {result.TotalLinesAnalyzed:N0}");
        sb.AppendLine($"Clone pairs found: {result.Metrics.TotalClonePairs}");
        sb.AppendLine($"Clone classes: {result.Metrics.TotalCloneClasses}");
        sb.AppendLine($"Clone coverage: {result.Metrics.CloneCoverage:F1}%");
        sb.AppendLine($"Cloned lines: {result.Metrics.ClonedLines:N0}");
        sb.AppendLine($"Average clone size: {result.Metrics.AverageCloneSize:F1} lines");
        sb.AppendLine($"Largest clone: {result.Metrics.LargestCloneSize} lines");
        sb.AppendLine($"Average similarity: {result.Metrics.AverageSimilarity:P1}");
        sb.AppendLine($"Potential lines saved: {result.Metrics.PotentialLinesSaved:N0}");
        sb.AppendLine();

        sb.AppendLine("--- BY CLONE TYPE ---");
        foreach (var (type, stats) in result.ByType.OrderBy(kv => kv.Key))
        {
            sb.AppendLine($"  {GetCloneTypeName(type)}:");
            sb.AppendLine($"    Pairs: {stats.PairCount} ({stats.Percentage:F1}%)");
            sb.AppendLine($"    Classes: {stats.ClassCount}");
            sb.AppendLine($"    Lines: {stats.TotalLines:N0}");
            sb.AppendLine($"    Avg similarity: {stats.AverageSimilarity:P1}");
        }
        sb.AppendLine();

        if (result.CloneClasses.Count > 0)
        {
            sb.AppendLine("--- TOP CLONE CLASSES ---");
            foreach (var cloneClass in result.CloneClasses.Take(10))
            {
                sb.AppendLine($"  [{cloneClass.Id}] {GetCloneTypeName(cloneClass.CloneType)}");
                sb.AppendLine($"    Instances: {cloneClass.InstanceCount} across {cloneClass.FileCount} files");
                sb.AppendLine($"    Total lines: {cloneClass.TotalLines}, Potential savings: {cloneClass.PotentialSavingsLines}");
                sb.AppendLine($"    Average similarity: {cloneClass.AverageSimilarity:P1}");

                foreach (var fragment in cloneClass.Fragments.Take(3))
                {
                    sb.AppendLine($"      - {fragment.FilePath}:{fragment.StartLine}-{fragment.EndLine}");
                    if (fragment.ContainingMethod != null)
                        sb.AppendLine($"        Method: {fragment.ContainingMethod}");
                }
                if (cloneClass.InstanceCount > 3)
                    sb.AppendLine($"      ... and {cloneClass.InstanceCount - 3} more instances");
                sb.AppendLine();
            }
        }

        if (result.ExtractionOpportunities.Count > 0)
        {
            sb.AppendLine("--- EXTRACTION OPPORTUNITIES ---");
            foreach (var opportunity in result.ExtractionOpportunities.Take(10))
            {
                sb.AppendLine($"  {opportunity.SuggestedName} ({opportunity.ExtractionType})");
                sb.AppendLine($"    {opportunity.Description}");
                sb.AppendLine($"    Confidence: {opportunity.Confidence:P0}, Complexity: {opportunity.Complexity}");
                sb.AppendLine($"    Estimated lines saved: {opportunity.EstimatedLinesSaved}");

                if (opportunity.SuggestedParameters.Count > 0)
                {
                    sb.AppendLine($"    Suggested parameters:");
                    foreach (var param in opportunity.SuggestedParameters)
                    {
                        sb.AppendLine($"      - {param.Type} {param.Name}");
                    }
                }

                if (opportunity.Risks.Count > 0)
                {
                    sb.AppendLine($"    Risks:");
                    foreach (var risk in opportunity.Risks)
                    {
                        sb.AppendLine($"      - {risk}");
                    }
                }
                sb.AppendLine();
            }
        }

        if (result.Warnings.Count > 0)
        {
            sb.AppendLine("--- WARNINGS ---");
            foreach (var warning in result.Warnings)
            {
                sb.AppendLine($"  - {warning}");
            }
        }

        sb.AppendLine("===========================================");

        return sb.ToString();
    }

    private static string GetCloneTypeName(CloneType type)
    {
        return type switch
        {
            CloneType.Type1_Exact => "Type 1 (Exact)",
            CloneType.Type2_Renamed => "Type 2 (Renamed)",
            CloneType.Type3_NearMiss => "Type 3 (Near-miss)",
            CloneType.Type4_Semantic => "Type 4 (Semantic)",
            _ => type.ToString()
        };
    }

    /// <summary>
    /// Generate a JSON representation of the results.
    /// </summary>
    public static string GenerateJsonReport(CloneDetectionResult result)
    {
        var options = new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase
        };

        // Create a simplified version for JSON serialization
        var report = new
        {
            result.AnalyzedPath,
            AnalyzedAt = result.AnalyzedAt.ToString("o"),
            DurationSeconds = result.Duration.TotalSeconds,
            result.FilesAnalyzed,
            result.TotalLinesAnalyzed,
            Metrics = new
            {
                result.Metrics.TotalClonePairs,
                result.Metrics.TotalCloneClasses,
                result.Metrics.ClonedLines,
                result.Metrics.CloneCoverage,
                result.Metrics.AverageCloneSize,
                result.Metrics.LargestCloneSize,
                result.Metrics.AverageSimilarity,
                result.Metrics.FilesWithClones,
                result.Metrics.PotentialLinesSaved,
                result.Metrics.CloneDensity
            },
            CloneClasses = result.CloneClasses.Select(c => new
            {
                c.Id,
                Type = c.CloneType.ToString(),
                c.InstanceCount,
                c.FileCount,
                c.TotalLines,
                c.PotentialSavingsLines,
                c.AverageSimilarity,
                Fragments = c.Fragments.Select(f => new
                {
                    f.FilePath,
                    f.StartLine,
                    f.EndLine,
                    f.ContainingMethod,
                    f.ContainingClass,
                    f.LineCount
                })
            }),
            ExtractionOpportunities = result.ExtractionOpportunities.Select(o => new
            {
                o.SuggestedName,
                ExtractionType = o.ExtractionType.ToString(),
                o.Confidence,
                Complexity = o.Complexity.ToString(),
                o.EstimatedLinesSaved,
                o.Description,
                Parameters = o.SuggestedParameters.Select(p => new
                {
                    p.Name,
                    p.Type,
                    p.VariesBetweenInstances
                }),
                o.Risks
            }),
            result.Warnings
        };

        return System.Text.Json.JsonSerializer.Serialize(report, options);
    }
}
