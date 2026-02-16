using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Clones.Models;
using System.Collections.Concurrent;

namespace BaseScanner.Analyzers.Clones;

/// <summary>
/// Core engine for clone detection using multiple algorithms and techniques.
/// Implements phases: normalization, fingerprinting, similarity detection, and clone class formation.
/// </summary>
public class CloneAnalysisEngine
{
    private readonly SemanticHasher _hasher;
    private readonly SyntaxNormalizer _normalizer;
    private readonly CloneClassifier _classifier;
    private readonly CloneDetectionOptions _options;

    // LSH buckets for fast approximate matching
    private readonly ConcurrentDictionary<long, List<string>> _lshBuckets = new();

    // Fragment index for quick lookups
    private readonly ConcurrentDictionary<string, CodeFragment> _fragmentIndex = new();

    // Hash indexes for different clone types
    private readonly ConcurrentDictionary<long, List<string>> _exactHashIndex = new();
    private readonly ConcurrentDictionary<long, List<string>> _normalizedHashIndex = new();

    public CloneAnalysisEngine(CloneDetectionOptions options)
    {
        _options = options;
        _hasher = new SemanticHasher(options.NGramSize, options.MinHashFunctions);
        _normalizer = new SyntaxNormalizer();
        _classifier = new CloneClassifier(_hasher, _normalizer, options);
    }

    /// <summary>
    /// Phase 1: Extract and normalize code fragments from a document.
    /// </summary>
    public async Task<List<CodeFragment>> ExtractFragmentsAsync(
        Document document,
        SemanticModel semanticModel)
    {
        var fragments = new List<CodeFragment>();
        var root = await document.GetSyntaxRootAsync();

        if (root == null || document.FilePath == null)
            return fragments;

        // Check exclude patterns
        if (ShouldExcludeFile(document.FilePath))
            return fragments;

        if (_options.MethodLevelOnly)
        {
            // Extract method-level fragments
            var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>();
            foreach (var method in methods)
            {
                var fragment = CreateFragment(method, document.FilePath, semanticModel);
                if (fragment != null && IsValidFragment(fragment))
                {
                    fragments.Add(fragment);
                }
            }
        }
        else
        {
            // Extract block-level fragments (more granular)
            fragments.AddRange(ExtractBlockFragments(root, document.FilePath, semanticModel));
        }

        return fragments;
    }

    /// <summary>
    /// Extract fragments from code blocks (method bodies, loops, if blocks, etc.).
    /// </summary>
    private List<CodeFragment> ExtractBlockFragments(
        SyntaxNode root,
        string filePath,
        SemanticModel semanticModel)
    {
        var fragments = new List<CodeFragment>();

        // Extract method bodies
        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            var body = method.Body ?? (SyntaxNode?)method.ExpressionBody;
            if (body != null)
            {
                var fragment = CreateFragment(body, filePath, semanticModel, method);
                if (fragment != null && IsValidFragment(fragment))
                {
                    fragments.Add(fragment);
                }
            }
        }

        // Extract significant blocks (loops, conditionals)
        foreach (var block in root.DescendantNodes().OfType<BlockSyntax>())
        {
            // Skip method bodies (already handled)
            if (block.Parent is MethodDeclarationSyntax)
                continue;

            // Only extract if block is substantial
            var lineCount = GetLineCount(block);
            if (lineCount >= _options.MinLines)
            {
                var method = block.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
                var fragment = CreateFragment(block, filePath, semanticModel, method);
                if (fragment != null && IsValidFragment(fragment))
                {
                    fragments.Add(fragment);
                }
            }
        }

        return fragments;
    }

    /// <summary>
    /// Create a CodeFragment from a syntax node.
    /// </summary>
    private CodeFragment? CreateFragment(
        SyntaxNode node,
        string filePath,
        SemanticModel semanticModel,
        MethodDeclarationSyntax? containingMethod = null)
    {
        var lineSpan = node.GetLocation().GetLineSpan();
        var lineCount = lineSpan.EndLinePosition.Line - lineSpan.StartLinePosition.Line + 1;

        if (lineCount < _options.MinLines || lineCount > _options.MaxLines)
            return null;

        var sourceCode = node.ToFullString();
        var tokenCount = node.DescendantTokens().Count();

        if (tokenCount < _options.MinTokens)
            return null;

        // Normalize the code
        _normalizer.Reset();
        var normalizedTokens = _normalizer.NormalizeTokens(node);
        var normalizedCode = string.Join(" ", normalizedTokens);

        // Compute hashes
        var exactHash = _hasher.ComputeExactHash(node);
        var normalizedHash = _hasher.ComputeStringHash(normalizedCode);
        var tokenFingerprints = _hasher.ComputeNormalizedFingerprints(normalizedTokens);
        var astHashes = _hasher.ComputeAstHashes(node);
        var controlFlowSignature = _hasher.ComputeControlFlowSignature(node);

        // Get containing class
        var containingClass = node.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();

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
    /// Phase 2: Index fragments for efficient lookup.
    /// </summary>
    public void IndexFragments(IEnumerable<CodeFragment> fragments)
    {
        foreach (var fragment in fragments)
        {
            // Add to fragment index
            _fragmentIndex[fragment.Id] = fragment;

            // Index by exact hash (Type 1)
            if (_options.DetectType1)
            {
                _exactHashIndex.AddOrUpdate(
                    fragment.SemanticHash,
                    _ => [fragment.Id],
                    (_, list) => { list.Add(fragment.Id); return list; });
            }

            // Index by normalized hash (Type 2)
            if (_options.DetectType2)
            {
                _normalizedHashIndex.AddOrUpdate(
                    fragment.NormalizedHash,
                    _ => [fragment.Id],
                    (_, list) => { list.Add(fragment.Id); return list; });
            }

            // Index in LSH buckets for Type 3/4
            if (_options.DetectType3 || _options.DetectType4)
            {
                var minHashSignature = _hasher.ComputeMinHashSignature(fragment.TokenFingerprints);
                var bands = _hasher.ComputeLshBands(minHashSignature);

                foreach (var band in bands)
                {
                    _lshBuckets.AddOrUpdate(
                        band,
                        _ => [fragment.Id],
                        (_, list) =>
                        {
                            if (!list.Contains(fragment.Id))
                                list.Add(fragment.Id);
                            return list;
                        });
                }
            }
        }
    }

    /// <summary>
    /// Phase 3: Detect clone pairs using indexed fragments.
    /// </summary>
    public List<ClonePair> DetectClonePairs()
    {
        var clonePairs = new ConcurrentBag<ClonePair>();
        var processedPairs = new ConcurrentDictionary<string, bool>();

        // Detect Type 1 clones (exact matches)
        if (_options.DetectType1)
        {
            Parallel.ForEach(_exactHashIndex, hashGroup =>
            {
                var fragmentIds = hashGroup.Value;
                if (fragmentIds.Count < 2) return;

                for (int i = 0; i < fragmentIds.Count; i++)
                {
                    for (int j = i + 1; j < fragmentIds.Count; j++)
                    {
                        var pairKey = GetPairKey(fragmentIds[i], fragmentIds[j]);
                        if (processedPairs.TryAdd(pairKey, true))
                        {
                            var fragment1 = _fragmentIndex[fragmentIds[i]];
                            var fragment2 = _fragmentIndex[fragmentIds[j]];

                            // Skip if same file and overlapping
                            if (FragmentsOverlap(fragment1, fragment2))
                                continue;

                            var pair = _classifier.ClassifyClonePair(fragment1, fragment2);
                            if (pair.Similarity >= _options.MinSimilarity)
                            {
                                clonePairs.Add(pair);
                            }
                        }
                    }
                }
            });
        }

        // Detect Type 2 clones (renamed)
        if (_options.DetectType2)
        {
            Parallel.ForEach(_normalizedHashIndex, hashGroup =>
            {
                var fragmentIds = hashGroup.Value;
                if (fragmentIds.Count < 2) return;

                for (int i = 0; i < fragmentIds.Count; i++)
                {
                    for (int j = i + 1; j < fragmentIds.Count; j++)
                    {
                        var pairKey = GetPairKey(fragmentIds[i], fragmentIds[j]);
                        if (processedPairs.TryAdd(pairKey, true))
                        {
                            var fragment1 = _fragmentIndex[fragmentIds[i]];
                            var fragment2 = _fragmentIndex[fragmentIds[j]];

                            if (FragmentsOverlap(fragment1, fragment2))
                                continue;

                            var pair = _classifier.ClassifyClonePair(fragment1, fragment2);
                            if (pair.Similarity >= _options.MinSimilarity)
                            {
                                clonePairs.Add(pair);
                            }
                        }
                    }
                }
            });
        }

        // Detect Type 3/4 clones using LSH
        if (_options.DetectType3 || _options.DetectType4)
        {
            Parallel.ForEach(_lshBuckets, bucket =>
            {
                var candidateIds = bucket.Value;
                if (candidateIds.Count < 2) return;

                for (int i = 0; i < candidateIds.Count; i++)
                {
                    for (int j = i + 1; j < candidateIds.Count; j++)
                    {
                        var pairKey = GetPairKey(candidateIds[i], candidateIds[j]);
                        if (!processedPairs.TryAdd(pairKey, true))
                            continue;

                        if (!_fragmentIndex.TryGetValue(candidateIds[i], out var fragment1) ||
                            !_fragmentIndex.TryGetValue(candidateIds[j], out var fragment2))
                            continue;

                        if (FragmentsOverlap(fragment1, fragment2))
                            continue;

                        // Compute actual similarity
                        var pair = _classifier.ClassifyClonePair(fragment1, fragment2);

                        if (pair.Similarity >= _options.MinSimilarity)
                        {
                            if ((_options.DetectType3 && pair.CloneType == CloneType.Type3_NearMiss) ||
                                (_options.DetectType4 && pair.CloneType == CloneType.Type4_Semantic))
                            {
                                clonePairs.Add(pair);
                            }
                        }
                    }
                }
            });
        }

        return clonePairs
            .OrderByDescending(p => p.Similarity)
            .Take(_options.MaxResults)
            .ToList();
    }

    /// <summary>
    /// Phase 4: Form clone classes from pairs.
    /// </summary>
    public List<CloneClass> FormCloneClasses(List<ClonePair> clonePairs)
    {
        return _classifier.FormCloneClasses(clonePairs);
    }

    /// <summary>
    /// Phase 5: Suggest extraction opportunities.
    /// </summary>
    public List<ExtractionOpportunity> SuggestExtractions(List<CloneClass> cloneClasses)
    {
        if (!_options.SuggestExtractions)
            return [];

        return _classifier.SuggestExtractions(cloneClasses);
    }

    /// <summary>
    /// Compute overall metrics for the analysis.
    /// </summary>
    public CloneMetrics ComputeMetrics(
        List<ClonePair> clonePairs,
        List<CloneClass> cloneClasses,
        int totalLinesAnalyzed)
    {
        if (clonePairs.Count == 0)
        {
            return new CloneMetrics
            {
                TotalClonePairs = 0,
                TotalCloneClasses = 0,
                ClonedLines = 0,
                CloneCoverage = 0,
                AverageCloneSize = 0,
                LargestCloneSize = 0,
                AverageSimilarity = 0,
                FilesWithClones = 0,
                PotentialLinesSaved = 0,
                CloneDensity = 0
            };
        }

        // Get unique cloned lines
        var clonedLines = new HashSet<string>();
        foreach (var cloneClass in cloneClasses)
        {
            foreach (var fragment in cloneClass.Fragments)
            {
                for (int line = fragment.StartLine; line <= fragment.EndLine; line++)
                {
                    clonedLines.Add($"{fragment.FilePath}:{line}");
                }
            }
        }

        var totalClonedLines = clonedLines.Count;
        var cloneCoverage = totalLinesAnalyzed > 0
            ? (double)totalClonedLines / totalLinesAnalyzed * 100
            : 0;

        var allFragments = cloneClasses.SelectMany(c => c.Fragments).ToList();
        var avgCloneSize = allFragments.Count > 0
            ? allFragments.Average(f => f.LineCount)
            : 0;

        var largestCloneSize = allFragments.Count > 0
            ? allFragments.Max(f => f.LineCount)
            : 0;

        var avgSimilarity = clonePairs.Average(p => p.Similarity);

        var filesWithClones = allFragments
            .Select(f => f.FilePath)
            .Distinct()
            .Count();

        var potentialSavings = cloneClasses.Sum(c => c.PotentialSavingsLines);

        var cloneDensity = totalLinesAnalyzed > 0
            ? (double)cloneClasses.Count / totalLinesAnalyzed * 1000
            : 0;

        return new CloneMetrics
        {
            TotalClonePairs = clonePairs.Count,
            TotalCloneClasses = cloneClasses.Count,
            ClonedLines = totalClonedLines,
            CloneCoverage = cloneCoverage,
            AverageCloneSize = avgCloneSize,
            LargestCloneSize = largestCloneSize,
            AverageSimilarity = avgSimilarity,
            FilesWithClones = filesWithClones,
            PotentialLinesSaved = potentialSavings,
            CloneDensity = cloneDensity
        };
    }

    /// <summary>
    /// Compute statistics by clone type.
    /// </summary>
    public Dictionary<CloneType, CloneTypeStatistics> ComputeStatisticsByType(
        List<ClonePair> clonePairs,
        List<CloneClass> cloneClasses)
    {
        var stats = new Dictionary<CloneType, CloneTypeStatistics>();

        var totalPairs = clonePairs.Count;
        if (totalPairs == 0) return stats;

        foreach (var type in Enum.GetValues<CloneType>())
        {
            var typePairs = clonePairs.Where(p => p.CloneType == type).ToList();
            var typeClasses = cloneClasses.Where(c => c.CloneType == type).ToList();

            if (typePairs.Count == 0 && typeClasses.Count == 0)
                continue;

            var totalLines = typeClasses.Sum(c => c.TotalLines);
            var avgSimilarity = typePairs.Count > 0 ? typePairs.Average(p => p.Similarity) : 0;
            var percentage = (double)typePairs.Count / totalPairs * 100;

            stats[type] = new CloneTypeStatistics
            {
                Type = type,
                PairCount = typePairs.Count,
                ClassCount = typeClasses.Count,
                TotalLines = totalLines,
                AverageSimilarity = avgSimilarity,
                Percentage = percentage
            };
        }

        return stats;
    }

    /// <summary>
    /// Clear all indexes and cached data.
    /// </summary>
    public void ClearIndexes()
    {
        _fragmentIndex.Clear();
        _exactHashIndex.Clear();
        _normalizedHashIndex.Clear();
        _lshBuckets.Clear();
    }

    // Helper methods

    private bool ShouldExcludeFile(string filePath)
    {
        if (!_options.IncludeGeneratedCode)
        {
            foreach (var pattern in _options.ExcludePatterns)
            {
                if (MatchesPattern(filePath, pattern))
                    return true;
            }
        }
        return false;
    }

    private bool MatchesPattern(string filePath, string pattern)
    {
        // Simple wildcard matching
        if (pattern.StartsWith("*"))
        {
            var suffix = pattern[1..];
            return filePath.EndsWith(suffix, StringComparison.OrdinalIgnoreCase);
        }
        return filePath.Contains(pattern, StringComparison.OrdinalIgnoreCase);
    }

    private bool IsValidFragment(CodeFragment fragment)
    {
        // Check minimum thresholds
        if (fragment.TokenCount < _options.MinTokens)
            return false;

        if (fragment.LineCount < _options.MinLines)
            return false;

        if (fragment.LineCount > _options.MaxLines)
            return false;

        // Check for trivial code (only braces, declarations, etc.)
        if (IsTrivialCode(fragment))
            return false;

        return true;
    }

    private bool IsTrivialCode(CodeFragment fragment)
    {
        // Check if the code is mostly empty or trivial
        var normalizedLength = fragment.NormalizedCode.Replace(" ", "").Length;
        if (normalizedLength < 20)
            return true;

        // Check for common trivial patterns
        var trivialPatterns = new[]
        {
            "return;",
            "throw new NotImplementedException();",
            "throw new NotSupportedException();",
            "return null;",
            "return false;",
            "return true;",
            "return 0;",
            "return string.Empty;",
            "return default;",
            "break;",
            "continue;"
        };

        var sourceCode = fragment.SourceCode.Trim();
        return trivialPatterns.Any(p => sourceCode.Equals(p, StringComparison.OrdinalIgnoreCase));
    }

    private bool FragmentsOverlap(CodeFragment f1, CodeFragment f2)
    {
        if (f1.FilePath != f2.FilePath)
            return false;

        // Check for line overlap
        return !(f1.EndLine < f2.StartLine || f2.EndLine < f1.StartLine);
    }

    private string GetPairKey(string id1, string id2)
    {
        // Ensure consistent ordering for pair key
        return string.Compare(id1, id2, StringComparison.Ordinal) <= 0
            ? $"{id1}|{id2}"
            : $"{id2}|{id1}";
    }

    private int GetLineCount(SyntaxNode node)
    {
        var lineSpan = node.GetLocation().GetLineSpan();
        return lineSpan.EndLinePosition.Line - lineSpan.StartLinePosition.Line + 1;
    }

    /// <summary>
    /// Find potential clone candidates for a specific fragment.
    /// </summary>
    public List<CodeFragment> FindCandidates(CodeFragment fragment)
    {
        var candidates = new HashSet<string>();

        // Check exact hash index
        if (_exactHashIndex.TryGetValue(fragment.SemanticHash, out var exactMatches))
        {
            foreach (var id in exactMatches)
            {
                if (id != fragment.Id)
                    candidates.Add(id);
            }
        }

        // Check normalized hash index
        if (_normalizedHashIndex.TryGetValue(fragment.NormalizedHash, out var normalizedMatches))
        {
            foreach (var id in normalizedMatches)
            {
                if (id != fragment.Id)
                    candidates.Add(id);
            }
        }

        // Check LSH buckets
        var minHashSignature = _hasher.ComputeMinHashSignature(fragment.TokenFingerprints);
        var bands = _hasher.ComputeLshBands(minHashSignature);

        foreach (var band in bands)
        {
            if (_lshBuckets.TryGetValue(band, out var lshMatches))
            {
                foreach (var id in lshMatches)
                {
                    if (id != fragment.Id)
                        candidates.Add(id);
                }
            }
        }

        return candidates
            .Where(id => _fragmentIndex.ContainsKey(id))
            .Select(id => _fragmentIndex[id])
            .Where(f => !FragmentsOverlap(fragment, f))
            .ToList();
    }

    /// <summary>
    /// Get all indexed fragments.
    /// </summary>
    public IReadOnlyDictionary<string, CodeFragment> GetFragmentIndex()
    {
        return _fragmentIndex;
    }
}
