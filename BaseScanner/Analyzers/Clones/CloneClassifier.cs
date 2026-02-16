using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Clones.Models;

namespace BaseScanner.Analyzers.Clones;

/// <summary>
/// Classifies clone pairs by type and determines similarity metrics.
/// </summary>
public class CloneClassifier
{
    private readonly SemanticHasher _hasher;
    private readonly SyntaxNormalizer _normalizer;
    private readonly CloneDetectionOptions _options;

    public CloneClassifier(
        SemanticHasher hasher,
        SyntaxNormalizer normalizer,
        CloneDetectionOptions options)
    {
        _hasher = hasher;
        _normalizer = normalizer;
        _options = options;
    }

    /// <summary>
    /// Classify a clone pair by determining its type and computing similarity.
    /// </summary>
    public ClonePair ClassifyClonePair(CodeFragment fragment1, CodeFragment fragment2)
    {
        // Try to classify from most specific (Type 1) to least specific (Type 4)
        var (cloneType, similarity, editDistance) = DetermineCloneType(fragment1, fragment2);

        var differences = cloneType switch
        {
            CloneType.Type1_Exact => [],
            CloneType.Type2_Renamed => FindRenamedDifferences(fragment1, fragment2),
            CloneType.Type3_NearMiss => FindNearMissDifferences(fragment1, fragment2),
            CloneType.Type4_Semantic => FindSemanticDifferences(fragment1, fragment2),
            _ => []
        };

        return new ClonePair
        {
            Fragment1 = fragment1,
            Fragment2 = fragment2,
            CloneType = cloneType,
            Similarity = similarity,
            EditDistance = editDistance,
            Differences = differences
        };
    }

    /// <summary>
    /// Determine the type of clone relationship between two fragments.
    /// </summary>
    public (CloneType Type, double Similarity, int EditDistance) DetermineCloneType(
        CodeFragment fragment1, CodeFragment fragment2)
    {
        // Type 1: Exact clones - same semantic hash
        if (fragment1.SemanticHash == fragment2.SemanticHash)
        {
            return (CloneType.Type1_Exact, 1.0, 0);
        }

        // Type 2: Renamed clones - same normalized hash
        if (fragment1.NormalizedHash == fragment2.NormalizedHash)
        {
            return (CloneType.Type2_Renamed, 1.0, 0);
        }

        // Compute fingerprint-based similarity
        var fingerprintSimilarity = ComputeFingerprintSimilarity(
            fragment1.TokenFingerprints, fragment2.TokenFingerprints);

        // Compute structural similarity using AST hashes
        var structuralSimilarity = ComputeAstSimilarity(
            fragment1.AstHashes, fragment2.AstHashes);

        // Type 3: Near-miss clones - high similarity with small edit distance
        if (fingerprintSimilarity >= _options.MinSimilarity)
        {
            var editDistance = ComputeEditDistance(fragment1.NormalizedCode, fragment2.NormalizedCode);

            if (editDistance <= _options.MaxEditDistance)
            {
                var similarity = (fingerprintSimilarity + structuralSimilarity) / 2;
                return (CloneType.Type3_NearMiss, similarity, editDistance);
            }
        }

        // Type 4: Semantic clones - similar control flow
        var controlFlowSimilarity = ComputeControlFlowSimilarity(
            fragment1.ControlFlowSignature, fragment2.ControlFlowSignature);

        if (controlFlowSimilarity >= _options.MinSimilarity)
        {
            return (CloneType.Type4_Semantic, controlFlowSimilarity, -1);
        }

        // Not a clone
        var overallSimilarity = (fingerprintSimilarity + structuralSimilarity + controlFlowSimilarity) / 3;
        return (CloneType.Type3_NearMiss, overallSimilarity, -1);
    }

    /// <summary>
    /// Compute Jaccard similarity between two sets of fingerprints.
    /// </summary>
    public double ComputeFingerprintSimilarity(List<long> fingerprints1, List<long> fingerprints2)
    {
        if (fingerprints1.Count == 0 || fingerprints2.Count == 0)
            return 0;

        var set1 = fingerprints1.ToHashSet();
        var set2 = fingerprints2.ToHashSet();

        var intersection = set1.Intersect(set2).Count();
        var union = set1.Union(set2).Count();

        return union > 0 ? (double)intersection / union : 0;
    }

    /// <summary>
    /// Compute similarity based on AST subtree hashes.
    /// </summary>
    public double ComputeAstSimilarity(List<long> hashes1, List<long> hashes2)
    {
        if (hashes1.Count == 0 || hashes2.Count == 0)
            return 0;

        var set1 = hashes1.ToHashSet();
        var set2 = hashes2.ToHashSet();

        var intersection = set1.Intersect(set2).Count();
        var union = set1.Union(set2).Count();

        return union > 0 ? (double)intersection / union : 0;
    }

    /// <summary>
    /// Compute similarity between control flow signatures.
    /// </summary>
    public double ComputeControlFlowSimilarity(string signature1, string signature2)
    {
        if (string.IsNullOrEmpty(signature1) || string.IsNullOrEmpty(signature2))
            return 0;

        var ops1 = signature1.Split('|');
        var ops2 = signature2.Split('|');

        // Use longest common subsequence for comparison
        var lcs = ComputeLcsLength(ops1, ops2);
        var maxLen = Math.Max(ops1.Length, ops2.Length);

        return maxLen > 0 ? (double)lcs / maxLen : 0;
    }

    /// <summary>
    /// Compute edit distance between two strings.
    /// </summary>
    public int ComputeEditDistance(string s1, string s2)
    {
        if (string.IsNullOrEmpty(s1)) return s2?.Length ?? 0;
        if (string.IsNullOrEmpty(s2)) return s1.Length;

        // Tokenize and compare tokens instead of characters for efficiency
        var tokens1 = s1.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var tokens2 = s2.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        return ComputeLevenshteinDistance(tokens1, tokens2);
    }

    private int ComputeLevenshteinDistance(string[] seq1, string[] seq2)
    {
        int m = seq1.Length;
        int n = seq2.Length;

        // Use two rows instead of full matrix for memory efficiency
        var prev = new int[n + 1];
        var curr = new int[n + 1];

        for (int j = 0; j <= n; j++)
            prev[j] = j;

        for (int i = 1; i <= m; i++)
        {
            curr[0] = i;

            for (int j = 1; j <= n; j++)
            {
                if (seq1[i - 1] == seq2[j - 1])
                {
                    curr[j] = prev[j - 1];
                }
                else
                {
                    curr[j] = 1 + Math.Min(
                        prev[j - 1], // substitution
                        Math.Min(prev[j], curr[j - 1]) // deletion/insertion
                    );
                }
            }

            (prev, curr) = (curr, prev);
        }

        return prev[n];
    }

    private int ComputeLcsLength(string[] seq1, string[] seq2)
    {
        int m = seq1.Length;
        int n = seq2.Length;

        var dp = new int[m + 1, n + 1];

        for (int i = 1; i <= m; i++)
        {
            for (int j = 1; j <= n; j++)
            {
                if (seq1[i - 1] == seq2[j - 1])
                {
                    dp[i, j] = dp[i - 1, j - 1] + 1;
                }
                else
                {
                    dp[i, j] = Math.Max(dp[i - 1, j], dp[i, j - 1]);
                }
            }
        }

        return dp[m, n];
    }

    /// <summary>
    /// Find differences between renamed clones (Type 2).
    /// </summary>
    private List<CloneDifference> FindRenamedDifferences(CodeFragment fragment1, CodeFragment fragment2)
    {
        var differences = new List<CloneDifference>();

        // Since these are renamed clones, we need to find the identifier mappings
        _normalizer.Reset();
        var tokens1 = _normalizer.NormalizeTokens(
            CSharpSyntaxTree.ParseText(fragment1.SourceCode).GetRoot());
        var map1 = _normalizer.GetIdentifierMappings();

        _normalizer.Reset();
        var tokens2 = _normalizer.NormalizeTokens(
            CSharpSyntaxTree.ParseText(fragment2.SourceCode).GetRoot());
        var map2 = _normalizer.GetIdentifierMappings();

        // Find identifiers that map to the same placeholder but have different original names
        foreach (var (key1, placeholder1) in map1)
        {
            var originalName1 = key1.Split(':').LastOrDefault() ?? key1;

            foreach (var (key2, placeholder2) in map2)
            {
                if (placeholder1 == placeholder2)
                {
                    var originalName2 = key2.Split(':').LastOrDefault() ?? key2;

                    if (originalName1 != originalName2)
                    {
                        differences.Add(new CloneDifference
                        {
                            Type = DifferenceType.IdentifierRenamed,
                            Fragment1Value = originalName1,
                            Fragment2Value = originalName2,
                            Description = $"Renamed: '{originalName1}' -> '{originalName2}'"
                        });
                    }
                }
            }
        }

        // Also check for literal differences
        var litMap1 = _normalizer.GetLiteralMappings();
        var litMap2 = _normalizer.GetLiteralMappings();

        foreach (var (key1, placeholder1) in litMap1)
        {
            foreach (var (key2, placeholder2) in litMap2)
            {
                if (placeholder1 == placeholder2 && key1 != key2)
                {
                    differences.Add(new CloneDifference
                    {
                        Type = DifferenceType.LiteralChanged,
                        Fragment1Value = key1.Split(':').LastOrDefault() ?? key1,
                        Fragment2Value = key2.Split(':').LastOrDefault() ?? key2,
                        Description = $"Literal changed: {key1} -> {key2}"
                    });
                }
            }
        }

        return differences;
    }

    /// <summary>
    /// Find differences between near-miss clones (Type 3).
    /// </summary>
    private List<CloneDifference> FindNearMissDifferences(CodeFragment fragment1, CodeFragment fragment2)
    {
        _normalizer.Reset();
        var tokens1 = _normalizer.NormalizeTokens(
            CSharpSyntaxTree.ParseText(fragment1.SourceCode).GetRoot());

        _normalizer.Reset();
        var tokens2 = _normalizer.NormalizeTokens(
            CSharpSyntaxTree.ParseText(fragment2.SourceCode).GetRoot());

        return _normalizer.CompareNormalizedTokens(
            tokens1, tokens2,
            fragment1.StartLine, fragment2.StartLine);
    }

    /// <summary>
    /// Find differences between semantic clones (Type 4).
    /// </summary>
    private List<CloneDifference> FindSemanticDifferences(CodeFragment fragment1, CodeFragment fragment2)
    {
        var differences = new List<CloneDifference>();

        var ops1 = fragment1.ControlFlowSignature.Split('|', StringSplitOptions.RemoveEmptyEntries);
        var ops2 = fragment2.ControlFlowSignature.Split('|', StringSplitOptions.RemoveEmptyEntries);

        // Find structural differences in control flow
        var alignment = AlignSequences(ops1.ToList(), ops2.ToList());

        foreach (var (op1, op2) in alignment)
        {
            if (op1 == null && op2 != null)
            {
                differences.Add(new CloneDifference
                {
                    Type = DifferenceType.StatementAdded,
                    Fragment2Value = op2,
                    Description = $"Control flow element added: {op2}"
                });
            }
            else if (op1 != null && op2 == null)
            {
                differences.Add(new CloneDifference
                {
                    Type = DifferenceType.StatementRemoved,
                    Fragment1Value = op1,
                    Description = $"Control flow element removed: {op1}"
                });
            }
            else if (op1 != op2)
            {
                differences.Add(new CloneDifference
                {
                    Type = DifferenceType.StatementModified,
                    Fragment1Value = op1,
                    Fragment2Value = op2,
                    Description = $"Control flow changed: {op1} -> {op2}"
                });
            }
        }

        return differences;
    }

    private List<(string?, string?)> AlignSequences(List<string> seq1, List<string> seq2)
    {
        int m = seq1.Count;
        int n = seq2.Count;

        var dp = new int[m + 1, n + 1];

        for (int i = 0; i <= m; i++) dp[i, 0] = i;
        for (int j = 0; j <= n; j++) dp[0, j] = j;

        for (int i = 1; i <= m; i++)
        {
            for (int j = 1; j <= n; j++)
            {
                if (seq1[i - 1] == seq2[j - 1])
                {
                    dp[i, j] = dp[i - 1, j - 1];
                }
                else
                {
                    dp[i, j] = 1 + Math.Min(
                        dp[i - 1, j - 1],
                        Math.Min(dp[i - 1, j], dp[i, j - 1])
                    );
                }
            }
        }

        var alignment = new List<(string?, string?)>();
        int x = m, y = n;

        while (x > 0 || y > 0)
        {
            if (x > 0 && y > 0 && seq1[x - 1] == seq2[y - 1])
            {
                alignment.Add((seq1[x - 1], seq2[y - 1]));
                x--;
                y--;
            }
            else if (x > 0 && y > 0 && dp[x, y] == dp[x - 1, y - 1] + 1)
            {
                alignment.Add((seq1[x - 1], seq2[y - 1]));
                x--;
                y--;
            }
            else if (x > 0 && dp[x, y] == dp[x - 1, y] + 1)
            {
                alignment.Add((seq1[x - 1], null));
                x--;
            }
            else
            {
                alignment.Add((null, seq2[y - 1]));
                y--;
            }
        }

        alignment.Reverse();
        return alignment;
    }

    /// <summary>
    /// Group clone pairs into clone classes.
    /// </summary>
    public List<CloneClass> FormCloneClasses(List<ClonePair> clonePairs)
    {
        // Use Union-Find to group related fragments
        var fragmentIds = new HashSet<string>();
        foreach (var pair in clonePairs)
        {
            fragmentIds.Add(pair.Fragment1.Id);
            fragmentIds.Add(pair.Fragment2.Id);
        }

        var parent = new Dictionary<string, string>();
        foreach (var id in fragmentIds)
        {
            parent[id] = id;
        }

        string Find(string id)
        {
            if (parent[id] != id)
            {
                parent[id] = Find(parent[id]);
            }
            return parent[id];
        }

        void Union(string id1, string id2)
        {
            var root1 = Find(id1);
            var root2 = Find(id2);
            if (root1 != root2)
            {
                parent[root1] = root2;
            }
        }

        // Union fragments that are clones of each other
        foreach (var pair in clonePairs)
        {
            Union(pair.Fragment1.Id, pair.Fragment2.Id);
        }

        // Group fragments by their root
        var fragmentGroups = new Dictionary<string, List<CodeFragment>>();
        var fragmentLookup = new Dictionary<string, CodeFragment>();

        foreach (var pair in clonePairs)
        {
            fragmentLookup[pair.Fragment1.Id] = pair.Fragment1;
            fragmentLookup[pair.Fragment2.Id] = pair.Fragment2;
        }

        foreach (var id in fragmentIds)
        {
            var root = Find(id);
            if (!fragmentGroups.ContainsKey(root))
            {
                fragmentGroups[root] = [];
            }
            if (fragmentLookup.TryGetValue(id, out var fragment))
            {
                if (!fragmentGroups[root].Any(f => f.Id == id))
                {
                    fragmentGroups[root].Add(fragment);
                }
            }
        }

        // Create clone classes
        var cloneClasses = new List<CloneClass>();
        int classId = 0;

        foreach (var (root, fragments) in fragmentGroups)
        {
            if (fragments.Count < 2) continue;

            // Determine the clone type for this class (most restrictive)
            var pairsInClass = clonePairs.Where(p =>
                Find(p.Fragment1.Id) == root &&
                Find(p.Fragment2.Id) == root).ToList();

            var cloneType = pairsInClass.Count > 0
                ? pairsInClass.Min(p => p.CloneType)
                : CloneType.Type3_NearMiss;

            var avgSimilarity = pairsInClass.Count > 0
                ? pairsInClass.Average(p => p.Similarity)
                : 0.8;

            // Select representative (smallest or first)
            var representative = fragments.OrderBy(f => f.LineCount).First();

            cloneClasses.Add(new CloneClass
            {
                Id = $"clone_class_{++classId}",
                CloneType = cloneType,
                Fragments = fragments.OrderBy(f => f.FilePath).ThenBy(f => f.StartLine).ToList(),
                Representative = representative,
                AverageSimilarity = avgSimilarity
            });
        }

        return cloneClasses.OrderByDescending(c => c.TotalLines).ToList();
    }

    /// <summary>
    /// Suggest extraction opportunities for clone classes.
    /// </summary>
    public List<ExtractionOpportunity> SuggestExtractions(List<CloneClass> cloneClasses)
    {
        var opportunities = new List<ExtractionOpportunity>();

        foreach (var cloneClass in cloneClasses)
        {
            if (cloneClass.InstanceCount < 2) continue;
            if (cloneClass.Representative == null) continue;

            var opportunity = AnalyzeExtractionOpportunity(cloneClass);
            if (opportunity != null)
            {
                opportunities.Add(opportunity);
            }
        }

        return opportunities.OrderByDescending(o => o.EstimatedLinesSaved).ToList();
    }

    private ExtractionOpportunity? AnalyzeExtractionOpportunity(CloneClass cloneClass)
    {
        var representative = cloneClass.Representative!;

        // Determine extraction type based on context
        var extractionType = DetermineExtractionType(cloneClass);

        // Generate suggested name
        var suggestedName = GenerateSuggestedName(representative, extractionType);

        // Analyze parameters needed
        var parameters = AnalyzeRequiredParameters(cloneClass);

        // Analyze return type
        var returnType = InferReturnType(representative);

        // Calculate confidence and complexity
        var (confidence, complexity, risks) = AssessExtraction(cloneClass, extractionType);

        if (confidence < 0.3) return null;

        return new ExtractionOpportunity
        {
            CloneClass = cloneClass,
            Confidence = confidence,
            SuggestedName = suggestedName,
            ExtractionType = extractionType,
            EstimatedLinesSaved = cloneClass.PotentialSavingsLines,
            SuggestedParameters = parameters,
            SuggestedReturnType = returnType,
            Description = GenerateExtractionDescription(cloneClass, extractionType, suggestedName),
            Complexity = complexity,
            Risks = risks
        };
    }

    private ExtractionType DetermineExtractionType(CloneClass cloneClass)
    {
        var representative = cloneClass.Representative!;

        // Check if clones span multiple classes
        var classes = cloneClass.Fragments
            .Select(f => f.ContainingClass)
            .Distinct()
            .ToList();

        if (classes.Count > 1)
        {
            // Check if classes share a base class
            // For now, suggest utility method
            return ExtractionType.ExtractUtilityMethod;
        }

        // If within same class, suggest regular method extraction
        if (representative.LineCount > 50)
        {
            return ExtractionType.ExtractClass;
        }

        if (representative.LineCount <= 10)
        {
            return ExtractionType.ExtractLocalFunction;
        }

        return ExtractionType.ExtractMethod;
    }

    private string GenerateSuggestedName(CodeFragment fragment, ExtractionType extractionType)
    {
        // Try to extract a meaningful name from the code
        var tree = CSharpSyntaxTree.ParseText(fragment.SourceCode);
        var root = tree.GetRoot();

        // Look for the main action in the code
        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>().ToList();
        var assignments = root.DescendantNodes().OfType<AssignmentExpressionSyntax>().ToList();

        string baseName = "ExtractedCode";

        if (invocations.Count > 0)
        {
            var mainCall = invocations.First();
            var methodName = mainCall.Expression switch
            {
                MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
                IdentifierNameSyntax id => id.Identifier.Text,
                _ => null
            };

            if (methodName != null)
            {
                baseName = methodName.StartsWith("Get") || methodName.StartsWith("Set") ||
                           methodName.StartsWith("Is") || methodName.StartsWith("Has")
                    ? methodName
                    : $"Process{methodName}";
            }
        }
        else if (assignments.Count > 0)
        {
            var mainAssign = assignments.First();
            var targetName = mainAssign.Left switch
            {
                IdentifierNameSyntax id => id.Identifier.Text,
                MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
                _ => null
            };

            if (targetName != null)
            {
                baseName = $"Setup{ToPascalCase(targetName)}";
            }
        }

        return extractionType switch
        {
            ExtractionType.ExtractClass => $"{baseName}Handler",
            ExtractionType.ExtractLocalFunction => baseName,
            ExtractionType.ExtractUtilityMethod => baseName,
            ExtractionType.ExtractExtensionMethod => baseName,
            _ => baseName
        };
    }

    private List<SuggestedParameter> AnalyzeRequiredParameters(CloneClass cloneClass)
    {
        var parameters = new List<SuggestedParameter>();

        if (cloneClass.CloneType == CloneType.Type1_Exact)
        {
            // No parameters needed for exact clones
            return parameters;
        }

        // For renamed clones, find the varying identifiers
        if (cloneClass.CloneType == CloneType.Type2_Renamed)
        {
            var identifierValues = new Dictionary<string, List<string>>();

            foreach (var fragment in cloneClass.Fragments)
            {
                _normalizer.Reset();
                var tree = CSharpSyntaxTree.ParseText(fragment.SourceCode);
                _normalizer.NormalizeTokens(tree.GetRoot());

                foreach (var (key, placeholder) in _normalizer.GetIdentifierMappings())
                {
                    var originalName = key.Split(':').LastOrDefault() ?? key;

                    if (!identifierValues.ContainsKey(placeholder))
                    {
                        identifierValues[placeholder] = [];
                    }

                    if (!identifierValues[placeholder].Contains(originalName))
                    {
                        identifierValues[placeholder].Add(originalName);
                    }
                }
            }

            // Parameters are identifiers that vary between instances
            foreach (var (placeholder, values) in identifierValues)
            {
                if (values.Count > 1)
                {
                    var paramType = InferTypeFromPlaceholder(placeholder);
                    var paramName = GenerateParameterName(values);

                    parameters.Add(new SuggestedParameter
                    {
                        Name = paramName,
                        Type = paramType,
                        VariesBetweenInstances = true,
                        SampleValues = values.Take(3).ToList()
                    });
                }
            }
        }

        return parameters;
    }

    private string InferTypeFromPlaceholder(string placeholder)
    {
        if (placeholder.StartsWith("$V") || placeholder.StartsWith("$P"))
            return "object"; // Could be refined with semantic analysis
        if (placeholder.StartsWith("$STR"))
            return "string";
        if (placeholder.StartsWith("$INT"))
            return "int";
        if (placeholder.StartsWith("$DOUBLE"))
            return "double";
        if (placeholder.StartsWith("$TYPE"))
            return "Type";

        return "object";
    }

    private string GenerateParameterName(List<string> sampleValues)
    {
        // Find common prefix or pattern
        if (sampleValues.Count == 0) return "value";

        var first = sampleValues[0];

        // If all start with same prefix
        var commonPrefix = first;
        foreach (var value in sampleValues.Skip(1))
        {
            while (!value.StartsWith(commonPrefix) && commonPrefix.Length > 0)
            {
                commonPrefix = commonPrefix[..^1];
            }
        }

        if (commonPrefix.Length >= 3)
        {
            return ToCamelCase(commonPrefix);
        }

        // Use the first sample as basis
        return ToCamelCase(first);
    }

    private string? InferReturnType(CodeFragment fragment)
    {
        var tree = CSharpSyntaxTree.ParseText(fragment.SourceCode);
        var root = tree.GetRoot();

        var returnStatements = root.DescendantNodes().OfType<ReturnStatementSyntax>().ToList();

        if (returnStatements.Count == 0)
            return "void";

        if (returnStatements.All(r => r.Expression == null))
            return "void";

        // For now, return object - could be refined with semantic analysis
        return null;
    }

    private (double confidence, ExtractionComplexity complexity, List<string> risks) AssessExtraction(
        CloneClass cloneClass, ExtractionType extractionType)
    {
        var risks = new List<string>();
        var complexity = ExtractionComplexity.Simple;
        var confidence = 0.9;

        // Check for varying control flow
        var signatures = cloneClass.Fragments
            .Select(f => f.ControlFlowSignature)
            .Distinct()
            .ToList();

        if (signatures.Count > 1)
        {
            risks.Add("Control flow varies between instances - may need conditional logic");
            complexity = ExtractionComplexity.Moderate;
            confidence -= 0.2;
        }

        // Check for many parameters needed
        var paramCount = AnalyzeRequiredParameters(cloneClass).Count;
        if (paramCount > 5)
        {
            risks.Add($"Many parameters ({paramCount}) would be needed - consider a parameter object");
            complexity = ExtractionComplexity.Moderate;
            confidence -= 0.1;
        }

        // Check if clones span different contexts
        var contexts = cloneClass.Fragments
            .Select(f => f.ContainingClass)
            .Distinct()
            .Count();

        if (contexts > 3)
        {
            risks.Add("Clones appear in many different classes - may indicate a missing abstraction");
            complexity = ExtractionComplexity.Complex;
            confidence -= 0.1;
        }

        // Type 3 and Type 4 clones are harder to extract
        if (cloneClass.CloneType == CloneType.Type3_NearMiss)
        {
            complexity = complexity == ExtractionComplexity.Simple
                ? ExtractionComplexity.Moderate
                : ExtractionComplexity.Complex;
            confidence -= 0.15;
        }
        else if (cloneClass.CloneType == CloneType.Type4_Semantic)
        {
            complexity = ExtractionComplexity.Complex;
            risks.Add("Semantic clones may require significant restructuring");
            confidence -= 0.3;
        }

        if (confidence < 0.3)
        {
            complexity = ExtractionComplexity.Risky;
        }

        return (Math.Max(0, confidence), complexity, risks);
    }

    private string GenerateExtractionDescription(
        CloneClass cloneClass, ExtractionType extractionType, string suggestedName)
    {
        var linesSaved = cloneClass.PotentialSavingsLines;
        var instanceCount = cloneClass.InstanceCount;

        return extractionType switch
        {
            ExtractionType.ExtractMethod =>
                $"Extract method '{suggestedName}' to eliminate {instanceCount} clone instances, saving ~{linesSaved} lines",

            ExtractionType.ExtractLocalFunction =>
                $"Extract local function '{suggestedName}' for {instanceCount} similar code blocks",

            ExtractionType.ExtractClass =>
                $"Extract class '{suggestedName}' to encapsulate repeated logic across {instanceCount} locations",

            ExtractionType.ExtractUtilityMethod =>
                $"Extract utility method '{suggestedName}' to share logic across {cloneClass.FileCount} files",

            ExtractionType.ExtractExtensionMethod =>
                $"Create extension method '{suggestedName}' for reuse across the codebase",

            ExtractionType.UseTemplateMethod =>
                $"Apply Template Method pattern with base method '{suggestedName}'",

            ExtractionType.UseStrategyPattern =>
                $"Apply Strategy pattern to abstract the {instanceCount} variations",

            _ => $"Refactor {instanceCount} clone instances into '{suggestedName}'"
        };
    }

    private string ToPascalCase(string text)
    {
        if (string.IsNullOrEmpty(text)) return text;
        return char.ToUpper(text[0]) + text[1..];
    }

    private string ToCamelCase(string text)
    {
        if (string.IsNullOrEmpty(text)) return text;
        return char.ToLower(text[0]) + text[1..];
    }
}
