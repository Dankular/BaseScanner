using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers;
using BaseScanner.ML.Models;

namespace BaseScanner.ML;

/// <summary>
/// Extracts features from code suggestions for confidence scoring.
/// </summary>
public class FeatureExtractor
{
    private readonly Dictionary<string, int> _projectPatternCounts = new();
    private readonly Dictionary<string, Dictionary<string, int>> _filePatternCounts = new();

    /// <summary>
    /// Extract features from an optimization opportunity.
    /// </summary>
    public async Task<SuggestionFeatures> ExtractFeaturesAsync(
        OptimizationOpportunity opportunity,
        Document? document = null,
        SemanticModel? semanticModel = null,
        SyntaxNode? root = null)
    {
        var suggestionId = GenerateSuggestionId(opportunity);

        // Get document info if not provided
        if (document != null && (semanticModel == null || root == null))
        {
            semanticModel = await document.GetSemanticModelAsync();
            root = await document.GetSyntaxRootAsync();
        }

        var features = new SuggestionFeatures
        {
            SuggestionId = suggestionId,
            PatternType = opportunity.Type,
            FilePath = opportunity.FilePath,
            StartLine = opportunity.StartLine,
            EndLine = opportunity.EndLine,
            CurrentCode = opportunity.CurrentCode,
            SuggestedCode = opportunity.SuggestedCode,
            MethodComplexity = 1,
            NestingDepth = 0,
            MethodLength = 0,
            PatternFrequencyInProject = GetProjectPatternFrequency(opportunity.Type),
            PatternFrequencyInFile = GetFilePatternFrequency(opportunity.FilePath, opportunity.Type),
            WasAppliedBefore = 0.5,
            WasRevertedBefore = 0.0,
            IsInTestCode = IsTestFile(opportunity.FilePath),
            IsInGeneratedCode = IsGeneratedFile(opportunity.FilePath),
            HasRelatedComment = false
        };

        if (root != null && semanticModel != null)
        {
            // Find the node at the specified location
            var node = FindNodeAtLocation(root, opportunity.StartLine, opportunity.EndLine);
            if (node != null)
            {
                features = features with
                {
                    MethodComplexity = CalculateMethodComplexity(node, root),
                    NestingDepth = CalculateNestingDepth(node),
                    MethodLength = CalculateMethodLength(node, root),
                    HasRelatedComment = HasNearbyComment(node, root)
                };
            }
        }

        return features;
    }

    /// <summary>
    /// Extract features for multiple opportunities.
    /// </summary>
    public async Task<List<SuggestionFeatures>> ExtractFeaturesAsync(
        IEnumerable<OptimizationOpportunity> opportunities,
        Project? project = null)
    {
        var results = new List<SuggestionFeatures>();

        // First, count patterns across the project
        CountPatterns(opportunities);

        // Group by file for efficient processing
        var byFile = opportunities.GroupBy(o => o.FilePath);

        foreach (var fileGroup in byFile)
        {
            Document? document = null;
            SemanticModel? semanticModel = null;
            SyntaxNode? root = null;

            if (project != null)
            {
                document = project.Documents.FirstOrDefault(d => d.FilePath == fileGroup.Key);
                if (document != null)
                {
                    semanticModel = await document.GetSemanticModelAsync();
                    root = await document.GetSyntaxRootAsync();
                }
            }

            foreach (var opportunity in fileGroup)
            {
                var features = await ExtractFeaturesAsync(opportunity, document, semanticModel, root);
                results.Add(features);
            }
        }

        return results;
    }

    /// <summary>
    /// Update features with historical feedback data.
    /// </summary>
    public SuggestionFeatures UpdateWithHistory(
        SuggestionFeatures features,
        PatternStatistics? stats)
    {
        if (stats == null) return features;

        return features with
        {
            WasAppliedBefore = stats.ApplicationRate,
            WasRevertedBefore = stats.ReversionRate
        };
    }

    private void CountPatterns(IEnumerable<OptimizationOpportunity> opportunities)
    {
        _projectPatternCounts.Clear();
        _filePatternCounts.Clear();

        foreach (var opp in opportunities)
        {
            // Count project-wide
            if (!_projectPatternCounts.ContainsKey(opp.Type))
                _projectPatternCounts[opp.Type] = 0;
            _projectPatternCounts[opp.Type]++;

            // Count per-file
            if (!_filePatternCounts.ContainsKey(opp.FilePath))
                _filePatternCounts[opp.FilePath] = new Dictionary<string, int>();
            if (!_filePatternCounts[opp.FilePath].ContainsKey(opp.Type))
                _filePatternCounts[opp.FilePath][opp.Type] = 0;
            _filePatternCounts[opp.FilePath][opp.Type]++;
        }
    }

    private int GetProjectPatternFrequency(string patternType)
    {
        return _projectPatternCounts.TryGetValue(patternType, out var count) ? count : 0;
    }

    private int GetFilePatternFrequency(string filePath, string patternType)
    {
        if (!_filePatternCounts.TryGetValue(filePath, out var fileCounts))
            return 0;
        return fileCounts.TryGetValue(patternType, out var count) ? count : 0;
    }

    private static string GenerateSuggestionId(OptimizationOpportunity opportunity)
    {
        var hash = HashCode.Combine(
            opportunity.FilePath,
            opportunity.StartLine,
            opportunity.Type,
            opportunity.CurrentCode.GetHashCode());
        return $"{opportunity.Type}_{opportunity.StartLine}_{Math.Abs(hash):X8}";
    }

    private static SyntaxNode? FindNodeAtLocation(SyntaxNode root, int startLine, int endLine)
    {
        // Find nodes that span the given line range
        var candidates = root.DescendantNodes()
            .Where(n =>
            {
                var lineSpan = n.GetLocation().GetLineSpan();
                var nodeStart = lineSpan.StartLinePosition.Line + 1;
                var nodeEnd = lineSpan.EndLinePosition.Line + 1;
                return nodeStart <= startLine && nodeEnd >= endLine;
            })
            .OrderBy(n => n.Span.Length) // Get the smallest node that contains the range
            .ToList();

        return candidates.FirstOrDefault();
    }

    private static int CalculateMethodComplexity(SyntaxNode node, SyntaxNode root)
    {
        // Find containing method
        var method = node.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
        if (method == null) return 1;

        // Calculate cyclomatic complexity
        int complexity = 1; // Base complexity

        foreach (var descendant in method.DescendantNodes())
        {
            complexity += descendant switch
            {
                IfStatementSyntax => 1,
                ConditionalExpressionSyntax => 1,
                WhileStatementSyntax => 1,
                ForStatementSyntax => 1,
                ForEachStatementSyntax => 1,
                DoStatementSyntax => 1,
                CaseSwitchLabelSyntax => 1,
                CasePatternSwitchLabelSyntax => 1,
                CatchClauseSyntax => 1,
                BinaryExpressionSyntax binary when
                    binary.IsKind(SyntaxKind.LogicalAndExpression) ||
                    binary.IsKind(SyntaxKind.LogicalOrExpression) ||
                    binary.IsKind(SyntaxKind.CoalesceExpression) => 1,
                ConditionalAccessExpressionSyntax => 1,
                _ => 0
            };
        }

        return complexity;
    }

    private static int CalculateNestingDepth(SyntaxNode node)
    {
        int depth = 0;
        var current = node.Parent;

        while (current != null)
        {
            if (current is BlockSyntax &&
                current.Parent is not (MethodDeclarationSyntax or
                    ConstructorDeclarationSyntax or
                    PropertyDeclarationSyntax or
                    AccessorDeclarationSyntax))
            {
                depth++;
            }
            else if (current is LambdaExpressionSyntax or
                     AnonymousFunctionExpressionSyntax)
            {
                depth++;
            }
            current = current.Parent;
        }

        return depth;
    }

    private static int CalculateMethodLength(SyntaxNode node, SyntaxNode root)
    {
        var method = node.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
        if (method == null) return 0;

        var lineSpan = method.GetLocation().GetLineSpan();
        return lineSpan.EndLinePosition.Line - lineSpan.StartLinePosition.Line + 1;
    }

    private static bool HasNearbyComment(SyntaxNode node, SyntaxNode root)
    {
        // Check for comments in the trivia around the node
        var triviaList = node.GetLeadingTrivia().Concat(node.GetTrailingTrivia());

        foreach (var trivia in triviaList)
        {
            if (trivia.IsKind(SyntaxKind.SingleLineCommentTrivia) ||
                trivia.IsKind(SyntaxKind.MultiLineCommentTrivia) ||
                trivia.IsKind(SyntaxKind.SingleLineDocumentationCommentTrivia) ||
                trivia.IsKind(SyntaxKind.MultiLineDocumentationCommentTrivia))
            {
                return true;
            }
        }

        // Also check the parent statement
        var statement = node.Ancestors().OfType<StatementSyntax>().FirstOrDefault();
        if (statement != null)
        {
            var statementTrivia = statement.GetLeadingTrivia();
            foreach (var trivia in statementTrivia)
            {
                if (trivia.IsKind(SyntaxKind.SingleLineCommentTrivia) ||
                    trivia.IsKind(SyntaxKind.MultiLineCommentTrivia))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static bool IsTestFile(string filePath)
    {
        if (string.IsNullOrEmpty(filePath)) return false;

        var fileName = Path.GetFileName(filePath);
        var directory = Path.GetDirectoryName(filePath) ?? "";

        // Check file name patterns
        if (fileName.EndsWith("Tests.cs", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith("Test.cs", StringComparison.OrdinalIgnoreCase) ||
            fileName.StartsWith("Test", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains(".Tests.", StringComparison.OrdinalIgnoreCase) ||
            fileName.Contains(".Test.", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Check directory patterns
        if (directory.Contains("Tests", StringComparison.OrdinalIgnoreCase) ||
            directory.Contains("Test", StringComparison.OrdinalIgnoreCase) ||
            directory.Contains("UnitTests", StringComparison.OrdinalIgnoreCase) ||
            directory.Contains("IntegrationTests", StringComparison.OrdinalIgnoreCase) ||
            directory.Contains("TestProject", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }

    private static bool IsGeneratedFile(string filePath)
    {
        if (string.IsNullOrEmpty(filePath)) return false;

        var fileName = Path.GetFileName(filePath);

        return fileName.EndsWith(".g.cs", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".generated.cs", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".Designer.cs", StringComparison.OrdinalIgnoreCase) ||
               fileName.Contains(".g.", StringComparison.OrdinalIgnoreCase) ||
               fileName.StartsWith("TemporaryGenerated", StringComparison.OrdinalIgnoreCase);
    }
}
