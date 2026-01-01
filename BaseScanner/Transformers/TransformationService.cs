using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Formatting;
using BaseScanner.Transformers.Core;
using BaseScanner.Transformers.Optimizations;
using BaseScanner.Services;
using BaseScanner.Analyzers.Optimizations;
using System.Collections.Concurrent;

namespace BaseScanner.Transformers;

/// <summary>
/// Orchestrates code transformations with preview, apply, and rollback capabilities.
/// </summary>
public class TransformationService
{
    private readonly List<ICodeTransformer> _transformers;
    private readonly BackupService _backupService;

    public TransformationService(BackupService backupService)
    {
        _backupService = backupService;
        _transformers = new List<ICodeTransformer>
        {
            new LinqTransformer(),
            new StringTransformer(),
            new AsyncTransformer(),
            new ModernCSharpTransformer(),
            new CollectionTransformer()
        };
    }

    /// <summary>
    /// Preview transformations without applying them.
    /// </summary>
    public async Task<PreviewResult> PreviewAsync(Project project, TransformationFilter filter)
    {
        var previews = new List<TransformationPreview>();
        var compilation = await project.GetCompilationAsync();
        if (compilation == null)
        {
            return new PreviewResult
            {
                Success = false,
                ErrorMessage = "Could not get project compilation",
                Previews = []
            };
        }

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null || !ShouldProcessFile(document.FilePath, filter))
                continue;

            var semanticModel = await document.GetSemanticModelAsync();
            var syntaxRoot = await document.GetSyntaxRootAsync();
            if (semanticModel == null || syntaxRoot == null)
                continue;

            var documentPreviews = await PreviewDocumentAsync(document, semanticModel, syntaxRoot, filter);
            previews.AddRange(documentPreviews);
        }

        // Apply limit if specified
        if (filter.MaxTransformations.HasValue)
        {
            previews = previews.Take(filter.MaxTransformations.Value).ToList();
        }

        return new PreviewResult
        {
            Success = true,
            Previews = previews,
            TotalTransformations = previews.Count,
            TransformationsByType = previews
                .GroupBy(p => p.TransformationType)
                .ToDictionary(g => g.Key, g => g.Count())
        };
    }

    /// <summary>
    /// Apply transformations with optional backup.
    /// </summary>
    public async Task<BatchTransformationResult> ApplyAsync(
        Project project,
        TransformationFilter filter,
        TransformationOptions options)
    {
        var results = new List<TransformationResult>();
        var appliedFiles = new List<string>();

        // Get preview first
        var preview = await PreviewAsync(project, filter);
        if (!preview.Success || preview.Previews.Count == 0)
        {
            return new BatchTransformationResult
            {
                Success = preview.Success,
                ErrorMessage = preview.ErrorMessage ?? "No transformations to apply",
                Results = []
            };
        }

        // Create backup before applying changes
        var filesToBackup = preview.Previews.Select(p => p.FilePath).Distinct().ToList();
        var backupId = await _backupService.CreateBackupAsync(filesToBackup);

        try
        {
            var compilation = await project.GetCompilationAsync();
            if (compilation == null)
            {
                return new BatchTransformationResult
                {
                    Success = false,
                    ErrorMessage = "Could not get project compilation",
                    Results = []
                };
            }

            // Group previews by file
            var previewsByFile = preview.Previews.GroupBy(p => p.FilePath);

            foreach (var fileGroup in previewsByFile)
            {
                var filePath = fileGroup.Key;
                var document = project.Documents.FirstOrDefault(d => d.FilePath == filePath);
                if (document == null)
                    continue;

                var result = await ApplyToDocumentAsync(document, fileGroup.ToList(), options, compilation);
                results.Add(result);

                if (result.Success)
                {
                    appliedFiles.Add(filePath);
                }
            }

            return new BatchTransformationResult
            {
                Success = results.All(r => r.Success),
                BackupId = backupId,
                Results = results,
                FilesModified = appliedFiles.Count,
                TotalTransformations = results.Sum(r => r.Changes.Count)
            };
        }
        catch (Exception ex)
        {
            // Attempt rollback on failure
            await _backupService.RestoreBackupAsync(backupId);
            return new BatchTransformationResult
            {
                Success = false,
                ErrorMessage = $"Transformation failed, rolled back: {ex.Message}",
                Results = results,
                BackupId = backupId
            };
        }
    }

    /// <summary>
    /// Rollback to a previous backup.
    /// </summary>
    public async Task<RollbackResult> RollbackAsync(string? backupId = null)
    {
        if (backupId == null)
        {
            var backups = await _backupService.ListBackupsAsync();
            if (backups.Count == 0)
            {
                return new RollbackResult
                {
                    Success = false,
                    ErrorMessage = "No backups available for rollback"
                };
            }
            backupId = backups.OrderByDescending(b => b.CreatedAt).First().Id;
        }

        var success = await _backupService.RestoreBackupAsync(backupId);
        return new RollbackResult
        {
            Success = success,
            BackupId = backupId,
            ErrorMessage = success ? null : "Failed to restore backup"
        };
    }

    private bool ShouldProcessFile(string filePath, TransformationFilter filter)
    {
        // Skip generated files
        var fileName = Path.GetFileName(filePath);
        if (fileName.EndsWith(".g.cs") || fileName.EndsWith(".Designer.cs"))
            return false;

        // Apply include/exclude patterns
        if (filter.IncludeFiles.Count > 0)
        {
            if (!filter.IncludeFiles.Any(p => MatchesGlob(filePath, p)))
                return false;
        }

        if (filter.ExcludeFiles.Count > 0)
        {
            if (filter.ExcludeFiles.Any(p => MatchesGlob(filePath, p)))
                return false;
        }

        return true;
    }

    private bool MatchesGlob(string path, string pattern)
    {
        // Simple glob matching
        var regex = "^" + System.Text.RegularExpressions.Regex.Escape(pattern)
            .Replace("\\*\\*", ".*")
            .Replace("\\*", "[^/\\\\]*")
            .Replace("\\?", ".") + "$";
        return System.Text.RegularExpressions.Regex.IsMatch(path, regex, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }

    private async Task<List<TransformationPreview>> PreviewDocumentAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode syntaxRoot,
        TransformationFilter filter)
    {
        var previews = new List<TransformationPreview>();

        foreach (var transformer in _transformers)
        {
            // Check category filter
            if (filter.Categories.Count > 0 && !filter.Categories.Contains(GetTransformerCategory(transformer)))
                continue;

            // Check type filter
            if (filter.Types.Count > 0 && !filter.Types.Contains(transformer.TransformationType))
                continue;

            // Find nodes this transformer can handle
            foreach (var node in syntaxRoot.DescendantNodes())
            {
                if (transformer.CanTransform(node, semanticModel))
                {
                    var lineSpan = node.GetLocation().GetLineSpan();
                    var confidence = GetTransformationConfidence(transformer, node, semanticModel);

                    // Check confidence filter
                    if (!MeetsConfidenceThreshold(confidence, filter.MinConfidence))
                        continue;

                    previews.Add(new TransformationPreview
                    {
                        FilePath = document.FilePath ?? "",
                        TransformationType = transformer.TransformationType,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        OriginalCode = node.ToFullString().Trim(),
                        SuggestedCode = GetSuggestedTransformation(transformer, node, semanticModel),
                        Confidence = confidence,
                        Category = GetTransformerCategory(transformer)
                    });
                }
            }
        }

        return previews;
    }

    private async Task<TransformationResult> ApplyToDocumentAsync(
        Document document,
        List<TransformationPreview> previews,
        TransformationOptions options,
        Compilation compilation)
    {
        var changes = new List<FileChange>();
        var currentDocument = document;

        try
        {
            foreach (var preview in previews.OrderByDescending(p => p.StartLine))
            {
                var semanticModel = await currentDocument.GetSemanticModelAsync();
                var syntaxRoot = await currentDocument.GetSyntaxRootAsync();
                if (semanticModel == null || syntaxRoot == null)
                    continue;

                // Find the node at this location
                var node = FindNodeAtLocation(syntaxRoot, preview.StartLine, preview.EndLine);
                if (node == null)
                    continue;

                // Find the transformer
                var transformer = _transformers.FirstOrDefault(t =>
                    t.TransformationType == preview.TransformationType &&
                    t.CanTransform(node, semanticModel));

                if (transformer == null)
                    continue;

                // Create context and apply transformation
                var context = new TransformationContext
                {
                    Workspace = document.Project.Solution.Workspace,
                    Solution = document.Project.Solution,
                    Project = document.Project,
                    Document = currentDocument,
                    SemanticModel = semanticModel,
                    SyntaxRoot = syntaxRoot,
                    Compilation = compilation,
                    Options = options
                };

                var result = await transformer.TransformAsync(context, node);
                if (result.Success && result.Changes.Count > 0)
                {
                    changes.AddRange(result.Changes);

                    // Update document with the change
                    var newRoot = syntaxRoot.ReplaceNode(node,
                        SyntaxFactory.ParseExpression(result.Changes[0].TransformedCode));

                    if (options.FormatOutput)
                    {
                        newRoot = Formatter.Format(newRoot, document.Project.Solution.Workspace);
                    }

                    currentDocument = currentDocument.WithSyntaxRoot(newRoot);
                }
            }

            // Write the final document
            if (changes.Count > 0 && document.FilePath != null)
            {
                var finalRoot = await currentDocument.GetSyntaxRootAsync();
                if (finalRoot != null)
                {
                    await File.WriteAllTextAsync(document.FilePath, finalRoot.ToFullString());
                }
            }

            return TransformationResult.Succeeded("Batch", changes);
        }
        catch (Exception ex)
        {
            return TransformationResult.Failed("Batch", ex.Message);
        }
    }

    private SyntaxNode? FindNodeAtLocation(SyntaxNode root, int startLine, int endLine)
    {
        foreach (var node in root.DescendantNodes())
        {
            var lineSpan = node.GetLocation().GetLineSpan();
            if (lineSpan.StartLinePosition.Line + 1 == startLine &&
                lineSpan.EndLinePosition.Line + 1 == endLine)
            {
                return node;
            }
        }
        return null;
    }

    private string GetTransformerCategory(ICodeTransformer transformer)
    {
        return transformer.TransformationType switch
        {
            var t when t.Contains("Linq") => "Performance",
            var t when t.Contains("String") => "Performance",
            var t when t.Contains("Async") => "Correctness",
            var t when t.Contains("Modern") => "Readability",
            var t when t.Contains("Collection") => "Performance",
            _ => "General"
        };
    }

    private string GetTransformationConfidence(ICodeTransformer transformer, SyntaxNode node, SemanticModel semanticModel)
    {
        // Most transformers have high confidence
        return "High";
    }

    private bool MeetsConfidenceThreshold(string confidence, string minConfidence)
    {
        var order = new Dictionary<string, int>
        {
            ["Low"] = 1,
            ["Medium"] = 2,
            ["High"] = 3
        };

        return order.GetValueOrDefault(confidence, 0) >= order.GetValueOrDefault(minConfidence, 0);
    }

    private string GetSuggestedTransformation(ICodeTransformer transformer, SyntaxNode node, SemanticModel semanticModel)
    {
        // Return a preview of what the transformation would produce
        // This is a simplified version - actual transformation done during apply
        return $"[{transformer.TransformationType} transformation preview]";
    }
}

/// <summary>
/// Filter for selecting which transformations to apply.
/// </summary>
public record TransformationFilter
{
    public List<string> Categories { get; init; } = [];
    public List<string> Types { get; init; } = [];
    public string MinConfidence { get; init; } = "High";
    public List<string> IncludeFiles { get; init; } = [];
    public List<string> ExcludeFiles { get; init; } = [];
    public int? MaxTransformations { get; init; }
}

/// <summary>
/// Preview of a single transformation.
/// </summary>
public record TransformationPreview
{
    public required string FilePath { get; init; }
    public required string TransformationType { get; init; }
    public required int StartLine { get; init; }
    public required int EndLine { get; init; }
    public required string OriginalCode { get; init; }
    public required string SuggestedCode { get; init; }
    public required string Confidence { get; init; }
    public required string Category { get; init; }
}

/// <summary>
/// Result of previewing transformations.
/// </summary>
public record PreviewResult
{
    public required bool Success { get; init; }
    public string? ErrorMessage { get; init; }
    public List<TransformationPreview> Previews { get; init; } = [];
    public int TotalTransformations { get; init; }
    public Dictionary<string, int> TransformationsByType { get; init; } = [];
}

/// <summary>
/// Result of batch transformation.
/// </summary>
public record BatchTransformationResult
{
    public required bool Success { get; init; }
    public string? BackupId { get; init; }
    public string? ErrorMessage { get; init; }
    public List<TransformationResult> Results { get; init; } = [];
    public int FilesModified { get; init; }
    public int TotalTransformations { get; init; }
}

/// <summary>
/// Result of a rollback operation.
/// </summary>
public record RollbackResult
{
    public required bool Success { get; init; }
    public string? BackupId { get; init; }
    public string? ErrorMessage { get; init; }
    public int FilesRestored { get; init; }
}
