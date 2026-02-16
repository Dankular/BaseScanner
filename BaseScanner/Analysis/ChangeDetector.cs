using BaseScanner.Analysis.Models;

namespace BaseScanner.Analysis;

/// <summary>
/// Detects changes in files since the last analysis by comparing content hashes.
/// Works with the AnalysisCache to determine which files need re-analysis.
/// </summary>
public class ChangeDetector
{
    private readonly AnalysisCache _cache;
    private readonly DependencyTracker _dependencyTracker;

    /// <summary>
    /// Creates a new change detector.
    /// </summary>
    /// <param name="cache">The analysis cache to compare against.</param>
    /// <param name="dependencyTracker">The dependency tracker for computing affected files.</param>
    public ChangeDetector(AnalysisCache cache, DependencyTracker dependencyTracker)
    {
        _cache = cache;
        _dependencyTracker = dependencyTracker;
    }

    /// <summary>
    /// Detects changes in the specified files compared to the cached state.
    /// </summary>
    /// <param name="currentFiles">List of current file paths to check.</param>
    /// <returns>A result describing what changed and what needs re-analysis.</returns>
    public ChangeDetectionResult DetectChanges(IEnumerable<string> currentFiles)
    {
        var result = new ChangeDetectionResult();
        var currentFileSet = currentFiles
            .Select(NormalizePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var cachedFiles = _cache.Cache.Files.Keys
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var changedFiles = new List<string>();
        var newFiles = new List<string>();
        var deletedFiles = new List<string>();
        var unchangedFiles = new List<string>();

        // Check each current file
        foreach (var filePath in currentFileSet)
        {
            if (!File.Exists(filePath))
                continue;

            var cachedEntry = _cache.GetFileEntry(filePath);

            if (cachedEntry == null)
            {
                // New file not in cache
                newFiles.Add(filePath);
            }
            else
            {
                // Check if file has changed
                var currentHash = ComputeFileHash(filePath);
                if (currentHash != cachedEntry.ContentHash)
                {
                    changedFiles.Add(filePath);
                }
                else
                {
                    unchangedFiles.Add(filePath);
                }
            }
        }

        // Check for deleted files
        foreach (var cachedFile in cachedFiles)
        {
            if (!currentFileSet.Contains(cachedFile))
            {
                deletedFiles.Add(cachedFile);
            }
        }

        // Compute affected files via dependency graph
        var directlyChangedFiles = changedFiles.Concat(newFiles).ToList();
        var affectedFiles = _dependencyTracker.GetAffectedFiles(directlyChangedFiles);

        // Remove files that are already in changed/new lists
        affectedFiles.ExceptWith(directlyChangedFiles);

        // Also remove unchanged files from affected (they will be re-analyzed)
        var affectedFromUnchanged = affectedFiles.Intersect(unchangedFiles).ToList();
        foreach (var file in affectedFromUnchanged)
        {
            unchangedFiles.Remove(file);
        }

        return new ChangeDetectionResult
        {
            ChangedFiles = changedFiles,
            NewFiles = newFiles,
            DeletedFiles = deletedFiles,
            UnchangedFiles = unchangedFiles,
            AffectedFiles = affectedFromUnchanged
        };
    }

    /// <summary>
    /// Quickly checks if any files have changed without full detection.
    /// </summary>
    public bool HasAnyChanges(IEnumerable<string> currentFiles)
    {
        var cachedFiles = _cache.Cache.Files;

        foreach (var filePath in currentFiles)
        {
            var normalizedPath = NormalizePath(filePath);

            if (!File.Exists(filePath))
                continue;

            if (!cachedFiles.TryGetValue(normalizedPath, out var cachedEntry))
                return true; // New file

            var currentHash = ComputeFileHash(filePath);
            if (currentHash != cachedEntry.ContentHash)
                return true; // Changed file
        }

        // Check for deleted files
        foreach (var cachedPath in cachedFiles.Keys)
        {
            if (!File.Exists(cachedPath))
                return true; // Deleted file
        }

        return false;
    }

    /// <summary>
    /// Gets files that have changed since a specific time.
    /// </summary>
    public List<string> GetFilesModifiedSince(IEnumerable<string> files, DateTime since)
    {
        var modifiedFiles = new List<string>();

        foreach (var filePath in files)
        {
            if (!File.Exists(filePath))
                continue;

            var fileInfo = new FileInfo(filePath);
            if (fileInfo.LastWriteTimeUtc > since)
            {
                modifiedFiles.Add(NormalizePath(filePath));
            }
        }

        return modifiedFiles;
    }

    /// <summary>
    /// Computes detailed change information for a single file.
    /// </summary>
    public FileChangeInfo GetFileChangeInfo(string filePath)
    {
        var normalizedPath = NormalizePath(filePath);
        var cachedEntry = _cache.GetFileEntry(normalizedPath);

        if (!File.Exists(filePath))
        {
            return new FileChangeInfo
            {
                FilePath = normalizedPath,
                Status = FileChangeStatus.Deleted,
                CurrentHash = null,
                CachedHash = cachedEntry?.ContentHash,
                LastAnalyzedAt = cachedEntry?.LastAnalyzedAt
            };
        }

        var currentHash = ComputeFileHash(filePath);
        var fileInfo = new FileInfo(filePath);

        if (cachedEntry == null)
        {
            return new FileChangeInfo
            {
                FilePath = normalizedPath,
                Status = FileChangeStatus.New,
                CurrentHash = currentHash,
                CachedHash = null,
                CurrentSize = fileInfo.Length,
                LastModified = fileInfo.LastWriteTimeUtc
            };
        }

        var status = currentHash == cachedEntry.ContentHash
            ? FileChangeStatus.Unchanged
            : FileChangeStatus.Modified;

        return new FileChangeInfo
        {
            FilePath = normalizedPath,
            Status = status,
            CurrentHash = currentHash,
            CachedHash = cachedEntry.ContentHash,
            CurrentSize = fileInfo.Length,
            CachedSize = cachedEntry.FileSize,
            LastModified = fileInfo.LastWriteTimeUtc,
            LastAnalyzedAt = cachedEntry.LastAnalyzedAt
        };
    }

    /// <summary>
    /// Gets a summary of changes for reporting.
    /// </summary>
    public ChangeSummary GetChangeSummary(ChangeDetectionResult result)
    {
        var totalChanges = result.ChangedFiles.Count + result.NewFiles.Count + result.DeletedFiles.Count;
        var percentChanged = result.UnchangedFiles.Count + totalChanges > 0
            ? (double)totalChanges / (result.UnchangedFiles.Count + totalChanges) * 100
            : 0;

        return new ChangeSummary
        {
            TotalFilesChecked = result.ChangedFiles.Count + result.NewFiles.Count +
                                result.DeletedFiles.Count + result.UnchangedFiles.Count,
            ChangedFileCount = result.ChangedFiles.Count,
            NewFileCount = result.NewFiles.Count,
            DeletedFileCount = result.DeletedFiles.Count,
            UnchangedFileCount = result.UnchangedFiles.Count,
            AffectedFileCount = result.AffectedFiles.Count,
            FilesToAnalyzeCount = result.FilesToAnalyze.Count,
            PercentChanged = percentChanged
        };
    }

    /// <summary>
    /// Validates that the cache is still valid for the current file state.
    /// </summary>
    public CacheValidationResult ValidateCache(IEnumerable<string> currentFiles)
    {
        var issues = new List<string>();
        var currentFileSet = currentFiles
            .Select(NormalizePath)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var cachedFiles = _cache.Cache.Files;
        var invalidEntries = 0;
        var missingFiles = 0;
        var hashMismatches = 0;

        foreach (var (path, entry) in cachedFiles)
        {
            if (!currentFileSet.Contains(path))
            {
                if (!File.Exists(path))
                {
                    issues.Add($"Cached file no longer exists: {Path.GetFileName(path)}");
                    invalidEntries++;
                    missingFiles++;
                }
            }
            else
            {
                var currentHash = ComputeFileHash(path);
                if (currentHash != entry.ContentHash)
                {
                    hashMismatches++;
                }
            }
        }

        return new CacheValidationResult
        {
            IsValid = invalidEntries == 0,
            InvalidEntryCount = invalidEntries,
            MissingFileCount = missingFiles,
            HashMismatchCount = hashMismatches,
            Issues = issues
        };
    }

    private static string ComputeFileHash(string filePath)
    {
        return AnalysisCache.ComputeFileHash(filePath);
    }

    private static string NormalizePath(string path)
    {
        return Path.GetFullPath(path).Replace('/', Path.DirectorySeparatorChar);
    }
}

/// <summary>
/// Status of a file change.
/// </summary>
public enum FileChangeStatus
{
    Unchanged,
    Modified,
    New,
    Deleted
}

/// <summary>
/// Detailed change information for a single file.
/// </summary>
public record FileChangeInfo
{
    public required string FilePath { get; init; }
    public required FileChangeStatus Status { get; init; }
    public string? CurrentHash { get; init; }
    public string? CachedHash { get; init; }
    public long? CurrentSize { get; init; }
    public long? CachedSize { get; init; }
    public DateTime? LastModified { get; init; }
    public DateTime? LastAnalyzedAt { get; init; }

    public long SizeDelta => (CurrentSize ?? 0) - (CachedSize ?? 0);
}

/// <summary>
/// Summary of detected changes.
/// </summary>
public record ChangeSummary
{
    public required int TotalFilesChecked { get; init; }
    public required int ChangedFileCount { get; init; }
    public required int NewFileCount { get; init; }
    public required int DeletedFileCount { get; init; }
    public required int UnchangedFileCount { get; init; }
    public required int AffectedFileCount { get; init; }
    public required int FilesToAnalyzeCount { get; init; }
    public required double PercentChanged { get; init; }

    public string Summary =>
        $"{FilesToAnalyzeCount} files to analyze ({ChangedFileCount} changed, {NewFileCount} new, " +
        $"{AffectedFileCount} affected by dependencies), {UnchangedFileCount} unchanged";
}

/// <summary>
/// Result of cache validation.
/// </summary>
public record CacheValidationResult
{
    public required bool IsValid { get; init; }
    public required int InvalidEntryCount { get; init; }
    public required int MissingFileCount { get; init; }
    public required int HashMismatchCount { get; init; }
    public List<string> Issues { get; init; } = [];
}
