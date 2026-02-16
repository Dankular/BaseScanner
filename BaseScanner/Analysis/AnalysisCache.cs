using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BaseScanner.Analysis.Models;

namespace BaseScanner.Analysis;

/// <summary>
/// Provides persistent caching for incremental analysis.
/// Stores cache data in .basescanner/cache/ directory.
/// </summary>
public class AnalysisCache
{
    private const int CurrentCacheVersion = 1;
    private const string CacheFileName = "analysis-cache.json";

    private readonly string _cacheDirectory;
    private readonly string _cacheFilePath;
    private readonly string _projectPath;

    private AnalysisCacheData? _cache;
    private readonly object _lock = new();

    /// <summary>
    /// Creates a new cache instance for the specified project.
    /// </summary>
    /// <param name="projectPath">Path to the project directory or .csproj file.</param>
    public AnalysisCache(string projectPath)
    {
        _projectPath = Path.GetDirectoryName(projectPath) ?? projectPath;
        _cacheDirectory = Path.Combine(_projectPath, ".basescanner", "cache");
        _cacheFilePath = Path.Combine(_cacheDirectory, CacheFileName);
    }

    /// <summary>
    /// Gets the path to the cache directory.
    /// </summary>
    public string CacheDirectory => _cacheDirectory;

    /// <summary>
    /// Gets the current cache data, loading it if necessary.
    /// </summary>
    public AnalysisCacheData Cache
    {
        get
        {
            lock (_lock)
            {
                if (_cache == null)
                {
                    _cache = LoadCacheSync() ?? CreateEmptyCache();
                }
                return _cache;
            }
        }
    }

    /// <summary>
    /// Loads the cache from disk asynchronously.
    /// </summary>
    public async Task<AnalysisCacheData?> LoadAsync()
    {
        if (!File.Exists(_cacheFilePath))
            return null;

        try
        {
            var json = await File.ReadAllTextAsync(_cacheFilePath);
            var cache = JsonSerializer.Deserialize<AnalysisCacheData>(json, GetJsonOptions());

            // Validate cache version and project path
            if (cache != null && cache.Version == CurrentCacheVersion &&
                cache.ProjectPath.Equals(_projectPath, StringComparison.OrdinalIgnoreCase))
            {
                lock (_lock)
                {
                    _cache = cache;
                }
                return cache;
            }

            // Cache is outdated or for different project
            return null;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Failed to load cache: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Saves the cache to disk asynchronously.
    /// </summary>
    public async Task SaveAsync()
    {
        AnalysisCacheData cacheToSave;
        lock (_lock)
        {
            if (_cache == null)
                return;

            cacheToSave = _cache with { LastUpdated = DateTime.UtcNow };
            _cache = cacheToSave;
        }

        try
        {
            Directory.CreateDirectory(_cacheDirectory);

            var json = JsonSerializer.Serialize(cacheToSave, GetJsonOptions());
            await File.WriteAllTextAsync(_cacheFilePath, json);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Warning: Failed to save cache: {ex.Message}");
        }
    }

    /// <summary>
    /// Clears the cache.
    /// </summary>
    public async Task ClearAsync()
    {
        lock (_lock)
        {
            _cache = CreateEmptyCache();
        }

        if (Directory.Exists(_cacheDirectory))
        {
            try
            {
                // Delete all cache files
                foreach (var file in Directory.GetFiles(_cacheDirectory))
                {
                    File.Delete(file);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to clear cache: {ex.Message}");
            }
        }

        await Task.CompletedTask;
    }

    /// <summary>
    /// Gets the cached entry for a specific file.
    /// </summary>
    public FileCacheEntry? GetFileEntry(string filePath)
    {
        var normalizedPath = NormalizePath(filePath);
        return Cache.Files.TryGetValue(normalizedPath, out var entry) ? entry : null;
    }

    /// <summary>
    /// Updates or adds a file cache entry.
    /// </summary>
    public void SetFileEntry(FileCacheEntry entry)
    {
        var normalizedPath = NormalizePath(entry.FilePath);
        lock (_lock)
        {
            if (_cache == null)
                _cache = CreateEmptyCache();

            _cache.Files[normalizedPath] = entry with { FilePath = normalizedPath };
        }
    }

    /// <summary>
    /// Removes a file from the cache.
    /// </summary>
    public void RemoveFileEntry(string filePath)
    {
        var normalizedPath = NormalizePath(filePath);
        lock (_lock)
        {
            _cache?.Files.Remove(normalizedPath);
        }
    }

    /// <summary>
    /// Checks if a file is cached and valid.
    /// </summary>
    public bool IsFileCached(string filePath)
    {
        var entry = GetFileEntry(filePath);
        if (entry == null)
            return false;

        // Verify the file still exists and hash matches
        if (!File.Exists(filePath))
            return false;

        var currentHash = ComputeFileHash(filePath);
        return entry.ContentHash == currentHash;
    }

    /// <summary>
    /// Updates the dependency graph.
    /// </summary>
    public void UpdateDependencyGraph(DependencyGraph graph)
    {
        lock (_lock)
        {
            if (_cache == null)
                _cache = CreateEmptyCache();

            _cache = _cache with { DependencyGraph = graph };
        }
    }

    /// <summary>
    /// Gets the current dependency graph.
    /// </summary>
    public DependencyGraph GetDependencyGraph()
    {
        return Cache.DependencyGraph;
    }

    /// <summary>
    /// Gets statistics about the cache.
    /// </summary>
    public CacheStatistics GetStatistics()
    {
        var cache = Cache;
        var validEntries = cache.Files.Values.Count(e => File.Exists(e.FilePath));
        var totalSize = cache.Files.Values.Sum(e => e.FileSize);

        return new CacheStatistics
        {
            TotalEntries = cache.Files.Count,
            ValidEntries = validEntries,
            InvalidEntries = cache.Files.Count - validEntries,
            TotalCachedBytes = totalSize,
            LastUpdated = cache.LastUpdated,
            CacheVersion = cache.Version,
            DependencyCount = cache.DependencyGraph.Dependencies.Count
        };
    }

    /// <summary>
    /// Removes stale entries (files that no longer exist).
    /// </summary>
    public void PruneStaleEntries()
    {
        lock (_lock)
        {
            if (_cache == null)
                return;

            var staleFiles = _cache.Files.Keys
                .Where(path => !File.Exists(path))
                .ToList();

            foreach (var file in staleFiles)
            {
                _cache.Files.Remove(file);
            }
        }
    }

    /// <summary>
    /// Invalidates cache entries older than the specified age.
    /// </summary>
    public void InvalidateOldEntries(TimeSpan maxAge)
    {
        var cutoff = DateTime.UtcNow - maxAge;
        lock (_lock)
        {
            if (_cache == null)
                return;

            var oldFiles = _cache.Files
                .Where(kvp => kvp.Value.LastAnalyzedAt < cutoff)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var file in oldFiles)
            {
                _cache.Files.Remove(file);
            }
        }
    }

    /// <summary>
    /// Computes the SHA256 hash of a file's content.
    /// </summary>
    public static string ComputeFileHash(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hash = sha256.ComputeHash(stream);
        return Convert.ToHexString(hash);
    }

    /// <summary>
    /// Computes the SHA256 hash of content string.
    /// </summary>
    public static string ComputeContentHash(string content)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(content);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToHexString(hash);
    }

    private AnalysisCacheData? LoadCacheSync()
    {
        if (!File.Exists(_cacheFilePath))
            return null;

        try
        {
            var json = File.ReadAllText(_cacheFilePath);
            var cache = JsonSerializer.Deserialize<AnalysisCacheData>(json, GetJsonOptions());

            if (cache != null && cache.Version == CurrentCacheVersion &&
                cache.ProjectPath.Equals(_projectPath, StringComparison.OrdinalIgnoreCase))
            {
                return cache;
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private AnalysisCacheData CreateEmptyCache()
    {
        return new AnalysisCacheData
        {
            Version = CurrentCacheVersion,
            LastUpdated = DateTime.UtcNow,
            ProjectPath = _projectPath,
            Files = new Dictionary<string, FileCacheEntry>(),
            DependencyGraph = new DependencyGraph()
        };
    }

    private static string NormalizePath(string path)
    {
        return Path.GetFullPath(path).Replace('/', Path.DirectorySeparatorChar);
    }

    private static JsonSerializerOptions GetJsonOptions()
    {
        return new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };
    }
}

/// <summary>
/// Statistics about the analysis cache.
/// </summary>
public record CacheStatistics
{
    public required int TotalEntries { get; init; }
    public required int ValidEntries { get; init; }
    public required int InvalidEntries { get; init; }
    public required long TotalCachedBytes { get; init; }
    public required DateTime LastUpdated { get; init; }
    public required int CacheVersion { get; init; }
    public required int DependencyCount { get; init; }

    public string FormattedSize => FormatBytes(TotalCachedBytes);

    private static string FormatBytes(long bytes)
    {
        string[] suffixes = ["B", "KB", "MB", "GB"];
        int i = 0;
        double size = bytes;
        while (size >= 1024 && i < suffixes.Length - 1)
        {
            size /= 1024;
            i++;
        }
        return $"{size:F1} {suffixes[i]}";
    }
}
