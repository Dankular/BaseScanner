using System.Text.Json;
using System.Text.Json.Serialization;
using BaseScanner.ML.Models;

namespace BaseScanner.ML;

/// <summary>
/// Stores and manages user feedback on suggestions.
/// Persists data to .basescanner/feedback.json.
/// </summary>
public class FeedbackStore
{
    private readonly string _storePath;
    private readonly object _lock = new();
    private FeedbackStoreData _data;
    private bool _isDirty;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    /// <summary>
    /// Creates a new feedback store for the specified project directory.
    /// </summary>
    public FeedbackStore(string projectDirectory)
    {
        var baseScannerDir = Path.Combine(projectDirectory, ".basescanner");
        Directory.CreateDirectory(baseScannerDir);
        _storePath = Path.Combine(baseScannerDir, "feedback.json");
        _data = LoadOrCreate();
    }

    /// <summary>
    /// Records that a user applied a suggestion.
    /// </summary>
    public void RecordApplied(SuggestionFeatures features, double? confidenceScore = null, string? comment = null)
    {
        RecordFeedback(features, FeedbackAction.Applied, confidenceScore, comment);
    }

    /// <summary>
    /// Records that a user rejected a suggestion.
    /// </summary>
    public void RecordRejected(SuggestionFeatures features, double? confidenceScore = null, string? comment = null)
    {
        RecordFeedback(features, FeedbackAction.Rejected, confidenceScore, comment);
    }

    /// <summary>
    /// Records that a user reverted a previously applied suggestion.
    /// </summary>
    public void RecordReverted(SuggestionFeatures features, double? confidenceScore = null, string? comment = null)
    {
        RecordFeedback(features, FeedbackAction.Reverted, confidenceScore, comment);
    }

    /// <summary>
    /// Records that a user skipped a suggestion without deciding.
    /// </summary>
    public void RecordSkipped(SuggestionFeatures features, double? confidenceScore = null)
    {
        RecordFeedback(features, FeedbackAction.Skipped, confidenceScore, null);
    }

    /// <summary>
    /// Records feedback for a suggestion.
    /// </summary>
    public void RecordFeedback(
        SuggestionFeatures features,
        FeedbackAction action,
        double? confidenceScore = null,
        string? comment = null)
    {
        var record = new FeedbackRecord
        {
            Id = Guid.NewGuid().ToString("N"),
            SuggestionId = features.SuggestionId,
            PatternType = features.PatternType,
            FilePath = features.FilePath,
            Action = action,
            Timestamp = DateTime.UtcNow,
            Features = features,
            ConfidenceScore = confidenceScore,
            Comment = comment
        };

        lock (_lock)
        {
            _data.Records.Add(record);
            UpdatePatternStats(features.PatternType, action);
            _data = _data with { LastUpdated = DateTime.UtcNow };
            _isDirty = true;
        }

        // Auto-save after each feedback
        Save();
    }

    /// <summary>
    /// Records feedback by suggestion ID (for simpler API).
    /// </summary>
    public void RecordFeedback(
        string suggestionId,
        string patternType,
        string filePath,
        FeedbackAction action,
        double? confidenceScore = null)
    {
        var minimalFeatures = new SuggestionFeatures
        {
            SuggestionId = suggestionId,
            PatternType = patternType,
            FilePath = filePath
        };

        RecordFeedback(minimalFeatures, action, confidenceScore);
    }

    /// <summary>
    /// Gets statistics for a specific pattern type.
    /// </summary>
    public PatternStatistics? GetPatternStatistics(string patternType)
    {
        lock (_lock)
        {
            return _data.PatternStats.TryGetValue(patternType, out var stats) ? stats : null;
        }
    }

    /// <summary>
    /// Gets all pattern statistics.
    /// </summary>
    public IReadOnlyDictionary<string, PatternStatistics> GetAllPatternStatistics()
    {
        lock (_lock)
        {
            return new Dictionary<string, PatternStatistics>(_data.PatternStats);
        }
    }

    /// <summary>
    /// Gets all feedback records.
    /// </summary>
    public IReadOnlyList<FeedbackRecord> GetAllRecords()
    {
        lock (_lock)
        {
            return _data.Records.ToList();
        }
    }

    /// <summary>
    /// Gets feedback records for a specific pattern type.
    /// </summary>
    public IReadOnlyList<FeedbackRecord> GetRecordsForPattern(string patternType)
    {
        lock (_lock)
        {
            return _data.Records
                .Where(r => r.PatternType == patternType)
                .ToList();
        }
    }

    /// <summary>
    /// Gets recent feedback records.
    /// </summary>
    public IReadOnlyList<FeedbackRecord> GetRecentRecords(int count = 100)
    {
        lock (_lock)
        {
            return _data.Records
                .OrderByDescending(r => r.Timestamp)
                .Take(count)
                .ToList();
        }
    }

    /// <summary>
    /// Checks if there is sufficient data for a pattern type.
    /// </summary>
    public bool HasSufficientData(string patternType, int minimumSamples = 5)
    {
        var stats = GetPatternStatistics(patternType);
        if (stats == null) return false;
        return (stats.AppliedCount + stats.RejectedCount) >= minimumSamples;
    }

    /// <summary>
    /// Saves the feedback store to disk.
    /// </summary>
    public void Save()
    {
        lock (_lock)
        {
            if (!_isDirty) return;

            try
            {
                var json = JsonSerializer.Serialize(_data, JsonOptions);
                File.WriteAllText(_storePath, json);
                _isDirty = false;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Warning: Failed to save feedback store: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Clears all feedback data.
    /// </summary>
    public void Clear()
    {
        lock (_lock)
        {
            _data = new FeedbackStoreData
            {
                Version = 1,
                Records = [],
                PatternStats = new Dictionary<string, PatternStatistics>(),
                LastUpdated = DateTime.UtcNow
            };
            _isDirty = true;
        }
        Save();
    }

    /// <summary>
    /// Rebuilds pattern statistics from all records.
    /// </summary>
    public void RebuildStatistics()
    {
        lock (_lock)
        {
            _data = _data with { PatternStats = new Dictionary<string, PatternStatistics>() };

            foreach (var record in _data.Records)
            {
                UpdatePatternStats(record.PatternType, record.Action);
            }

            _data = _data with { LastUpdated = DateTime.UtcNow };
            _isDirty = true;
        }
        Save();
    }

    /// <summary>
    /// Gets a summary of the feedback store.
    /// </summary>
    public FeedbackSummary GetSummary()
    {
        lock (_lock)
        {
            return new FeedbackSummary
            {
                TotalRecords = _data.Records.Count,
                TotalPatterns = _data.PatternStats.Count,
                AppliedCount = _data.Records.Count(r => r.Action == FeedbackAction.Applied),
                RejectedCount = _data.Records.Count(r => r.Action == FeedbackAction.Rejected),
                RevertedCount = _data.Records.Count(r => r.Action == FeedbackAction.Reverted),
                SkippedCount = _data.Records.Count(r => r.Action == FeedbackAction.Skipped),
                LastUpdated = _data.LastUpdated,
                OldestRecord = _data.Records.MinBy(r => r.Timestamp)?.Timestamp,
                NewestRecord = _data.Records.MaxBy(r => r.Timestamp)?.Timestamp
            };
        }
    }

    private FeedbackStoreData LoadOrCreate()
    {
        try
        {
            if (File.Exists(_storePath))
            {
                var json = File.ReadAllText(_storePath);
                var data = JsonSerializer.Deserialize<FeedbackStoreData>(json, JsonOptions);
                if (data != null)
                {
                    return data;
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Warning: Failed to load feedback store, creating new: {ex.Message}");
        }

        return new FeedbackStoreData
        {
            Version = 1,
            Records = [],
            PatternStats = new Dictionary<string, PatternStatistics>(),
            LastUpdated = DateTime.UtcNow
        };
    }

    private void UpdatePatternStats(string patternType, FeedbackAction action)
    {
        if (!_data.PatternStats.TryGetValue(patternType, out var stats))
        {
            stats = new PatternStatistics { PatternType = patternType };
        }

        stats = action switch
        {
            FeedbackAction.Applied => stats with
            {
                TotalSuggestions = stats.TotalSuggestions + 1,
                AppliedCount = stats.AppliedCount + 1,
                LastUpdated = DateTime.UtcNow
            },
            FeedbackAction.Rejected => stats with
            {
                TotalSuggestions = stats.TotalSuggestions + 1,
                RejectedCount = stats.RejectedCount + 1,
                LastUpdated = DateTime.UtcNow
            },
            FeedbackAction.Reverted => stats with
            {
                RevertedCount = stats.RevertedCount + 1,
                LastUpdated = DateTime.UtcNow
            },
            FeedbackAction.Skipped => stats with
            {
                TotalSuggestions = stats.TotalSuggestions + 1,
                SkippedCount = stats.SkippedCount + 1,
                LastUpdated = DateTime.UtcNow
            },
            _ => stats
        };

        _data.PatternStats[patternType] = stats;
    }
}

/// <summary>
/// Summary of the feedback store contents.
/// </summary>
public record FeedbackSummary
{
    public int TotalRecords { get; init; }
    public int TotalPatterns { get; init; }
    public int AppliedCount { get; init; }
    public int RejectedCount { get; init; }
    public int RevertedCount { get; init; }
    public int SkippedCount { get; init; }
    public DateTime LastUpdated { get; init; }
    public DateTime? OldestRecord { get; init; }
    public DateTime? NewestRecord { get; init; }

    public double OverallApplicationRate =>
        (AppliedCount + RejectedCount) > 0
            ? (double)AppliedCount / (AppliedCount + RejectedCount)
            : 0.5;

    public double OverallReversionRate =>
        AppliedCount > 0
            ? (double)RevertedCount / AppliedCount
            : 0.0;
}
