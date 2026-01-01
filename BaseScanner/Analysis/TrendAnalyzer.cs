using System.Diagnostics;
using System.Text.Json;

namespace BaseScanner.Analysis;

/// <summary>
/// Analyzes metric trends over time using git history.
/// </summary>
public class TrendAnalyzer
{
    private readonly string _projectPath;
    private readonly string _dataPath;

    public TrendAnalyzer(string projectPath)
    {
        _projectPath = projectPath;
        _dataPath = Path.Combine(projectPath, ".basescanner", "history");
        Directory.CreateDirectory(_dataPath);
    }

    /// <summary>
    /// Save current metrics for historical tracking.
    /// </summary>
    public async Task SaveMetricsSnapshotAsync(ProjectMetrics metrics)
    {
        var snapshot = new MetricsSnapshot
        {
            Timestamp = DateTime.UtcNow,
            CommitHash = await GetCurrentCommitHashAsync(),
            CommitMessage = await GetCurrentCommitMessageAsync(),
            Metrics = metrics
        };

        var fileName = $"metrics-{snapshot.Timestamp:yyyyMMdd-HHmmss}.json";
        var filePath = Path.Combine(_dataPath, fileName);

        var json = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(filePath, json);
    }

    /// <summary>
    /// Get metrics history.
    /// </summary>
    public async Task<List<MetricsSnapshot>> GetHistoryAsync(TimeSpan? since = null)
    {
        var snapshots = new List<MetricsSnapshot>();
        var cutoff = since.HasValue ? DateTime.UtcNow - since.Value : DateTime.MinValue;

        if (!Directory.Exists(_dataPath))
            return snapshots;

        foreach (var file in Directory.GetFiles(_dataPath, "metrics-*.json"))
        {
            try
            {
                var json = await File.ReadAllTextAsync(file);
                var snapshot = JsonSerializer.Deserialize<MetricsSnapshot>(json);

                if (snapshot != null && snapshot.Timestamp >= cutoff)
                {
                    snapshots.Add(snapshot);
                }
            }
            catch
            {
                // Skip corrupted files
            }
        }

        return snapshots.OrderBy(s => s.Timestamp).ToList();
    }

    /// <summary>
    /// Analyze trends between two snapshots.
    /// </summary>
    public TrendAnalysis AnalyzeTrends(MetricsSnapshot older, MetricsSnapshot newer)
    {
        return new TrendAnalysis
        {
            Period = new DateRange(older.Timestamp, newer.Timestamp),

            // Health
            HealthScoreChange = newer.Metrics.HealthScore - older.Metrics.HealthScore,
            HealthTrend = GetTrend(older.Metrics.HealthScore, newer.Metrics.HealthScore, isHigherBetter: true),

            // Security
            SecurityIssuesChange = newer.Metrics.SecurityVulnerabilities - older.Metrics.SecurityVulnerabilities,
            SecurityTrend = GetTrend(older.Metrics.SecurityVulnerabilities, newer.Metrics.SecurityVulnerabilities, isHigherBetter: false),
            CriticalIssuesChange = newer.Metrics.CriticalSecurityIssues - older.Metrics.CriticalSecurityIssues,

            // Complexity
            ComplexityChange = newer.Metrics.AverageCyclomaticComplexity - older.Metrics.AverageCyclomaticComplexity,
            ComplexityTrend = GetTrend(older.Metrics.AverageCyclomaticComplexity, newer.Metrics.AverageCyclomaticComplexity, isHigherBetter: false),

            // Maintainability
            MaintainabilityChange = newer.Metrics.MaintainabilityIndex - older.Metrics.MaintainabilityIndex,
            MaintainabilityTrend = GetTrend(older.Metrics.MaintainabilityIndex, newer.Metrics.MaintainabilityIndex, isHigherBetter: true),

            // Code size
            LinesChange = newer.Metrics.TotalLines - older.Metrics.TotalLines,
            MethodsChange = newer.Metrics.TotalMethods - older.Metrics.TotalMethods
        };
    }

    /// <summary>
    /// Analyze trends from git history.
    /// </summary>
    public async Task<GitTrendAnalysis> AnalyzeGitTrendsAsync(int commitCount = 10)
    {
        var commits = await GetRecentCommitsAsync(commitCount);
        var analysis = new GitTrendAnalysis
        {
            AnalyzedCommits = commits.Count
        };

        if (commits.Count == 0)
            return analysis;

        // Get file change statistics
        foreach (var commit in commits)
        {
            var stats = await GetCommitStatsAsync(commit.Hash);
            analysis.TotalFilesChanged += stats.FilesChanged;
            analysis.TotalAdditions += stats.Additions;
            analysis.TotalDeletions += stats.Deletions;

            // Track most changed files
            foreach (var file in stats.ChangedFiles)
            {
                if (!analysis.MostChangedFiles.ContainsKey(file))
                    analysis.MostChangedFiles[file] = 0;
                analysis.MostChangedFiles[file]++;
            }
        }

        // Find most frequently changed files
        analysis.Hotspots = analysis.MostChangedFiles
            .OrderByDescending(kvp => kvp.Value)
            .Take(10)
            .Select(kvp => new ChangeHotspot { FilePath = kvp.Key, ChangeCount = kvp.Value })
            .ToList();

        // Analyze commit patterns
        analysis.CommitsPerDay = commits
            .GroupBy(c => c.Date.Date)
            .ToDictionary(g => g.Key, g => g.Count());

        // Analyze authors
        analysis.AuthorContributions = commits
            .GroupBy(c => c.Author)
            .ToDictionary(g => g.Key, g => g.Count());

        return analysis;
    }

    /// <summary>
    /// Detect regressions by comparing with baseline.
    /// </summary>
    public async Task<List<Regression>> DetectRegressionsAsync()
    {
        var regressions = new List<Regression>();
        var history = await GetHistoryAsync(TimeSpan.FromDays(7));

        if (history.Count < 2)
            return regressions;

        var baseline = history.First();
        var current = history.Last();

        // Check security regressions
        if (current.Metrics.CriticalSecurityIssues > baseline.Metrics.CriticalSecurityIssues)
        {
            regressions.Add(new Regression
            {
                Type = "Security",
                Severity = "Critical",
                Message = $"Critical security issues increased from {baseline.Metrics.CriticalSecurityIssues} to {current.Metrics.CriticalSecurityIssues}",
                BaselineValue = baseline.Metrics.CriticalSecurityIssues,
                CurrentValue = current.Metrics.CriticalSecurityIssues,
                BaselineCommit = baseline.CommitHash,
                CurrentCommit = current.CommitHash
            });
        }

        if (current.Metrics.HighSecurityIssues > baseline.Metrics.HighSecurityIssues)
        {
            regressions.Add(new Regression
            {
                Type = "Security",
                Severity = "High",
                Message = $"High security issues increased from {baseline.Metrics.HighSecurityIssues} to {current.Metrics.HighSecurityIssues}",
                BaselineValue = baseline.Metrics.HighSecurityIssues,
                CurrentValue = current.Metrics.HighSecurityIssues,
                BaselineCommit = baseline.CommitHash,
                CurrentCommit = current.CommitHash
            });
        }

        // Check health score regression
        if (current.Metrics.HealthScore < baseline.Metrics.HealthScore - 10)
        {
            regressions.Add(new Regression
            {
                Type = "Health",
                Severity = "Medium",
                Message = $"Health score dropped from {baseline.Metrics.HealthScore} to {current.Metrics.HealthScore}",
                BaselineValue = baseline.Metrics.HealthScore,
                CurrentValue = current.Metrics.HealthScore,
                BaselineCommit = baseline.CommitHash,
                CurrentCommit = current.CommitHash
            });
        }

        // Check complexity regression
        if (current.Metrics.MethodsAboveThreshold > baseline.Metrics.MethodsAboveThreshold + 5)
        {
            regressions.Add(new Regression
            {
                Type = "Complexity",
                Severity = "Medium",
                Message = $"Complex methods increased from {baseline.Metrics.MethodsAboveThreshold} to {current.Metrics.MethodsAboveThreshold}",
                BaselineValue = baseline.Metrics.MethodsAboveThreshold,
                CurrentValue = current.Metrics.MethodsAboveThreshold,
                BaselineCommit = baseline.CommitHash,
                CurrentCommit = current.CommitHash
            });
        }

        return regressions;
    }

    private Trend GetTrend(double oldValue, double newValue, bool isHigherBetter)
    {
        var diff = newValue - oldValue;
        var threshold = Math.Abs(oldValue) * 0.05; // 5% change threshold

        if (Math.Abs(diff) < threshold)
            return Trend.Stable;

        var isImproving = (diff > 0) == isHigherBetter;
        return isImproving ? Trend.Improving : Trend.Declining;
    }

    private async Task<string> GetCurrentCommitHashAsync()
    {
        try
        {
            return await RunGitCommandAsync("rev-parse --short HEAD");
        }
        catch
        {
            return "unknown";
        }
    }

    private async Task<string> GetCurrentCommitMessageAsync()
    {
        try
        {
            return await RunGitCommandAsync("log -1 --format=%s");
        }
        catch
        {
            return "";
        }
    }

    private async Task<List<GitCommit>> GetRecentCommitsAsync(int count)
    {
        var commits = new List<GitCommit>();

        try
        {
            var output = await RunGitCommandAsync($"log -{count} --format=%H|%s|%an|%aI");
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines)
            {
                var parts = line.Split('|');
                if (parts.Length >= 4)
                {
                    commits.Add(new GitCommit
                    {
                        Hash = parts[0].Trim(),
                        Message = parts[1].Trim(),
                        Author = parts[2].Trim(),
                        Date = DateTime.Parse(parts[3].Trim())
                    });
                }
            }
        }
        catch
        {
            // Git not available or not a git repo
        }

        return commits;
    }

    private async Task<CommitStats> GetCommitStatsAsync(string commitHash)
    {
        var stats = new CommitStats();

        try
        {
            var output = await RunGitCommandAsync($"show --stat --format= {commitHash}");
            var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

            foreach (var line in lines)
            {
                if (line.Contains("|"))
                {
                    var parts = line.Split('|');
                    if (parts.Length >= 1)
                    {
                        stats.ChangedFiles.Add(parts[0].Trim());
                        stats.FilesChanged++;
                    }
                }
                else if (line.Contains("insertion") || line.Contains("deletion"))
                {
                    // Parse summary line
                    var words = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    for (int i = 0; i < words.Length - 1; i++)
                    {
                        if (int.TryParse(words[i], out var num))
                        {
                            if (words[i + 1].StartsWith("insertion"))
                                stats.Additions = num;
                            else if (words[i + 1].StartsWith("deletion"))
                                stats.Deletions = num;
                        }
                    }
                }
            }
        }
        catch
        {
            // Git not available
        }

        return stats;
    }

    private async Task<string> RunGitCommandAsync(string arguments)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "git",
                Arguments = arguments,
                WorkingDirectory = _projectPath,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        process.Start();
        var output = await process.StandardOutput.ReadToEndAsync();
        await process.WaitForExitAsync();

        return output.Trim();
    }
}

/// <summary>
/// A snapshot of metrics at a point in time.
/// </summary>
public record MetricsSnapshot
{
    public DateTime Timestamp { get; init; }
    public string? CommitHash { get; init; }
    public string? CommitMessage { get; init; }
    public required ProjectMetrics Metrics { get; init; }
}

/// <summary>
/// Analysis of trends between two snapshots.
/// </summary>
public record TrendAnalysis
{
    public DateRange Period { get; init; } = new(DateTime.MinValue, DateTime.MaxValue);

    // Health
    public int HealthScoreChange { get; init; }
    public Trend HealthTrend { get; init; }

    // Security
    public int SecurityIssuesChange { get; init; }
    public Trend SecurityTrend { get; init; }
    public int CriticalIssuesChange { get; init; }

    // Complexity
    public double ComplexityChange { get; init; }
    public Trend ComplexityTrend { get; init; }

    // Maintainability
    public double MaintainabilityChange { get; init; }
    public Trend MaintainabilityTrend { get; init; }

    // Code size
    public int LinesChange { get; init; }
    public int MethodsChange { get; init; }
}

public record DateRange(DateTime Start, DateTime End);

public enum Trend
{
    Improving,
    Stable,
    Declining
}

/// <summary>
/// Analysis from git history.
/// </summary>
public record GitTrendAnalysis
{
    public int AnalyzedCommits { get; init; }
    public int TotalFilesChanged { get; set; }
    public int TotalAdditions { get; set; }
    public int TotalDeletions { get; set; }
    public Dictionary<string, int> MostChangedFiles { get; init; } = [];
    public List<ChangeHotspot> Hotspots { get; set; } = [];
    public Dictionary<DateTime, int> CommitsPerDay { get; set; } = [];
    public Dictionary<string, int> AuthorContributions { get; set; } = [];
}

public record ChangeHotspot
{
    public required string FilePath { get; init; }
    public required int ChangeCount { get; init; }
}

public record GitCommit
{
    public required string Hash { get; init; }
    public required string Message { get; init; }
    public required string Author { get; init; }
    public required DateTime Date { get; init; }
}

public record CommitStats
{
    public int FilesChanged { get; set; }
    public int Additions { get; set; }
    public int Deletions { get; set; }
    public List<string> ChangedFiles { get; init; } = [];
}

/// <summary>
/// A detected regression.
/// </summary>
public record Regression
{
    public required string Type { get; init; }
    public required string Severity { get; init; }
    public required string Message { get; init; }
    public required double BaselineValue { get; init; }
    public required double CurrentValue { get; init; }
    public string? BaselineCommit { get; init; }
    public string? CurrentCommit { get; init; }
}
