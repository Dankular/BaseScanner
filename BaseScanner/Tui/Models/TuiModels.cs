namespace BaseScanner.Tui.Models;

/// <summary>
/// Represents an issue displayed in the TUI.
/// </summary>
public record TuiIssue
{
    public required string Id { get; init; }
    public required string Type { get; init; }
    public required string Severity { get; init; }
    public required string Category { get; init; }
    public required string Message { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public int EndLine { get; init; }
    public string? CodeSnippet { get; init; }
    public string? SuggestedFix { get; init; }
    public string? CweId { get; init; }
    public string? Recommendation { get; init; }
    public string? Confidence { get; init; }

    /// <summary>
    /// Whether this issue has an auto-fix available.
    /// </summary>
    public bool HasFix => !string.IsNullOrEmpty(SuggestedFix);

    /// <summary>
    /// Get display color based on severity.
    /// </summary>
    public string SeverityColor => Severity.ToUpperInvariant() switch
    {
        "CRITICAL" => "red bold",
        "HIGH" => "red",
        "MEDIUM" => "yellow",
        "LOW" => "blue",
        "INFO" => "grey",
        _ => "white"
    };

    /// <summary>
    /// Get short severity label for display.
    /// </summary>
    public string SeverityLabel => Severity.ToUpperInvariant() switch
    {
        "CRITICAL" => "CRIT",
        "HIGH" => "HIGH",
        "MEDIUM" => "MED",
        "LOW" => "LOW",
        "INFO" => "INFO",
        _ => Severity.ToUpperInvariant()
    };
}

/// <summary>
/// Current state of the TUI application.
/// </summary>
public class TuiState
{
    /// <summary>
    /// All issues loaded from analysis.
    /// </summary>
    public List<TuiIssue> AllIssues { get; set; } = [];

    /// <summary>
    /// Issues after applying current filter.
    /// </summary>
    public List<TuiIssue> FilteredIssues { get; set; } = [];

    /// <summary>
    /// Currently selected issue index (in filtered list).
    /// </summary>
    public int SelectedIndex { get; set; }

    /// <summary>
    /// Set of selected issue IDs for batch operations.
    /// </summary>
    public HashSet<string> SelectedIssueIds { get; set; } = [];

    /// <summary>
    /// Stack of operations for undo functionality.
    /// </summary>
    public Stack<TuiOperation> UndoStack { get; set; } = new();

    /// <summary>
    /// Current filter settings.
    /// </summary>
    public TuiFilter CurrentFilter { get; set; } = new();

    /// <summary>
    /// Current view mode.
    /// </summary>
    public TuiViewMode ViewMode { get; set; } = TuiViewMode.IssueList;

    /// <summary>
    /// Whether filter panel is open.
    /// </summary>
    public bool IsFilterPanelOpen { get; set; }

    /// <summary>
    /// Search query string.
    /// </summary>
    public string SearchQuery { get; set; } = string.Empty;

    /// <summary>
    /// Whether search is active.
    /// </summary>
    public bool IsSearchActive { get; set; }

    /// <summary>
    /// Path to the project being analyzed.
    /// </summary>
    public string ProjectPath { get; set; } = string.Empty;

    /// <summary>
    /// Status message to display.
    /// </summary>
    public string StatusMessage { get; set; } = string.Empty;

    /// <summary>
    /// Whether the application is currently processing.
    /// </summary>
    public bool IsProcessing { get; set; }

    /// <summary>
    /// Get the currently selected issue, or null if none.
    /// </summary>
    public TuiIssue? CurrentIssue =>
        SelectedIndex >= 0 && SelectedIndex < FilteredIssues.Count
            ? FilteredIssues[SelectedIndex]
            : null;

    /// <summary>
    /// Move selection up.
    /// </summary>
    public void MoveUp()
    {
        if (SelectedIndex > 0)
            SelectedIndex--;
    }

    /// <summary>
    /// Move selection down.
    /// </summary>
    public void MoveDown()
    {
        if (SelectedIndex < FilteredIssues.Count - 1)
            SelectedIndex++;
    }

    /// <summary>
    /// Toggle selection of current issue.
    /// </summary>
    public void ToggleSelection()
    {
        var issue = CurrentIssue;
        if (issue == null) return;

        if (SelectedIssueIds.Contains(issue.Id))
            SelectedIssueIds.Remove(issue.Id);
        else
            SelectedIssueIds.Add(issue.Id);
    }

    /// <summary>
    /// Apply the current filter to refresh filtered issues.
    /// </summary>
    public void ApplyFilter()
    {
        var query = AllIssues.AsEnumerable();

        // Severity filter
        if (CurrentFilter.Severities.Count > 0)
        {
            query = query.Where(i => CurrentFilter.Severities.Contains(i.Severity.ToUpperInvariant()));
        }

        // Category filter
        if (CurrentFilter.Categories.Count > 0)
        {
            query = query.Where(i => CurrentFilter.Categories.Contains(i.Category));
        }

        // File filter
        if (!string.IsNullOrEmpty(CurrentFilter.FilePattern))
        {
            query = query.Where(i => i.FilePath.Contains(CurrentFilter.FilePattern, StringComparison.OrdinalIgnoreCase));
        }

        // Has fix filter
        if (CurrentFilter.OnlyWithFix)
        {
            query = query.Where(i => i.HasFix);
        }

        // Search query
        if (!string.IsNullOrEmpty(SearchQuery))
        {
            query = query.Where(i =>
                i.Message.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ||
                i.FilePath.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase) ||
                i.Type.Contains(SearchQuery, StringComparison.OrdinalIgnoreCase));
        }

        FilteredIssues = query.ToList();

        // Adjust selection if needed
        if (SelectedIndex >= FilteredIssues.Count)
            SelectedIndex = Math.Max(0, FilteredIssues.Count - 1);
    }

    /// <summary>
    /// Clear all selections.
    /// </summary>
    public void ClearSelections()
    {
        SelectedIssueIds.Clear();
    }

    /// <summary>
    /// Select all visible issues.
    /// </summary>
    public void SelectAll()
    {
        foreach (var issue in FilteredIssues)
        {
            SelectedIssueIds.Add(issue.Id);
        }
    }
}

/// <summary>
/// Filter settings for issues.
/// </summary>
public class TuiFilter
{
    /// <summary>
    /// Filter by severity levels.
    /// </summary>
    public HashSet<string> Severities { get; set; } = [];

    /// <summary>
    /// Filter by categories.
    /// </summary>
    public HashSet<string> Categories { get; set; } = [];

    /// <summary>
    /// Filter by file path pattern.
    /// </summary>
    public string FilePattern { get; set; } = string.Empty;

    /// <summary>
    /// Only show issues with available fixes.
    /// </summary>
    public bool OnlyWithFix { get; set; }

    /// <summary>
    /// Get a display string for the current filter.
    /// </summary>
    public string DisplayString
    {
        get
        {
            var parts = new List<string>();

            if (Severities.Count > 0)
                parts.Add($"Sev: {string.Join(",", Severities)}");
            if (Categories.Count > 0)
                parts.Add($"Cat: {string.Join(",", Categories)}");
            if (!string.IsNullOrEmpty(FilePattern))
                parts.Add($"File: {FilePattern}");
            if (OnlyWithFix)
                parts.Add("With Fix");

            return parts.Count > 0 ? string.Join(" | ", parts) : "All";
        }
    }

    /// <summary>
    /// Check if any filter is active.
    /// </summary>
    public bool IsActive =>
        Severities.Count > 0 ||
        Categories.Count > 0 ||
        !string.IsNullOrEmpty(FilePattern) ||
        OnlyWithFix;

    /// <summary>
    /// Reset all filters.
    /// </summary>
    public void Reset()
    {
        Severities.Clear();
        Categories.Clear();
        FilePattern = string.Empty;
        OnlyWithFix = false;
    }
}

/// <summary>
/// Represents an operation that can be undone.
/// </summary>
public record TuiOperation
{
    public required TuiOperationType Type { get; init; }
    public required string Description { get; init; }
    public required string IssueId { get; init; }
    public required string FilePath { get; init; }
    public required string OriginalContent { get; init; }
    public required DateTime Timestamp { get; init; }
    public string? BackupId { get; init; }
}

/// <summary>
/// Types of operations.
/// </summary>
public enum TuiOperationType
{
    ApplyFix,
    Skip,
    BatchApply
}

/// <summary>
/// View modes for the TUI.
/// </summary>
public enum TuiViewMode
{
    IssueList,
    IssueDetail,
    DiffPreview,
    FilterPanel,
    Help
}

/// <summary>
/// Result of applying a fix.
/// </summary>
public record TuiApplyResult
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
    public TuiOperation? Operation { get; init; }
    public int FilesModified { get; init; }
}

/// <summary>
/// Available categories for filtering.
/// </summary>
public static class IssueCategories
{
    public const string Security = "Security";
    public const string Performance = "Performance";
    public const string Exceptions = "Exceptions";
    public const string Resources = "Resources";
    public const string Refactoring = "Refactoring";
    public const string CodeQuality = "CodeQuality";
    public const string MagicValues = "MagicValues";
    public const string Dependencies = "Dependencies";
    public const string Safety = "Safety";
    public const string Optimization = "Optimization";

    public static readonly string[] All =
    [
        Security, Performance, Exceptions, Resources, Refactoring,
        CodeQuality, MagicValues, Dependencies, Safety, Optimization
    ];
}

/// <summary>
/// Severity levels.
/// </summary>
public static class IssueSeverity
{
    public const string Critical = "CRITICAL";
    public const string High = "HIGH";
    public const string Medium = "MEDIUM";
    public const string Low = "LOW";
    public const string Info = "INFO";

    public static readonly string[] All = [Critical, High, Medium, Low, Info];

    public static int GetPriority(string severity) => severity.ToUpperInvariant() switch
    {
        "CRITICAL" => 0,
        "HIGH" => 1,
        "MEDIUM" => 2,
        "LOW" => 3,
        "INFO" => 4,
        _ => 5
    };
}
