using Spectre.Console;
using BaseScanner.Tui.Models;

namespace BaseScanner.Tui;

/// <summary>
/// Issue list component displaying all issues with selection and navigation.
/// </summary>
public class IssueListView
{
    private readonly TuiState _state;
    private readonly FilterPanel _filterPanel;
    private int _pageSize = 15;
    private int _scrollOffset;

    public IssueListView(TuiState state)
    {
        _state = state;
        _filterPanel = new FilterPanel(state);
    }

    /// <summary>
    /// Render the issue list.
    /// </summary>
    public void Render()
    {
        RenderHeader();
        RenderIssueTable();
        RenderPreviewPane();
        RenderStatusBar();
    }

    private void RenderHeader()
    {
        // Title bar
        var title = new Rule("[bold cyan]BaseScanner Interactive[/]")
        {
            Justification = Justify.Left,
            Style = Style.Parse("cyan")
        };
        AnsiConsole.Write(title);

        // Toolbar
        var toolbar = new Table()
            .Border(TableBorder.None)
            .HideHeaders()
            .AddColumn(new TableColumn("Toolbar"));

        var toolbarContent = "[yellow][[F1]][/] Help  " +
                           "[yellow][[F2]][/] Filter  " +
                           "[yellow][[F3]][/] Apply  " +
                           "[yellow][[F5]][/] Refresh  " +
                           "[yellow][[Q]][/] Quit";

        toolbar.AddRow(toolbarContent);
        AnsiConsole.Write(toolbar);

        // Stats line
        var statsLine = new Table()
            .Border(TableBorder.None)
            .HideHeaders()
            .AddColumn(new TableColumn("Stats").Width(Console.WindowWidth - 4));

        var filterSummary = _filterPanel.GetFilterSummary();
        var selectedCount = _state.SelectedIssueIds.Count;
        var selectedText = selectedCount > 0 ? $"[green]{selectedCount} selected[/]  " : "";

        statsLine.AddRow($"[bold]Issues ({_state.FilteredIssues.Count} of {_state.AllIssues.Count})[/]  {selectedText}{filterSummary}");

        AnsiConsole.Write(statsLine);
        AnsiConsole.WriteLine();
    }

    private void RenderIssueTable()
    {
        // Calculate visible window
        AdjustScrollOffset();
        var visibleIssues = _state.FilteredIssues
            .Skip(_scrollOffset)
            .Take(_pageSize)
            .ToList();

        var table = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Grey)
            .AddColumn(new TableColumn("[grey]#[/]").Width(3).Centered())
            .AddColumn(new TableColumn("[grey]Sel[/]").Width(3).Centered())
            .AddColumn(new TableColumn("[grey]Sev[/]").Width(6).Centered())
            .AddColumn(new TableColumn("[grey]Type[/]").Width(25))
            .AddColumn(new TableColumn("[grey]File[/]").Width(25))
            .AddColumn(new TableColumn("[grey]Line[/]").Width(5).RightAligned())
            .AddColumn(new TableColumn("[grey]Fix[/]").Width(3).Centered());

        for (int i = 0; i < visibleIssues.Count; i++)
        {
            var issue = visibleIssues[i];
            var globalIndex = _scrollOffset + i;
            var isSelected = globalIndex == _state.SelectedIndex;
            var isMarked = _state.SelectedIssueIds.Contains(issue.Id);

            // Row formatting
            var rowStyle = isSelected ? "on grey23" : "";
            var marker = isSelected ? "[cyan]>[/]" : " ";
            var checkbox = isMarked ? "[green]X[/]" : "[grey]o[/]";

            // Severity badge
            var sevBadge = issue.Severity.ToUpperInvariant() switch
            {
                "CRITICAL" => "[white on red]CRIT[/]",
                "HIGH" => "[red]HIGH[/]",
                "MEDIUM" => "[yellow]MED[/]",
                "LOW" => "[blue]LOW[/]",
                _ => $"[grey]{issue.SeverityLabel}[/]"
            };

            // Type (truncated)
            var typeDisplay = issue.Type.Length > 23
                ? issue.Type[..20] + "..."
                : issue.Type;

            // File (just filename)
            var fileName = Path.GetFileName(issue.FilePath);
            if (fileName.Length > 23)
                fileName = fileName[..20] + "...";

            // Fix indicator
            var fixIndicator = issue.HasFix ? "[green]Y[/]" : "[grey]-[/]";

            // Apply row style
            if (isSelected)
            {
                table.AddRow(
                    $"[{rowStyle}]{marker}[/]",
                    $"[{rowStyle}]{checkbox}[/]",
                    $"[{rowStyle}]{sevBadge}[/]",
                    $"[{rowStyle}]{Markup.Escape(typeDisplay)}[/]",
                    $"[{rowStyle}]{Markup.Escape(fileName)}[/]",
                    $"[{rowStyle}]{issue.Line}[/]",
                    $"[{rowStyle}]{fixIndicator}[/]");
            }
            else
            {
                table.AddRow(
                    marker,
                    checkbox,
                    sevBadge,
                    Markup.Escape(typeDisplay),
                    Markup.Escape(fileName),
                    issue.Line.ToString(),
                    fixIndicator);
            }
        }

        // Show scroll indicators
        if (_scrollOffset > 0)
        {
            AnsiConsole.MarkupLine("[grey]  ... {0} more above ...[/]", _scrollOffset);
        }

        AnsiConsole.Write(table);

        var remaining = _state.FilteredIssues.Count - (_scrollOffset + _pageSize);
        if (remaining > 0)
        {
            AnsiConsole.MarkupLine("[grey]  ... {0} more below ...[/]", remaining);
        }
    }

    private void RenderPreviewPane()
    {
        var issue = _state.CurrentIssue;
        if (issue == null)
        {
            return;
        }

        AnsiConsole.WriteLine();

        // Message
        var message = issue.Message.Length > 100
            ? issue.Message[..97] + "..."
            : issue.Message;

        AnsiConsole.MarkupLine($"[grey]Message:[/] {Markup.Escape(message)}");

        // Inline diff preview
        if (!string.IsNullOrEmpty(issue.CodeSnippet) || !string.IsNullOrEmpty(issue.SuggestedFix))
        {
            AnsiConsole.MarkupLine("[grey]Preview:[/]");
            DiffPreviewView.RenderInlineDiff(issue, 2);
        }
    }

    private void RenderStatusBar()
    {
        AnsiConsole.WriteLine();

        var statusText = new List<string>();

        // Navigation hints
        statusText.Add("[grey]Navigation:[/] [yellow]j/k[/] or [yellow]Up/Down[/]");
        statusText.Add("[yellow]Space[/] Select");
        statusText.Add("[yellow]Enter[/] Details");
        statusText.Add("[yellow]A[/] Apply");
        statusText.Add("[yellow]/[/] Search");

        AnsiConsole.MarkupLine(string.Join("  ", statusText));

        // Status message
        if (!string.IsNullOrEmpty(_state.StatusMessage))
        {
            AnsiConsole.MarkupLine($"\n[green]{Markup.Escape(_state.StatusMessage)}[/]");
        }

        // Search query
        if (_state.IsSearchActive && !string.IsNullOrEmpty(_state.SearchQuery))
        {
            AnsiConsole.MarkupLine($"\n[yellow]Search:[/] {Markup.Escape(_state.SearchQuery)}");
        }
    }

    private void AdjustScrollOffset()
    {
        // Ensure selected item is visible
        if (_state.SelectedIndex < _scrollOffset)
        {
            _scrollOffset = _state.SelectedIndex;
        }
        else if (_state.SelectedIndex >= _scrollOffset + _pageSize)
        {
            _scrollOffset = _state.SelectedIndex - _pageSize + 1;
        }

        // Clamp scroll offset
        _scrollOffset = Math.Max(0, Math.Min(_scrollOffset, Math.Max(0, _state.FilteredIssues.Count - _pageSize)));
    }

    /// <summary>
    /// Handle page up navigation.
    /// </summary>
    public void PageUp()
    {
        _state.SelectedIndex = Math.Max(0, _state.SelectedIndex - _pageSize);
    }

    /// <summary>
    /// Handle page down navigation.
    /// </summary>
    public void PageDown()
    {
        _state.SelectedIndex = Math.Min(_state.FilteredIssues.Count - 1, _state.SelectedIndex + _pageSize);
    }

    /// <summary>
    /// Go to first issue.
    /// </summary>
    public void GoToFirst()
    {
        _state.SelectedIndex = 0;
        _scrollOffset = 0;
    }

    /// <summary>
    /// Go to last issue.
    /// </summary>
    public void GoToLast()
    {
        _state.SelectedIndex = Math.Max(0, _state.FilteredIssues.Count - 1);
    }

    /// <summary>
    /// Set the page size based on terminal height.
    /// </summary>
    public void UpdatePageSize()
    {
        // Reserve lines for header, footer, preview
        var availableLines = Console.WindowHeight - 15;
        _pageSize = Math.Max(5, Math.Min(30, availableLines));
    }

    /// <summary>
    /// Get the filter panel.
    /// </summary>
    public FilterPanel FilterPanel => _filterPanel;

    /// <summary>
    /// Render a summary by severity.
    /// </summary>
    public void RenderSeveritySummary()
    {
        var bySeverity = _state.AllIssues
            .GroupBy(i => i.Severity.ToUpperInvariant())
            .OrderBy(g => IssueSeverity.GetPriority(g.Key))
            .ToList();

        var chart = new BarChart()
            .Width(60)
            .Label("[bold]Issues by Severity[/]");

        foreach (var group in bySeverity)
        {
            var color = group.Key switch
            {
                "CRITICAL" => Color.Red,
                "HIGH" => Color.Red3,
                "MEDIUM" => Color.Yellow,
                "LOW" => Color.Blue,
                _ => Color.Grey
            };

            chart.AddItem(group.Key, group.Count(), color);
        }

        AnsiConsole.Write(chart);
    }

    /// <summary>
    /// Render a summary by category.
    /// </summary>
    public void RenderCategorySummary()
    {
        var byCategory = _state.AllIssues
            .GroupBy(i => i.Category)
            .OrderByDescending(g => g.Count())
            .Take(10)
            .ToList();

        var chart = new BarChart()
            .Width(60)
            .Label("[bold]Issues by Category[/]");

        var colors = new[] { Color.Cyan1, Color.Green, Color.Yellow, Color.Blue, Color.Purple, Color.Orange1 };
        var colorIndex = 0;

        foreach (var group in byCategory)
        {
            chart.AddItem(group.Key, group.Count(), colors[colorIndex % colors.Length]);
            colorIndex++;
        }

        AnsiConsole.Write(chart);
    }
}
