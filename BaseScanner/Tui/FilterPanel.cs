using Spectre.Console;
using Spectre.Console.Rendering;
using BaseScanner.Tui.Models;

namespace BaseScanner.Tui;

/// <summary>
/// Filter panel component for filtering issues by severity, category, and file.
/// </summary>
public class FilterPanel
{
    private readonly TuiState _state;
    private int _selectedFilterSection;
    private int _selectedItemIndex;
    private readonly List<string> _availableCategories = [];
    private readonly List<string> _availableFiles = [];

    public FilterPanel(TuiState state)
    {
        _state = state;
    }

    /// <summary>
    /// Initialize available filter options from current issues.
    /// </summary>
    public void Initialize()
    {
        _availableCategories.Clear();
        _availableCategories.AddRange(_state.AllIssues
            .Select(i => i.Category)
            .Distinct()
            .OrderBy(c => c));

        _availableFiles.Clear();
        _availableFiles.AddRange(_state.AllIssues
            .Select(i => Path.GetFileName(i.FilePath))
            .Distinct()
            .OrderBy(f => f)
            .Take(50)); // Limit for display
    }

    /// <summary>
    /// Render the filter panel.
    /// </summary>
    public void Render()
    {
        var panel = new Panel(BuildFilterContent())
            .Header("[bold cyan]Filter Issues[/]")
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Cyan1)
            .Padding(1, 0);

        AnsiConsole.Write(panel);

        // Instructions
        AnsiConsole.MarkupLine("\n[grey]Use [yellow]Tab[/] to switch sections, [yellow]Space[/] to toggle, [yellow]Enter[/] to apply, [yellow]R[/] to reset, [yellow]Esc[/] to cancel[/]");
    }

    private IRenderable BuildFilterContent()
    {
        var grid = new Grid();
        grid.AddColumn(new GridColumn().Width(30));
        grid.AddColumn(new GridColumn().Width(30));
        grid.AddColumn(new GridColumn().Width(30));

        // Severity column
        var severityPanel = BuildSeverityPanel();

        // Category column
        var categoryPanel = BuildCategoryPanel();

        // Options column
        var optionsPanel = BuildOptionsPanel();

        grid.AddRow(severityPanel, categoryPanel, optionsPanel);

        return grid;
    }

    private Panel BuildSeverityPanel()
    {
        var lines = new List<string>();

        foreach (var severity in IssueSeverity.All)
        {
            var isSelected = _state.CurrentFilter.Severities.Contains(severity);
            var checkbox = isSelected ? "[green][[X]][/]" : "[grey][[ ]][/]";
            var count = _state.AllIssues.Count(i => i.Severity.Equals(severity, StringComparison.OrdinalIgnoreCase));

            var color = severity switch
            {
                "CRITICAL" => "red bold",
                "HIGH" => "red",
                "MEDIUM" => "yellow",
                "LOW" => "blue",
                _ => "grey"
            };

            var highlight = _selectedFilterSection == 0 && _selectedItemIndex == Array.IndexOf(IssueSeverity.All, severity)
                ? " on grey23"
                : "";

            lines.Add($"{checkbox} [{color}{highlight}]{severity}[/] [grey]({count})[/]");
        }

        return new Panel(string.Join("\n", lines))
            .Header(_selectedFilterSection == 0 ? "[bold yellow]Severity[/]" : "[dim]Severity[/]")
            .Border(BoxBorder.Square)
            .BorderColor(_selectedFilterSection == 0 ? Color.Yellow : Color.Grey);
    }

    private Panel BuildCategoryPanel()
    {
        var lines = new List<string>();
        var displayCategories = _availableCategories.Take(8).ToList();

        for (int i = 0; i < displayCategories.Count; i++)
        {
            var category = displayCategories[i];
            var isSelected = _state.CurrentFilter.Categories.Contains(category);
            var checkbox = isSelected ? "[green][[X]][/]" : "[grey][[ ]][/]";
            var count = _state.AllIssues.Count(issue => issue.Category == category);

            var highlight = _selectedFilterSection == 1 && _selectedItemIndex == i
                ? " on grey23"
                : "";

            lines.Add($"{checkbox} [{highlight}]{category}[/] [grey]({count})[/]");
        }

        if (_availableCategories.Count > 8)
        {
            lines.Add($"[grey]... and {_availableCategories.Count - 8} more[/]");
        }

        return new Panel(string.Join("\n", lines))
            .Header(_selectedFilterSection == 1 ? "[bold yellow]Category[/]" : "[dim]Category[/]")
            .Border(BoxBorder.Square)
            .BorderColor(_selectedFilterSection == 1 ? Color.Yellow : Color.Grey);
    }

    private Panel BuildOptionsPanel()
    {
        var lines = new List<string>
        {
            $"{(_state.CurrentFilter.OnlyWithFix ? "[green][[X]][/]" : "[grey][[ ]][/]")} Only with fix available",
            "",
            "[grey]File pattern:[/]",
            $"  [{(_selectedFilterSection == 2 ? "yellow" : "white")}]{(_state.CurrentFilter.FilePattern.Length > 0 ? _state.CurrentFilter.FilePattern : "(any)")}[/]",
            "",
            "[grey]Current filter:[/]",
            $"  {_state.CurrentFilter.DisplayString}",
            "",
            $"[grey]Matching issues: [white]{_state.FilteredIssues.Count}[/] / {_state.AllIssues.Count}[/]"
        };

        return new Panel(string.Join("\n", lines))
            .Header(_selectedFilterSection == 2 ? "[bold yellow]Options[/]" : "[dim]Options[/]")
            .Border(BoxBorder.Square)
            .BorderColor(_selectedFilterSection == 2 ? Color.Yellow : Color.Grey);
    }

    /// <summary>
    /// Handle navigation input.
    /// </summary>
    public void HandleInput(ConsoleKeyInfo keyInfo)
    {
        switch (keyInfo.Key)
        {
            case ConsoleKey.Tab:
                _selectedFilterSection = (_selectedFilterSection + 1) % 3;
                _selectedItemIndex = 0;
                break;

            case ConsoleKey.UpArrow:
                if (_selectedItemIndex > 0)
                    _selectedItemIndex--;
                break;

            case ConsoleKey.DownArrow:
                var maxIndex = _selectedFilterSection switch
                {
                    0 => IssueSeverity.All.Length - 1,
                    1 => Math.Min(_availableCategories.Count - 1, 7),
                    2 => 0,
                    _ => 0
                };
                if (_selectedItemIndex < maxIndex)
                    _selectedItemIndex++;
                break;

            case ConsoleKey.Spacebar:
                ToggleCurrentSelection();
                break;
        }
    }

    private void ToggleCurrentSelection()
    {
        switch (_selectedFilterSection)
        {
            case 0: // Severity
                var severity = IssueSeverity.All[_selectedItemIndex];
                if (_state.CurrentFilter.Severities.Contains(severity))
                    _state.CurrentFilter.Severities.Remove(severity);
                else
                    _state.CurrentFilter.Severities.Add(severity);
                break;

            case 1: // Category
                if (_selectedItemIndex < _availableCategories.Count)
                {
                    var category = _availableCategories[_selectedItemIndex];
                    if (_state.CurrentFilter.Categories.Contains(category))
                        _state.CurrentFilter.Categories.Remove(category);
                    else
                        _state.CurrentFilter.Categories.Add(category);
                }
                break;

            case 2: // Options
                _state.CurrentFilter.OnlyWithFix = !_state.CurrentFilter.OnlyWithFix;
                break;
        }

        // Update filtered results
        _state.ApplyFilter();
    }

    /// <summary>
    /// Show interactive filter dialog using Spectre.Console prompts.
    /// </summary>
    public void ShowInteractiveFilter()
    {
        AnsiConsole.Clear();

        // Severity selection
        var severityPrompt = new MultiSelectionPrompt<string>()
            .Title("[cyan]Select severity levels to show:[/]")
            .NotRequired()
            .PageSize(10)
            .InstructionsText("[grey](Press [blue]<space>[/] to toggle, [green]<enter>[/] to accept)[/]")
            .AddChoices(IssueSeverity.All);

        // Pre-select current filter values
        foreach (var severity in _state.CurrentFilter.Severities)
        {
            severityPrompt.Select(severity);
        }

        var severities = AnsiConsole.Prompt(severityPrompt);
        _state.CurrentFilter.Severities = severities.ToHashSet();

        // Category selection
        if (_availableCategories.Count > 0)
        {
            var categoryPrompt = new MultiSelectionPrompt<string>()
                .Title("[cyan]Select categories to show:[/]")
                .NotRequired()
                .PageSize(15)
                .InstructionsText("[grey](Press [blue]<space>[/] to toggle, [green]<enter>[/] to accept)[/]")
                .AddChoices(_availableCategories);

            // Pre-select current filter values
            foreach (var category in _state.CurrentFilter.Categories)
            {
                if (_availableCategories.Contains(category))
                {
                    categoryPrompt.Select(category);
                }
            }

            var categories = AnsiConsole.Prompt(categoryPrompt);
            _state.CurrentFilter.Categories = categories.ToHashSet();
        }

        // File pattern
        var filePattern = AnsiConsole.Prompt(
            new TextPrompt<string>("[cyan]File pattern (or empty for all):[/]")
                .AllowEmpty()
                .DefaultValue(_state.CurrentFilter.FilePattern));

        _state.CurrentFilter.FilePattern = filePattern;

        // Only with fix
        _state.CurrentFilter.OnlyWithFix = AnsiConsole.Confirm(
            "Only show issues with available fixes?",
            _state.CurrentFilter.OnlyWithFix);

        _state.ApplyFilter();
    }

    /// <summary>
    /// Get a compact filter summary for the status bar.
    /// </summary>
    public string GetFilterSummary()
    {
        if (!_state.CurrentFilter.IsActive)
            return "[grey]Filter: All[/]";

        var parts = new List<string>();

        if (_state.CurrentFilter.Severities.Count > 0)
        {
            var sevDisplay = _state.CurrentFilter.Severities.Count <= 2
                ? string.Join(",", _state.CurrentFilter.Severities)
                : $"{_state.CurrentFilter.Severities.Count} severities";
            parts.Add(sevDisplay);
        }

        if (_state.CurrentFilter.Categories.Count > 0)
        {
            var catDisplay = _state.CurrentFilter.Categories.Count <= 2
                ? string.Join(",", _state.CurrentFilter.Categories)
                : $"{_state.CurrentFilter.Categories.Count} categories";
            parts.Add(catDisplay);
        }

        if (!string.IsNullOrEmpty(_state.CurrentFilter.FilePattern))
        {
            parts.Add($"*{_state.CurrentFilter.FilePattern}*");
        }

        if (_state.CurrentFilter.OnlyWithFix)
        {
            parts.Add("fixable");
        }

        return $"[yellow]Filter: {string.Join(" | ", parts)}[/]";
    }
}
