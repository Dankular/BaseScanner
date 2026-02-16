using Microsoft.CodeAnalysis;
using Spectre.Console;
using BaseScanner.Tui.Models;
using BaseScanner.Services;

namespace BaseScanner.Tui;

/// <summary>
/// Main TUI controller for interactive mode.
/// Coordinates all views and handles the main event loop.
/// </summary>
public class InteractiveMode
{
    private readonly TuiState _state;
    private readonly KeyBindings _keyBindings;
    private readonly IssueListView _issueListView;
    private readonly IssueDetailView _issueDetailView;
    private readonly DiffPreviewView _diffPreviewView;
    private readonly FilterPanel _filterPanel;
    private readonly BackupService _backupService;
    private bool _running;
    private Project? _project;

    public InteractiveMode(string projectPath)
    {
        _state = new TuiState { ProjectPath = projectPath };
        _keyBindings = new KeyBindings();
        _issueListView = new IssueListView(_state);
        _issueDetailView = new IssueDetailView(_state);
        _diffPreviewView = new DiffPreviewView(_state);
        _filterPanel = new FilterPanel(_state);
        _backupService = new BackupService(projectPath);
    }

    /// <summary>
    /// Run the interactive TUI mode.
    /// </summary>
    public async Task<int> RunAsync(Project project, AnalysisResult analysisResult)
    {
        _project = project;

        // Convert analysis results to TUI issues
        LoadIssuesFromAnalysis(analysisResult);

        if (_state.AllIssues.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]No issues found! Your code looks great.[/]");
            return 0;
        }

        _filterPanel.Initialize();
        _state.ApplyFilter();
        _issueListView.UpdatePageSize();

        _running = true;
        Console.CursorVisible = false;

        try
        {
            // Show initial summary
            ShowWelcome();

            while (_running)
            {
                Render();
                await HandleInputAsync();
            }
        }
        finally
        {
            Console.CursorVisible = true;
            AnsiConsole.Clear();
        }

        return 0;
    }

    private void ShowWelcome()
    {
        AnsiConsole.Clear();

        var panel = new Panel(
            $"Loaded [cyan]{_state.AllIssues.Count}[/] issues from analysis.\n\n" +
            $"[grey]Project:[/] {Markup.Escape(_state.ProjectPath)}\n\n" +
            "Press any key to continue...")
            .Header("[bold cyan]BaseScanner Interactive Mode[/]")
            .Border(BoxBorder.Double)
            .BorderColor(Color.Cyan1)
            .Padding(2, 1);

        AnsiConsole.Write(panel);

        // Show severity breakdown
        _issueListView.RenderSeveritySummary();

        Console.ReadKey(true);
    }

    private void Render()
    {
        AnsiConsole.Clear();

        switch (_state.ViewMode)
        {
            case TuiViewMode.IssueList:
                _issueListView.Render();
                break;

            case TuiViewMode.IssueDetail:
                _issueDetailView.Render();
                break;

            case TuiViewMode.DiffPreview:
                _diffPreviewView.Render();
                break;

            case TuiViewMode.FilterPanel:
                _filterPanel.Render();
                break;

            case TuiViewMode.Help:
                RenderHelp();
                break;
        }
    }

    private async Task HandleInputAsync()
    {
        var keyInfo = Console.ReadKey(true);

        // Handle search mode specially
        if (_state.IsSearchActive)
        {
            HandleSearchInput(keyInfo);
            return;
        }

        var action = _keyBindings.GetAction(keyInfo, _state.ViewMode);

        if (action == null)
        {
            return;
        }

        switch (action.Value)
        {
            // Navigation
            case TuiAction.MoveUp:
                _state.MoveUp();
                break;

            case TuiAction.MoveDown:
                _state.MoveDown();
                break;

            case TuiAction.PageUp:
                _issueListView.PageUp();
                break;

            case TuiAction.PageDown:
                _issueListView.PageDown();
                break;

            case TuiAction.GoToFirst:
                _issueListView.GoToFirst();
                break;

            case TuiAction.GoToLast:
                _issueListView.GoToLast();
                break;

            case TuiAction.ScrollUp:
                if (_state.ViewMode == TuiViewMode.IssueDetail)
                    _issueDetailView.ScrollUp();
                else if (_state.ViewMode == TuiViewMode.DiffPreview)
                    _diffPreviewView.ScrollUp();
                break;

            case TuiAction.ScrollDown:
                if (_state.ViewMode == TuiViewMode.IssueDetail)
                    _issueDetailView.ScrollDown();
                else if (_state.ViewMode == TuiViewMode.DiffPreview)
                    _diffPreviewView.ScrollDown();
                break;

            // Selection
            case TuiAction.ToggleSelection:
                _state.ToggleSelection();
                break;

            case TuiAction.SelectAll:
                _state.SelectAll();
                _state.StatusMessage = $"Selected all {_state.FilteredIssues.Count} issues";
                break;

            case TuiAction.DeselectAll:
                _state.ClearSelections();
                _state.StatusMessage = "Cleared all selections";
                break;

            // View switching
            case TuiAction.ViewDetails:
                if (_state.CurrentIssue != null)
                {
                    _issueDetailView.ResetScroll();
                    _state.ViewMode = TuiViewMode.IssueDetail;
                }
                break;

            case TuiAction.ShowDiff:
                if (_state.CurrentIssue != null)
                {
                    _diffPreviewView.ResetScroll();
                    _state.ViewMode = TuiViewMode.DiffPreview;
                }
                break;

            case TuiAction.OpenFilter:
                _filterPanel.ShowInteractiveFilter();
                break;

            case TuiAction.ShowHelp:
                _state.ViewMode = TuiViewMode.Help;
                break;

            case TuiAction.Back:
                HandleBack();
                break;

            // Actions
            case TuiAction.ApplyFix:
                await ApplyFixAsync();
                break;

            case TuiAction.Skip:
                SkipCurrentIssue();
                break;

            case TuiAction.Undo:
                await UndoLastOperationAsync();
                break;

            case TuiAction.Refresh:
                _state.StatusMessage = "Refreshing...";
                // In a real implementation, would re-run analysis
                _state.ApplyFilter();
                _state.StatusMessage = "Refreshed issue list";
                break;

            case TuiAction.Search:
                _state.IsSearchActive = true;
                _state.SearchQuery = string.Empty;
                break;

            case TuiAction.ResetFilter:
                _state.CurrentFilter.Reset();
                _state.SearchQuery = string.Empty;
                _state.ApplyFilter();
                _state.StatusMessage = "Filters reset";
                break;

            case TuiAction.Quit:
                if (ConfirmQuit())
                {
                    _running = false;
                }
                break;
        }
    }

    private void HandleSearchInput(ConsoleKeyInfo keyInfo)
    {
        switch (keyInfo.Key)
        {
            case ConsoleKey.Enter:
                _state.IsSearchActive = false;
                _state.ApplyFilter();
                break;

            case ConsoleKey.Escape:
                _state.IsSearchActive = false;
                _state.SearchQuery = string.Empty;
                _state.ApplyFilter();
                break;

            case ConsoleKey.Backspace:
                if (_state.SearchQuery.Length > 0)
                {
                    _state.SearchQuery = _state.SearchQuery[..^1];
                    _state.ApplyFilter();
                }
                break;

            default:
                if (!char.IsControl(keyInfo.KeyChar))
                {
                    _state.SearchQuery += keyInfo.KeyChar;
                    _state.ApplyFilter();
                }
                break;
        }
    }

    private void HandleBack()
    {
        switch (_state.ViewMode)
        {
            case TuiViewMode.IssueDetail:
            case TuiViewMode.DiffPreview:
            case TuiViewMode.FilterPanel:
            case TuiViewMode.Help:
                _state.ViewMode = TuiViewMode.IssueList;
                break;

            case TuiViewMode.IssueList:
                // Escape in list view shows quit confirmation
                if (ConfirmQuit())
                {
                    _running = false;
                }
                break;
        }
    }

    private async Task ApplyFixAsync()
    {
        var issue = _state.CurrentIssue;
        if (issue == null)
        {
            _state.StatusMessage = "No issue selected";
            return;
        }

        if (!issue.HasFix)
        {
            _state.StatusMessage = "No auto-fix available for this issue";
            return;
        }

        // Check if we should apply to selected issues or just current
        var issuesToApply = _state.SelectedIssueIds.Count > 0
            ? _state.FilteredIssues.Where(i => _state.SelectedIssueIds.Contains(i.Id) && i.HasFix).ToList()
            : new List<TuiIssue> { issue };

        if (issuesToApply.Count == 0)
        {
            _state.StatusMessage = "No fixable issues in selection";
            return;
        }

        // Confirm batch apply
        if (issuesToApply.Count > 1)
        {
            if (!ConfirmApply(issuesToApply.Count))
            {
                return;
            }
        }

        _state.IsProcessing = true;
        _state.StatusMessage = $"Applying {issuesToApply.Count} fix(es)...";

        try
        {
            // Create backup
            var filesToBackup = issuesToApply.Select(i => i.FilePath).Distinct().ToList();
            var backupId = await _backupService.CreateBackupAsync(filesToBackup);

            var appliedCount = 0;
            foreach (var issueToFix in issuesToApply)
            {
                var result = await ApplySingleFixAsync(issueToFix);
                if (result)
                {
                    appliedCount++;

                    // Record operation for undo
                    var originalContent = await File.ReadAllTextAsync(issueToFix.FilePath);
                    _state.UndoStack.Push(new TuiOperation
                    {
                        Type = TuiOperationType.ApplyFix,
                        Description = $"Applied fix: {issueToFix.Type}",
                        IssueId = issueToFix.Id,
                        FilePath = issueToFix.FilePath,
                        OriginalContent = originalContent,
                        Timestamp = DateTime.Now,
                        BackupId = backupId
                    });

                    // Remove from lists
                    _state.AllIssues.RemoveAll(i => i.Id == issueToFix.Id);
                    _state.SelectedIssueIds.Remove(issueToFix.Id);
                }
            }

            _state.ApplyFilter();
            _state.StatusMessage = $"Applied {appliedCount} fix(es). Press U to undo.";
        }
        catch (Exception ex)
        {
            _state.StatusMessage = $"Error applying fix: {ex.Message}";
        }
        finally
        {
            _state.IsProcessing = false;
        }
    }

    private async Task<bool> ApplySingleFixAsync(TuiIssue issue)
    {
        if (string.IsNullOrEmpty(issue.SuggestedFix) || string.IsNullOrEmpty(issue.CodeSnippet))
        {
            return false;
        }

        try
        {
            var content = await File.ReadAllTextAsync(issue.FilePath);
            var newContent = content.Replace(issue.CodeSnippet, issue.SuggestedFix);

            if (content == newContent)
            {
                // Code snippet not found exactly - might need smarter matching
                return false;
            }

            await File.WriteAllTextAsync(issue.FilePath, newContent);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void SkipCurrentIssue()
    {
        var issue = _state.CurrentIssue;
        if (issue == null)
        {
            return;
        }

        // Remove from current view but not from AllIssues
        _state.FilteredIssues.Remove(issue);
        _state.SelectedIssueIds.Remove(issue.Id);

        // Adjust selection
        if (_state.SelectedIndex >= _state.FilteredIssues.Count)
        {
            _state.SelectedIndex = Math.Max(0, _state.FilteredIssues.Count - 1);
        }

        _state.StatusMessage = $"Skipped: {issue.Type}";
    }

    private async Task UndoLastOperationAsync()
    {
        if (_state.UndoStack.Count == 0)
        {
            _state.StatusMessage = "Nothing to undo";
            return;
        }

        var operation = _state.UndoStack.Pop();

        try
        {
            if (!string.IsNullOrEmpty(operation.BackupId))
            {
                var success = await _backupService.RestoreBackupAsync(operation.BackupId);
                if (success)
                {
                    _state.StatusMessage = $"Undone: {operation.Description}";
                    // TODO: Re-add the issue to the list
                }
                else
                {
                    _state.StatusMessage = "Failed to undo - backup not found";
                }
            }
        }
        catch (Exception ex)
        {
            _state.StatusMessage = $"Undo failed: {ex.Message}";
        }
    }

    private bool ConfirmQuit()
    {
        if (_state.UndoStack.Count == 0)
        {
            return true;
        }

        AnsiConsole.Clear();
        return AnsiConsole.Confirm(
            $"You have {_state.UndoStack.Count} unsaved changes. Are you sure you want to quit?",
            false);
    }

    private bool ConfirmApply(int count)
    {
        AnsiConsole.Clear();
        return AnsiConsole.Confirm(
            $"Apply fixes to {count} issues?",
            true);
    }

    private void RenderHelp()
    {
        var helpPanel = new Panel(BuildHelpContent())
            .Header("[bold cyan]Keyboard Shortcuts[/]")
            .Border(BoxBorder.Double)
            .BorderColor(Color.Cyan1)
            .Padding(2, 1);

        AnsiConsole.Write(helpPanel);

        AnsiConsole.MarkupLine("\n[grey]Press [yellow]Esc[/] or [yellow]Q[/] to close help[/]");
    }

    private string BuildHelpContent()
    {
        var sections = new Dictionary<string, List<(string Key, string Description)>>
        {
            ["Navigation"] = new()
            {
                ("Up/Down, j/k", "Move selection"),
                ("PgUp/PgDn", "Page up/down"),
                ("Home/End", "Go to first/last"),
                ("Enter", "View issue details"),
            },
            ["Selection"] = new()
            {
                ("Space", "Toggle issue selection"),
                ("Ctrl+A", "Select all visible"),
                ("Ctrl+D", "Deselect all"),
            },
            ["Actions"] = new()
            {
                ("A", "Apply fix to selected"),
                ("S", "Skip current issue"),
                ("U, Ctrl+Z", "Undo last action"),
            },
            ["Filter & Search"] = new()
            {
                ("F, F2", "Open filter panel"),
                ("/", "Search issues"),
                ("R", "Reset filters"),
            },
            ["Views"] = new()
            {
                ("D", "Show diff preview"),
                ("F1", "Show this help"),
                ("F5", "Refresh"),
            },
            ["General"] = new()
            {
                ("Esc", "Back / Cancel"),
                ("Q", "Quit"),
            }
        };

        var lines = new List<string>();

        foreach (var section in sections)
        {
            lines.Add($"[bold yellow]{section.Key}[/]");
            foreach (var (key, desc) in section.Value)
            {
                lines.Add($"  [cyan]{key,-15}[/] {desc}");
            }
            lines.Add("");
        }

        return string.Join("\n", lines);
    }

    private void LoadIssuesFromAnalysis(AnalysisResult result)
    {
        var issues = new List<TuiIssue>();
        var issueId = 0;

        // Security issues
        if (result.Security?.Vulnerabilities != null)
        {
            foreach (var vuln in result.Security.Vulnerabilities)
            {
                issues.Add(new TuiIssue
                {
                    Id = $"sec-{issueId++}",
                    Type = vuln.VulnerabilityType,
                    Severity = vuln.Severity,
                    Category = IssueCategories.Security,
                    Message = vuln.Description,
                    FilePath = vuln.FilePath,
                    Line = vuln.StartLine,
                    EndLine = vuln.EndLine,
                    CodeSnippet = vuln.VulnerableCode,
                    SuggestedFix = vuln.SecureCode,
                    CweId = vuln.CweId,
                    Recommendation = vuln.Recommendation,
                    Confidence = vuln.Confidence
                });
            }
        }

        // Performance issues
        if (result.PerformanceIssues != null)
        {
            foreach (var issue in result.PerformanceIssues)
            {
                issues.Add(new TuiIssue
                {
                    Id = $"perf-{issueId++}",
                    Type = issue.Type,
                    Severity = issue.Severity,
                    Category = IssueCategories.Performance,
                    Message = issue.Message,
                    FilePath = issue.FilePath,
                    Line = issue.Line,
                    CodeSnippet = issue.CodeSnippet
                });
            }
        }

        // Exception handling issues
        if (result.ExceptionHandlingIssues != null)
        {
            foreach (var issue in result.ExceptionHandlingIssues)
            {
                issues.Add(new TuiIssue
                {
                    Id = $"exc-{issueId++}",
                    Type = issue.Type,
                    Severity = issue.Severity,
                    Category = IssueCategories.Exceptions,
                    Message = issue.Message,
                    FilePath = issue.FilePath,
                    Line = issue.Line,
                    CodeSnippet = issue.CodeSnippet
                });
            }
        }

        // Resource leak issues
        if (result.ResourceLeakIssues != null)
        {
            foreach (var issue in result.ResourceLeakIssues)
            {
                issues.Add(new TuiIssue
                {
                    Id = $"res-{issueId++}",
                    Type = issue.Type,
                    Severity = issue.Severity,
                    Category = IssueCategories.Resources,
                    Message = issue.Message,
                    FilePath = issue.FilePath,
                    Line = issue.Line,
                    CodeSnippet = issue.CodeSnippet
                });
            }
        }

        // Optimization opportunities
        if (result.Optimizations?.Opportunities != null)
        {
            foreach (var opt in result.Optimizations.Opportunities)
            {
                issues.Add(new TuiIssue
                {
                    Id = $"opt-{issueId++}",
                    Type = opt.Type,
                    Severity = opt.Confidence == "High" ? "MEDIUM" : "LOW",
                    Category = IssueCategories.Optimization,
                    Message = opt.Description,
                    FilePath = opt.FilePath,
                    Line = opt.StartLine,
                    EndLine = opt.EndLine,
                    CodeSnippet = opt.CurrentCode,
                    SuggestedFix = opt.SuggestedCode,
                    Confidence = opt.Confidence
                });
            }
        }

        // Refactoring issues (long methods, god classes)
        if (result.Refactoring != null)
        {
            foreach (var lm in result.Refactoring.LongMethods ?? [])
            {
                issues.Add(new TuiIssue
                {
                    Id = $"ref-{issueId++}",
                    Type = "Long Method",
                    Severity = "MEDIUM",
                    Category = IssueCategories.Refactoring,
                    Message = $"Method {lm.MethodName} has {lm.LineCount} lines (complexity: {lm.Complexity})",
                    FilePath = lm.FilePath,
                    Line = lm.Line
                });
            }

            foreach (var gc in result.Refactoring.GodClasses ?? [])
            {
                issues.Add(new TuiIssue
                {
                    Id = $"ref-{issueId++}",
                    Type = "God Class",
                    Severity = "HIGH",
                    Category = IssueCategories.Refactoring,
                    Message = $"Class {gc.ClassName} has {gc.MethodCount} methods, {gc.FieldCount} fields (LCOM: {gc.LCOM:F2})",
                    FilePath = gc.FilePath,
                    Line = gc.Line
                });
            }
        }

        // Safety issues
        if (result.Safety != null)
        {
            foreach (var ns in result.Safety.NullIssues ?? [])
            {
                issues.Add(new TuiIssue
                {
                    Id = $"safe-{issueId++}",
                    Type = ns.Type,
                    Severity = ns.Severity,
                    Category = IssueCategories.Safety,
                    Message = ns.Description,
                    FilePath = ns.FilePath,
                    Line = ns.Line
                });
            }
        }

        // Sort by severity priority
        _state.AllIssues = issues
            .OrderBy(i => IssueSeverity.GetPriority(i.Severity))
            .ThenBy(i => i.FilePath)
            .ThenBy(i => i.Line)
            .ToList();
    }
}
