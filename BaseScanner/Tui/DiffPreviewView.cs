using Spectre.Console;
using BaseScanner.Tui.Models;

namespace BaseScanner.Tui;

/// <summary>
/// Diff preview component showing before/after code changes.
/// </summary>
public class DiffPreviewView
{
    private readonly TuiState _state;
    private int _scrollOffset;
    private const int MaxVisibleLines = 20;

    public DiffPreviewView(TuiState state)
    {
        _state = state;
    }

    /// <summary>
    /// Render the diff preview for the current issue.
    /// </summary>
    public void Render()
    {
        var issue = _state.CurrentIssue;
        if (issue == null)
        {
            AnsiConsole.MarkupLine("[yellow]No issue selected[/]");
            return;
        }

        RenderHeader(issue);
        RenderDiff(issue);
        RenderFooter(issue);
    }

    private void RenderHeader(TuiIssue issue)
    {
        var headerTable = new Table()
            .Border(TableBorder.None)
            .HideHeaders()
            .AddColumn(new TableColumn("Label").Width(15))
            .AddColumn(new TableColumn("Value"));

        headerTable.AddRow("[grey]File:[/]", $"[cyan]{issue.FilePath}[/]");
        headerTable.AddRow("[grey]Line:[/]", $"[white]{issue.Line}[/]");
        headerTable.AddRow("[grey]Issue:[/]", $"[{issue.SeverityColor}]{issue.Message}[/]");

        var headerPanel = new Panel(headerTable)
            .Header("[bold cyan]Diff Preview[/]")
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Cyan1);

        AnsiConsole.Write(headerPanel);
    }

    private void RenderDiff(TuiIssue issue)
    {
        if (string.IsNullOrEmpty(issue.CodeSnippet) && string.IsNullOrEmpty(issue.SuggestedFix))
        {
            var noChangePanel = new Panel("[yellow]No code change available for this issue.[/]")
                .Border(BoxBorder.Rounded)
                .BorderColor(Color.Yellow);
            AnsiConsole.Write(noChangePanel);
            return;
        }

        var diffLines = GenerateDiffLines(issue);
        var visibleLines = diffLines.Skip(_scrollOffset).Take(MaxVisibleLines).ToList();

        var content = new List<string>();

        foreach (var line in visibleLines)
        {
            content.Add(FormatDiffLine(line));
        }

        // Add scroll indicators
        if (_scrollOffset > 0)
        {
            content.Insert(0, "[grey]  ... more above ...[/]");
        }
        if (_scrollOffset + MaxVisibleLines < diffLines.Count)
        {
            content.Add("[grey]  ... more below ...[/]");
        }

        var diffPanel = new Panel(string.Join("\n", content))
            .Header($"[bold]Changes ({diffLines.Count} lines)[/]")
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.White)
            .Padding(1, 0);

        AnsiConsole.Write(diffPanel);
    }

    private List<DiffLine> GenerateDiffLines(TuiIssue issue)
    {
        var lines = new List<DiffLine>();
        var lineNumber = Math.Max(1, issue.Line - 3);

        // Add context before (if we had full file context)
        lines.Add(new DiffLine(DiffLineType.Context, lineNumber++, "// ... context ..."));

        // Original code
        if (!string.IsNullOrEmpty(issue.CodeSnippet))
        {
            var originalLines = issue.CodeSnippet.Split('\n', StringSplitOptions.None);
            foreach (var line in originalLines)
            {
                lines.Add(new DiffLine(DiffLineType.Removed, lineNumber++, line.TrimEnd('\r')));
            }
        }

        // Suggested fix
        if (!string.IsNullOrEmpty(issue.SuggestedFix))
        {
            var fixLines = issue.SuggestedFix.Split('\n', StringSplitOptions.None);
            foreach (var line in fixLines)
            {
                lines.Add(new DiffLine(DiffLineType.Added, lineNumber++, line.TrimEnd('\r')));
            }
        }

        // Add context after
        lines.Add(new DiffLine(DiffLineType.Context, lineNumber, "// ... context ..."));

        return lines;
    }

    private string FormatDiffLine(DiffLine line)
    {
        var prefix = line.Type switch
        {
            DiffLineType.Added => "[green]+[/]",
            DiffLineType.Removed => "[red]-[/]",
            DiffLineType.Context => "[grey] [/]",
            _ => " "
        };

        var lineNumColor = line.Type switch
        {
            DiffLineType.Added => "green",
            DiffLineType.Removed => "red",
            _ => "grey"
        };

        var contentColor = line.Type switch
        {
            DiffLineType.Added => "green",
            DiffLineType.Removed => "red",
            _ => "white"
        };

        var escapedContent = Markup.Escape(line.Content);
        return $"[{lineNumColor}]{line.LineNumber,4}[/] {prefix} [{contentColor}]{escapedContent}[/]";
    }

    private void RenderFooter(TuiIssue issue)
    {
        AnsiConsole.WriteLine();

        var instructions = new Table()
            .Border(TableBorder.None)
            .HideHeaders()
            .AddColumn(new TableColumn("Keys"))
            .AddColumn(new TableColumn("Description"));

        instructions.AddRow("[yellow]A[/]", "Apply this fix");
        instructions.AddRow("[yellow]S[/]", "Skip this issue");
        instructions.AddRow("[yellow]Up/Down[/]", "Scroll diff");
        instructions.AddRow("[yellow]Esc[/]", "Back to list");

        AnsiConsole.Write(instructions);

        if (issue.HasFix)
        {
            AnsiConsole.MarkupLine("\n[green]This issue has an auto-fix available.[/]");
        }
        else
        {
            AnsiConsole.MarkupLine("\n[yellow]This issue requires manual fix.[/]");
        }
    }

    /// <summary>
    /// Scroll up in the diff view.
    /// </summary>
    public void ScrollUp()
    {
        if (_scrollOffset > 0)
            _scrollOffset--;
    }

    /// <summary>
    /// Scroll down in the diff view.
    /// </summary>
    public void ScrollDown()
    {
        _scrollOffset++;
    }

    /// <summary>
    /// Reset scroll position.
    /// </summary>
    public void ResetScroll()
    {
        _scrollOffset = 0;
    }

    /// <summary>
    /// Render a compact inline diff for the issue list.
    /// </summary>
    public static void RenderInlineDiff(TuiIssue issue, int maxLines = 3)
    {
        if (string.IsNullOrEmpty(issue.CodeSnippet) && string.IsNullOrEmpty(issue.SuggestedFix))
        {
            return;
        }

        var lines = new List<string>();

        // Show removed lines
        if (!string.IsNullOrEmpty(issue.CodeSnippet))
        {
            var originalLines = issue.CodeSnippet.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in originalLines.Take(maxLines))
            {
                var trimmed = line.Trim();
                if (trimmed.Length > 60)
                    trimmed = trimmed[..57] + "...";
                lines.Add($"[red]- {Markup.Escape(trimmed)}[/]");
            }
        }

        // Show added lines
        if (!string.IsNullOrEmpty(issue.SuggestedFix))
        {
            var fixLines = issue.SuggestedFix.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in fixLines.Take(maxLines))
            {
                var trimmed = line.Trim();
                if (trimmed.Length > 60)
                    trimmed = trimmed[..57] + "...";
                lines.Add($"[green]+ {Markup.Escape(trimmed)}[/]");
            }
        }

        foreach (var line in lines.Take(maxLines * 2))
        {
            AnsiConsole.MarkupLine($"  {line}");
        }
    }

    /// <summary>
    /// Generate a unified diff string for display or export.
    /// </summary>
    public static string GenerateUnifiedDiff(TuiIssue issue)
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine($"--- a/{Path.GetFileName(issue.FilePath)}");
        sb.AppendLine($"+++ b/{Path.GetFileName(issue.FilePath)}");
        sb.AppendLine($"@@ -{issue.Line},1 +{issue.Line},1 @@");

        if (!string.IsNullOrEmpty(issue.CodeSnippet))
        {
            foreach (var line in issue.CodeSnippet.Split('\n'))
            {
                sb.AppendLine($"-{line.TrimEnd('\r')}");
            }
        }

        if (!string.IsNullOrEmpty(issue.SuggestedFix))
        {
            foreach (var line in issue.SuggestedFix.Split('\n'))
            {
                sb.AppendLine($"+{line.TrimEnd('\r')}");
            }
        }

        return sb.ToString();
    }
}

/// <summary>
/// A line in a diff output.
/// </summary>
internal record DiffLine(DiffLineType Type, int LineNumber, string Content);

/// <summary>
/// Type of diff line.
/// </summary>
internal enum DiffLineType
{
    Context,
    Added,
    Removed
}
