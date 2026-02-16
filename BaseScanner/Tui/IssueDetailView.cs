using Spectre.Console;
using BaseScanner.Tui.Models;

namespace BaseScanner.Tui;

/// <summary>
/// Detail view component showing full information about a selected issue.
/// </summary>
public class IssueDetailView
{
    private readonly TuiState _state;
    private readonly DiffPreviewView _diffView;
    private int _scrollOffset;
    private const int MaxVisibleLines = 25;

    public IssueDetailView(TuiState state)
    {
        _state = state;
        _diffView = new DiffPreviewView(state);
    }

    /// <summary>
    /// Render the full detail view for the current issue.
    /// </summary>
    public void Render()
    {
        var issue = _state.CurrentIssue;
        if (issue == null)
        {
            RenderNoIssue();
            return;
        }

        RenderIssueHeader(issue);
        RenderIssueDetails(issue);
        RenderCodeSection(issue);
        RenderRecommendation(issue);
        RenderActions(issue);
    }

    private void RenderNoIssue()
    {
        var panel = new Panel("[yellow]No issue selected[/]")
            .Header("[bold]Issue Details[/]")
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Yellow);

        AnsiConsole.Write(panel);
        AnsiConsole.MarkupLine("\n[grey]Press [yellow]Esc[/] to go back to the issue list.[/]");
    }

    private void RenderIssueHeader(TuiIssue issue)
    {
        // Title bar with severity and type
        var titleColor = issue.SeverityColor;
        var severityBadge = issue.Severity.ToUpperInvariant() switch
        {
            "CRITICAL" => "[white on red] CRITICAL [/]",
            "HIGH" => "[white on red3] HIGH [/]",
            "MEDIUM" => "[black on yellow] MEDIUM [/]",
            "LOW" => "[white on blue] LOW [/]",
            _ => $"[grey] {issue.Severity.ToUpperInvariant()} [/]"
        };

        var header = new Rule($"{severityBadge} [bold]{Markup.Escape(issue.Type)}[/]")
        {
            Justification = Justify.Left,
            Style = Style.Parse(titleColor)
        };
        AnsiConsole.Write(header);
    }

    private void RenderIssueDetails(TuiIssue issue)
    {
        var detailsTable = new Table()
            .Border(TableBorder.None)
            .HideHeaders()
            .AddColumn(new TableColumn("Label").Width(16))
            .AddColumn(new TableColumn("Value"));

        // Location
        detailsTable.AddRow(
            "[grey]Location:[/]",
            $"[cyan]{Markup.Escape(issue.FilePath)}[/]:[yellow]{issue.Line}[/]");

        // Category
        detailsTable.AddRow(
            "[grey]Category:[/]",
            $"[white]{issue.Category}[/]");

        // CWE (for security issues)
        if (!string.IsNullOrEmpty(issue.CweId))
        {
            detailsTable.AddRow(
                "[grey]CWE:[/]",
                $"[cyan]{issue.CweId}[/] [grey](https://cwe.mitre.org/data/definitions/{issue.CweId.Replace("CWE-", "")}.html)[/]");
        }

        // Confidence
        if (!string.IsNullOrEmpty(issue.Confidence))
        {
            var confColor = issue.Confidence.ToUpperInvariant() switch
            {
                "HIGH" => "green",
                "MEDIUM" => "yellow",
                _ => "grey"
            };
            detailsTable.AddRow(
                "[grey]Confidence:[/]",
                $"[{confColor}]{issue.Confidence}[/]");
        }

        // Fix available
        detailsTable.AddRow(
            "[grey]Auto-fix:[/]",
            issue.HasFix ? "[green]Available[/]" : "[grey]Not available[/]");

        AnsiConsole.Write(detailsTable);
        AnsiConsole.WriteLine();

        // Message
        var messagePanel = new Panel(Markup.Escape(issue.Message))
            .Header("[bold]Description[/]")
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Grey)
            .Padding(1, 0);

        AnsiConsole.Write(messagePanel);
    }

    private void RenderCodeSection(TuiIssue issue)
    {
        if (string.IsNullOrEmpty(issue.CodeSnippet) && string.IsNullOrEmpty(issue.SuggestedFix))
        {
            return;
        }

        AnsiConsole.WriteLine();

        // Current code
        if (!string.IsNullOrEmpty(issue.CodeSnippet))
        {
            var currentCode = new Panel(FormatCodeBlock(issue.CodeSnippet))
                .Header("[bold red]Current Code[/]")
                .Border(BoxBorder.Rounded)
                .BorderColor(Color.Red)
                .Padding(1, 0);

            AnsiConsole.Write(currentCode);
        }

        // Suggested fix
        if (!string.IsNullOrEmpty(issue.SuggestedFix))
        {
            var suggestedCode = new Panel(FormatCodeBlock(issue.SuggestedFix))
                .Header("[bold green]Suggested Fix[/]")
                .Border(BoxBorder.Rounded)
                .BorderColor(Color.Green)
                .Padding(1, 0);

            AnsiConsole.Write(suggestedCode);
        }
    }

    private string FormatCodeBlock(string code)
    {
        var lines = code.Split('\n', StringSplitOptions.None);
        var formattedLines = new List<string>();
        var lineNum = 1;

        foreach (var line in lines)
        {
            var trimmedLine = line.TrimEnd('\r');
            var escapedLine = Markup.Escape(trimmedLine);
            formattedLines.Add($"[grey]{lineNum,3}[/] [white]{escapedLine}[/]");
            lineNum++;
        }

        return string.Join("\n", formattedLines);
    }

    private void RenderRecommendation(TuiIssue issue)
    {
        if (string.IsNullOrEmpty(issue.Recommendation))
        {
            return;
        }

        AnsiConsole.WriteLine();

        var recPanel = new Panel(Markup.Escape(issue.Recommendation))
            .Header("[bold cyan]Recommendation[/]")
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Cyan1)
            .Padding(1, 0);

        AnsiConsole.Write(recPanel);
    }

    private void RenderActions(TuiIssue issue)
    {
        AnsiConsole.WriteLine();

        var actionsTable = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Grey)
            .AddColumn(new TableColumn("[bold]Key[/]").Centered())
            .AddColumn(new TableColumn("[bold]Action[/]"));

        if (issue.HasFix)
        {
            actionsTable.AddRow("[yellow]A[/]", "Apply fix");
        }
        actionsTable.AddRow("[yellow]D[/]", "Show diff preview");
        actionsTable.AddRow("[yellow]S[/]", "Skip this issue");
        actionsTable.AddRow("[yellow]Esc[/]", "Back to list");

        AnsiConsole.Write(actionsTable);

        // Status
        if (_state.SelectedIssueIds.Contains(issue.Id))
        {
            AnsiConsole.MarkupLine("\n[green]This issue is selected for batch processing.[/]");
        }
    }

    /// <summary>
    /// Render a compact summary suitable for a side panel.
    /// </summary>
    public void RenderCompact()
    {
        var issue = _state.CurrentIssue;
        if (issue == null)
        {
            AnsiConsole.MarkupLine("[grey]Select an issue to see details[/]");
            return;
        }

        var lines = new List<string>
        {
            $"[{issue.SeverityColor}]{issue.SeverityLabel}[/] {Markup.Escape(issue.Type)}",
            "",
            $"[grey]File:[/] {Markup.Escape(Path.GetFileName(issue.FilePath))}",
            $"[grey]Line:[/] {issue.Line}",
            $"[grey]Category:[/] {issue.Category}",
            ""
        };

        // Truncated message
        var msg = issue.Message.Length > 100
            ? issue.Message[..97] + "..."
            : issue.Message;
        lines.Add(Markup.Escape(msg));

        // Preview inline diff
        if (issue.HasFix)
        {
            lines.Add("");
            lines.Add("[grey]Preview:[/]");
        }

        var panel = new Panel(string.Join("\n", lines))
            .Header("[bold]Details[/]")
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Grey);

        AnsiConsole.Write(panel);

        // Add inline diff
        if (issue.HasFix)
        {
            DiffPreviewView.RenderInlineDiff(issue, 2);
        }
    }

    /// <summary>
    /// Handle scroll up.
    /// </summary>
    public void ScrollUp()
    {
        if (_scrollOffset > 0)
            _scrollOffset--;
    }

    /// <summary>
    /// Handle scroll down.
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
    /// Get the associated diff view.
    /// </summary>
    public DiffPreviewView DiffView => _diffView;
}
