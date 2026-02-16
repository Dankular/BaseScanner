using BaseScanner.Tui.Models;

namespace BaseScanner.Tui;

/// <summary>
/// Keyboard shortcuts and their handlers for the TUI.
/// </summary>
public class KeyBindings
{
    private readonly Dictionary<ConsoleKey, KeyBinding> _bindings = new();
    private readonly Dictionary<(ConsoleKey, ConsoleModifiers), KeyBinding> _modifiedBindings = new();

    public KeyBindings()
    {
        SetupDefaultBindings();
    }

    private void SetupDefaultBindings()
    {
        // Navigation
        Register(ConsoleKey.UpArrow, "Move up", TuiAction.MoveUp, TuiViewMode.IssueList);
        Register(ConsoleKey.DownArrow, "Move down", TuiAction.MoveDown, TuiViewMode.IssueList);
        Register(ConsoleKey.K, "Move up (vim)", TuiAction.MoveUp, TuiViewMode.IssueList);
        Register(ConsoleKey.J, "Move down (vim)", TuiAction.MoveDown, TuiViewMode.IssueList);
        Register(ConsoleKey.PageUp, "Page up", TuiAction.PageUp, TuiViewMode.IssueList);
        Register(ConsoleKey.PageDown, "Page down", TuiAction.PageDown, TuiViewMode.IssueList);
        Register(ConsoleKey.Home, "Go to first", TuiAction.GoToFirst, TuiViewMode.IssueList);
        Register(ConsoleKey.End, "Go to last", TuiAction.GoToLast, TuiViewMode.IssueList);

        // Selection
        Register(ConsoleKey.Spacebar, "Toggle selection", TuiAction.ToggleSelection, TuiViewMode.IssueList);
        Register(ConsoleKey.Enter, "View details", TuiAction.ViewDetails, TuiViewMode.IssueList);
        Register(ConsoleKey.A, "Apply selected fix", TuiAction.ApplyFix, TuiViewMode.IssueList);
        Register(ConsoleKey.S, "Skip issue", TuiAction.Skip, TuiViewMode.IssueList);

        // Filter and search
        Register(ConsoleKey.F, "Open filter panel", TuiAction.OpenFilter, TuiViewMode.IssueList);
        Register(ConsoleKey.Divide, "Search", TuiAction.Search, TuiViewMode.IssueList); // '/' key
        Register(ConsoleKey.Oem2, "Search", TuiAction.Search, TuiViewMode.IssueList); // '/' key alternate

        // Function keys
        Register(ConsoleKey.F1, "Show help", TuiAction.ShowHelp);
        Register(ConsoleKey.F2, "Open filter", TuiAction.OpenFilter);
        Register(ConsoleKey.F3, "Apply selected", TuiAction.ApplyFix);
        Register(ConsoleKey.F5, "Refresh", TuiAction.Refresh);

        // Undo and misc
        Register(ConsoleKey.U, "Undo last", TuiAction.Undo, TuiViewMode.IssueList);
        Register(ConsoleKey.Z, ConsoleModifiers.Control, "Undo last", TuiAction.Undo);
        Register(ConsoleKey.R, "Reset filter", TuiAction.ResetFilter, TuiViewMode.IssueList);

        // Exit
        Register(ConsoleKey.Q, "Quit", TuiAction.Quit);
        Register(ConsoleKey.Escape, "Back/Cancel", TuiAction.Back);

        // Batch operations
        Register(ConsoleKey.A, ConsoleModifiers.Control, "Select all", TuiAction.SelectAll);
        Register(ConsoleKey.D, ConsoleModifiers.Control, "Deselect all", TuiAction.DeselectAll);

        // Detail view navigation
        Register(ConsoleKey.UpArrow, "Scroll up", TuiAction.ScrollUp, TuiViewMode.IssueDetail);
        Register(ConsoleKey.DownArrow, "Scroll down", TuiAction.ScrollDown, TuiViewMode.IssueDetail);
        Register(ConsoleKey.D, "Show diff", TuiAction.ShowDiff, TuiViewMode.IssueDetail);
        Register(ConsoleKey.A, "Apply fix", TuiAction.ApplyFix, TuiViewMode.IssueDetail);
        Register(ConsoleKey.Escape, "Back to list", TuiAction.Back, TuiViewMode.IssueDetail);

        // Diff view
        Register(ConsoleKey.A, "Apply fix", TuiAction.ApplyFix, TuiViewMode.DiffPreview);
        Register(ConsoleKey.Escape, "Back", TuiAction.Back, TuiViewMode.DiffPreview);

        // Filter panel
        Register(ConsoleKey.Enter, "Apply filter", TuiAction.ApplyFilterSelection, TuiViewMode.FilterPanel);
        Register(ConsoleKey.Escape, "Close filter", TuiAction.Back, TuiViewMode.FilterPanel);
        Register(ConsoleKey.R, "Reset filter", TuiAction.ResetFilter, TuiViewMode.FilterPanel);

        // Help view
        Register(ConsoleKey.Escape, "Close help", TuiAction.Back, TuiViewMode.Help);
        Register(ConsoleKey.Q, "Close help", TuiAction.Back, TuiViewMode.Help);
    }

    /// <summary>
    /// Register a key binding.
    /// </summary>
    public void Register(ConsoleKey key, string description, TuiAction action, TuiViewMode? viewMode = null)
    {
        _bindings[key] = new KeyBinding
        {
            Key = key,
            Description = description,
            Action = action,
            ViewMode = viewMode
        };
    }

    /// <summary>
    /// Register a key binding with modifiers.
    /// </summary>
    public void Register(ConsoleKey key, ConsoleModifiers modifiers, string description, TuiAction action, TuiViewMode? viewMode = null)
    {
        _modifiedBindings[(key, modifiers)] = new KeyBinding
        {
            Key = key,
            Modifiers = modifiers,
            Description = description,
            Action = action,
            ViewMode = viewMode
        };
    }

    /// <summary>
    /// Get the action for a key press.
    /// </summary>
    public TuiAction? GetAction(ConsoleKeyInfo keyInfo, TuiViewMode currentMode)
    {
        // Check modified bindings first
        if (keyInfo.Modifiers != 0)
        {
            if (_modifiedBindings.TryGetValue((keyInfo.Key, keyInfo.Modifiers), out var modBinding))
            {
                if (modBinding.ViewMode == null || modBinding.ViewMode == currentMode)
                {
                    return modBinding.Action;
                }
            }
        }

        // Check regular bindings
        if (_bindings.TryGetValue(keyInfo.Key, out var binding))
        {
            if (binding.ViewMode == null || binding.ViewMode == currentMode)
            {
                return binding.Action;
            }
        }

        return null;
    }

    /// <summary>
    /// Get all bindings for help display.
    /// </summary>
    public IEnumerable<KeyBinding> GetAllBindings()
    {
        return _bindings.Values.Concat(_modifiedBindings.Values)
            .OrderBy(b => b.ViewMode ?? TuiViewMode.IssueList)
            .ThenBy(b => b.Description);
    }

    /// <summary>
    /// Get bindings for a specific view mode.
    /// </summary>
    public IEnumerable<KeyBinding> GetBindingsForMode(TuiViewMode mode)
    {
        return _bindings.Values.Concat(_modifiedBindings.Values)
            .Where(b => b.ViewMode == null || b.ViewMode == mode)
            .OrderBy(b => b.Description);
    }

    /// <summary>
    /// Get the key display string for a binding.
    /// </summary>
    public static string GetKeyDisplayString(KeyBinding binding)
    {
        var parts = new List<string>();

        if (binding.Modifiers.HasFlag(ConsoleModifiers.Control))
            parts.Add("Ctrl");
        if (binding.Modifiers.HasFlag(ConsoleModifiers.Alt))
            parts.Add("Alt");
        if (binding.Modifiers.HasFlag(ConsoleModifiers.Shift))
            parts.Add("Shift");

        var keyName = binding.Key switch
        {
            ConsoleKey.UpArrow => "[up]",
            ConsoleKey.DownArrow => "[down]",
            ConsoleKey.LeftArrow => "[left]",
            ConsoleKey.RightArrow => "[right]",
            ConsoleKey.Spacebar => "Space",
            ConsoleKey.Enter => "Enter",
            ConsoleKey.Escape => "Esc",
            ConsoleKey.PageUp => "PgUp",
            ConsoleKey.PageDown => "PgDn",
            ConsoleKey.Divide or ConsoleKey.Oem2 => "/",
            ConsoleKey.F1 => "F1",
            ConsoleKey.F2 => "F2",
            ConsoleKey.F3 => "F3",
            ConsoleKey.F4 => "F4",
            ConsoleKey.F5 => "F5",
            _ => binding.Key.ToString()
        };

        parts.Add(keyName);
        return string.Join("+", parts);
    }
}

/// <summary>
/// A single key binding.
/// </summary>
public record KeyBinding
{
    public required ConsoleKey Key { get; init; }
    public ConsoleModifiers Modifiers { get; init; }
    public required string Description { get; init; }
    public required TuiAction Action { get; init; }
    public TuiViewMode? ViewMode { get; init; }
}

/// <summary>
/// Available TUI actions.
/// </summary>
public enum TuiAction
{
    // Navigation
    MoveUp,
    MoveDown,
    PageUp,
    PageDown,
    GoToFirst,
    GoToLast,
    ScrollUp,
    ScrollDown,

    // Selection
    ToggleSelection,
    SelectAll,
    DeselectAll,

    // View switching
    ViewDetails,
    ShowDiff,
    OpenFilter,
    ShowHelp,
    Back,

    // Actions
    ApplyFix,
    Skip,
    Undo,
    Refresh,
    Search,
    ResetFilter,
    ApplyFilterSelection,
    Quit
}
