using Microsoft.CodeAnalysis;

namespace BaseScanner.Server.Models;

/// <summary>
/// LSP diagnostic severity levels.
/// </summary>
public enum LspDiagnosticSeverity
{
    Error = 1,
    Warning = 2,
    Information = 3,
    Hint = 4
}

/// <summary>
/// Represents a position in a document.
/// </summary>
public record LspPosition
{
    public int Line { get; init; }
    public int Character { get; init; }

    public static LspPosition FromLineSpan(FileLinePositionSpan span, bool start = true) =>
        new()
        {
            Line = start ? span.StartLinePosition.Line : span.EndLinePosition.Line,
            Character = start ? span.StartLinePosition.Character : span.EndLinePosition.Character
        };
}

/// <summary>
/// Represents a range in a document.
/// </summary>
public record LspRange
{
    public required LspPosition Start { get; init; }
    public required LspPosition End { get; init; }

    public static LspRange FromLineSpan(FileLinePositionSpan span) =>
        new()
        {
            Start = LspPosition.FromLineSpan(span, start: true),
            End = LspPosition.FromLineSpan(span, start: false)
        };

    public static LspRange FromLine(int line, int startChar = 0, int endChar = 0) =>
        new()
        {
            Start = new LspPosition { Line = line, Character = startChar },
            End = new LspPosition { Line = line, Character = endChar > 0 ? endChar : 1000 }
        };
}

/// <summary>
/// Represents an LSP diagnostic.
/// </summary>
public record LspDiagnostic
{
    public required LspRange Range { get; init; }
    public required LspDiagnosticSeverity Severity { get; init; }
    public string? Code { get; init; }
    public string? Source { get; init; } = "BaseScanner";
    public required string Message { get; init; }
    public List<LspDiagnosticRelatedInfo>? RelatedInformation { get; init; }
    public LspDiagnosticData? Data { get; init; }
}

/// <summary>
/// Related information for a diagnostic.
/// </summary>
public record LspDiagnosticRelatedInfo
{
    public required LspLocation Location { get; init; }
    public required string Message { get; init; }
}

/// <summary>
/// Location in a document.
/// </summary>
public record LspLocation
{
    public required string Uri { get; init; }
    public required LspRange Range { get; init; }
}

/// <summary>
/// Additional data for a diagnostic.
/// </summary>
public record LspDiagnosticData
{
    /// <summary>
    /// The type of issue for quick fix matching.
    /// </summary>
    public required string IssueType { get; init; }

    /// <summary>
    /// Category of the issue (performance, security, etc.)
    /// </summary>
    public string? Category { get; init; }

    /// <summary>
    /// Whether a quick fix is available.
    /// </summary>
    public bool HasQuickFix { get; init; }

    /// <summary>
    /// Suggested replacement code if applicable.
    /// </summary>
    public string? SuggestedCode { get; init; }

    /// <summary>
    /// Original code for the issue.
    /// </summary>
    public string? OriginalCode { get; init; }

    /// <summary>
    /// Confidence level of the diagnostic.
    /// </summary>
    public string? Confidence { get; init; }
}

/// <summary>
/// Represents a code action (quick fix).
/// </summary>
public record LspCodeAction
{
    public required string Title { get; init; }
    public string? Kind { get; init; } = "quickfix";
    public List<LspDiagnostic>? Diagnostics { get; init; }
    public bool? IsPreferred { get; init; }
    public LspWorkspaceEdit? Edit { get; init; }
    public LspCommand? Command { get; init; }
}

/// <summary>
/// Code action kinds.
/// </summary>
public static class LspCodeActionKind
{
    public const string QuickFix = "quickfix";
    public const string Refactor = "refactor";
    public const string RefactorExtract = "refactor.extract";
    public const string RefactorInline = "refactor.inline";
    public const string RefactorRewrite = "refactor.rewrite";
    public const string Source = "source";
    public const string SourceOrganizeImports = "source.organizeImports";
}

/// <summary>
/// Represents a workspace edit.
/// </summary>
public record LspWorkspaceEdit
{
    public Dictionary<string, List<LspTextEdit>>? Changes { get; init; }
    public List<LspTextDocumentEdit>? DocumentChanges { get; init; }
}

/// <summary>
/// Represents a text edit.
/// </summary>
public record LspTextEdit
{
    public required LspRange Range { get; init; }
    public required string NewText { get; init; }
}

/// <summary>
/// Represents a document edit.
/// </summary>
public record LspTextDocumentEdit
{
    public required LspVersionedTextDocumentIdentifier TextDocument { get; init; }
    public required List<LspTextEdit> Edits { get; init; }
}

/// <summary>
/// Versioned text document identifier.
/// </summary>
public record LspVersionedTextDocumentIdentifier
{
    public required string Uri { get; init; }
    public int? Version { get; init; }
}

/// <summary>
/// Represents a command.
/// </summary>
public record LspCommand
{
    public required string Title { get; init; }
    public required string CommandId { get; init; }
    public List<object>? Arguments { get; init; }
}

/// <summary>
/// Represents a code lens.
/// </summary>
public record LspCodeLens
{
    public required LspRange Range { get; init; }
    public LspCommand? Command { get; init; }
    public object? Data { get; init; }
}

/// <summary>
/// Data attached to a code lens for resolution.
/// </summary>
public record LspCodeLensData
{
    public required string DocumentUri { get; init; }
    public required string MethodName { get; init; }
    public required int Line { get; init; }
}

/// <summary>
/// Represents hover information.
/// </summary>
public record LspHover
{
    public required LspMarkupContent Contents { get; init; }
    public LspRange? Range { get; init; }
}

/// <summary>
/// Markup content for hover, completion, etc.
/// </summary>
public record LspMarkupContent
{
    public required string Kind { get; init; }
    public required string Value { get; init; }
}

/// <summary>
/// Markup content kinds.
/// </summary>
public static class LspMarkupKind
{
    public const string PlainText = "plaintext";
    public const string Markdown = "markdown";
}

/// <summary>
/// Method metrics for code lens display.
/// </summary>
public record MethodMetricsInfo
{
    public required string MethodName { get; init; }
    public required string ClassName { get; init; }
    public required string FilePath { get; init; }
    public required int Line { get; init; }
    public required int CyclomaticComplexity { get; init; }
    public required int LineCount { get; init; }
    public double? TestCoverage { get; init; }
    public int? NestingDepth { get; init; }
    public int? ParameterCount { get; init; }
}

/// <summary>
/// Issue info for diagnostics.
/// </summary>
public record IssueInfo
{
    public required string Type { get; init; }
    public required string Message { get; init; }
    public required string FilePath { get; init; }
    public required int StartLine { get; init; }
    public required int EndLine { get; init; }
    public int StartColumn { get; init; }
    public int EndColumn { get; init; }
    public required string Severity { get; init; }
    public string? Category { get; init; }
    public string? CurrentCode { get; init; }
    public string? SuggestedCode { get; init; }
    public string? Confidence { get; init; }
    public List<string>? Recommendations { get; init; }
}

/// <summary>
/// Document state for tracking open documents.
/// </summary>
public record DocumentState
{
    public required string Uri { get; init; }
    public required string Content { get; init; }
    public required int Version { get; init; }
    public DateTime LastAnalyzed { get; init; }
    public List<LspDiagnostic> Diagnostics { get; init; } = [];
    public List<MethodMetricsInfo> MethodMetrics { get; init; } = [];
}

/// <summary>
/// Configuration options for the LSP server.
/// </summary>
public record LspServerOptions
{
    /// <summary>
    /// Whether to run in stdio mode (default) or TCP.
    /// </summary>
    public bool UseStdio { get; init; } = true;

    /// <summary>
    /// TCP port to listen on if not using stdio.
    /// </summary>
    public int TcpPort { get; init; } = 5007;

    /// <summary>
    /// Debounce delay for document analysis in milliseconds.
    /// </summary>
    public int AnalysisDebounceMs { get; init; } = 500;

    /// <summary>
    /// Maximum number of diagnostics per file.
    /// </summary>
    public int MaxDiagnosticsPerFile { get; init; } = 100;

    /// <summary>
    /// Which analyzers to enable.
    /// </summary>
    public AnalyzerSettings Analyzers { get; init; } = new();
}

/// <summary>
/// Settings for which analyzers to run.
/// </summary>
public record AnalyzerSettings
{
    public bool Performance { get; init; } = true;
    public bool Security { get; init; } = true;
    public bool Refactoring { get; init; } = true;
    public bool Optimization { get; init; } = true;
    public bool CodeQuality { get; init; } = true;
    public bool ExceptionHandling { get; init; } = true;
    public bool ResourceLeaks { get; init; } = true;
}
