using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Server.Models;
using BaseScanner.Transformers;
using BaseScanner.Transformers.Core;
using BaseScanner.Services;

namespace BaseScanner.Server;

/// <summary>
/// Provides code actions (quick fixes) for LSP integration.
/// Uses the existing transformer infrastructure to provide fixes.
/// </summary>
public class CodeActionProvider
{
    private readonly DiagnosticsProvider _diagnosticsProvider;
    private readonly TransformationService? _transformationService;

    public CodeActionProvider(DiagnosticsProvider diagnosticsProvider, TransformationService? transformationService = null)
    {
        _diagnosticsProvider = diagnosticsProvider;
        _transformationService = transformationService;
    }

    /// <summary>
    /// Get code actions for a range in a document.
    /// </summary>
    public async Task<List<LspCodeAction>> GetCodeActionsAsync(
        string documentUri,
        LspRange range,
        string content,
        CancellationToken cancellationToken = default)
    {
        var actions = new List<LspCodeAction>();
        var diagnostics = _diagnosticsProvider.GetDiagnostics(documentUri);

        // Filter diagnostics that overlap with the requested range
        var relevantDiagnostics = diagnostics
            .Where(d => RangesOverlap(d.Range, range))
            .ToList();

        foreach (var diagnostic in relevantDiagnostics)
        {
            var diagnosticActions = await GetActionsForDiagnosticAsync(
                documentUri, content, diagnostic, cancellationToken);
            actions.AddRange(diagnosticActions);
        }

        // Add refactoring actions that are always available
        var refactoringActions = await GetRefactoringActionsAsync(
            documentUri, content, range, cancellationToken);
        actions.AddRange(refactoringActions);

        return actions;
    }

    private async Task<List<LspCodeAction>> GetActionsForDiagnosticAsync(
        string documentUri,
        string content,
        LspDiagnostic diagnostic,
        CancellationToken cancellationToken)
    {
        var actions = new List<LspCodeAction>();
        var data = diagnostic.Data;

        if (data == null || !data.HasQuickFix)
            return actions;

        switch (data.IssueType)
        {
            case "AsyncVoid":
                actions.Add(CreateAsyncVoidFix(documentUri, diagnostic));
                break;

            case "MissingConfigureAwait":
                actions.Add(CreateConfigureAwaitFix(documentUri, diagnostic));
                break;

            case "EmptyCatch":
                actions.AddRange(CreateEmptyCatchFixes(documentUri, diagnostic));
                break;

            case "MissingUsing":
                actions.Add(CreateUsingFix(documentUri, diagnostic));
                break;

            case "StringConcatInLoop":
                actions.Add(CreateStringBuilderFix(documentUri, diagnostic, content));
                break;

            default:
                // Check if we have a suggested code replacement
                if (!string.IsNullOrEmpty(data.SuggestedCode) && !string.IsNullOrEmpty(data.OriginalCode))
                {
                    actions.Add(new LspCodeAction
                    {
                        Title = $"Apply suggested fix: {data.IssueType}",
                        Kind = LspCodeActionKind.QuickFix,
                        Diagnostics = [diagnostic],
                        IsPreferred = true,
                        Edit = new LspWorkspaceEdit
                        {
                            Changes = new Dictionary<string, List<LspTextEdit>>
                            {
                                [documentUri] =
                                [
                                    new LspTextEdit
                                    {
                                        Range = diagnostic.Range,
                                        NewText = data.SuggestedCode
                                    }
                                ]
                            }
                        }
                    });
                }
                break;
        }

        return actions;
    }

    private LspCodeAction CreateAsyncVoidFix(string documentUri, LspDiagnostic diagnostic)
    {
        return new LspCodeAction
        {
            Title = "Change return type to Task",
            Kind = LspCodeActionKind.QuickFix,
            Diagnostics = [diagnostic],
            IsPreferred = true,
            Edit = new LspWorkspaceEdit
            {
                Changes = new Dictionary<string, List<LspTextEdit>>
                {
                    [documentUri] =
                    [
                        new LspTextEdit
                        {
                            Range = new LspRange
                            {
                                Start = diagnostic.Range.Start,
                                End = new LspPosition
                                {
                                    Line = diagnostic.Range.Start.Line,
                                    Character = diagnostic.Range.Start.Character + 4 // "void"
                                }
                            },
                            NewText = "Task"
                        }
                    ]
                }
            }
        };
    }

    private LspCodeAction CreateConfigureAwaitFix(string documentUri, LspDiagnostic diagnostic)
    {
        var originalCode = diagnostic.Data?.OriginalCode ?? "";
        var suggestedCode = diagnostic.Data?.SuggestedCode ?? $"{originalCode}.ConfigureAwait(false)";

        return new LspCodeAction
        {
            Title = "Add ConfigureAwait(false)",
            Kind = LspCodeActionKind.QuickFix,
            Diagnostics = [diagnostic],
            Edit = new LspWorkspaceEdit
            {
                Changes = new Dictionary<string, List<LspTextEdit>>
                {
                    [documentUri] =
                    [
                        new LspTextEdit
                        {
                            Range = diagnostic.Range,
                            NewText = suggestedCode
                        }
                    ]
                }
            }
        };
    }

    private List<LspCodeAction> CreateEmptyCatchFixes(string documentUri, LspDiagnostic diagnostic)
    {
        var actions = new List<LspCodeAction>();

        // Add logging option
        actions.Add(new LspCodeAction
        {
            Title = "Add logging to catch block",
            Kind = LspCodeActionKind.QuickFix,
            Diagnostics = [diagnostic],
            IsPreferred = true,
            Edit = new LspWorkspaceEdit
            {
                Changes = new Dictionary<string, List<LspTextEdit>>
                {
                    [documentUri] =
                    [
                        new LspTextEdit
                        {
                            Range = new LspRange
                            {
                                Start = new LspPosition
                                {
                                    Line = diagnostic.Range.Start.Line + 1,
                                    Character = 0
                                },
                                End = new LspPosition
                                {
                                    Line = diagnostic.Range.Start.Line + 1,
                                    Character = 0
                                }
                            },
                            NewText = "    // TODO: Add appropriate logging\n    Console.Error.WriteLine(ex.Message);\n"
                        }
                    ]
                }
            }
        });

        // Add rethrow option
        actions.Add(new LspCodeAction
        {
            Title = "Rethrow exception",
            Kind = LspCodeActionKind.QuickFix,
            Diagnostics = [diagnostic],
            Edit = new LspWorkspaceEdit
            {
                Changes = new Dictionary<string, List<LspTextEdit>>
                {
                    [documentUri] =
                    [
                        new LspTextEdit
                        {
                            Range = new LspRange
                            {
                                Start = new LspPosition
                                {
                                    Line = diagnostic.Range.Start.Line + 1,
                                    Character = 0
                                },
                                End = new LspPosition
                                {
                                    Line = diagnostic.Range.Start.Line + 1,
                                    Character = 0
                                }
                            },
                            NewText = "    throw;\n"
                        }
                    ]
                }
            }
        });

        return actions;
    }

    private LspCodeAction CreateUsingFix(string documentUri, LspDiagnostic diagnostic)
    {
        var originalCode = diagnostic.Data?.OriginalCode ?? "";
        var suggestedCode = diagnostic.Data?.SuggestedCode ?? originalCode;

        return new LspCodeAction
        {
            Title = "Wrap with using statement",
            Kind = LspCodeActionKind.QuickFix,
            Diagnostics = [diagnostic],
            IsPreferred = true,
            Edit = new LspWorkspaceEdit
            {
                Changes = new Dictionary<string, List<LspTextEdit>>
                {
                    [documentUri] =
                    [
                        new LspTextEdit
                        {
                            Range = diagnostic.Range,
                            NewText = suggestedCode
                        }
                    ]
                }
            }
        };
    }

    private LspCodeAction CreateStringBuilderFix(string documentUri, LspDiagnostic diagnostic, string content)
    {
        // This is a more complex fix that would need to analyze the context
        return new LspCodeAction
        {
            Title = "Convert to StringBuilder (manual refactoring required)",
            Kind = LspCodeActionKind.QuickFix,
            Diagnostics = [diagnostic],
            Command = new LspCommand
            {
                Title = "Open documentation",
                CommandId = "basescanner.openDocs",
                Arguments = ["stringbuilder-pattern"]
            }
        };
    }

    private async Task<List<LspCodeAction>> GetRefactoringActionsAsync(
        string documentUri,
        string content,
        LspRange range,
        CancellationToken cancellationToken)
    {
        var actions = new List<LspCodeAction>();

        try
        {
            var syntaxTree = CSharpSyntaxTree.ParseText(content, cancellationToken: cancellationToken);
            var root = await syntaxTree.GetRootAsync(cancellationToken);

            // Find the node at the cursor position
            var position = GetPositionFromRange(content, range.Start);
            var node = root.FindNode(new Microsoft.CodeAnalysis.Text.TextSpan(position, 1));

            // Method extraction for selections
            if (range.Start.Line != range.End.Line || range.Start.Character != range.End.Character)
            {
                var method = node.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
                if (method != null)
                {
                    actions.Add(new LspCodeAction
                    {
                        Title = "Extract Method",
                        Kind = LspCodeActionKind.RefactorExtract,
                        Command = new LspCommand
                        {
                            Title = "Extract Method",
                            CommandId = "basescanner.extractMethod",
                            Arguments = [documentUri, range.Start.Line, range.End.Line]
                        }
                    });
                }
            }

            // Method at cursor - offer simplification if complex
            var currentMethod = node.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            if (currentMethod != null)
            {
                var complexity = CalculateCyclomaticComplexity(currentMethod);
                if (complexity > 10)
                {
                    actions.Add(new LspCodeAction
                    {
                        Title = $"Simplify Method (CC: {complexity})",
                        Kind = LspCodeActionKind.Refactor,
                        Command = new LspCommand
                        {
                            Title = "Simplify Method",
                            CommandId = "basescanner.simplifyMethod",
                            Arguments = [documentUri, currentMethod.Identifier.Text]
                        }
                    });
                }
            }

            // Class at cursor - offer split if god class
            var currentClass = node.AncestorsAndSelf().OfType<ClassDeclarationSyntax>().FirstOrDefault();
            if (currentClass != null)
            {
                var methodCount = currentClass.Members.OfType<MethodDeclarationSyntax>().Count();
                if (methodCount > 15)
                {
                    actions.Add(new LspCodeAction
                    {
                        Title = $"Split Class ({methodCount} methods)",
                        Kind = LspCodeActionKind.Refactor,
                        Command = new LspCommand
                        {
                            Title = "Split Class",
                            CommandId = "basescanner.splitClass",
                            Arguments = [documentUri, currentClass.Identifier.Text]
                        }
                    });
                }
            }

            // Inline expression
            if (node is LocalDeclarationStatementSyntax localDecl)
            {
                var variable = localDecl.Declaration.Variables.FirstOrDefault();
                if (variable?.Initializer != null)
                {
                    actions.Add(new LspCodeAction
                    {
                        Title = $"Inline variable '{variable.Identifier.Text}'",
                        Kind = LspCodeActionKind.RefactorInline,
                        Command = new LspCommand
                        {
                            Title = "Inline Variable",
                            CommandId = "basescanner.inlineVariable",
                            Arguments = [documentUri, variable.Identifier.Text, range.Start.Line]
                        }
                    });
                }
            }

            // Convert to expression body
            if (currentMethod?.Body != null && currentMethod.Body.Statements.Count == 1)
            {
                var statement = currentMethod.Body.Statements[0];
                if (statement is ReturnStatementSyntax or ExpressionStatementSyntax)
                {
                    actions.Add(new LspCodeAction
                    {
                        Title = "Convert to expression body",
                        Kind = LspCodeActionKind.RefactorRewrite,
                        Command = new LspCommand
                        {
                            Title = "Convert to Expression Body",
                            CommandId = "basescanner.convertToExpressionBody",
                            Arguments = [documentUri, currentMethod.Identifier.Text]
                        }
                    });
                }
            }

            // Add null check
            if (node is ParameterSyntax parameter)
            {
                actions.Add(new LspCodeAction
                {
                    Title = $"Add null check for '{parameter.Identifier.Text}'",
                    Kind = LspCodeActionKind.QuickFix,
                    Command = new LspCommand
                    {
                        Title = "Add Null Check",
                        CommandId = "basescanner.addNullCheck",
                        Arguments = [documentUri, parameter.Identifier.Text, range.Start.Line]
                    }
                });
            }
        }
        catch (Exception)
        {
            // Ignore parsing errors for refactoring suggestions
        }

        return actions;
    }

    private static int GetPositionFromRange(string content, LspPosition position)
    {
        var lines = content.Split('\n');
        var offset = 0;
        for (var i = 0; i < position.Line && i < lines.Length; i++)
        {
            offset += lines[i].Length + 1; // +1 for newline
        }
        return offset + position.Character;
    }

    private static bool RangesOverlap(LspRange a, LspRange b)
    {
        // Check if ranges overlap
        if (a.End.Line < b.Start.Line) return false;
        if (b.End.Line < a.Start.Line) return false;
        if (a.End.Line == b.Start.Line && a.End.Character < b.Start.Character) return false;
        if (b.End.Line == a.Start.Line && b.End.Character < a.Start.Character) return false;
        return true;
    }

    private static int CalculateCyclomaticComplexity(MethodDeclarationSyntax method)
    {
        var complexity = 1;
        var body = (SyntaxNode?)method.Body ?? method.ExpressionBody;
        if (body == null) return complexity;

        foreach (var node in body.DescendantNodes())
        {
            switch (node)
            {
                case IfStatementSyntax:
                case ConditionalExpressionSyntax:
                case CaseSwitchLabelSyntax:
                case CasePatternSwitchLabelSyntax:
                case ForStatementSyntax:
                case ForEachStatementSyntax:
                case WhileStatementSyntax:
                case DoStatementSyntax:
                case CatchClauseSyntax:
                    complexity++;
                    break;
                case BinaryExpressionSyntax binary when
                    binary.IsKind(SyntaxKind.LogicalAndExpression) ||
                    binary.IsKind(SyntaxKind.LogicalOrExpression) ||
                    binary.IsKind(SyntaxKind.CoalesceExpression):
                    complexity++;
                    break;
            }
        }

        return complexity;
    }
}
