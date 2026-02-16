using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.MSBuild;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MediatR;
using Newtonsoft.Json.Linq;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Server;
using OmniSharp.Extensions.LanguageServer.Protocol.Server.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Window;
using OmniSharp.Extensions.LanguageServer.Protocol.Workspace;
using OmniSharp.Extensions.LanguageServer.Server;
using BaseScanner.Server.Models;
using BaseScanner.Services;
using BaseScanner.Transformers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using LspDiagnosticSeverity = BaseScanner.Server.Models.LspDiagnosticSeverity;
using OmniDiagnostic = OmniSharp.Extensions.LanguageServer.Protocol.Models.Diagnostic;
using OmniDiagnosticSeverity = OmniSharp.Extensions.LanguageServer.Protocol.Models.DiagnosticSeverity;

namespace BaseScanner.Server;

/// <summary>
/// Main LSP server for BaseScanner.
/// Provides real-time diagnostics, code actions, code lens, and hover information.
/// </summary>
public class BaseScannerLanguageServer
{
    private readonly LspServerOptions _options;
    private readonly DiagnosticsProvider _diagnosticsProvider;
    private readonly CodeActionProvider _codeActionProvider;
    private readonly CodeLensProvider _codeLensProvider;
    private readonly HoverProvider _hoverProvider;
    private readonly ConcurrentDictionary<string, string> _documentContents = new();

    private OmniSharp.Extensions.LanguageServer.Server.LanguageServer? _server;
    private ILanguageServerFacade? _serverFacade;
    private Project? _workspaceProject;

    public BaseScannerLanguageServer(LspServerOptions options)
    {
        _options = options;
        _diagnosticsProvider = new DiagnosticsProvider(options);
        _codeLensProvider = new CodeLensProvider();
        _codeActionProvider = new CodeActionProvider(_diagnosticsProvider);
        _hoverProvider = new HoverProvider(_diagnosticsProvider, _codeLensProvider);

        // Subscribe to diagnostic updates
        _diagnosticsProvider.DiagnosticsUpdated += OnDiagnosticsUpdated;
    }

    /// <summary>
    /// Start the language server.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        if (_options.UseStdio)
        {
            await RunWithStdioAsync(cancellationToken);
        }
        else
        {
            await RunWithTcpAsync(cancellationToken);
        }
    }

    private async Task RunWithStdioAsync(CancellationToken cancellationToken)
    {
        _server = await OmniSharp.Extensions.LanguageServer.Server.LanguageServer.From(
            options => ConfigureServer(options, Console.OpenStandardInput(), Console.OpenStandardOutput()),
            cancellationToken);

        await _server.WaitForExit;
    }

    private async Task RunWithTcpAsync(CancellationToken cancellationToken)
    {
        var listener = new TcpListener(IPAddress.Loopback, _options.TcpPort);
        listener.Start();

        Console.Error.WriteLine($"BaseScanner LSP server listening on port {_options.TcpPort}");

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var client = await listener.AcceptTcpClientAsync(cancellationToken);
                Console.Error.WriteLine("Client connected");

                var stream = client.GetStream();
                _server = await OmniSharp.Extensions.LanguageServer.Server.LanguageServer.From(
                    options => ConfigureServer(options, stream, stream),
                    cancellationToken);

                await _server.WaitForExit;

                client.Close();
                Console.Error.WriteLine("Client disconnected");
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
            }
        }

        listener.Stop();
    }

    private void ConfigureServer(LanguageServerOptions options, Stream input, Stream output)
    {
        options
            .WithInput(input)
            .WithOutput(output)
            .ConfigureLogging(logging =>
            {
                logging.SetMinimumLevel(LogLevel.Warning);
            })
            .WithServices(services =>
            {
                services.AddSingleton(this);
                services.AddSingleton(_diagnosticsProvider);
                services.AddSingleton(_codeActionProvider);
                services.AddSingleton(_codeLensProvider);
                services.AddSingleton(_hoverProvider);
            })
            .WithHandler<TextDocumentSyncHandler>()
            .WithHandler<DiagnosticHandler>()
            .WithHandler<CodeActionHandler>()
            .WithHandler<CodeLensHandler>()
            .WithHandler<HoverHandler>()
            .OnInitialize(async (server, request, token) =>
            {
                _serverFacade = server;

                // Initialize workspace if a root path is provided
                if (request.RootPath != null)
                {
                    await InitializeWorkspaceAsync(request.RootPath);
                }
                else if (request.RootUri != null)
                {
                    var path = request.RootUri.GetFileSystemPath();
                    await InitializeWorkspaceAsync(path);
                }

                server.Window.LogInfo($"BaseScanner LSP server initialized");
            })
            .OnInitialized((server, request, response, token) =>
            {
                server.Window.LogInfo("BaseScanner ready for analysis");
                return Task.CompletedTask;
            });
    }

    private async Task InitializeWorkspaceAsync(string workspacePath)
    {
        try
        {
            // Find .csproj file
            string? projectPath = null;

            if (File.Exists(workspacePath) && workspacePath.EndsWith(".csproj"))
            {
                projectPath = workspacePath;
            }
            else if (Directory.Exists(workspacePath))
            {
                var csprojFiles = Directory.GetFiles(workspacePath, "*.csproj", SearchOption.TopDirectoryOnly);
                if (csprojFiles.Length == 1)
                {
                    projectPath = csprojFiles[0];
                }
            }

            if (projectPath != null)
            {
                AnalysisService.EnsureMSBuildRegistered();
                var workspace = MSBuildWorkspace.Create();
                _workspaceProject = await workspace.OpenProjectAsync(projectPath);
                await _diagnosticsProvider.InitializeAsync(_workspaceProject);

                _serverFacade?.Window.LogInfo($"Loaded project: {Path.GetFileName(projectPath)}");
            }
        }
        catch (Exception ex)
        {
            _serverFacade?.Window.LogWarning($"Failed to load workspace: {ex.Message}");
        }
    }

    private void OnDiagnosticsUpdated(string documentUri, List<LspDiagnostic> diagnostics)
    {
        if (_serverFacade == null) return;

        // Convert to OmniSharp diagnostics
        var omniDiagnostics = diagnostics.Select(d => new OmniDiagnostic
        {
            Range = new OmniSharp.Extensions.LanguageServer.Protocol.Models.Range
            {
                Start = new Position(d.Range.Start.Line, d.Range.Start.Character),
                End = new Position(d.Range.End.Line, d.Range.End.Character)
            },
            Severity = d.Severity switch
            {
                LspDiagnosticSeverity.Error => OmniDiagnosticSeverity.Error,
                LspDiagnosticSeverity.Warning => OmniDiagnosticSeverity.Warning,
                LspDiagnosticSeverity.Information => OmniDiagnosticSeverity.Information,
                LspDiagnosticSeverity.Hint => OmniDiagnosticSeverity.Hint,
                _ => OmniDiagnosticSeverity.Information
            },
            Code = d.Code,
            Source = d.Source,
            Message = d.Message
        }).ToList();

        _serverFacade.TextDocument.PublishDiagnostics(new PublishDiagnosticsParams
        {
            Uri = DocumentUri.Parse(documentUri),
            Diagnostics = new Container<OmniDiagnostic>(omniDiagnostics)
        });
    }

    internal void UpdateDocument(string uri, string content, int version)
    {
        _documentContents[uri] = content;
        _diagnosticsProvider.QueueAnalysis(uri, content, version);
    }

    internal string? GetDocumentContent(string uri)
    {
        return _documentContents.TryGetValue(uri, out var content) ? content : null;
    }

    internal void CloseDocument(string uri)
    {
        _documentContents.TryRemove(uri, out _);
        _diagnosticsProvider.ClearDiagnostics(uri);
    }
}

/// <summary>
/// Handles text document synchronization.
/// </summary>
internal class TextDocumentSyncHandler : TextDocumentSyncHandlerBase
{
    private readonly BaseScannerLanguageServer _server;
    private readonly DiagnosticsProvider _diagnosticsProvider;

    public TextDocumentSyncHandler(BaseScannerLanguageServer server, DiagnosticsProvider diagnosticsProvider)
    {
        _server = server;
        _diagnosticsProvider = diagnosticsProvider;
    }

    public override TextDocumentAttributes GetTextDocumentAttributes(DocumentUri uri)
    {
        return new TextDocumentAttributes(uri, "csharp");
    }

    protected override TextDocumentSyncRegistrationOptions CreateRegistrationOptions(
        TextSynchronizationCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new TextDocumentSyncRegistrationOptions
        {
            DocumentSelector = TextDocumentSelector.ForLanguage("csharp"),
            Change = TextDocumentSyncKind.Full,
            Save = new SaveOptions { IncludeText = true }
        };
    }

    public override Task<Unit> Handle(DidOpenTextDocumentParams request, CancellationToken cancellationToken)
    {
        var uri = request.TextDocument.Uri.ToString();
        _server.UpdateDocument(uri, request.TextDocument.Text, request.TextDocument.Version ?? 0);
        return Unit.Task;
    }

    public override Task<Unit> Handle(DidChangeTextDocumentParams request, CancellationToken cancellationToken)
    {
        var uri = request.TextDocument.Uri.ToString();
        var content = request.ContentChanges.LastOrDefault()?.Text ?? "";
        _server.UpdateDocument(uri, content, request.TextDocument.Version ?? 0);
        return Unit.Task;
    }

    public override Task<Unit> Handle(DidSaveTextDocumentParams request, CancellationToken cancellationToken)
    {
        if (request.Text != null)
        {
            var uri = request.TextDocument.Uri.ToString();
            _server.UpdateDocument(uri, request.Text, 0);
        }
        return Unit.Task;
    }

    public override Task<Unit> Handle(DidCloseTextDocumentParams request, CancellationToken cancellationToken)
    {
        var uri = request.TextDocument.Uri.ToString();
        _server.CloseDocument(uri);
        return Unit.Task;
    }
}

/// <summary>
/// Handles diagnostic requests.
/// </summary>
internal class DiagnosticHandler : IDocumentDiagnosticHandler
{
    private readonly DiagnosticsProvider _diagnosticsProvider;
    private readonly BaseScannerLanguageServer _server;

    public DiagnosticHandler(DiagnosticsProvider diagnosticsProvider, BaseScannerLanguageServer server)
    {
        _diagnosticsProvider = diagnosticsProvider;
        _server = server;
    }

    public DiagnosticsRegistrationOptions GetRegistrationOptions(
        DiagnosticClientCapabilities capability,
        ClientCapabilities clientCapabilities)
    {
        return new DiagnosticsRegistrationOptions
        {
            DocumentSelector = TextDocumentSelector.ForLanguage("csharp"),
            Identifier = "basescanner",
            InterFileDependencies = true,
            WorkspaceDiagnostics = true
        };
    }

    public async Task<RelatedDocumentDiagnosticReport> Handle(
        DocumentDiagnosticParams request,
        CancellationToken cancellationToken)
    {
        var uri = request.TextDocument.Uri.ToString();
        var content = _server.GetDocumentContent(uri);

        if (content == null)
            return new RelatedFullDocumentDiagnosticReport { Items = new Container<OmniDiagnostic>() };

        var diagnostics = await _diagnosticsProvider.AnalyzeDocumentAsync(uri, content, cancellationToken);

        var omniDiagnostics = diagnostics.Select(d => new OmniDiagnostic
        {
            Range = new OmniSharp.Extensions.LanguageServer.Protocol.Models.Range
            {
                Start = new Position(d.Range.Start.Line, d.Range.Start.Character),
                End = new Position(d.Range.End.Line, d.Range.End.Character)
            },
            Severity = MapSeverity(d.Severity),
            Code = d.Code,
            Source = d.Source,
            Message = d.Message
        }).ToList();

        return new RelatedFullDocumentDiagnosticReport
        {
            Items = new Container<OmniDiagnostic>(omniDiagnostics)
        };
    }

    public async Task<WorkspaceDiagnosticReport> Handle(
        WorkspaceDiagnosticParams request,
        CancellationToken cancellationToken)
    {
        var allDiagnostics = await _diagnosticsProvider.AnalyzeWorkspaceAsync(cancellationToken);
        var reports = new List<WorkspaceDocumentDiagnosticReport>();

        foreach (var kvp in allDiagnostics)
        {
            var omniDiagnostics = kvp.Value.Select(d => new OmniDiagnostic
            {
                Range = new OmniSharp.Extensions.LanguageServer.Protocol.Models.Range
                {
                    Start = new Position(d.Range.Start.Line, d.Range.Start.Character),
                    End = new Position(d.Range.End.Line, d.Range.End.Character)
                },
                Severity = MapSeverity(d.Severity),
                Code = d.Code,
                Source = d.Source,
                Message = d.Message
            }).ToList();

            reports.Add(new WorkspaceFullDocumentDiagnosticReport
            {
                Uri = DocumentUri.Parse(kvp.Key),
                Items = new Container<OmniDiagnostic>(omniDiagnostics)
            });
        }

        // Create WorkspaceDiagnosticReport using default + with expression
        var container = new Container<WorkspaceDocumentDiagnosticReport>(reports);
        return default(WorkspaceDiagnosticReport) with { Items = container };
    }

    private static OmniDiagnosticSeverity MapSeverity(LspDiagnosticSeverity severity) => severity switch
    {
        LspDiagnosticSeverity.Error => OmniDiagnosticSeverity.Error,
        LspDiagnosticSeverity.Warning => OmniDiagnosticSeverity.Warning,
        LspDiagnosticSeverity.Information => OmniDiagnosticSeverity.Information,
        LspDiagnosticSeverity.Hint => OmniDiagnosticSeverity.Hint,
        _ => OmniDiagnosticSeverity.Information
    };
}

/// <summary>
/// Handles code action requests.
/// </summary>
internal class CodeActionHandler : ICodeActionHandler
{
    private readonly CodeActionProvider _codeActionProvider;
    private readonly BaseScannerLanguageServer _server;

    public CodeActionHandler(CodeActionProvider codeActionProvider, BaseScannerLanguageServer server)
    {
        _codeActionProvider = codeActionProvider;
        _server = server;
    }

    public CodeActionRegistrationOptions GetRegistrationOptions(
        CodeActionCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new CodeActionRegistrationOptions
        {
            DocumentSelector = TextDocumentSelector.ForLanguage("csharp"),
            CodeActionKinds = new Container<CodeActionKind>(
                CodeActionKind.QuickFix,
                CodeActionKind.Refactor,
                CodeActionKind.RefactorExtract,
                CodeActionKind.RefactorInline,
                CodeActionKind.RefactorRewrite)
        };
    }

    public async Task<CommandOrCodeActionContainer> Handle(
        CodeActionParams request,
        CancellationToken cancellationToken)
    {
        var uri = request.TextDocument.Uri.ToString();
        var content = _server.GetDocumentContent(uri);

        if (content == null)
            return new CommandOrCodeActionContainer();

        var range = new LspRange
        {
            Start = new LspPosition { Line = request.Range.Start.Line, Character = request.Range.Start.Character },
            End = new LspPosition { Line = request.Range.End.Line, Character = request.Range.End.Character }
        };

        var actions = await _codeActionProvider.GetCodeActionsAsync(uri, range, content, cancellationToken);

        var omniActions = actions.Select(a =>
        {
            WorkspaceEdit? workspaceEdit = null;
            if (a.Edit != null)
            {
                var changes = new Dictionary<DocumentUri, IEnumerable<TextEdit>>();

                if (a.Edit.Changes != null)
                {
                    foreach (var kvp in a.Edit.Changes)
                    {
                        changes[DocumentUri.Parse(kvp.Key)] = kvp.Value.Select(e => new TextEdit
                        {
                            Range = new OmniSharp.Extensions.LanguageServer.Protocol.Models.Range
                            {
                                Start = new Position(e.Range.Start.Line, e.Range.Start.Character),
                                End = new Position(e.Range.End.Line, e.Range.End.Character)
                            },
                            NewText = e.NewText
                        });
                    }
                }

                workspaceEdit = new WorkspaceEdit { Changes = changes };
            }

            Command? command = null;
            if (a.Command != null)
            {
                var args = a.Command.Arguments != null
                    ? new JArray(a.Command.Arguments.Select(arg => JToken.FromObject(arg)))
                    : null;

                command = new Command
                {
                    Title = a.Command.Title,
                    Name = a.Command.CommandId,
                    Arguments = args
                };
            }

            var codeAction = new CodeAction
            {
                Title = a.Title,
                Kind = a.Kind switch
                {
                    LspCodeActionKind.QuickFix => CodeActionKind.QuickFix,
                    LspCodeActionKind.Refactor => CodeActionKind.Refactor,
                    LspCodeActionKind.RefactorExtract => CodeActionKind.RefactorExtract,
                    LspCodeActionKind.RefactorInline => CodeActionKind.RefactorInline,
                    LspCodeActionKind.RefactorRewrite => CodeActionKind.RefactorRewrite,
                    _ => CodeActionKind.QuickFix
                },
                IsPreferred = a.IsPreferred ?? false,
                Edit = workspaceEdit,
                Command = command
            };

            return new CommandOrCodeAction(codeAction);
        }).ToList();

        return new CommandOrCodeActionContainer(omniActions);
    }
}

/// <summary>
/// Handles code lens requests.
/// </summary>
internal class CodeLensHandler : ICodeLensHandler, ICodeLensResolveHandler
{
    private readonly CodeLensProvider _codeLensProvider;
    private readonly BaseScannerLanguageServer _server;
    private CodeLensCapability? _capability;

    public Guid Id { get; } = Guid.NewGuid();

    public CodeLensHandler(CodeLensProvider codeLensProvider, BaseScannerLanguageServer server)
    {
        _codeLensProvider = codeLensProvider;
        _server = server;
    }

    public void SetCapability(CodeLensCapability capability, ClientCapabilities clientCapabilities)
    {
        _capability = capability;
    }

    public CodeLensRegistrationOptions GetRegistrationOptions(
        CodeLensCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new CodeLensRegistrationOptions
        {
            DocumentSelector = TextDocumentSelector.ForLanguage("csharp"),
            ResolveProvider = true
        };
    }

    public async Task<CodeLensContainer> Handle(
        CodeLensParams request,
        CancellationToken cancellationToken)
    {
        var uri = request.TextDocument.Uri.ToString();
        var content = _server.GetDocumentContent(uri);

        if (content == null)
            return new CodeLensContainer();

        var lenses = await _codeLensProvider.GetCodeLensesAsync(uri, content, cancellationToken);

        var omniLenses = lenses.Select(l => new CodeLens
        {
            Range = new OmniSharp.Extensions.LanguageServer.Protocol.Models.Range
            {
                Start = new Position(l.Range.Start.Line, l.Range.Start.Character),
                End = new Position(l.Range.End.Line, l.Range.End.Character)
            },
            Command = l.Command != null ? new Command
            {
                Title = l.Command.Title,
                Name = l.Command.CommandId,
                Arguments = l.Command.Arguments != null
                    ? new JArray(l.Command.Arguments.Select(arg => JToken.FromObject(arg)))
                    : null
            } : null,
            Data = l.Data != null ? JToken.FromObject(l.Data) : null
        }).ToList();

        return new CodeLensContainer(omniLenses);
    }

    public Task<CodeLens> Handle(CodeLens request, CancellationToken cancellationToken)
    {
        // Resolve code lens - the command is already set, so just return
        return Task.FromResult(request);
    }
}

/// <summary>
/// Handles hover requests.
/// </summary>
internal class HoverHandler : IHoverHandler
{
    private readonly HoverProvider _hoverProvider;
    private readonly BaseScannerLanguageServer _server;

    public HoverHandler(HoverProvider hoverProvider, BaseScannerLanguageServer server)
    {
        _hoverProvider = hoverProvider;
        _server = server;
    }

    public HoverRegistrationOptions GetRegistrationOptions(
        HoverCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new HoverRegistrationOptions
        {
            DocumentSelector = TextDocumentSelector.ForLanguage("csharp")
        };
    }

    public async Task<Hover?> Handle(HoverParams request, CancellationToken cancellationToken)
    {
        var uri = request.TextDocument.Uri.ToString();
        var content = _server.GetDocumentContent(uri);

        if (content == null)
            return null;

        var position = new LspPosition
        {
            Line = request.Position.Line,
            Character = request.Position.Character
        };

        var hover = await _hoverProvider.GetHoverAsync(uri, position, content, cancellationToken);

        if (hover == null)
            return null;

        return new Hover
        {
            Contents = new MarkedStringsOrMarkupContent(new MarkupContent
            {
                Kind = hover.Contents.Kind == LspMarkupKind.Markdown
                    ? MarkupKind.Markdown
                    : MarkupKind.PlainText,
                Value = hover.Contents.Value
            }),
            Range = hover.Range != null ? new OmniSharp.Extensions.LanguageServer.Protocol.Models.Range
            {
                Start = new Position(hover.Range.Start.Line, hover.Range.Start.Character),
                End = new Position(hover.Range.End.Line, hover.Range.End.Character)
            } : null
        };
    }
}
