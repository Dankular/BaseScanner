using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analysis;

/// <summary>
/// Tracks tainted data from sources to sinks for security analysis.
/// </summary>
public class TaintTracker
{
    private static readonly HashSet<string> DefaultSources = new()
    {
        // HTTP/Web
        "Request.QueryString", "Request.Form", "Request.Params", "Request.Cookies",
        "HttpContext.Request", "Request.Body", "Request.Headers",
        // ASP.NET Core
        "FromBody", "FromQuery", "FromRoute", "FromForm", "FromHeader",
        // Console/File
        "Console.ReadLine", "File.ReadAllText", "File.ReadAllLines", "StreamReader.ReadLine",
        // Environment
        "Environment.GetEnvironmentVariable",
        // Database
        "SqlDataReader", "DbDataReader", "IDataReader"
    };

    private static readonly HashSet<string> DefaultSinks = new()
    {
        // SQL
        "SqlCommand", "CommandText", "ExecuteSql", "FromSqlRaw", "ExecuteSqlRaw",
        // Command Execution
        "Process.Start", "ProcessStartInfo.FileName", "ProcessStartInfo.Arguments",
        // File Operations
        "File.ReadAllText", "File.WriteAllText", "File.Delete", "FileStream",
        "StreamReader", "StreamWriter", "Directory.Delete",
        // Web Output
        "Response.Write", "HtmlEncoder", "JavaScriptEncoder",
        // LDAP
        "DirectorySearcher.Filter", "DirectoryEntry.Path",
        // XPath
        "SelectNodes", "SelectSingleNode", "XPathNavigator.Select"
    };

    private static readonly HashSet<string> Sanitizers = new()
    {
        // HTML Encoding
        "HtmlEncode", "HtmlDecode", "JavaScriptStringEncode", "UrlEncode",
        // Validation
        "Regex.IsMatch", "Regex.Match", "TryParse", "Parse",
        // Path
        "Path.GetFileName", "Path.GetFullPath", "Path.Combine",
        // SQL
        "Parameters.Add", "AddWithValue", "SqlParameter",
        // Generic
        "Sanitize", "Escape", "Encode", "Validate"
    };

    /// <summary>
    /// Track taint flow through a project.
    /// </summary>
    public async Task<List<TaintFlow>> TrackAsync(
        Project project,
        TaintConfiguration? config = null)
    {
        config ??= TaintConfiguration.Default;
        var flows = new List<TaintFlow>();

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null)
                continue;

            var semanticModel = await document.GetSemanticModelAsync();
            var syntaxRoot = await document.GetSyntaxRootAsync();

            if (semanticModel == null || syntaxRoot == null)
                continue;

            // Find all methods
            foreach (var method in syntaxRoot.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                var methodFlows = AnalyzeMethod(method, semanticModel, document.FilePath, config);
                flows.AddRange(methodFlows);
            }
        }

        return flows;
    }

    /// <summary>
    /// Analyze a single method for taint flows.
    /// </summary>
    public List<TaintFlow> AnalyzeMethod(
        MethodDeclarationSyntax method,
        SemanticModel semanticModel,
        string filePath,
        TaintConfiguration config)
    {
        var flows = new List<TaintFlow>();
        var taintedVariables = new Dictionary<string, TaintSource>();

        // Mark parameters as tainted sources
        foreach (var param in method.ParameterList.Parameters)
        {
            var paramName = param.Identifier.Text;

            // Check if parameter has source attributes
            var hasSourceAttribute = param.AttributeLists
                .SelectMany(al => al.Attributes)
                .Any(a => IsSourceAttribute(a.Name.ToString()));

            if (hasSourceAttribute || config.TreatParametersAsTainted)
            {
                taintedVariables[paramName] = new TaintSource
                {
                    SourceType = "Parameter",
                    SourceName = paramName,
                    Line = param.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                    FilePath = filePath
                };
            }
        }

        // Find explicit sources in method body
        FindTaintSources(method, semanticModel, taintedVariables, filePath, config);

        // Propagate taint through the method
        PropagateTaint(method, semanticModel, taintedVariables, config);

        // Find sinks and check if tainted data reaches them
        var sinks = FindTaintSinks(method, semanticModel, filePath, config);

        foreach (var sink in sinks)
        {
            // Check if any tainted variable reaches this sink
            var taintedAtSink = GetTaintedVariablesAtSink(sink, taintedVariables, semanticModel);

            foreach (var (varName, source) in taintedAtSink)
            {
                // Check if there's a sanitizer between source and sink
                var isSanitized = CheckForSanitizer(source.Line, sink.Line, varName, method, config);

                flows.Add(new TaintFlow
                {
                    Source = source,
                    Sink = sink,
                    TaintedVariable = varName,
                    Path = BuildFlowPath(source, sink, varName, method),
                    IsSanitized = isSanitized,
                    SanitizerLocation = isSanitized ? FindSanitizerLocation(source.Line, sink.Line, varName, method) : null
                });
            }
        }

        return flows;
    }

    private void FindTaintSources(
        MethodDeclarationSyntax method,
        SemanticModel semanticModel,
        Dictionary<string, TaintSource> taintedVariables,
        string filePath,
        TaintConfiguration config)
    {
        var sources = config.CustomSources.Count > 0 ? config.CustomSources : DefaultSources;

        // Check invocations for source methods
        foreach (var invocation in method.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var invocationText = invocation.Expression.ToString();

            if (sources.Any(s => invocationText.Contains(s)))
            {
                // Find the variable this is assigned to
                var assignedVar = GetAssignedVariable(invocation);
                if (assignedVar != null)
                {
                    taintedVariables[assignedVar] = new TaintSource
                    {
                        SourceType = "MethodCall",
                        SourceName = invocationText,
                        Line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        FilePath = filePath
                    };
                }
            }
        }

        // Check member access for source properties
        foreach (var memberAccess in method.DescendantNodes().OfType<MemberAccessExpressionSyntax>())
        {
            var accessText = memberAccess.ToString();

            if (sources.Any(s => accessText.Contains(s)))
            {
                var assignedVar = GetAssignedVariable(memberAccess);
                if (assignedVar != null)
                {
                    taintedVariables[assignedVar] = new TaintSource
                    {
                        SourceType = "PropertyAccess",
                        SourceName = accessText,
                        Line = memberAccess.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        FilePath = filePath
                    };
                }
            }
        }
    }

    private void PropagateTaint(
        MethodDeclarationSyntax method,
        SemanticModel semanticModel,
        Dictionary<string, TaintSource> taintedVariables,
        TaintConfiguration config)
    {
        // Iterate until no more propagation occurs
        bool changed;
        do
        {
            changed = false;

            // Check assignments
            foreach (var assignment in method.DescendantNodes().OfType<AssignmentExpressionSyntax>())
            {
                if (assignment.Left is not IdentifierNameSyntax leftId)
                    continue;

                var targetVar = leftId.Identifier.Text;
                if (taintedVariables.ContainsKey(targetVar))
                    continue;

                // Check if right side uses any tainted variable
                var usedVars = assignment.Right.DescendantNodes()
                    .OfType<IdentifierNameSyntax>()
                    .Select(id => id.Identifier.Text);

                foreach (var usedVar in usedVars)
                {
                    if (taintedVariables.TryGetValue(usedVar, out var source))
                    {
                        taintedVariables[targetVar] = source;
                        changed = true;
                        break;
                    }
                }
            }

            // Check variable declarations
            foreach (var varDecl in method.DescendantNodes().OfType<VariableDeclaratorSyntax>())
            {
                if (varDecl.Initializer == null)
                    continue;

                var targetVar = varDecl.Identifier.Text;
                if (taintedVariables.ContainsKey(targetVar))
                    continue;

                var usedVars = varDecl.Initializer.Value.DescendantNodes()
                    .OfType<IdentifierNameSyntax>()
                    .Select(id => id.Identifier.Text);

                foreach (var usedVar in usedVars)
                {
                    if (taintedVariables.TryGetValue(usedVar, out var source))
                    {
                        taintedVariables[targetVar] = source;
                        changed = true;
                        break;
                    }
                }
            }

        } while (changed);
    }

    private List<TaintSink> FindTaintSinks(
        MethodDeclarationSyntax method,
        SemanticModel semanticModel,
        string filePath,
        TaintConfiguration config)
    {
        var sinks = new List<TaintSink>();
        var sinkPatterns = config.CustomSinks.Count > 0 ? config.CustomSinks : DefaultSinks;

        // Check invocations
        foreach (var invocation in method.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var invocationText = invocation.Expression.ToString();

            if (sinkPatterns.Any(s => invocationText.Contains(s)))
            {
                sinks.Add(new TaintSink
                {
                    SinkType = "MethodCall",
                    SinkName = invocationText,
                    Line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                    FilePath = filePath,
                    Arguments = invocation.ArgumentList.Arguments
                        .Select(a => a.Expression.ToString())
                        .ToList()
                });
            }
        }

        // Check object creations
        foreach (var creation in method.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            var typeInfo = semanticModel.GetTypeInfo(creation);
            var typeName = typeInfo.Type?.Name ?? "";

            if (sinkPatterns.Any(s => typeName.Contains(s) || creation.Type.ToString().Contains(s)))
            {
                sinks.Add(new TaintSink
                {
                    SinkType = "ObjectCreation",
                    SinkName = creation.Type.ToString(),
                    Line = creation.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                    FilePath = filePath,
                    Arguments = creation.ArgumentList?.Arguments
                        .Select(a => a.Expression.ToString())
                        .ToList() ?? new List<string>()
                });
            }
        }

        // Check property assignments
        foreach (var assignment in method.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is MemberAccessExpressionSyntax memberAccess)
            {
                var propName = memberAccess.Name.Identifier.Text;
                if (sinkPatterns.Any(s => propName.Contains(s)))
                {
                    sinks.Add(new TaintSink
                    {
                        SinkType = "PropertyAssignment",
                        SinkName = memberAccess.ToString(),
                        Line = assignment.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        FilePath = filePath,
                        Arguments = new List<string> { assignment.Right.ToString() }
                    });
                }
            }
        }

        return sinks;
    }

    private Dictionary<string, TaintSource> GetTaintedVariablesAtSink(
        TaintSink sink,
        Dictionary<string, TaintSource> taintedVariables,
        SemanticModel semanticModel)
    {
        var result = new Dictionary<string, TaintSource>();

        foreach (var arg in sink.Arguments)
        {
            // Parse the argument to find variable references
            foreach (var (varName, source) in taintedVariables)
            {
                if (arg.Contains(varName))
                {
                    result[varName] = source;
                }
            }
        }

        return result;
    }

    private bool CheckForSanitizer(
        int sourceLine,
        int sinkLine,
        string variable,
        MethodDeclarationSyntax method,
        TaintConfiguration config)
    {
        var sanitizers = config.CustomSanitizers.Count > 0 ? config.CustomSanitizers : Sanitizers;

        // Look for sanitizer calls between source and sink
        foreach (var invocation in method.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
            if (line <= sourceLine || line >= sinkLine)
                continue;

            var invocationText = invocation.ToString();
            if (sanitizers.Any(s => invocationText.Contains(s)))
            {
                // Check if this sanitizer operates on our variable
                if (invocationText.Contains(variable))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private string? FindSanitizerLocation(
        int sourceLine,
        int sinkLine,
        string variable,
        MethodDeclarationSyntax method)
    {
        foreach (var invocation in method.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
            if (line <= sourceLine || line >= sinkLine)
                continue;

            var invocationText = invocation.ToString();
            if (Sanitizers.Any(s => invocationText.Contains(s)) && invocationText.Contains(variable))
            {
                return $"Line {line}: {invocationText}";
            }
        }

        return null;
    }

    private List<string> BuildFlowPath(
        TaintSource source,
        TaintSink sink,
        string variable,
        MethodDeclarationSyntax method)
    {
        var path = new List<string>
        {
            $"[Source] Line {source.Line}: {source.SourceName}",
            $"[Variable] {variable}"
        };

        // Find intermediate assignments
        foreach (var assignment in method.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            var line = assignment.GetLocation().GetLineSpan().StartLinePosition.Line + 1;
            if (line > source.Line && line < sink.Line)
            {
                if (assignment.ToString().Contains(variable))
                {
                    path.Add($"[Flow] Line {line}: {assignment.Left} = ...");
                }
            }
        }

        path.Add($"[Sink] Line {sink.Line}: {sink.SinkName}");
        return path;
    }

    private string? GetAssignedVariable(SyntaxNode node)
    {
        var parent = node.Parent;

        // Check for direct assignment
        if (parent is AssignmentExpressionSyntax assignment &&
            assignment.Left is IdentifierNameSyntax id)
        {
            return id.Identifier.Text;
        }

        // Check for variable declaration
        if (parent is EqualsValueClauseSyntax equals &&
            equals.Parent is VariableDeclaratorSyntax varDecl)
        {
            return varDecl.Identifier.Text;
        }

        return null;
    }

    private bool IsSourceAttribute(string attributeName)
    {
        return attributeName is "FromBody" or "FromQuery" or "FromRoute" or "FromForm" or "FromHeader";
    }
}

/// <summary>
/// Configuration for taint tracking.
/// </summary>
public record TaintConfiguration
{
    public bool TreatParametersAsTainted { get; init; } = true;
    public HashSet<string> CustomSources { get; init; } = new();
    public HashSet<string> CustomSinks { get; init; } = new();
    public HashSet<string> CustomSanitizers { get; init; } = new();

    public static TaintConfiguration Default => new();
}

/// <summary>
/// A source of tainted data.
/// </summary>
public record TaintSource
{
    public required string SourceType { get; init; }
    public required string SourceName { get; init; }
    public required int Line { get; init; }
    public required string FilePath { get; init; }
}

/// <summary>
/// A sink where tainted data may cause harm.
/// </summary>
public record TaintSink
{
    public required string SinkType { get; init; }
    public required string SinkName { get; init; }
    public required int Line { get; init; }
    public required string FilePath { get; init; }
    public List<string> Arguments { get; init; } = [];
}

/// <summary>
/// A flow of tainted data from source to sink.
/// </summary>
public record TaintFlow
{
    public required TaintSource Source { get; init; }
    public required TaintSink Sink { get; init; }
    public required string TaintedVariable { get; init; }
    public required List<string> Path { get; init; }
    public required bool IsSanitized { get; init; }
    public string? SanitizerLocation { get; init; }
}
