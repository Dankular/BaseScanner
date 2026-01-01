using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FlowAnalysis;

namespace BaseScanner.Analysis;

/// <summary>
/// Provides data flow analysis capabilities for tracking variable assignments and values.
/// </summary>
public class DataFlowEngine
{
    /// <summary>
    /// Analyze data flow within a method.
    /// </summary>
    public async Task<DataFlowResult> AnalyzeMethodAsync(
        MethodDeclarationSyntax method,
        SemanticModel semanticModel)
    {
        var result = new DataFlowResult
        {
            MethodName = method.Identifier.Text
        };

        if (method.Body == null && method.ExpressionBody == null)
            return result;

        try
        {
            // Use Roslyn's built-in data flow analysis
            var dataFlowAnalysis = method.Body != null
                ? semanticModel.AnalyzeDataFlow(method.Body)
                : semanticModel.AnalyzeDataFlow(method.ExpressionBody!.Expression);

            if (dataFlowAnalysis == null || !dataFlowAnalysis.Succeeded)
            {
                result.Success = false;
                return result;
            }

            result.Success = true;

            // Variables that are definitely assigned
            result.DefinitelyAssigned = dataFlowAnalysis.AlwaysAssigned
                .Select(s => s.Name)
                .ToList();

            // Variables read before being written
            result.ReadBeforeWritten = dataFlowAnalysis.DataFlowsIn
                .Select(s => s.Name)
                .ToList();

            // Variables written and then read outside
            result.WrittenAndReadOutside = dataFlowAnalysis.DataFlowsOut
                .Select(s => s.Name)
                .ToList();

            // Variables that are read
            result.ReadVariables = dataFlowAnalysis.ReadInside
                .Select(s => s.Name)
                .ToList();

            // Variables that are written
            result.WrittenVariables = dataFlowAnalysis.WrittenInside
                .Select(s => s.Name)
                .ToList();

            // Captured variables (closures)
            result.CapturedVariables = dataFlowAnalysis.Captured
                .Select(s => s.Name)
                .ToList();

            // Analyze reaching definitions
            result.ReachingDefinitions = AnalyzeReachingDefinitions(method, semanticModel);

            // Analyze constant propagation
            result.ConstantValues = AnalyzeConstantPropagation(method, semanticModel);
        }
        catch
        {
            result.Success = false;
        }

        return result;
    }

    /// <summary>
    /// Track what definitions reach each use of a variable.
    /// </summary>
    public Dictionary<string, List<ReachingDefinition>> AnalyzeReachingDefinitions(
        MethodDeclarationSyntax method,
        SemanticModel semanticModel)
    {
        var definitions = new Dictionary<string, List<ReachingDefinition>>();

        // Find all assignments
        var assignments = method.DescendantNodes()
            .OfType<AssignmentExpressionSyntax>()
            .ToList();

        var declarations = method.DescendantNodes()
            .OfType<VariableDeclaratorSyntax>()
            .Where(v => v.Initializer != null)
            .ToList();

        // Track each variable's definitions
        foreach (var assignment in assignments)
        {
            if (assignment.Left is IdentifierNameSyntax identifier)
            {
                var varName = identifier.Identifier.Text;
                var lineSpan = assignment.GetLocation().GetLineSpan();

                if (!definitions.ContainsKey(varName))
                    definitions[varName] = new List<ReachingDefinition>();

                definitions[varName].Add(new ReachingDefinition
                {
                    VariableName = varName,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Expression = assignment.Right.ToFullString().Trim(),
                    DefinitionType = "Assignment"
                });
            }
        }

        foreach (var decl in declarations)
        {
            var varName = decl.Identifier.Text;
            var lineSpan = decl.GetLocation().GetLineSpan();

            if (!definitions.ContainsKey(varName))
                definitions[varName] = new List<ReachingDefinition>();

            definitions[varName].Add(new ReachingDefinition
            {
                VariableName = varName,
                Line = lineSpan.StartLinePosition.Line + 1,
                Expression = decl.Initializer?.Value.ToFullString().Trim() ?? "",
                DefinitionType = "Declaration"
            });
        }

        return definitions;
    }

    /// <summary>
    /// Identify compile-time constant values.
    /// </summary>
    public Dictionary<string, object?> AnalyzeConstantPropagation(
        MethodDeclarationSyntax method,
        SemanticModel semanticModel)
    {
        var constants = new Dictionary<string, object?>();

        // Find local declarations with literal values
        foreach (var decl in method.DescendantNodes().OfType<LocalDeclarationStatementSyntax>())
        {
            if (decl.Modifiers.Any(SyntaxKind.ConstKeyword))
            {
                foreach (var variable in decl.Declaration.Variables)
                {
                    if (variable.Initializer?.Value is LiteralExpressionSyntax literal)
                    {
                        constants[variable.Identifier.Text] = literal.Token.Value;
                    }
                }
            }
        }

        // Find variables assigned only once with constant values
        var assignments = method.DescendantNodes()
            .OfType<AssignmentExpressionSyntax>()
            .Where(a => a.Left is IdentifierNameSyntax)
            .GroupBy(a => ((IdentifierNameSyntax)a.Left).Identifier.Text)
            .Where(g => g.Count() == 1)
            .ToList();

        foreach (var group in assignments)
        {
            var assignment = group.First();
            if (assignment.Right is LiteralExpressionSyntax literal)
            {
                var varName = ((IdentifierNameSyntax)assignment.Left).Identifier.Text;
                if (!constants.ContainsKey(varName))
                {
                    constants[varName] = literal.Token.Value;
                }
            }
        }

        return constants;
    }

    /// <summary>
    /// Check if a variable may have multiple values at a given point.
    /// </summary>
    public bool HasMultipleReachingDefinitions(
        string variableName,
        int atLine,
        Dictionary<string, List<ReachingDefinition>> reachingDefs)
    {
        if (!reachingDefs.TryGetValue(variableName, out var definitions))
            return false;

        var reachingAtLine = definitions.Where(d => d.Line < atLine).ToList();
        return reachingAtLine.Count > 1;
    }

    /// <summary>
    /// Get possible values for a variable at a given point.
    /// </summary>
    public List<string> GetPossibleValues(
        string variableName,
        int atLine,
        Dictionary<string, List<ReachingDefinition>> reachingDefs)
    {
        if (!reachingDefs.TryGetValue(variableName, out var definitions))
            return new List<string>();

        return definitions
            .Where(d => d.Line < atLine)
            .Select(d => d.Expression)
            .Distinct()
            .ToList();
    }

    /// <summary>
    /// Analyze live variables at each point in a method.
    /// </summary>
    public async Task<LiveVariableAnalysis> AnalyzeLiveVariablesAsync(
        MethodDeclarationSyntax method,
        SemanticModel semanticModel)
    {
        var result = new LiveVariableAnalysis();

        // For each statement, determine which variables are live (will be read later)
        var statements = method.Body?.Statements.ToList() ?? new List<StatementSyntax>();

        for (int i = statements.Count - 1; i >= 0; i--)
        {
            var stmt = statements[i];
            var lineSpan = stmt.GetLocation().GetLineSpan();
            var line = lineSpan.StartLinePosition.Line + 1;

            var liveVars = new HashSet<string>();

            // Variables used in this statement and later
            foreach (var laterStmt in statements.Skip(i))
            {
                var usedVars = laterStmt.DescendantNodes()
                    .OfType<IdentifierNameSyntax>()
                    .Select(id => id.Identifier.Text)
                    .Distinct();

                foreach (var v in usedVars)
                {
                    liveVars.Add(v);
                }
            }

            // Remove variables that are killed (written) in this statement
            var killedVars = GetKilledVariables(stmt);
            foreach (var v in killedVars)
            {
                liveVars.Remove(v);
            }

            result.LiveVariablesAtLine[line] = liveVars.ToList();
        }

        return result;
    }

    private HashSet<string> GetKilledVariables(StatementSyntax stmt)
    {
        var killed = new HashSet<string>();

        // Variable declarations
        if (stmt is LocalDeclarationStatementSyntax localDecl)
        {
            foreach (var v in localDecl.Declaration.Variables)
            {
                killed.Add(v.Identifier.Text);
            }
        }

        // Assignments
        foreach (var assignment in stmt.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is IdentifierNameSyntax id)
            {
                killed.Add(id.Identifier.Text);
            }
        }

        return killed;
    }
}

/// <summary>
/// Result of data flow analysis.
/// </summary>
public record DataFlowResult
{
    public required string MethodName { get; init; }
    public bool Success { get; set; }
    public List<string> DefinitelyAssigned { get; set; } = [];
    public List<string> ReadBeforeWritten { get; set; } = [];
    public List<string> WrittenAndReadOutside { get; set; } = [];
    public List<string> ReadVariables { get; set; } = [];
    public List<string> WrittenVariables { get; set; } = [];
    public List<string> CapturedVariables { get; set; } = [];
    public Dictionary<string, List<ReachingDefinition>> ReachingDefinitions { get; set; } = [];
    public Dictionary<string, object?> ConstantValues { get; set; } = [];
}

/// <summary>
/// A definition that reaches a certain point.
/// </summary>
public record ReachingDefinition
{
    public required string VariableName { get; init; }
    public required int Line { get; init; }
    public required string Expression { get; init; }
    public required string DefinitionType { get; init; }
}

/// <summary>
/// Result of live variable analysis.
/// </summary>
public record LiveVariableAnalysis
{
    public Dictionary<int, List<string>> LiveVariablesAtLine { get; init; } = [];
}
