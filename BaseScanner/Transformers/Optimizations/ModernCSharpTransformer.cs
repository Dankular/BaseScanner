using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Transformers.Core;

namespace BaseScanner.Transformers.Optimizations;

/// <summary>
/// Transforms code to use modern C# features for improved readability.
/// </summary>
public class ModernCSharpTransformer : ICodeTransformer
{
    public string TransformationType => "ModernCSharp";

    public bool CanTransform(SyntaxNode node, SemanticModel semanticModel)
    {
        return IsNullCheckWithAssignment(node, semanticModel) ||
               IsTypeCheckWithCast(node, semanticModel) ||
               IsVerboseNullCheck(node, semanticModel) ||
               IsExplicitTypeThatCanBeVar(node, semanticModel) ||
               IsOldStyleSwitch(node, semanticModel) ||
               IsUsingWithoutBraces(node, semanticModel);
    }

    public async Task<TransformationResult> TransformAsync(TransformationContext context, SyntaxNode targetNode)
    {
        string? transformedCode = null;
        string? description = null;

        if (IsNullCheckWithAssignment(targetNode, context.SemanticModel))
        {
            transformedCode = TransformNullCheckAssignment(targetNode as IfStatementSyntax);
            description = "if null check to ??=";
        }
        else if (IsTypeCheckWithCast(targetNode, context.SemanticModel))
        {
            transformedCode = TransformTypeCheckCast(targetNode as IfStatementSyntax);
            description = "is/as check to pattern matching";
        }
        else if (IsVerboseNullCheck(targetNode, context.SemanticModel))
        {
            transformedCode = TransformVerboseNullCheck(targetNode as ConditionalExpressionSyntax);
            description = "Conditional null check to ??";
        }
        else if (IsExplicitTypeThatCanBeVar(targetNode, context.SemanticModel))
        {
            transformedCode = TransformToVar(targetNode as LocalDeclarationStatementSyntax);
            description = "Explicit type to var";
        }
        else if (IsOldStyleSwitch(targetNode, context.SemanticModel))
        {
            transformedCode = TransformToSwitchExpression(targetNode as SwitchStatementSyntax);
            description = "Switch statement to switch expression";
        }
        else if (IsUsingWithoutBraces(targetNode, context.SemanticModel))
        {
            transformedCode = TransformToUsingDeclaration(targetNode as UsingStatementSyntax);
            description = "Using statement to using declaration";
        }

        if (transformedCode == null)
            return TransformationResult.Failed(TransformationType, "Could not determine transformation");

        var originalCode = targetNode.ToFullString().Trim();
        var diff = DiffGenerator.GenerateUnifiedDiff(originalCode, transformedCode, context.Document.FilePath ?? "");

        return TransformationResult.Succeeded(TransformationType, new List<FileChange>
        {
            new FileChange
            {
                FilePath = context.Document.FilePath ?? "",
                OriginalCode = originalCode,
                TransformedCode = transformedCode,
                UnifiedDiff = diff,
                StartLine = targetNode.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                EndLine = targetNode.GetLocation().GetLineSpan().EndLinePosition.Line + 1
            }
        });
    }

    private bool IsNullCheckWithAssignment(SyntaxNode node, SemanticModel semanticModel)
    {
        // Pattern: if (x == null) x = value;
        if (node is not IfStatementSyntax ifStatement)
            return false;

        if (ifStatement.Else != null)
            return false;

        // Check condition is == null
        if (ifStatement.Condition is not BinaryExpressionSyntax binary)
            return false;

        if (binary.Kind() != SyntaxKind.EqualsExpression)
            return false;

        var isNullCheck = IsNullLiteral(binary.Left) || IsNullLiteral(binary.Right);
        if (!isNullCheck)
            return false;

        // Check body is single assignment
        var body = GetSingleStatement(ifStatement.Statement);
        if (body is not ExpressionStatementSyntax exprStmt)
            return false;

        if (exprStmt.Expression is not AssignmentExpressionSyntax)
            return false;

        return true;
    }

    private bool IsTypeCheckWithCast(SyntaxNode node, SemanticModel semanticModel)
    {
        // Pattern: if (x is Type) { var y = (Type)x; ... }
        if (node is not IfStatementSyntax ifStatement)
            return false;

        // Check condition is 'is Type'
        if (ifStatement.Condition is not BinaryExpressionSyntax binary)
            return false;

        if (binary.Kind() != SyntaxKind.IsExpression)
            return false;

        // Check if body contains a cast to the same type
        if (ifStatement.Statement is BlockSyntax block && block.Statements.Count > 0)
        {
            var firstStmt = block.Statements[0];
            if (firstStmt is LocalDeclarationStatementSyntax localDecl)
            {
                var variable = localDecl.Declaration.Variables.FirstOrDefault();
                if (variable?.Initializer?.Value is CastExpressionSyntax cast)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private bool IsVerboseNullCheck(SyntaxNode node, SemanticModel semanticModel)
    {
        // Pattern: x != null ? x : defaultValue  or  x == null ? defaultValue : x
        if (node is not ConditionalExpressionSyntax conditional)
            return false;

        if (conditional.Condition is not BinaryExpressionSyntax binary)
            return false;

        if (binary.Kind() is not (SyntaxKind.EqualsExpression or SyntaxKind.NotEqualsExpression))
            return false;

        // Check if comparing to null
        if (!IsNullLiteral(binary.Left) && !IsNullLiteral(binary.Right))
            return false;

        var variable = IsNullLiteral(binary.Left) ? binary.Right : binary.Left;

        // Check if one branch is the variable
        var trueExpr = conditional.WhenTrue.ToString().Trim();
        var falseExpr = conditional.WhenFalse.ToString().Trim();
        var varExpr = variable.ToString().Trim();

        return trueExpr == varExpr || falseExpr == varExpr;
    }

    private bool IsExplicitTypeThatCanBeVar(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not LocalDeclarationStatementSyntax localDecl)
            return false;

        // Skip if already var
        if (localDecl.Declaration.Type.IsVar)
            return false;

        // Must have initializer
        var variable = localDecl.Declaration.Variables.FirstOrDefault();
        if (variable?.Initializer == null)
            return false;

        // Check if the initializer makes the type obvious
        var initializer = variable.Initializer.Value;

        // new Type()
        if (initializer is ObjectCreationExpressionSyntax)
            return true;

        // Cast expression
        if (initializer is CastExpressionSyntax)
            return true;

        // Literal with explicit type (e.g., int x = 5)
        if (initializer is LiteralExpressionSyntax)
            return true;

        return false;
    }

    private bool IsOldStyleSwitch(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not SwitchStatementSyntax switchStmt)
            return false;

        // Check if all sections just return or assign to a variable
        var hasOnlySimpleReturns = switchStmt.Sections.All(section =>
        {
            if (section.Statements.Count == 0)
                return false;

            var lastStmt = section.Statements.Last();
            return lastStmt is ReturnStatementSyntax ||
                   lastStmt is BreakStatementSyntax;
        });

        return hasOnlySimpleReturns;
    }

    private bool IsUsingWithoutBraces(SyntaxNode node, SemanticModel semanticModel)
    {
        if (node is not UsingStatementSyntax usingStmt)
            return false;

        // Check if the statement inside is a block that runs to end of containing block
        // For simplicity, only transform if using is followed by just one statement in block
        return usingStmt.Declaration != null;
    }

    private bool IsNullLiteral(ExpressionSyntax expr)
    {
        return expr is LiteralExpressionSyntax literal &&
               literal.IsKind(SyntaxKind.NullLiteralExpression);
    }

    private StatementSyntax? GetSingleStatement(StatementSyntax statement)
    {
        if (statement is BlockSyntax block && block.Statements.Count == 1)
            return block.Statements[0];
        return statement;
    }

    private string? TransformNullCheckAssignment(IfStatementSyntax? ifStmt)
    {
        if (ifStmt == null)
            return null;

        var binary = ifStmt.Condition as BinaryExpressionSyntax;
        if (binary == null)
            return null;

        var variable = IsNullLiteral(binary.Left) ? binary.Right : binary.Left;
        var body = GetSingleStatement(ifStmt.Statement);

        if (body is not ExpressionStatementSyntax exprStmt)
            return null;

        if (exprStmt.Expression is not AssignmentExpressionSyntax assignment)
            return null;

        var value = assignment.Right.ToFullString().Trim();
        return $"{variable.ToFullString().Trim()} ??= {value};";
    }

    private string? TransformTypeCheckCast(IfStatementSyntax? ifStmt)
    {
        if (ifStmt == null)
            return null;

        var binary = ifStmt.Condition as BinaryExpressionSyntax;
        if (binary == null || binary.Kind() != SyntaxKind.IsExpression)
            return null;

        var variable = binary.Left.ToFullString().Trim();
        var typeName = binary.Right.ToFullString().Trim();

        // Get the variable name from the cast in the body
        if (ifStmt.Statement is BlockSyntax block && block.Statements.Count > 0)
        {
            var firstStmt = block.Statements[0] as LocalDeclarationStatementSyntax;
            if (firstStmt != null)
            {
                var varName = firstStmt.Declaration.Variables[0].Identifier.Text;

                // Rebuild the if with pattern matching
                var remainingStatements = block.Statements.Skip(1)
                    .Select(s => s.ToFullString().Trim())
                    .ToList();

                var bodyCode = string.Join("\n    ", remainingStatements);
                return $"if ({variable} is {typeName} {varName})\n{{\n    {bodyCode}\n}}";
            }
        }

        return null;
    }

    private string? TransformVerboseNullCheck(ConditionalExpressionSyntax? conditional)
    {
        if (conditional == null)
            return null;

        var binary = conditional.Condition as BinaryExpressionSyntax;
        if (binary == null)
            return null;

        var variable = IsNullLiteral(binary.Left) ? binary.Right : binary.Left;
        var varExpr = variable.ToString().Trim();
        var trueExpr = conditional.WhenTrue.ToString().Trim();
        var falseExpr = conditional.WhenFalse.ToString().Trim();

        // x != null ? x : default  =>  x ?? default
        if (binary.Kind() == SyntaxKind.NotEqualsExpression && trueExpr == varExpr)
        {
            return $"{varExpr} ?? {falseExpr}";
        }

        // x == null ? default : x  =>  x ?? default
        if (binary.Kind() == SyntaxKind.EqualsExpression && falseExpr == varExpr)
        {
            return $"{varExpr} ?? {trueExpr}";
        }

        return null;
    }

    private string? TransformToVar(LocalDeclarationStatementSyntax? localDecl)
    {
        if (localDecl == null)
            return null;

        var variable = localDecl.Declaration.Variables.FirstOrDefault();
        if (variable == null)
            return null;

        var initializer = variable.Initializer?.Value.ToFullString().Trim() ?? "";
        return $"var {variable.Identifier.Text} = {initializer};";
    }

    private string? TransformToSwitchExpression(SwitchStatementSyntax? switchStmt)
    {
        if (switchStmt == null)
            return null;

        var expression = switchStmt.Expression.ToFullString().Trim();
        var arms = new List<string>();

        foreach (var section in switchStmt.Sections)
        {
            var returnStmt = section.Statements.OfType<ReturnStatementSyntax>().FirstOrDefault();
            if (returnStmt?.Expression == null)
                continue;

            var result = returnStmt.Expression.ToFullString().Trim();

            foreach (var label in section.Labels)
            {
                if (label is CaseSwitchLabelSyntax caseLabel)
                {
                    arms.Add($"    {caseLabel.Value.ToFullString().Trim()} => {result}");
                }
                else if (label is DefaultSwitchLabelSyntax)
                {
                    arms.Add($"    _ => {result}");
                }
            }
        }

        return $"{expression} switch\n{{\n{string.Join(",\n", arms)}\n}}";
    }

    private string? TransformToUsingDeclaration(UsingStatementSyntax? usingStmt)
    {
        if (usingStmt?.Declaration == null)
            return null;

        var variable = usingStmt.Declaration.Variables.FirstOrDefault();
        if (variable == null)
            return null;

        var type = usingStmt.Declaration.Type.ToFullString().Trim();
        var name = variable.Identifier.Text;
        var initializer = variable.Initializer?.Value.ToFullString().Trim() ?? "";

        return $"using {type} {name} = {initializer};";
    }
}
