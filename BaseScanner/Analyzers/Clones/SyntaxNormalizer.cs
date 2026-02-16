using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Clones.Models;
using System.Text;

namespace BaseScanner.Analyzers.Clones;

/// <summary>
/// Normalizes code for clone comparison by replacing identifiers with placeholders,
/// normalizing formatting, and abstracting away superficial differences.
/// </summary>
public class SyntaxNormalizer
{
    private readonly bool _normalizeIdentifiers;
    private readonly bool _normalizeLiterals;
    private readonly bool _normalizeTypes;
    private readonly bool _normalizeWhitespace;

    private Dictionary<string, string> _identifierMap = [];
    private Dictionary<string, string> _literalMap = [];
    private Dictionary<string, string> _typeMap = [];

    private int _identifierCounter;
    private int _literalCounter;
    private int _typeCounter;

    public SyntaxNormalizer(
        bool normalizeIdentifiers = true,
        bool normalizeLiterals = true,
        bool normalizeTypes = false,
        bool normalizeWhitespace = true)
    {
        _normalizeIdentifiers = normalizeIdentifiers;
        _normalizeLiterals = normalizeLiterals;
        _normalizeTypes = normalizeTypes;
        _normalizeWhitespace = normalizeWhitespace;
    }

    /// <summary>
    /// Reset the normalization mappings for a new comparison context.
    /// </summary>
    public void Reset()
    {
        _identifierMap.Clear();
        _literalMap.Clear();
        _typeMap.Clear();
        _identifierCounter = 0;
        _literalCounter = 0;
        _typeCounter = 0;
    }

    /// <summary>
    /// Normalize a syntax node to a string representation.
    /// </summary>
    public string NormalizeToString(SyntaxNode node)
    {
        Reset();
        var tokens = NormalizeTokens(node);
        return string.Join(" ", tokens);
    }

    /// <summary>
    /// Normalize a syntax node to a list of normalized tokens.
    /// </summary>
    public List<string> NormalizeTokens(SyntaxNode node)
    {
        var tokens = new List<string>();

        foreach (var token in node.DescendantTokens())
        {
            var normalizedToken = NormalizeToken(token, node);
            if (!string.IsNullOrWhiteSpace(normalizedToken))
            {
                tokens.Add(normalizedToken);
            }
        }

        return tokens;
    }

    /// <summary>
    /// Normalize a single token.
    /// </summary>
    private string NormalizeToken(SyntaxToken token, SyntaxNode context)
    {
        // Skip whitespace and trivia tokens
        if (token.IsKind(SyntaxKind.EndOfFileToken))
            return "";

        // Handle identifiers
        if (token.IsKind(SyntaxKind.IdentifierToken) && _normalizeIdentifiers)
        {
            return NormalizeIdentifier(token, context);
        }

        // Handle literals
        if (IsLiteralToken(token) && _normalizeLiterals)
        {
            return NormalizeLiteral(token);
        }

        // Handle type names
        if (_normalizeTypes && IsTypeName(token, context))
        {
            return NormalizeTypeName(token);
        }

        // Return the token text for keywords and operators
        return token.ValueText;
    }

    private string NormalizeIdentifier(SyntaxToken token, SyntaxNode context)
    {
        var text = token.ValueText;
        var parent = token.Parent;

        // Don't normalize keywords used as identifiers
        if (SyntaxFacts.GetKeywordKind(text) != SyntaxKind.None)
            return text;

        // Don't normalize well-known framework types and methods
        if (IsWellKnownIdentifier(text))
            return text;

        // Classify the identifier
        var identifierType = ClassifyIdentifier(token, parent);

        // Create a mapping key that includes context
        var key = $"{identifierType}:{text}";

        if (!_identifierMap.TryGetValue(key, out var normalized))
        {
            normalized = $"${identifierType}{++_identifierCounter}";
            _identifierMap[key] = normalized;
        }

        return normalized;
    }

    private string ClassifyIdentifier(SyntaxToken token, SyntaxNode? parent)
    {
        return parent switch
        {
            MethodDeclarationSyntax m when m.Identifier == token => "M",
            ParameterSyntax => "P",
            VariableDeclaratorSyntax => "V",
            PropertyDeclarationSyntax p when p.Identifier == token => "PROP",
            FieldDeclarationSyntax => "F",
            ClassDeclarationSyntax c when c.Identifier == token => "C",
            InterfaceDeclarationSyntax i when i.Identifier == token => "I",
            ForEachStatementSyntax f when f.Identifier == token => "V",
            CatchDeclarationSyntax => "V",
            TypeParameterSyntax => "T",
            _ => "ID"
        };
    }

    private string NormalizeLiteral(SyntaxToken token)
    {
        // Handle boolean and null literals directly
        switch (token.Kind())
        {
            case SyntaxKind.TrueKeyword:
                return "true";
            case SyntaxKind.FalseKeyword:
                return "false";
            case SyntaxKind.NullKeyword:
                return "null";
        }

        var literalType = token.Kind() switch
        {
            SyntaxKind.StringLiteralToken => "STR",
            SyntaxKind.InterpolatedStringTextToken => "STR",
            SyntaxKind.NumericLiteralToken => ClassifyNumericLiteral(token),
            SyntaxKind.CharacterLiteralToken => "CHAR",
            _ => "LIT"
        };

        // Keep small integers as-is (common loop bounds)
        if (literalType == "INT" && token.Value is int intVal && intVal >= 0 && intVal <= 10)
        {
            return token.ValueText;
        }

        var key = $"{literalType}:{token.ValueText}";

        if (!_literalMap.TryGetValue(key, out var normalized))
        {
            normalized = $"${literalType}{++_literalCounter}";
            _literalMap[key] = normalized;
        }

        return normalized;
    }

    private string ClassifyNumericLiteral(SyntaxToken token)
    {
        return token.Value switch
        {
            int => "INT",
            long => "LONG",
            float => "FLOAT",
            double => "DOUBLE",
            decimal => "DEC",
            _ => "NUM"
        };
    }

    private string NormalizeTypeName(SyntaxToken token)
    {
        var text = token.ValueText;

        // Don't normalize built-in types
        if (IsBuiltInType(text))
            return text;

        if (!_typeMap.TryGetValue(text, out var normalized))
        {
            normalized = $"$TYPE{++_typeCounter}";
            _typeMap[text] = normalized;
        }

        return normalized;
    }

    private bool IsLiteralToken(SyntaxToken token)
    {
        return token.Kind() switch
        {
            SyntaxKind.StringLiteralToken => true,
            SyntaxKind.InterpolatedStringTextToken => true,
            SyntaxKind.NumericLiteralToken => true,
            SyntaxKind.CharacterLiteralToken => true,
            _ => false
        };
    }

    private bool IsTypeName(SyntaxToken token, SyntaxNode context)
    {
        var parent = token.Parent;
        return parent is TypeSyntax ||
               parent is GenericNameSyntax ||
               parent is QualifiedNameSyntax;
    }

    private bool IsWellKnownIdentifier(string identifier)
    {
        return identifier switch
        {
            // Common BCL types
            "Object" or "String" or "Int32" or "Int64" or "Boolean" or
            "Double" or "Single" or "Decimal" or "Char" or "Byte" or
            "DateTime" or "TimeSpan" or "Guid" or "Uri" or
            "List" or "Dictionary" or "HashSet" or "Queue" or "Stack" or
            "Array" or "Enumerable" or "Queryable" or
            "Task" or "ValueTask" or "CancellationToken" or
            "IEnumerable" or "ICollection" or "IList" or "IDictionary" or
            "IDisposable" or "IAsyncDisposable" or
            "Console" or "File" or "Directory" or "Path" or
            "Math" or "Convert" or "Activator" or
            "Exception" or "ArgumentException" or "InvalidOperationException" or
            "NotImplementedException" or "NotSupportedException" or
            // Common methods
            "ToString" or "GetHashCode" or "Equals" or "CompareTo" or
            "Dispose" or "DisposeAsync" or
            "Add" or "Remove" or "Contains" or "Clear" or "Count" or
            "Where" or "Select" or "First" or "FirstOrDefault" or
            "Any" or "All" or "Single" or "SingleOrDefault" or
            "ToList" or "ToArray" or "ToDictionary" or
            "OrderBy" or "OrderByDescending" or "GroupBy" or
            "GetType" or "GetType" or "nameof" or "typeof" or
            // Common properties
            "Length" or "Count" or "Value" or "Key" or
            "Message" or "InnerException" or "StackTrace"
            => true,
            _ => false
        };
    }

    private bool IsBuiltInType(string typeName)
    {
        return typeName switch
        {
            "void" or "bool" or "byte" or "sbyte" or
            "short" or "ushort" or "int" or "uint" or
            "long" or "ulong" or "float" or "double" or
            "decimal" or "char" or "string" or "object" or
            "dynamic" or "var" => true,
            _ => false
        };
    }

    /// <summary>
    /// Create a normalized representation of a syntax node.
    /// </summary>
    public NormalizedNode NormalizeNode(SyntaxNode node)
    {
        Reset();
        return NormalizeNodeRecursive(node);
    }

    private NormalizedNode NormalizeNodeRecursive(SyntaxNode node)
    {
        var tokens = new List<string>();

        // Collect tokens that are direct children of this node
        foreach (var token in node.ChildTokens())
        {
            var normalized = NormalizeToken(token, node);
            if (!string.IsNullOrWhiteSpace(normalized))
            {
                tokens.Add(normalized);
            }
        }

        // Recursively normalize child nodes
        var children = node.ChildNodes()
            .Select(NormalizeNodeRecursive)
            .ToList();

        // Compute structure hash
        var structureHash = ComputeNodeHash(node.Kind().ToString(), tokens, children);

        return new NormalizedNode
        {
            NodeKind = node.Kind().ToString(),
            Tokens = tokens,
            Children = children,
            StructureHash = structureHash
        };
    }

    private long ComputeNodeHash(string nodeKind, List<string> tokens, List<NormalizedNode> children)
    {
        unchecked
        {
            long hash = 17;
            hash = hash * 31 + nodeKind.GetHashCode();

            foreach (var token in tokens)
            {
                hash = hash * 31 + token.GetHashCode();
            }

            foreach (var child in children)
            {
                hash = hash * 31 + child.StructureHash;
            }

            return hash;
        }
    }

    /// <summary>
    /// Extract a canonical form of the code that removes superficial differences.
    /// </summary>
    public string ExtractCanonicalForm(SyntaxNode node)
    {
        Reset();
        var sb = new StringBuilder();
        ExtractCanonicalFormRecursive(node, sb, 0);
        return sb.ToString();
    }

    private void ExtractCanonicalFormRecursive(SyntaxNode node, StringBuilder sb, int indent)
    {
        var indentStr = new string(' ', indent * 2);

        switch (node)
        {
            case BlockSyntax block:
                sb.AppendLine($"{indentStr}{{");
                foreach (var statement in block.Statements)
                {
                    ExtractCanonicalFormRecursive(statement, sb, indent + 1);
                }
                sb.AppendLine($"{indentStr}}}");
                break;

            case IfStatementSyntax ifStmt:
                sb.AppendLine($"{indentStr}if (COND)");
                ExtractCanonicalFormRecursive(ifStmt.Statement, sb, indent);
                if (ifStmt.Else != null)
                {
                    sb.AppendLine($"{indentStr}else");
                    ExtractCanonicalFormRecursive(ifStmt.Else.Statement, sb, indent);
                }
                break;

            case ForStatementSyntax:
                sb.AppendLine($"{indentStr}for (INIT; COND; INCR)");
                break;

            case ForEachStatementSyntax foreachStmt:
                sb.AppendLine($"{indentStr}foreach (VAR in COLLECTION)");
                ExtractCanonicalFormRecursive(foreachStmt.Statement, sb, indent);
                break;

            case WhileStatementSyntax whileStmt:
                sb.AppendLine($"{indentStr}while (COND)");
                ExtractCanonicalFormRecursive(whileStmt.Statement, sb, indent);
                break;

            case SwitchStatementSyntax:
                sb.AppendLine($"{indentStr}switch (EXPR)");
                break;

            case TryStatementSyntax tryStmt:
                sb.AppendLine($"{indentStr}try");
                ExtractCanonicalFormRecursive(tryStmt.Block, sb, indent);
                foreach (var catchClause in tryStmt.Catches)
                {
                    sb.AppendLine($"{indentStr}catch (EXCEPTION)");
                    ExtractCanonicalFormRecursive(catchClause.Block, sb, indent);
                }
                if (tryStmt.Finally != null)
                {
                    sb.AppendLine($"{indentStr}finally");
                    ExtractCanonicalFormRecursive(tryStmt.Finally.Block, sb, indent);
                }
                break;

            case ReturnStatementSyntax:
                sb.AppendLine($"{indentStr}return EXPR;");
                break;

            case ThrowStatementSyntax:
                sb.AppendLine($"{indentStr}throw EXPR;");
                break;

            case ExpressionStatementSyntax exprStmt:
                var exprType = ClassifyExpression(exprStmt.Expression);
                sb.AppendLine($"{indentStr}{exprType};");
                break;

            case LocalDeclarationStatementSyntax:
                sb.AppendLine($"{indentStr}VAR = EXPR;");
                break;

            default:
                // For other node types, just output the normalized tokens
                var tokens = NormalizeTokens(node);
                if (tokens.Count > 0)
                {
                    sb.AppendLine($"{indentStr}{string.Join(" ", tokens)}");
                }
                break;
        }
    }

    private string ClassifyExpression(ExpressionSyntax expression)
    {
        return expression switch
        {
            AssignmentExpressionSyntax => "ASSIGN",
            InvocationExpressionSyntax => "CALL",
            ObjectCreationExpressionSyntax => "NEW",
            AwaitExpressionSyntax => "AWAIT",
            PostfixUnaryExpressionSyntax post when post.IsKind(SyntaxKind.PostIncrementExpression) => "INCR",
            PostfixUnaryExpressionSyntax post when post.IsKind(SyntaxKind.PostDecrementExpression) => "DECR",
            PrefixUnaryExpressionSyntax pre when pre.IsKind(SyntaxKind.PreIncrementExpression) => "INCR",
            PrefixUnaryExpressionSyntax pre when pre.IsKind(SyntaxKind.PreDecrementExpression) => "DECR",
            _ => "EXPR"
        };
    }

    /// <summary>
    /// Get the mapping of original identifiers to normalized placeholders.
    /// </summary>
    public IReadOnlyDictionary<string, string> GetIdentifierMappings()
    {
        return _identifierMap;
    }

    /// <summary>
    /// Get the mapping of original literals to normalized placeholders.
    /// </summary>
    public IReadOnlyDictionary<string, string> GetLiteralMappings()
    {
        return _literalMap;
    }

    /// <summary>
    /// Compare two normalized token sequences and identify differences.
    /// </summary>
    public List<CloneDifference> CompareNormalizedTokens(
        List<string> tokens1, List<string> tokens2,
        int line1Start, int line2Start)
    {
        var differences = new List<CloneDifference>();

        // Use dynamic programming for optimal alignment
        var alignment = AlignTokenSequences(tokens1, tokens2);

        int line1 = line1Start;
        int line2 = line2Start;

        foreach (var (t1, t2) in alignment)
        {
            if (t1 == null && t2 != null)
            {
                differences.Add(new CloneDifference
                {
                    Type = DifferenceType.StatementAdded,
                    Fragment2Line = line2,
                    Fragment2Value = t2,
                    Description = $"Added: {t2}"
                });
            }
            else if (t1 != null && t2 == null)
            {
                differences.Add(new CloneDifference
                {
                    Type = DifferenceType.StatementRemoved,
                    Fragment1Line = line1,
                    Fragment1Value = t1,
                    Description = $"Removed: {t1}"
                });
            }
            else if (t1 != t2)
            {
                var diffType = ClassifyDifference(t1!, t2!);
                differences.Add(new CloneDifference
                {
                    Type = diffType,
                    Fragment1Line = line1,
                    Fragment2Line = line2,
                    Fragment1Value = t1,
                    Fragment2Value = t2,
                    Description = $"Changed: {t1} -> {t2}"
                });
            }

            if (t1 != null) line1++;
            if (t2 != null) line2++;
        }

        return differences;
    }

    private DifferenceType ClassifyDifference(string token1, string token2)
    {
        // Check if both are placeholders
        if (token1.StartsWith("$") && token2.StartsWith("$"))
        {
            var type1 = GetPlaceholderType(token1);
            var type2 = GetPlaceholderType(token2);

            if (type1 == type2)
            {
                return type1 switch
                {
                    "ID" or "V" or "P" or "M" => DifferenceType.IdentifierRenamed,
                    "STR" or "INT" or "NUM" => DifferenceType.LiteralChanged,
                    "TYPE" => DifferenceType.TypeChanged,
                    _ => DifferenceType.StatementModified
                };
            }
        }

        // Check for operator differences
        if (IsOperator(token1) && IsOperator(token2))
        {
            return DifferenceType.OperatorChanged;
        }

        return DifferenceType.StatementModified;
    }

    private string GetPlaceholderType(string placeholder)
    {
        if (!placeholder.StartsWith("$")) return "";

        // Extract the type prefix (letters before the number)
        var type = "";
        for (int i = 1; i < placeholder.Length; i++)
        {
            if (char.IsDigit(placeholder[i])) break;
            type += placeholder[i];
        }
        return type;
    }

    private bool IsOperator(string token)
    {
        return token switch
        {
            "+" or "-" or "*" or "/" or "%" or
            "==" or "!=" or "<" or ">" or "<=" or ">=" or
            "&&" or "||" or "!" or
            "&" or "|" or "^" or "~" or
            "<<" or ">>" or
            "=" or "+=" or "-=" or "*=" or "/=" or
            "++" or "--" => true,
            _ => false
        };
    }

    private List<(string?, string?)> AlignTokenSequences(List<string> seq1, List<string> seq2)
    {
        int m = seq1.Count;
        int n = seq2.Count;

        // DP table for edit distance
        var dp = new int[m + 1, n + 1];

        for (int i = 0; i <= m; i++) dp[i, 0] = i;
        for (int j = 0; j <= n; j++) dp[0, j] = j;

        for (int i = 1; i <= m; i++)
        {
            for (int j = 1; j <= n; j++)
            {
                if (seq1[i - 1] == seq2[j - 1])
                {
                    dp[i, j] = dp[i - 1, j - 1];
                }
                else
                {
                    dp[i, j] = 1 + Math.Min(
                        dp[i - 1, j - 1], // substitution
                        Math.Min(
                            dp[i - 1, j],   // deletion
                            dp[i, j - 1]    // insertion
                        )
                    );
                }
            }
        }

        // Backtrack to find alignment
        var alignment = new List<(string?, string?)>();
        int x = m, y = n;

        while (x > 0 || y > 0)
        {
            if (x > 0 && y > 0 && seq1[x - 1] == seq2[y - 1])
            {
                alignment.Add((seq1[x - 1], seq2[y - 1]));
                x--;
                y--;
            }
            else if (x > 0 && y > 0 && dp[x, y] == dp[x - 1, y - 1] + 1)
            {
                alignment.Add((seq1[x - 1], seq2[y - 1]));
                x--;
                y--;
            }
            else if (x > 0 && dp[x, y] == dp[x - 1, y] + 1)
            {
                alignment.Add((seq1[x - 1], null));
                x--;
            }
            else
            {
                alignment.Add((null, seq2[y - 1]));
                y--;
            }
        }

        alignment.Reverse();
        return alignment;
    }
}
