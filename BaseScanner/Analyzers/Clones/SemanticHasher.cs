using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Clones.Models;

namespace BaseScanner.Analyzers.Clones;

/// <summary>
/// Generates semantic fingerprints and hashes for code comparison.
/// Uses multiple hashing strategies for different clone types.
/// </summary>
public class SemanticHasher
{
    private readonly int _ngramSize;
    private readonly int _minHashFunctions;
    private readonly Random _random;
    private readonly long[] _hashCoefficientsA;
    private readonly long[] _hashCoefficientsB;
    private const long LargePrime = 4294967311L;

    public SemanticHasher(int ngramSize = 5, int minHashFunctions = 100)
    {
        _ngramSize = ngramSize;
        _minHashFunctions = minHashFunctions;
        _random = new Random(42); // Fixed seed for reproducibility

        // Pre-compute hash coefficients for MinHash
        _hashCoefficientsA = new long[minHashFunctions];
        _hashCoefficientsB = new long[minHashFunctions];
        for (int i = 0; i < minHashFunctions; i++)
        {
            _hashCoefficientsA[i] = _random.NextInt64(1, LargePrime);
            _hashCoefficientsB[i] = _random.NextInt64(0, LargePrime);
        }
    }

    /// <summary>
    /// Compute an exact hash (Type 1 clones) - ignores whitespace and comments only.
    /// </summary>
    public long ComputeExactHash(SyntaxNode node)
    {
        var tokens = node.DescendantTokens()
            .Where(t => !t.IsKind(SyntaxKind.EndOfFileToken))
            .Select(t => t.ValueText);

        return ComputeStringHash(string.Join(" ", tokens));
    }

    /// <summary>
    /// Compute a normalized hash (Type 2 clones) - identifiers replaced with placeholders.
    /// </summary>
    public long ComputeNormalizedHash(SyntaxNode node, SyntaxNormalizer normalizer)
    {
        var normalizedCode = normalizer.NormalizeToString(node);
        return ComputeStringHash(normalizedCode);
    }

    /// <summary>
    /// Compute token n-gram fingerprints for similarity comparison.
    /// </summary>
    public List<long> ComputeTokenFingerprints(SyntaxNode node)
    {
        var tokens = ExtractTokenSequence(node);
        if (tokens.Count < _ngramSize)
            return [];

        var fingerprints = new List<long>();

        for (int i = 0; i <= tokens.Count - _ngramSize; i++)
        {
            var ngram = tokens.Skip(i).Take(_ngramSize);
            var hash = ComputeStringHash(string.Join(" ", ngram));
            fingerprints.Add(hash);
        }

        return fingerprints;
    }

    /// <summary>
    /// Compute token n-gram fingerprints from normalized tokens.
    /// </summary>
    public List<long> ComputeNormalizedFingerprints(List<string> normalizedTokens)
    {
        if (normalizedTokens.Count < _ngramSize)
            return [];

        var fingerprints = new List<long>();

        for (int i = 0; i <= normalizedTokens.Count - _ngramSize; i++)
        {
            var ngram = normalizedTokens.Skip(i).Take(_ngramSize);
            var hash = ComputeStringHash(string.Join(" ", ngram));
            fingerprints.Add(hash);
        }

        return fingerprints;
    }

    /// <summary>
    /// Compute AST subtree hashes for structural comparison.
    /// </summary>
    public List<long> ComputeAstHashes(SyntaxNode node, int minDepth = 2)
    {
        var hashes = new List<long>();
        ComputeAstHashesRecursive(node, hashes, 0, minDepth);
        return hashes;
    }

    private long ComputeAstHashesRecursive(SyntaxNode node, List<long> hashes, int depth, int minDepth)
    {
        var childHashes = new List<long>();

        foreach (var child in node.ChildNodes())
        {
            var childHash = ComputeAstHashesRecursive(child, hashes, depth + 1, minDepth);
            childHashes.Add(childHash);
        }

        // Create hash from node kind and child hashes
        var nodeHash = CombineHashes(
            node.Kind().ToString().GetHashCode(),
            childHashes.ToArray()
        );

        // Only add hashes for nodes at or beyond minimum depth
        if (depth >= minDepth && node.ChildNodes().Any())
        {
            hashes.Add(nodeHash);
        }

        return nodeHash;
    }

    /// <summary>
    /// Compute a structural hash that captures the shape of the AST.
    /// </summary>
    public long ComputeStructuralHash(SyntaxNode node)
    {
        return ComputeStructuralHashRecursive(node);
    }

    private long ComputeStructuralHashRecursive(SyntaxNode node)
    {
        var childHashes = node.ChildNodes()
            .Select(ComputeStructuralHashRecursive)
            .ToArray();

        // Only include the node kind, not the actual content
        return CombineHashes(node.Kind().ToString().GetHashCode(), childHashes);
    }

    /// <summary>
    /// Compute MinHash signature for fast similarity estimation.
    /// </summary>
    public long[] ComputeMinHashSignature(IEnumerable<long> shingles)
    {
        var shingleSet = shingles.ToHashSet();
        var signature = new long[_minHashFunctions];

        for (int i = 0; i < _minHashFunctions; i++)
        {
            signature[i] = long.MaxValue;
        }

        foreach (var shingle in shingleSet)
        {
            for (int i = 0; i < _minHashFunctions; i++)
            {
                var hash = ((_hashCoefficientsA[i] * shingle + _hashCoefficientsB[i]) % LargePrime);
                if (hash < signature[i])
                {
                    signature[i] = hash;
                }
            }
        }

        return signature;
    }

    /// <summary>
    /// Estimate Jaccard similarity between two MinHash signatures.
    /// </summary>
    public double EstimateJaccardSimilarity(long[] signature1, long[] signature2)
    {
        if (signature1.Length != signature2.Length)
            return 0;

        int matches = 0;
        for (int i = 0; i < signature1.Length; i++)
        {
            if (signature1[i] == signature2[i])
                matches++;
        }

        return (double)matches / signature1.Length;
    }

    /// <summary>
    /// Compute a control flow signature for semantic clone detection.
    /// </summary>
    public string ComputeControlFlowSignature(SyntaxNode node)
    {
        var operations = new List<string>();
        ComputeControlFlowSignatureRecursive(node, operations);
        return string.Join("|", operations);
    }

    private void ComputeControlFlowSignatureRecursive(SyntaxNode node, List<string> operations)
    {
        switch (node)
        {
            case IfStatementSyntax:
                operations.Add("IF");
                break;
            case ElseClauseSyntax:
                operations.Add("ELSE");
                break;
            case ForStatementSyntax:
                operations.Add("FOR");
                break;
            case ForEachStatementSyntax:
                operations.Add("FOREACH");
                break;
            case WhileStatementSyntax:
                operations.Add("WHILE");
                break;
            case DoStatementSyntax:
                operations.Add("DO");
                break;
            case SwitchStatementSyntax:
                operations.Add("SWITCH");
                break;
            case SwitchExpressionSyntax:
                operations.Add("SWITCH_EXPR");
                break;
            case TryStatementSyntax:
                operations.Add("TRY");
                break;
            case CatchClauseSyntax:
                operations.Add("CATCH");
                break;
            case FinallyClauseSyntax:
                operations.Add("FINALLY");
                break;
            case ReturnStatementSyntax:
                operations.Add("RETURN");
                break;
            case ThrowStatementSyntax:
                operations.Add("THROW");
                break;
            case BreakStatementSyntax:
                operations.Add("BREAK");
                break;
            case ContinueStatementSyntax:
                operations.Add("CONTINUE");
                break;
            case AssignmentExpressionSyntax:
                operations.Add("ASSIGN");
                break;
            case InvocationExpressionSyntax:
                operations.Add("CALL");
                break;
            case ObjectCreationExpressionSyntax:
                operations.Add("NEW");
                break;
            case AwaitExpressionSyntax:
                operations.Add("AWAIT");
                break;
            case LockStatementSyntax:
                operations.Add("LOCK");
                break;
            case UsingStatementSyntax:
                operations.Add("USING");
                break;
            case LocalDeclarationStatementSyntax:
                operations.Add("DECL");
                break;
        }

        foreach (var child in node.ChildNodes())
        {
            ComputeControlFlowSignatureRecursive(child, operations);
        }
    }

    /// <summary>
    /// Compute a semantic hash based on operations performed.
    /// </summary>
    public long ComputeSemanticOperationHash(SyntaxNode node, SemanticModel? semanticModel)
    {
        var operations = new List<string>();
        CollectSemanticOperations(node, operations, semanticModel);
        return ComputeStringHash(string.Join(";", operations));
    }

    private void CollectSemanticOperations(SyntaxNode node, List<string> operations, SemanticModel? semanticModel)
    {
        switch (node)
        {
            case AssignmentExpressionSyntax assignment:
                operations.Add($"ASSIGN:{GetTypeSignature(assignment.Left, semanticModel)}");
                break;

            case InvocationExpressionSyntax invocation:
                var methodName = GetMethodSignature(invocation, semanticModel);
                operations.Add($"CALL:{methodName}");
                break;

            case ObjectCreationExpressionSyntax creation:
                var typeName = creation.Type.ToString();
                operations.Add($"NEW:{typeName}");
                break;

            case BinaryExpressionSyntax binary:
                operations.Add($"BINOP:{binary.Kind()}");
                break;

            case PrefixUnaryExpressionSyntax prefixUnary:
                operations.Add($"UNOP:{prefixUnary.Kind()}");
                break;

            case PostfixUnaryExpressionSyntax postfixUnary:
                operations.Add($"UNOP:{postfixUnary.Kind()}");
                break;

            case ConditionalExpressionSyntax:
                operations.Add("TERNARY");
                break;

            case ReturnStatementSyntax ret:
                var retType = ret.Expression != null ? GetTypeSignature(ret.Expression, semanticModel) : "void";
                operations.Add($"RETURN:{retType}");
                break;
        }

        foreach (var child in node.ChildNodes())
        {
            CollectSemanticOperations(child, operations, semanticModel);
        }
    }

    private string GetTypeSignature(SyntaxNode node, SemanticModel? semanticModel)
    {
        if (semanticModel == null) return "unknown";

        var typeInfo = semanticModel.GetTypeInfo(node);
        return typeInfo.Type?.ToDisplayString(SymbolDisplayFormat.MinimallyQualifiedFormat) ?? "unknown";
    }

    private string GetMethodSignature(InvocationExpressionSyntax invocation, SemanticModel? semanticModel)
    {
        if (semanticModel == null)
        {
            return invocation.Expression switch
            {
                MemberAccessExpressionSyntax ma => ma.Name.Identifier.Text,
                IdentifierNameSyntax id => id.Identifier.Text,
                _ => "unknown"
            };
        }

        var symbolInfo = semanticModel.GetSymbolInfo(invocation);
        if (symbolInfo.Symbol is IMethodSymbol method)
        {
            return $"{method.ContainingType?.Name}.{method.Name}({method.Parameters.Length})";
        }

        return "unknown";
    }

    /// <summary>
    /// Extract the token sequence from a syntax node.
    /// </summary>
    public List<string> ExtractTokenSequence(SyntaxNode node)
    {
        return node.DescendantTokens()
            .Where(t => !t.IsKind(SyntaxKind.EndOfFileToken))
            .Where(t => !t.IsKind(SyntaxKind.OpenBraceToken))
            .Where(t => !t.IsKind(SyntaxKind.CloseBraceToken))
            .Where(t => !t.IsKind(SyntaxKind.SemicolonToken))
            .Select(t => MapTokenKind(t))
            .ToList();
    }

    private string MapTokenKind(SyntaxToken token)
    {
        // For keywords and operators, use the kind
        if (token.IsKeyword() || IsOperator(token.Kind()))
        {
            return token.Kind().ToString();
        }

        // For identifiers and literals, use the value
        return token.ValueText;
    }

    private static bool IsOperator(SyntaxKind kind)
    {
        return kind switch
        {
            SyntaxKind.PlusToken or SyntaxKind.MinusToken or SyntaxKind.AsteriskToken or
            SyntaxKind.SlashToken or SyntaxKind.PercentToken or SyntaxKind.AmpersandToken or
            SyntaxKind.BarToken or SyntaxKind.CaretToken or SyntaxKind.TildeToken or
            SyntaxKind.ExclamationToken or SyntaxKind.EqualsToken or SyntaxKind.LessThanToken or
            SyntaxKind.GreaterThanToken or SyntaxKind.QuestionToken or SyntaxKind.ColonToken or
            SyntaxKind.PlusPlusToken or SyntaxKind.MinusMinusToken or SyntaxKind.LessThanLessThanToken or
            SyntaxKind.GreaterThanGreaterThanToken or SyntaxKind.EqualsEqualsToken or SyntaxKind.ExclamationEqualsToken or
            SyntaxKind.LessThanEqualsToken or SyntaxKind.GreaterThanEqualsToken or SyntaxKind.AmpersandAmpersandToken or
            SyntaxKind.BarBarToken or SyntaxKind.PlusEqualsToken or SyntaxKind.MinusEqualsToken or
            SyntaxKind.AsteriskEqualsToken or SyntaxKind.SlashEqualsToken or SyntaxKind.PercentEqualsToken or
            SyntaxKind.AmpersandEqualsToken or SyntaxKind.BarEqualsToken or SyntaxKind.CaretEqualsToken or
            SyntaxKind.LessThanLessThanEqualsToken or SyntaxKind.GreaterThanGreaterThanEqualsToken or
            SyntaxKind.QuestionQuestionToken or SyntaxKind.QuestionQuestionEqualsToken => true,
            _ => false
        };
    }

    /// <summary>
    /// Compute hash combining multiple values.
    /// </summary>
    private long CombineHashes(int nodeKind, long[] childHashes)
    {
        unchecked
        {
            long hash = 17;
            hash = hash * 31 + nodeKind;
            foreach (var childHash in childHashes)
            {
                hash = hash * 31 + childHash;
            }
            return hash;
        }
    }

    /// <summary>
    /// Compute a stable hash for a string.
    /// </summary>
    public long ComputeStringHash(string input)
    {
        if (string.IsNullOrEmpty(input))
            return 0;

        unchecked
        {
            // FNV-1a hash - using signed values that work within long range
            long hash = unchecked((long)14695981039346656037UL);
            foreach (char c in input)
            {
                hash ^= c;
                hash *= 1099511628211L;
            }
            return hash;
        }
    }

    /// <summary>
    /// Compute locality-sensitive hash bands for approximate matching.
    /// </summary>
    public List<long> ComputeLshBands(long[] minHashSignature, int bandsCount = 20)
    {
        if (minHashSignature.Length == 0)
            return [];

        int rowsPerBand = minHashSignature.Length / bandsCount;
        var bands = new List<long>();

        for (int band = 0; band < bandsCount; band++)
        {
            long bandHash = 0;
            for (int row = 0; row < rowsPerBand; row++)
            {
                int idx = band * rowsPerBand + row;
                if (idx < minHashSignature.Length)
                {
                    bandHash = bandHash * 31 + minHashSignature[idx];
                }
            }
            bands.Add(bandHash);
        }

        return bands;
    }

    /// <summary>
    /// Build a control flow graph from a method body.
    /// </summary>
    public ControlFlowGraph BuildControlFlowGraph(SyntaxNode methodBody)
    {
        var nodes = new List<ControlFlowNode>();
        var nodeId = 0;

        var entry = new ControlFlowNode
        {
            Id = $"node_{nodeId++}",
            NodeType = "entry"
        };
        nodes.Add(entry);

        var exit = new ControlFlowNode
        {
            Id = $"node_{nodeId++}",
            NodeType = "exit"
        };

        // Build nodes from statements
        var statementNodes = new List<ControlFlowNode>();
        foreach (var statement in methodBody.DescendantNodes().OfType<StatementSyntax>())
        {
            var (nodeType, operation, isBranch, isLoop) = ClassifyStatement(statement);
            var node = new ControlFlowNode
            {
                Id = $"node_{nodeId++}",
                NodeType = nodeType,
                Operation = operation,
                IsBranch = isBranch,
                IsLoopHeader = isLoop
            };
            statementNodes.Add(node);
        }

        nodes.AddRange(statementNodes);
        nodes.Add(exit);

        // Connect entry to first statement
        if (statementNodes.Count > 0)
        {
            entry.Successors.Add(statementNodes[0].Id);
            statementNodes[0].Predecessors.Add(entry.Id);
        }
        else
        {
            entry.Successors.Add(exit.Id);
            exit.Predecessors.Add(entry.Id);
        }

        // Connect sequential statements
        for (int i = 0; i < statementNodes.Count - 1; i++)
        {
            statementNodes[i].Successors.Add(statementNodes[i + 1].Id);
            statementNodes[i + 1].Predecessors.Add(statementNodes[i].Id);
        }

        // Connect last statement to exit
        if (statementNodes.Count > 0)
        {
            var last = statementNodes[^1];
            last.Successors.Add(exit.Id);
            exit.Predecessors.Add(last.Id);
        }

        // Build signature
        var signature = string.Join("-", nodes.Select(n => $"{n.NodeType}:{n.Operation}"));

        return new ControlFlowGraph
        {
            Entry = entry,
            Exit = exit,
            Nodes = nodes,
            Signature = signature
        };
    }

    private (string nodeType, string operation, bool isBranch, bool isLoop) ClassifyStatement(StatementSyntax statement)
    {
        return statement switch
        {
            IfStatementSyntax => ("branch", "if", true, false),
            ForStatementSyntax => ("loop", "for", true, true),
            ForEachStatementSyntax => ("loop", "foreach", true, true),
            WhileStatementSyntax => ("loop", "while", true, true),
            DoStatementSyntax => ("loop", "do", true, true),
            SwitchStatementSyntax => ("branch", "switch", true, false),
            TryStatementSyntax => ("try", "try", false, false),
            ReturnStatementSyntax => ("return", "return", false, false),
            ThrowStatementSyntax => ("throw", "throw", false, false),
            ExpressionStatementSyntax expr => ("statement", ClassifyExpression(expr.Expression), false, false),
            LocalDeclarationStatementSyntax => ("declaration", "decl", false, false),
            _ => ("statement", "other", false, false)
        };
    }

    private string ClassifyExpression(ExpressionSyntax expression)
    {
        return expression switch
        {
            AssignmentExpressionSyntax => "assign",
            InvocationExpressionSyntax => "call",
            ObjectCreationExpressionSyntax => "new",
            AwaitExpressionSyntax => "await",
            _ => "expr"
        };
    }
}
