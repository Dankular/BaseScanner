using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;
using BaseScanner.Analyzers.Documentation.Models;
using System.Text.RegularExpressions;

namespace BaseScanner.Analyzers.Documentation.Detectors;

/// <summary>
/// Detects stale, outdated, or contradicting comments.
/// Includes detection of TODO, FIXME, HACK comments and references to removed code.
/// </summary>
public class StaleDocDetector : DocDetectorBase
{
    public override DocIssueCategory Category => DocIssueCategory.StaleDocumentation;
    public override string Name => "Stale Documentation Detector";
    public override string Description => "Detects outdated comments, TODO/FIXME/HACK markers, and documentation referencing removed code.";

    // Patterns for action items
    private static readonly Regex TodoPattern = new(@"\b(TODO|TO\s*DO)\b[\s:]*(.{0,100})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex FixmePattern = new(@"\b(FIXME|FIX\s*ME|FIX)\b[\s:]*(.{0,100})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex HackPattern = new(@"\b(HACK|WORKAROUND|KLUDGE)\b[\s:]*(.{0,100})", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex BugPattern = new(@"\b(BUG|XXX)\b[\s:]*(.{0,100})", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Pattern for param references in documentation
    private static readonly Regex ParamRefPattern = new(@"<param(?:ref)?\s+name\s*=\s*""(\w+)""", RegexOptions.Compiled);
    private static readonly Regex SeeRefPattern = new(@"<see\s+cref\s*=\s*""([^""]+)""", RegexOptions.Compiled);

    public override async Task<List<DocumentationIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext? context = null)
    {
        var issues = new List<DocumentationIssue>();
        var filePath = document.FilePath ?? "";

        // Check for TODO/FIXME/HACK comments
        issues.AddRange(DetectActionItemComments(root, filePath));

        // Check for stale parameter documentation
        issues.AddRange(await DetectStaleParamDocsAsync(root, semanticModel, filePath));

        // Check for stale see references
        issues.AddRange(await DetectStaleSeeRefsAsync(root, semanticModel, filePath));

        // Check for commented-out code
        issues.AddRange(DetectCommentedOutCode(root, filePath));

        // Check for misleading or contradicting comments
        issues.AddRange(await DetectContradictingCommentsAsync(root, semanticModel, filePath));

        return issues;
    }

    private List<DocumentationIssue> DetectActionItemComments(SyntaxNode root, string filePath)
    {
        var issues = new List<DocumentationIssue>();

        // Get all trivia (comments)
        var triviaList = root.DescendantTrivia()
            .Where(t => t.IsKind(SyntaxKind.SingleLineCommentTrivia) ||
                       t.IsKind(SyntaxKind.MultiLineCommentTrivia) ||
                       t.IsKind(SyntaxKind.SingleLineDocumentationCommentTrivia) ||
                       t.IsKind(SyntaxKind.MultiLineDocumentationCommentTrivia));

        foreach (var trivia in triviaList)
        {
            var text = trivia.ToString();
            var location = trivia.GetLocation().GetLineSpan();
            var line = location.StartLinePosition.Line + 1;

            // Check TODO
            var todoMatch = TodoPattern.Match(text);
            if (todoMatch.Success)
            {
                var description = todoMatch.Groups[2].Value.Trim();
                issues.Add(CreateIssue(
                    DocumentationIssueType.TodoComment,
                    DocIssueSeverity.Warning,
                    filePath,
                    line,
                    line,
                    "TODO",
                    "Comment",
                    $"Unresolved TODO: {(description.Length > 80 ? description[..80] + "..." : description)}",
                    "Address the TODO item or create a tracking issue",
                    currentCode: text.Trim(),
                    metadata: new Dictionary<string, object> { ["TodoText"] = description }));
            }

            // Check FIXME
            var fixmeMatch = FixmePattern.Match(text);
            if (fixmeMatch.Success)
            {
                var description = fixmeMatch.Groups[2].Value.Trim();
                issues.Add(CreateIssue(
                    DocumentationIssueType.FixmeComment,
                    DocIssueSeverity.Major,
                    filePath,
                    line,
                    line,
                    "FIXME",
                    "Comment",
                    $"Unresolved FIXME: {(description.Length > 80 ? description[..80] + "..." : description)}",
                    "Fix the issue or create a bug report",
                    currentCode: text.Trim(),
                    metadata: new Dictionary<string, object> { ["FixmeText"] = description }));
            }

            // Check HACK
            var hackMatch = HackPattern.Match(text);
            if (hackMatch.Success)
            {
                var description = hackMatch.Groups[2].Value.Trim();
                issues.Add(CreateIssue(
                    DocumentationIssueType.HackComment,
                    DocIssueSeverity.Minor,
                    filePath,
                    line,
                    line,
                    "HACK",
                    "Comment",
                    $"Code workaround: {(description.Length > 80 ? description[..80] + "..." : description)}",
                    "Consider refactoring to remove the hack",
                    currentCode: text.Trim(),
                    metadata: new Dictionary<string, object> { ["HackText"] = description }));
            }

            // Check BUG/XXX
            var bugMatch = BugPattern.Match(text);
            if (bugMatch.Success)
            {
                var description = bugMatch.Groups[2].Value.Trim();
                issues.Add(CreateIssue(
                    DocumentationIssueType.FixmeComment,
                    DocIssueSeverity.Major,
                    filePath,
                    line,
                    line,
                    "BUG",
                    "Comment",
                    $"Known bug marker: {(description.Length > 80 ? description[..80] + "..." : description)}",
                    "Fix the bug or create a tracking issue",
                    currentCode: text.Trim(),
                    metadata: new Dictionary<string, object> { ["BugText"] = description }));
            }
        }

        return issues;
    }

    private Task<List<DocumentationIssue>> DetectStaleParamDocsAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        // Check methods
        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(method);
            if (symbol == null) continue;

            var xmlDoc = symbol.GetDocumentationCommentXml();
            if (string.IsNullOrEmpty(xmlDoc)) continue;

            // Get actual parameter names
            var actualParams = symbol.Parameters.Select(p => p.Name).ToHashSet();

            // Find documented parameters
            var docParamMatches = ParamRefPattern.Matches(xmlDoc);
            foreach (Match match in docParamMatches)
            {
                var docParamName = match.Groups[1].Value;
                if (!actualParams.Contains(docParamName))
                {
                    var (startLine, endLine) = GetLineSpan(method.Identifier);
                    issues.Add(CreateIssue(
                        DocumentationIssueType.MismatchedParamDoc,
                        DocIssueSeverity.Minor,
                        filePath,
                        startLine,
                        endLine,
                        $"{method.Identifier.Text}.{docParamName}",
                        "Parameter",
                        $"Documentation references parameter '{docParamName}' which does not exist in method '{method.Identifier.Text}'",
                        "Remove the stale parameter documentation or correct the parameter name",
                        currentCode: $"<param name=\"{docParamName}\">",
                        confidence: 95));
                }
            }
        }

        // Check constructors
        foreach (var ctor in root.DescendantNodes().OfType<ConstructorDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(ctor);
            if (symbol == null) continue;

            var xmlDoc = symbol.GetDocumentationCommentXml();
            if (string.IsNullOrEmpty(xmlDoc)) continue;

            var actualParams = symbol.Parameters.Select(p => p.Name).ToHashSet();

            var docParamMatches = ParamRefPattern.Matches(xmlDoc);
            foreach (Match match in docParamMatches)
            {
                var docParamName = match.Groups[1].Value;
                if (!actualParams.Contains(docParamName))
                {
                    var (startLine, endLine) = GetLineSpan(ctor.Identifier);
                    issues.Add(CreateIssue(
                        DocumentationIssueType.MismatchedParamDoc,
                        DocIssueSeverity.Minor,
                        filePath,
                        startLine,
                        endLine,
                        $"{ctor.Identifier.Text}.{docParamName}",
                        "Parameter",
                        $"Constructor documentation references parameter '{docParamName}' which does not exist",
                        "Remove the stale parameter documentation or correct the parameter name",
                        currentCode: $"<param name=\"{docParamName}\">",
                        confidence: 95));
                }
            }
        }

        return Task.FromResult(issues);
    }

    private Task<List<DocumentationIssue>> DetectStaleSeeRefsAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        // Collect all symbols in the compilation
        var allSymbolNames = new HashSet<string>();

        foreach (var typeDecl in root.DescendantNodes().OfType<TypeDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(typeDecl);
            if (symbol != null)
            {
                allSymbolNames.Add(symbol.Name);
                allSymbolNames.Add(symbol.ToDisplayString());

                foreach (var member in symbol.GetMembers())
                {
                    allSymbolNames.Add(member.Name);
                    allSymbolNames.Add(member.ToDisplayString());
                }
            }
        }

        // Check documentation for stale see references
        foreach (var node in root.DescendantNodes())
        {
            ISymbol? symbol = node switch
            {
                TypeDeclarationSyntax t => semanticModel.GetDeclaredSymbol(t),
                MethodDeclarationSyntax m => semanticModel.GetDeclaredSymbol(m),
                PropertyDeclarationSyntax p => semanticModel.GetDeclaredSymbol(p),
                _ => null
            };

            if (symbol == null) continue;

            var xmlDoc = symbol.GetDocumentationCommentXml();
            if (string.IsNullOrEmpty(xmlDoc)) continue;

            var seeMatches = SeeRefPattern.Matches(xmlDoc);
            foreach (Match match in seeMatches)
            {
                var cref = match.Groups[1].Value;

                // Extract the simple name from cref (e.g., "T:Namespace.TypeName" -> "TypeName")
                var simpleName = cref;
                if (cref.Contains('.'))
                {
                    simpleName = cref.Split('.').Last();
                }
                if (cref.Contains(':'))
                {
                    simpleName = cref.Split(':').Last();
                    if (simpleName.Contains('.'))
                    {
                        simpleName = simpleName.Split('.').Last();
                    }
                }

                // Remove parentheses for method references
                if (simpleName.Contains('('))
                {
                    simpleName = simpleName.Split('(')[0];
                }

                // This is a heuristic check - if the name looks like it might be stale
                if (!allSymbolNames.Contains(simpleName) &&
                    !IsWellKnownType(simpleName) &&
                    !cref.StartsWith("System.") &&
                    !cref.StartsWith("Microsoft."))
                {
                    var (startLine, endLine) = GetLineSpan(node);
                    issues.Add(CreateIssue(
                        DocumentationIssueType.ObsoleteReference,
                        DocIssueSeverity.Warning,
                        filePath,
                        startLine,
                        endLine,
                        symbol.Name,
                        GetSymbolKind(symbol),
                        $"Documentation references '{cref}' which may not exist",
                        "Verify the reference exists or update the documentation",
                        currentCode: $"<see cref=\"{cref}\"/>",
                        confidence: 60)); // Lower confidence since we can't verify all external references
                }
            }
        }

        return Task.FromResult(issues);
    }

    private List<DocumentationIssue> DetectCommentedOutCode(SyntaxNode root, string filePath)
    {
        var issues = new List<DocumentationIssue>();

        // Pattern matching for commented out code
        var codePatterns = new[]
        {
            new Regex(@"^\s*//\s*(if|else|for|foreach|while|switch|return|var|public|private|protected|class|struct|interface)\s", RegexOptions.Compiled),
            new Regex(@"^\s*//\s*\w+\s*[=<>!]+\s*\w+", RegexOptions.Compiled), // Assignment or comparison
            new Regex(@"^\s*//\s*\w+\s*\.\s*\w+\s*\(", RegexOptions.Compiled), // Method call
            new Regex(@"^\s*//\s*\w+\s*\(.*\)\s*;", RegexOptions.Compiled), // Function call with semicolon
        };

        var consecutiveCodeLines = new List<(int Line, string Text)>();
        var lastCodeLine = -1;

        foreach (var trivia in root.DescendantTrivia().Where(t => t.IsKind(SyntaxKind.SingleLineCommentTrivia)))
        {
            var text = trivia.ToString();
            var location = trivia.GetLocation().GetLineSpan();
            var line = location.StartLinePosition.Line + 1;

            var looksLikeCode = codePatterns.Any(p => p.IsMatch(text));

            if (looksLikeCode)
            {
                if (lastCodeLine == line - 1 || lastCodeLine == -1)
                {
                    consecutiveCodeLines.Add((line, text.TrimStart('/', ' ')));
                    lastCodeLine = line;
                }
                else
                {
                    // Process previous block if it has multiple lines
                    if (consecutiveCodeLines.Count >= 3)
                    {
                        ReportCommentedCodeBlock(issues, filePath, consecutiveCodeLines);
                    }

                    consecutiveCodeLines.Clear();
                    consecutiveCodeLines.Add((line, text.TrimStart('/', ' ')));
                    lastCodeLine = line;
                }
            }
        }

        // Process final block
        if (consecutiveCodeLines.Count >= 3)
        {
            ReportCommentedCodeBlock(issues, filePath, consecutiveCodeLines);
        }

        // Check for block comments with code
        foreach (var trivia in root.DescendantTrivia().Where(t => t.IsKind(SyntaxKind.MultiLineCommentTrivia)))
        {
            var text = trivia.ToString();
            var location = trivia.GetLocation().GetLineSpan();
            var startLine = location.StartLinePosition.Line + 1;
            var endLine = location.EndLinePosition.Line + 1;

            // Check if it contains multiple code-like lines
            var lines = text.Split('\n');
            var codeLikeLines = lines.Count(line =>
                codePatterns.Any(p => p.IsMatch("// " + line.Trim('/', '*', ' '))));

            if (codeLikeLines >= 3)
            {
                issues.Add(CreateIssue(
                    DocumentationIssueType.StaleComment,
                    DocIssueSeverity.Warning,
                    filePath,
                    startLine,
                    endLine,
                    "CommentedCode",
                    "Comment",
                    $"Block of commented-out code detected ({codeLikeLines} lines)",
                    "Remove commented-out code or use version control instead",
                    currentCode: text.Length > 200 ? text[..200] + "..." : text,
                    confidence: 75));
            }
        }

        return issues;
    }

    private void ReportCommentedCodeBlock(
        List<DocumentationIssue> issues,
        string filePath,
        List<(int Line, string Text)> lines)
    {
        var startLine = lines.First().Line;
        var endLine = lines.Last().Line;
        var preview = string.Join("\n", lines.Take(3).Select(l => l.Text));

        issues.Add(CreateIssue(
            DocumentationIssueType.StaleComment,
            DocIssueSeverity.Warning,
            filePath,
            startLine,
            endLine,
            "CommentedCode",
            "Comment",
            $"Block of commented-out code detected ({lines.Count} lines)",
            "Remove commented-out code or use version control instead",
            currentCode: preview + (lines.Count > 3 ? "\n..." : ""),
            confidence: 80));
    }

    private Task<List<DocumentationIssue>> DetectContradictingCommentsAsync(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var issues = new List<DocumentationIssue>();

        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            var symbol = semanticModel.GetDeclaredSymbol(method);
            if (symbol == null) continue;

            var xmlDoc = symbol.GetDocumentationCommentXml();
            if (string.IsNullOrEmpty(xmlDoc)) continue;

            var (startLine, endLine) = GetLineSpan(method.Identifier);
            var methodName = method.Identifier.Text;

            // Check if documentation says "returns" something but method is void
            if (symbol.ReturnsVoid)
            {
                var returnsMatch = Regex.Match(xmlDoc, @"<returns>([^<]+)</returns>", RegexOptions.IgnoreCase);
                if (returnsMatch.Success)
                {
                    var returnDesc = returnsMatch.Groups[1].Value.Trim();
                    if (!string.IsNullOrEmpty(returnDesc) && !returnDesc.Equals("void", StringComparison.OrdinalIgnoreCase))
                    {
                        issues.Add(CreateIssue(
                            DocumentationIssueType.StaleComment,
                            DocIssueSeverity.Minor,
                            filePath,
                            startLine,
                            endLine,
                            methodName,
                            "Method",
                            $"Method '{methodName}' is void but has <returns> documentation: \"{returnDesc}\"",
                            "Remove the <returns> tag since the method returns void",
                            confidence: 90));
                    }
                }
            }

            // Check if documentation mentions async but method is not async
            if (xmlDoc.Contains("asynchronous", StringComparison.OrdinalIgnoreCase) ||
                xmlDoc.Contains("async", StringComparison.OrdinalIgnoreCase))
            {
                if (!symbol.IsAsync && !symbol.ReturnType.Name.StartsWith("Task"))
                {
                    issues.Add(CreateIssue(
                        DocumentationIssueType.StaleComment,
                        DocIssueSeverity.Warning,
                        filePath,
                        startLine,
                        endLine,
                        methodName,
                        "Method",
                        $"Documentation mentions async/asynchronous but method '{methodName}' is synchronous",
                        "Update documentation to reflect the actual behavior or make the method async",
                        confidence: 70));
                }
            }

            // Check for "throws" documentation when no exceptions are possible
            if (xmlDoc.Contains("<exception", StringComparison.OrdinalIgnoreCase))
            {
                // Check if the method body contains any throw statements
                var hasThrow = method.DescendantNodes().Any(n => n is ThrowStatementSyntax || n is ThrowExpressionSyntax);
                if (!hasThrow && method.Body != null)
                {
                    // This is a lower confidence issue since exceptions could be thrown by called methods
                    issues.Add(CreateIssue(
                        DocumentationIssueType.StaleComment,
                        DocIssueSeverity.Info,
                        filePath,
                        startLine,
                        endLine,
                        methodName,
                        "Method",
                        $"Method '{methodName}' has exception documentation but contains no throw statements",
                        "Verify if the exception documentation is still accurate",
                        confidence: 40));
                }
            }
        }

        return Task.FromResult(issues);
    }

    private static bool IsWellKnownType(string name)
    {
        var wellKnownTypes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Object", "String", "Int32", "Boolean", "Double", "Decimal",
            "DateTime", "DateTimeOffset", "TimeSpan", "Guid",
            "List", "Dictionary", "IEnumerable", "IList", "ICollection",
            "Task", "ValueTask", "CancellationToken",
            "Exception", "ArgumentException", "InvalidOperationException",
            "Action", "Func", "Predicate",
            "EventHandler", "EventArgs"
        };

        return wellKnownTypes.Contains(name);
    }

    private static string GetSymbolKind(ISymbol symbol)
    {
        return symbol switch
        {
            INamedTypeSymbol => "Type",
            IMethodSymbol => "Method",
            IPropertySymbol => "Property",
            IFieldSymbol => "Field",
            IEventSymbol => "Event",
            IParameterSymbol => "Parameter",
            _ => "Symbol"
        };
    }
}
