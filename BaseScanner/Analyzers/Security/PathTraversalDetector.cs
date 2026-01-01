using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Security;

/// <summary>
/// Detects path traversal vulnerabilities in file operations.
/// </summary>
public class PathTraversalDetector : ISecurityDetector
{
    public string Category => "Path Traversal";

    private static readonly HashSet<string> FileOperationMethods = new()
    {
        // File class
        "ReadAllText", "ReadAllBytes", "ReadAllLines", "ReadLines",
        "WriteAllText", "WriteAllBytes", "WriteAllLines",
        "OpenRead", "OpenWrite", "OpenText", "Open", "Create",
        "Delete", "Copy", "Move", "Exists",
        // Directory class
        "CreateDirectory", "Delete", "Exists", "GetFiles", "GetDirectories",
        "EnumerateFiles", "EnumerateDirectories", "Move",
        // FileStream
        "FileStream",
        // StreamReader/Writer
        "StreamReader", "StreamWriter",
        // Path operations that may be vulnerable when combined with file ops
        "Combine", "GetFullPath"
    };

    private static readonly HashSet<string> PathMethods = new()
    {
        "Combine", "Join", "GetFullPath", "GetRelativePath"
    };

    public Task<List<SecurityVulnerability>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context)
    {
        var vulnerabilities = new List<SecurityVulnerability>();
        var filePath = document.FilePath ?? "";

        // Detect file operations with potentially tainted paths
        DetectTaintedFileOperations(root, semanticModel, filePath, vulnerabilities);

        // Detect Path.Combine with user input without validation
        DetectUnsafePathCombine(root, semanticModel, filePath, vulnerabilities);

        // Detect missing path canonicalization
        DetectMissingCanonicalization(root, semanticModel, filePath, vulnerabilities);

        return Task.FromResult(vulnerabilities);
    }

    private void DetectTaintedFileOperations(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            string? methodName = null;
            string? className = null;

            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                methodName = memberAccess.Name.Identifier.Text;
                var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                className = symbol?.ContainingType?.Name;
            }

            if (methodName == null || className == null)
                continue;

            // Check if it's a file operation
            if ((className is "File" or "Directory" or "FileInfo" or "DirectoryInfo" or "FileStream") &&
                FileOperationMethods.Contains(methodName))
            {
                // Check first argument for potential taint
                if (invocation.ArgumentList.Arguments.Count > 0)
                {
                    var pathArg = invocation.ArgumentList.Arguments[0].Expression;
                    if (IsPotentiallyTaintedPath(pathArg, semanticModel))
                    {
                        var lineSpan = invocation.GetLocation().GetLineSpan();
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            VulnerabilityType = "Path Traversal",
                            Severity = "High",
                            CweId = "CWE-22",
                            FilePath = filePath,
                            StartLine = lineSpan.StartLinePosition.Line + 1,
                            EndLine = lineSpan.EndLinePosition.Line + 1,
                            Description = $"{className}.{methodName}() called with potentially user-controlled path. Attackers may access files outside the intended directory.",
                            Recommendation = "Validate and sanitize file paths. Use Path.GetFullPath() and verify the result starts with the expected base directory.",
                            VulnerableCode = invocation.ToFullString().Trim(),
                            SecureCode = GetSecureCodeSuggestion(methodName),
                            Confidence = "Medium"
                        });
                    }
                }
            }
        }

        // Check for FileStream constructor
        foreach (var creation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            var typeInfo = semanticModel.GetTypeInfo(creation);
            if (typeInfo.Type?.Name is "FileStream" or "StreamReader" or "StreamWriter")
            {
                if (creation.ArgumentList?.Arguments.Count > 0)
                {
                    var pathArg = creation.ArgumentList.Arguments[0].Expression;
                    if (IsPotentiallyTaintedPath(pathArg, semanticModel))
                    {
                        var lineSpan = creation.GetLocation().GetLineSpan();
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            VulnerabilityType = "Path Traversal",
                            Severity = "High",
                            CweId = "CWE-22",
                            FilePath = filePath,
                            StartLine = lineSpan.StartLinePosition.Line + 1,
                            EndLine = lineSpan.EndLinePosition.Line + 1,
                            Description = $"{typeInfo.Type.Name} created with potentially user-controlled path.",
                            Recommendation = "Validate file paths against a whitelist of allowed directories.",
                            VulnerableCode = creation.ToFullString().Trim(),
                            SecureCode = GetSecureCodeSuggestion("FileStream"),
                            Confidence = "Medium"
                        });
                    }
                }
            }
        }
    }

    private void DetectUnsafePathCombine(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
                PathMethods.Contains(memberAccess.Name.Identifier.Text))
            {
                var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                if (symbol?.ContainingType?.Name != "Path")
                    continue;

                // Check if any argument might be user-controlled
                var hasTaintedArg = invocation.ArgumentList.Arguments
                    .Skip(1) // Skip base path
                    .Any(arg => IsPotentiallyTaintedPath(arg.Expression, semanticModel));

                if (hasTaintedArg)
                {
                    // Check if result is validated
                    var parentMethod = invocation.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
                    if (parentMethod != null && !HasPathValidation(parentMethod, invocation))
                    {
                        var lineSpan = invocation.GetLocation().GetLineSpan();
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            VulnerabilityType = "Unsafe Path Combination",
                            Severity = "Medium",
                            CweId = "CWE-22",
                            FilePath = filePath,
                            StartLine = lineSpan.StartLinePosition.Line + 1,
                            EndLine = lineSpan.EndLinePosition.Line + 1,
                            Description = "Path.Combine/Join with user input without validation. Input like '../../../etc/passwd' can escape the base directory.",
                            Recommendation = "After combining paths, use GetFullPath() and verify the result starts with the expected base directory.",
                            VulnerableCode = invocation.ToFullString().Trim(),
                            SecureCode = "var fullPath = Path.GetFullPath(Path.Combine(baseDir, userInput));\nif (!fullPath.StartsWith(Path.GetFullPath(baseDir))) throw new SecurityException();",
                            Confidence = "Medium"
                        });
                    }
                }
            }
        }
    }

    private void DetectMissingCanonicalization(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Find methods that take path parameters and use them in file operations
        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            // Check if method has string parameters that look like paths
            var pathParams = method.ParameterList.Parameters
                .Where(p => IsLikelyPathParameter(p))
                .ToList();

            if (pathParams.Count == 0)
                continue;

            // Check if the parameter is used in file operations without GetFullPath
            foreach (var param in pathParams)
            {
                var paramName = param.Identifier.Text;
                var usages = method.DescendantNodes()
                    .OfType<IdentifierNameSyntax>()
                    .Where(id => id.Identifier.Text == paramName)
                    .ToList();

                var hasGetFullPath = usages.Any(u =>
                    u.Parent is ArgumentSyntax arg &&
                    arg.Parent?.Parent is InvocationExpressionSyntax inv &&
                    inv.Expression is MemberAccessExpressionSyntax ma &&
                    ma.Name.Identifier.Text == "GetFullPath");

                var hasFileOperation = usages.Any(u =>
                    u.Ancestors().OfType<InvocationExpressionSyntax>().Any(inv =>
                    {
                        if (inv.Expression is MemberAccessExpressionSyntax ma)
                        {
                            var symbol = semanticModel.GetSymbolInfo(inv).Symbol as IMethodSymbol;
                            return symbol?.ContainingType?.Name is "File" or "Directory" or "FileInfo" or "DirectoryInfo";
                        }
                        return false;
                    }));

                if (hasFileOperation && !hasGetFullPath)
                {
                    var lineSpan = param.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "Missing Path Canonicalization",
                        Severity = "Low",
                        CweId = "CWE-22",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = $"Path parameter '{paramName}' used in file operations without canonicalization. This may allow path traversal.",
                        Recommendation = "Use Path.GetFullPath() to canonicalize paths and validate against expected base directory.",
                        VulnerableCode = method.Identifier.Text + "(" + param.ToString() + ")",
                        SecureCode = "var canonicalPath = Path.GetFullPath(path);\nif (!canonicalPath.StartsWith(allowedBaseDir)) throw new ArgumentException();",
                        Confidence = "Low"
                    });
                }
            }
        }
    }

    private bool IsPotentiallyTaintedPath(ExpressionSyntax expr, SemanticModel semanticModel)
    {
        // Direct string concatenation
        if (expr is BinaryExpressionSyntax binary && binary.Kind() == SyntaxKind.AddExpression)
            return true;

        // String interpolation
        if (expr is InterpolatedStringExpressionSyntax)
            return true;

        // Variable with suspicious name
        if (expr is IdentifierNameSyntax identifier)
        {
            var name = identifier.Identifier.Text.ToLowerInvariant();
            var taintedPatterns = new[] { "input", "user", "request", "param", "file", "path", "name", "url", "query" };
            if (taintedPatterns.Any(p => name.Contains(p)))
                return true;
        }

        // Method parameter
        if (expr is IdentifierNameSyntax id)
        {
            var symbol = semanticModel.GetSymbolInfo(id).Symbol;
            if (symbol is IParameterSymbol)
                return true;
        }

        // Path.Combine result without validation
        if (expr is InvocationExpressionSyntax invocation &&
            invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
            PathMethods.Contains(memberAccess.Name.Identifier.Text))
        {
            return true;
        }

        return false;
    }

    private bool IsLikelyPathParameter(ParameterSyntax param)
    {
        var name = param.Identifier.Text.ToLowerInvariant();
        var pathPatterns = new[] { "path", "file", "directory", "dir", "folder", "filename", "filepath" };

        if (pathPatterns.Any(p => name.Contains(p)))
            return true;

        // Check type
        var typeName = param.Type?.ToString() ?? "";
        return typeName == "string" && pathPatterns.Any(p => name.Contains(p));
    }

    private bool HasPathValidation(MethodDeclarationSyntax method, InvocationExpressionSyntax pathCombine)
    {
        // Look for GetFullPath call after the Path.Combine
        // and a StartsWith check
        var hasGetFullPath = method.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Any(inv => inv.Expression is MemberAccessExpressionSyntax ma &&
                       ma.Name.Identifier.Text == "GetFullPath");

        var hasStartsWith = method.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Any(inv => inv.Expression is MemberAccessExpressionSyntax ma &&
                       ma.Name.Identifier.Text == "StartsWith");

        return hasGetFullPath && hasStartsWith;
    }

    private string GetSecureCodeSuggestion(string methodName)
    {
        return @"// Secure file access pattern:
var baseDir = Path.GetFullPath(""/allowed/directory"");
var requestedPath = Path.GetFullPath(Path.Combine(baseDir, userInput));
if (!requestedPath.StartsWith(baseDir + Path.DirectorySeparatorChar))
    throw new SecurityException(""Path traversal attempt detected"");
// Now safe to use requestedPath";
    }
}
