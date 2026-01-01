using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Security;

/// <summary>
/// Detects various injection vulnerabilities: SQL, Command, LDAP, XPath, Log injection.
/// </summary>
public class InjectionDetector : ISecurityDetector
{
    public string Category => "Injection";

    private static readonly HashSet<string> SqlCommandTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.Data.SqlClient.SqlCommand",
        "Microsoft.Data.SqlClient.SqlCommand",
        "System.Data.Common.DbCommand",
        "System.Data.IDbCommand",
        "MySql.Data.MySqlClient.MySqlCommand",
        "Npgsql.NpgsqlCommand",
        "System.Data.OleDb.OleDbCommand",
        "System.Data.Odbc.OdbcCommand"
    };

    private static readonly HashSet<string> DangerousProcessMethods = new()
    {
        "Start", "StartInfo"
    };

    public Task<List<SecurityVulnerability>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context)
    {
        var vulnerabilities = new List<SecurityVulnerability>();
        var filePath = document.FilePath ?? "";

        // SQL Injection
        DetectSqlInjection(root, semanticModel, filePath, vulnerabilities);

        // Command Injection
        DetectCommandInjection(root, semanticModel, filePath, vulnerabilities);

        // Log Injection
        DetectLogInjection(root, semanticModel, filePath, vulnerabilities);

        // LDAP Injection
        DetectLdapInjection(root, semanticModel, filePath, vulnerabilities);

        // XPath Injection
        DetectXPathInjection(root, semanticModel, filePath, vulnerabilities);

        return Task.FromResult(vulnerabilities);
    }

    private void DetectSqlInjection(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Find SQL command constructions with string concatenation
        foreach (var creation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            var typeInfo = semanticModel.GetTypeInfo(creation);
            var typeName = typeInfo.Type?.ToDisplayString() ?? "";

            if (!SqlCommandTypes.Contains(typeName))
                continue;

            // Check constructor arguments for string concatenation
            if (creation.ArgumentList?.Arguments.Count > 0)
            {
                var firstArg = creation.ArgumentList.Arguments[0].Expression;
                if (IsPotentiallyTaintedString(firstArg, semanticModel))
                {
                    ReportSqlInjection(creation, firstArg, filePath, vulnerabilities);
                }
            }
        }

        // Find CommandText property assignments with concatenation
        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is MemberAccessExpressionSyntax memberAccess)
            {
                if (memberAccess.Name.Identifier.Text == "CommandText")
                {
                    if (IsPotentiallyTaintedString(assignment.Right, semanticModel))
                    {
                        ReportSqlInjection(assignment, assignment.Right, filePath, vulnerabilities);
                    }
                }
            }
        }

        // Find ExecuteSql/FromSqlRaw with string concatenation (EF Core)
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var methodName = memberAccess.Name.Identifier.Text;
                if (methodName is "ExecuteSqlRaw" or "FromSqlRaw" or "ExecuteSql" or "FromSql")
                {
                    if (invocation.ArgumentList.Arguments.Count > 0)
                    {
                        var firstArg = invocation.ArgumentList.Arguments[0].Expression;
                        if (IsPotentiallyTaintedString(firstArg, semanticModel))
                        {
                            ReportSqlInjection(invocation, firstArg, filePath, vulnerabilities);
                        }
                    }
                }
            }
        }
    }

    private void ReportSqlInjection(
        SyntaxNode node,
        ExpressionSyntax taintedExpr,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        var lineSpan = node.GetLocation().GetLineSpan();
        vulnerabilities.Add(new SecurityVulnerability
        {
            VulnerabilityType = "SQL Injection",
            Severity = "Critical",
            CweId = "CWE-89",
            FilePath = filePath,
            StartLine = lineSpan.StartLinePosition.Line + 1,
            EndLine = lineSpan.EndLinePosition.Line + 1,
            Description = "SQL query constructed using string concatenation or interpolation. This may allow SQL injection attacks.",
            Recommendation = "Use parameterized queries with SqlParameter or Entity Framework's parameterized methods.",
            VulnerableCode = node.ToFullString().Trim(),
            SecureCode = "// Use parameterized query:\n// cmd.CommandText = \"SELECT * FROM Users WHERE Id = @id\";\n// cmd.Parameters.AddWithValue(\"@id\", userId);",
            Confidence = "High"
        });
    }

    private void DetectCommandInjection(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
            if (symbol == null)
                continue;

            var typeName = symbol.ContainingType?.ToDisplayString() ?? "";

            // Process.Start with potentially tainted arguments
            if (typeName == "System.Diagnostics.Process" && symbol.Name == "Start")
            {
                if (invocation.ArgumentList.Arguments.Count > 0)
                {
                    var firstArg = invocation.ArgumentList.Arguments[0].Expression;
                    if (IsPotentiallyTaintedString(firstArg, semanticModel))
                    {
                        var lineSpan = invocation.GetLocation().GetLineSpan();
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            VulnerabilityType = "Command Injection",
                            Severity = "Critical",
                            CweId = "CWE-78",
                            FilePath = filePath,
                            StartLine = lineSpan.StartLinePosition.Line + 1,
                            EndLine = lineSpan.EndLinePosition.Line + 1,
                            Description = "Process started with potentially user-controlled input. This may allow command injection attacks.",
                            Recommendation = "Validate and sanitize all input. Use a whitelist of allowed commands. Avoid shell execution when possible.",
                            VulnerableCode = invocation.ToFullString().Trim(),
                            SecureCode = "// Validate input against whitelist\n// Use ProcessStartInfo.UseShellExecute = false\n// Escape special characters",
                            Confidence = "High"
                        });
                    }
                }
            }

            // ProcessStartInfo.FileName or Arguments assignment
            if (typeName == "System.Diagnostics.ProcessStartInfo")
            {
                // This is handled by property assignments below
            }
        }

        // Check ProcessStartInfo property assignments
        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is MemberAccessExpressionSyntax memberAccess)
            {
                var propName = memberAccess.Name.Identifier.Text;
                if (propName is "FileName" or "Arguments")
                {
                    var symbol = semanticModel.GetSymbolInfo(memberAccess).Symbol as IPropertySymbol;
                    if (symbol?.ContainingType?.ToDisplayString() == "System.Diagnostics.ProcessStartInfo")
                    {
                        if (IsPotentiallyTaintedString(assignment.Right, semanticModel))
                        {
                            var lineSpan = assignment.GetLocation().GetLineSpan();
                            vulnerabilities.Add(new SecurityVulnerability
                            {
                                VulnerabilityType = "Command Injection",
                                Severity = "Critical",
                                CweId = "CWE-78",
                                FilePath = filePath,
                                StartLine = lineSpan.StartLinePosition.Line + 1,
                                EndLine = lineSpan.EndLinePosition.Line + 1,
                                Description = $"ProcessStartInfo.{propName} set with potentially user-controlled input.",
                                Recommendation = "Validate and sanitize all input before using in process execution.",
                                VulnerableCode = assignment.ToFullString().Trim(),
                                SecureCode = "// Validate input, use whitelist, escape special characters",
                                Confidence = "High"
                            });
                        }
                    }
                }
            }
        }
    }

    private void DetectLogInjection(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        var logMethods = new HashSet<string> { "Log", "LogInformation", "LogWarning", "LogError",
            "LogDebug", "LogTrace", "LogCritical", "Info", "Warn", "Error", "Debug", "Fatal" };

        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var methodName = memberAccess.Name.Identifier.Text;
                if (!logMethods.Contains(methodName))
                    continue;

                // Check if any argument contains string concatenation with potential user input
                foreach (var arg in invocation.ArgumentList.Arguments)
                {
                    if (ContainsNewlineInTaintedString(arg.Expression, semanticModel))
                    {
                        var lineSpan = invocation.GetLocation().GetLineSpan();
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            VulnerabilityType = "Log Injection",
                            Severity = "Medium",
                            CweId = "CWE-117",
                            FilePath = filePath,
                            StartLine = lineSpan.StartLinePosition.Line + 1,
                            EndLine = lineSpan.EndLinePosition.Line + 1,
                            Description = "User input logged without sanitization. Attackers may inject fake log entries or corrupt log files.",
                            Recommendation = "Sanitize user input before logging. Remove or encode newlines and control characters.",
                            VulnerableCode = invocation.ToFullString().Trim(),
                            SecureCode = "// Sanitize input: input.Replace(\"\\n\", \" \").Replace(\"\\r\", \" \")",
                            Confidence = "Medium"
                        });
                        break;
                    }
                }
            }
        }
    }

    private void DetectLdapInjection(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        foreach (var creation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            var typeInfo = semanticModel.GetTypeInfo(creation);
            var typeName = typeInfo.Type?.ToDisplayString() ?? "";

            if (typeName.Contains("DirectorySearcher") || typeName.Contains("DirectoryEntry"))
            {
                // Check Filter property assignments
                foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
                {
                    if (assignment.Left is MemberAccessExpressionSyntax memberAccess &&
                        memberAccess.Name.Identifier.Text == "Filter")
                    {
                        if (IsPotentiallyTaintedString(assignment.Right, semanticModel))
                        {
                            var lineSpan = assignment.GetLocation().GetLineSpan();
                            vulnerabilities.Add(new SecurityVulnerability
                            {
                                VulnerabilityType = "LDAP Injection",
                                Severity = "High",
                                CweId = "CWE-90",
                                FilePath = filePath,
                                StartLine = lineSpan.StartLinePosition.Line + 1,
                                EndLine = lineSpan.EndLinePosition.Line + 1,
                                Description = "LDAP filter constructed with potentially user-controlled input.",
                                Recommendation = "Escape special LDAP characters: *, (, ), \\, NUL. Use parameterized LDAP queries if available.",
                                VulnerableCode = assignment.ToFullString().Trim(),
                                SecureCode = "// Escape special characters: \\28 for (, \\29 for ), \\2a for *, \\5c for \\",
                                Confidence = "High"
                            });
                        }
                    }
                }
            }
        }
    }

    private void DetectXPathInjection(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        var xpathMethods = new HashSet<string> { "SelectNodes", "SelectSingleNode", "Compile", "Evaluate" };

        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var methodName = memberAccess.Name.Identifier.Text;
                if (!xpathMethods.Contains(methodName))
                    continue;

                var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                var typeName = symbol?.ContainingType?.ToDisplayString() ?? "";

                if (typeName.Contains("XmlNode") || typeName.Contains("XPathNavigator") ||
                    typeName.Contains("XPathExpression"))
                {
                    if (invocation.ArgumentList.Arguments.Count > 0)
                    {
                        var firstArg = invocation.ArgumentList.Arguments[0].Expression;
                        if (IsPotentiallyTaintedString(firstArg, semanticModel))
                        {
                            var lineSpan = invocation.GetLocation().GetLineSpan();
                            vulnerabilities.Add(new SecurityVulnerability
                            {
                                VulnerabilityType = "XPath Injection",
                                Severity = "High",
                                CweId = "CWE-643",
                                FilePath = filePath,
                                StartLine = lineSpan.StartLinePosition.Line + 1,
                                EndLine = lineSpan.EndLinePosition.Line + 1,
                                Description = "XPath query constructed with potentially user-controlled input.",
                                Recommendation = "Use parameterized XPath queries or validate/escape user input.",
                                VulnerableCode = invocation.ToFullString().Trim(),
                                SecureCode = "// Use XPathExpression.Compile with validated input\n// Or escape special characters: ', \", <, >, &",
                                Confidence = "High"
                            });
                        }
                    }
                }
            }
        }
    }

    private bool IsPotentiallyTaintedString(ExpressionSyntax expr, SemanticModel semanticModel)
    {
        // String concatenation
        if (expr is BinaryExpressionSyntax binary && binary.Kind() == SyntaxKind.AddExpression)
        {
            var typeInfo = semanticModel.GetTypeInfo(binary);
            if (typeInfo.Type?.SpecialType == SpecialType.System_String)
                return true;
        }

        // String interpolation
        if (expr is InterpolatedStringExpressionSyntax)
            return true;

        // string.Format
        if (expr is InvocationExpressionSyntax invocation &&
            invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
            memberAccess.Name.Identifier.Text == "Format")
        {
            return true;
        }

        // Variable that might contain user input (heuristic)
        if (expr is IdentifierNameSyntax identifier)
        {
            var name = identifier.Identifier.Text.ToLowerInvariant();
            var taintedNames = new[] { "input", "query", "user", "request", "param", "arg", "data", "value", "text", "name", "id" };
            if (taintedNames.Any(t => name.Contains(t)))
                return true;
        }

        return false;
    }

    private bool ContainsNewlineInTaintedString(ExpressionSyntax expr, SemanticModel semanticModel)
    {
        // Check if the expression could contain user input that might have newlines
        return IsPotentiallyTaintedString(expr, semanticModel);
    }
}
