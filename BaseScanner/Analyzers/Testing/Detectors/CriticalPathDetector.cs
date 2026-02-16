using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Testing.Models;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Testing.Detectors;

/// <summary>
/// Detects critical code paths (security, error handling, data validation) that lack test coverage.
/// Identifies security-sensitive code, authentication/authorization logic, and data processing
/// that should be thoroughly tested.
/// </summary>
public class CriticalPathDetector : TestDetectorBase, ICriticalPathDetector
{
    public override string Category => "CriticalPath";
    public override string Description => "Identifies critical code paths without test coverage";

    public IReadOnlyList<CriticalPathType> DetectablePathTypes => new[]
    {
        CriticalPathType.Authentication,
        CriticalPathType.Authorization,
        CriticalPathType.DataValidation,
        CriticalPathType.SqlQuery,
        CriticalPathType.FileAccess,
        CriticalPathType.NetworkAccess,
        CriticalPathType.Cryptography,
        CriticalPathType.Deserialization,
        CriticalPathType.ErrorHandling,
        CriticalPathType.FinancialCalculation,
        CriticalPathType.PersonalDataProcessing,
        CriticalPathType.ConfigurationLoading,
        CriticalPathType.ExternalApiCall,
        CriticalPathType.DataPersistence
    };

    public override async Task<TestDetectionResult> DetectAsync(
        Project project,
        RawCoverageData? coverageData,
        CodeContext context)
    {
        var criticalPaths = new List<CriticalPathWithoutTests>();

        // Build set of tested methods
        var testedMethods = await BuildTestedMethodsSetAsync(project);

        // Build coverage lookup
        var coverageLookup = coverageData != null
            ? BuildCoverageLookup(coverageData)
            : new Dictionary<string, HashSet<int>>();

        foreach (var document in project.Documents)
        {
            if (ShouldSkipFile(document.FilePath))
                continue;

            if (IsTestFile(document.FilePath))
                continue;

            var semanticModel = await document.GetSemanticModelAsync();
            var root = await document.GetSyntaxRootAsync();

            if (semanticModel == null || root == null)
                continue;

            // Analyze each method for critical paths
            foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                var symbol = semanticModel.GetDeclaredSymbol(method);
                if (symbol == null || symbol.IsImplicitlyDeclared)
                    continue;

                // Check if this method is tested
                var isTested = IsMethodTested(method, symbol, testedMethods, coverageLookup, document.FilePath!);

                if (isTested)
                    continue;

                // Identify critical path types in this method
                var detectedPaths = DetectCriticalPaths(method, symbol, document, semanticModel);
                criticalPaths.AddRange(detectedPaths);
            }
        }

        return new TestDetectionResult
        {
            DetectorName = Category,
            Smells = [],
            QualityIssues = [],
            CriticalPaths = criticalPaths
                .OrderBy(p => SeverityOrder(p.Severity))
                .ThenBy(p => p.PathType)
                .ToList(),
            UncoveredMethods = [],
            UncoveredBranches = []
        };
    }

    private async Task<HashSet<string>> BuildTestedMethodsSetAsync(Project project)
    {
        var testedMethods = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var document in project.Documents)
        {
            if (!IsTestFile(document.FilePath))
                continue;

            var root = await document.GetSyntaxRootAsync();
            if (root == null)
                continue;

            // Find method calls in test methods
            foreach (var testMethod in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                if (!IsTestMethod(testMethod))
                    continue;

                foreach (var invocation in testMethod.DescendantNodes().OfType<InvocationExpressionSyntax>())
                {
                    if (invocation.Expression is MemberAccessExpressionSyntax ma)
                    {
                        testedMethods.Add(ma.Name.ToString());
                    }
                    else if (invocation.Expression is IdentifierNameSyntax id)
                    {
                        testedMethods.Add(id.Identifier.Text);
                    }
                }
            }
        }

        return testedMethods;
    }

    private Dictionary<string, HashSet<int>> BuildCoverageLookup(RawCoverageData coverageData)
    {
        var lookup = new Dictionary<string, HashSet<int>>(StringComparer.OrdinalIgnoreCase);

        foreach (var module in coverageData.Modules)
        {
            foreach (var file in module.Files)
            {
                if (string.IsNullOrEmpty(file.FilePath))
                    continue;

                var normalizedPath = NormalizePath(file.FilePath);
                if (!lookup.ContainsKey(normalizedPath))
                    lookup[normalizedPath] = new HashSet<int>();

                foreach (var (line, hits) in file.LineHits)
                {
                    if (hits > 0)
                        lookup[normalizedPath].Add(line);
                }
            }
        }

        return lookup;
    }

    private bool IsMethodTested(
        MethodDeclarationSyntax method,
        IMethodSymbol symbol,
        HashSet<string> testedMethods,
        Dictionary<string, HashSet<int>> coverageLookup,
        string filePath)
    {
        // Check if method name appears in test invocations
        if (testedMethods.Contains(symbol.Name))
            return true;

        // Check coverage data
        var normalizedPath = NormalizePath(filePath);
        if (coverageLookup.TryGetValue(normalizedPath, out var coveredLines))
        {
            var (startLine, endLine) = GetLineSpan(method);
            for (var line = startLine; line <= endLine; line++)
            {
                if (coveredLines.Contains(line))
                    return true;
            }
        }

        return false;
    }

    private List<CriticalPathWithoutTests> DetectCriticalPaths(
        MethodDeclarationSyntax method,
        IMethodSymbol symbol,
        Document document,
        SemanticModel semanticModel)
    {
        var paths = new List<CriticalPathWithoutTests>();
        var (startLine, endLine) = GetLineSpan(method);
        var methodName = symbol.Name;
        var className = symbol.ContainingType?.Name ?? "Unknown";

        // Check each critical path type
        if (IsAuthenticationCode(method, symbol))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.Authentication,
                "Authentication logic without tests",
                "High risk - authentication bypass could allow unauthorized access",
                new[] {
                    "Test valid credentials return success",
                    "Test invalid credentials return failure",
                    "Test account lockout after failed attempts",
                    "Test session management"
                }));
        }

        if (IsAuthorizationCode(method, symbol))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.Authorization,
                "Authorization logic without tests",
                "High risk - authorization bypass could allow privilege escalation",
                new[] {
                    "Test authorized users can access resource",
                    "Test unauthorized users are denied",
                    "Test role-based access control",
                    "Test permission inheritance"
                }));
        }

        if (IsDataValidation(method, symbol))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.DataValidation,
                "Data validation without tests",
                "Medium risk - invalid data could cause errors or security issues",
                new[] {
                    "Test with null input",
                    "Test with empty input",
                    "Test with boundary values",
                    "Test with malformed input"
                }));
        }

        if (IsSqlQuery(method, semanticModel))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.SqlQuery,
                "SQL query execution without tests",
                "Critical risk - SQL injection vulnerability if not parameterized",
                new[] {
                    "Test with parameterized queries",
                    "Test SQL injection prevention",
                    "Test with special characters in input",
                    "Test transaction handling"
                }));
        }

        if (IsFileAccess(method, semanticModel))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.FileAccess,
                "File system access without tests",
                "Medium risk - path traversal or unauthorized file access",
                new[] {
                    "Test path traversal prevention",
                    "Test file permission handling",
                    "Test with non-existent files",
                    "Test with locked files"
                }));
        }

        if (IsNetworkAccess(method, semanticModel))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.NetworkAccess,
                "Network access without tests",
                "Medium risk - network errors or security issues",
                new[] {
                    "Test connection timeout handling",
                    "Test certificate validation",
                    "Test retry logic",
                    "Test with mock server responses"
                }));
        }

        if (IsCryptography(method, semanticModel))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.Cryptography,
                "Cryptographic operations without tests",
                "Critical risk - weak crypto could expose sensitive data",
                new[] {
                    "Test encryption/decryption roundtrip",
                    "Test with known test vectors",
                    "Test key management",
                    "Test handling of corrupted data"
                }));
        }

        if (IsDeserialization(method, semanticModel))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.Deserialization,
                "Deserialization without tests",
                "Critical risk - unsafe deserialization could allow code execution",
                new[] {
                    "Test with valid serialized data",
                    "Test with malformed data",
                    "Test type safety",
                    "Test size limits"
                }));
        }

        if (IsErrorHandling(method))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.ErrorHandling,
                "Error handling without tests",
                "Medium risk - unhandled errors could crash application or leak information",
                new[] {
                    "Test exception is caught properly",
                    "Test error is logged",
                    "Test user receives appropriate error message",
                    "Test cleanup happens on error"
                }));
        }

        if (IsFinancialCalculation(method, symbol))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.FinancialCalculation,
                "Financial calculation without tests",
                "Critical risk - calculation errors could cause financial loss",
                new[] {
                    "Test with known expected results",
                    "Test decimal precision",
                    "Test rounding behavior",
                    "Test edge cases (zero, negative, overflow)"
                }));
        }

        if (IsPersonalDataProcessing(method, symbol))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.PersonalDataProcessing,
                "Personal data processing without tests",
                "High risk - privacy violations could have legal consequences",
                new[] {
                    "Test data is properly anonymized/encrypted",
                    "Test access controls are enforced",
                    "Test audit logging",
                    "Test data retention policies"
                }));
        }

        if (IsConfigurationLoading(method, symbol))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.ConfigurationLoading,
                "Configuration loading without tests",
                "Medium risk - misconfiguration could cause security issues",
                new[] {
                    "Test with missing configuration",
                    "Test with invalid values",
                    "Test default value handling",
                    "Test environment-specific configuration"
                }));
        }

        if (IsExternalApiCall(method, semanticModel))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.ExternalApiCall,
                "External API call without tests",
                "Medium risk - API failures could affect application stability",
                new[] {
                    "Test successful response handling",
                    "Test error response handling",
                    "Test timeout handling",
                    "Test rate limiting"
                }));
        }

        if (IsDataPersistence(method, semanticModel))
        {
            paths.Add(CreateCriticalPath(method, symbol, document, CriticalPathType.DataPersistence,
                "Data persistence without tests",
                "High risk - data loss or corruption",
                new[] {
                    "Test successful save/update/delete",
                    "Test concurrent access handling",
                    "Test transaction rollback",
                    "Test constraint violations"
                }));
        }

        return paths;
    }

    private CriticalPathWithoutTests CreateCriticalPath(
        MethodDeclarationSyntax method,
        IMethodSymbol symbol,
        Document document,
        CriticalPathType pathType,
        string description,
        string riskAssessment,
        string[] suggestedTests)
    {
        var (startLine, endLine) = GetLineSpan(method);

        return new CriticalPathWithoutTests
        {
            MethodName = symbol.Name,
            ClassName = symbol.ContainingType?.Name ?? "Unknown",
            FilePath = document.FilePath ?? "",
            StartLine = startLine,
            EndLine = endLine,
            PathType = pathType,
            Severity = GetPathTypeSeverity(pathType),
            Description = description,
            RiskAssessment = riskAssessment,
            SuggestedTests = suggestedTests.ToList()
        };
    }

    private bool IsAuthenticationCode(MethodDeclarationSyntax method, IMethodSymbol symbol)
    {
        var text = method.ToString().ToLowerInvariant();
        var name = symbol.Name.ToLowerInvariant();

        var authPatterns = new[]
        {
            "authenticate", "login", "logout", "signin", "signout",
            "password", "credential", "validateuser", "verifyuser"
        };

        return authPatterns.Any(p => name.Contains(p) || text.Contains(p));
    }

    private bool IsAuthorizationCode(MethodDeclarationSyntax method, IMethodSymbol symbol)
    {
        var text = method.ToString().ToLowerInvariant();
        var name = symbol.Name.ToLowerInvariant();

        // Check for authorize attribute
        foreach (var attr in method.AttributeLists.SelectMany(al => al.Attributes))
        {
            if (attr.Name.ToString().Contains("Authorize"))
                return true;
        }

        var authzPatterns = new[]
        {
            "authorize", "permission", "role", "claim", "policy",
            "isauthorized", "hasrole", "haspermission", "checkaccess"
        };

        return authzPatterns.Any(p => name.Contains(p) || text.Contains(p));
    }

    private bool IsDataValidation(MethodDeclarationSyntax method, IMethodSymbol symbol)
    {
        var text = method.ToString().ToLowerInvariant();
        var name = symbol.Name.ToLowerInvariant();

        var validationPatterns = new[]
        {
            "validate", "isvalid", "verify", "check", "sanitize",
            "argumentnullexception", "argumentexception", "validationexception"
        };

        return validationPatterns.Any(p => name.Contains(p) || text.Contains(p));
    }

    private bool IsSqlQuery(MethodDeclarationSyntax method, SemanticModel semanticModel)
    {
        var text = method.ToString();

        var sqlPatterns = new[]
        {
            "ExecuteNonQuery", "ExecuteReader", "ExecuteScalar",
            "SqlCommand", "SqlConnection", "DbCommand",
            "SELECT ", "INSERT ", "UPDATE ", "DELETE ",
            "FromSqlRaw", "ExecuteSqlRaw"
        };

        return sqlPatterns.Any(p => text.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsFileAccess(MethodDeclarationSyntax method, SemanticModel semanticModel)
    {
        var text = method.ToString();

        var filePatterns = new[]
        {
            "File.Read", "File.Write", "File.Create", "File.Delete", "File.Open",
            "FileStream", "StreamReader", "StreamWriter",
            "Directory.Create", "Directory.Delete", "Directory.GetFiles",
            "Path.Combine"
        };

        return filePatterns.Any(p => text.Contains(p));
    }

    private bool IsNetworkAccess(MethodDeclarationSyntax method, SemanticModel semanticModel)
    {
        var text = method.ToString();

        var networkPatterns = new[]
        {
            "HttpClient", "WebClient", "WebRequest",
            "TcpClient", "UdpClient", "Socket",
            "GetAsync", "PostAsync", "SendAsync",
            "DownloadString", "UploadString"
        };

        return networkPatterns.Any(p => text.Contains(p));
    }

    private bool IsCryptography(MethodDeclarationSyntax method, SemanticModel semanticModel)
    {
        var text = method.ToString();

        var cryptoPatterns = new[]
        {
            "Encrypt", "Decrypt", "HashAlgorithm", "SHA", "MD5", "AES",
            "RSA", "SymmetricAlgorithm", "AsymmetricAlgorithm",
            "ProtectedData", "HMAC", "RandomNumberGenerator"
        };

        return cryptoPatterns.Any(p => text.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsDeserialization(MethodDeclarationSyntax method, SemanticModel semanticModel)
    {
        var text = method.ToString();

        var deserializePatterns = new[]
        {
            "Deserialize", "FromJson", "FromXml",
            "JsonSerializer", "XmlSerializer", "BinaryFormatter",
            "JsonConvert.DeserializeObject", "Newtonsoft"
        };

        return deserializePatterns.Any(p => text.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsErrorHandling(MethodDeclarationSyntax method)
    {
        // Check for try-catch blocks
        return method.DescendantNodes().OfType<TryStatementSyntax>().Any();
    }

    private bool IsFinancialCalculation(MethodDeclarationSyntax method, IMethodSymbol symbol)
    {
        var text = method.ToString().ToLowerInvariant();
        var name = symbol.Name.ToLowerInvariant();

        var financialPatterns = new[]
        {
            "price", "amount", "total", "tax", "discount",
            "interest", "payment", "balance", "invoice",
            "currency", "money", "financial"
        };

        // Also check for decimal type usage in calculations
        var hasDecimalCalculation = method.DescendantNodes()
            .OfType<BinaryExpressionSyntax>()
            .Any(b => b.ToString().Contains("decimal"));

        return financialPatterns.Any(p => name.Contains(p) || text.Contains(p)) || hasDecimalCalculation;
    }

    private bool IsPersonalDataProcessing(MethodDeclarationSyntax method, IMethodSymbol symbol)
    {
        var text = method.ToString().ToLowerInvariant();
        var name = symbol.Name.ToLowerInvariant();

        var piiPatterns = new[]
        {
            "email", "phone", "address", "ssn", "socialsecurity",
            "creditcard", "passport", "license", "dateofbirth",
            "personaldata", "sensitivedata", "pii", "gdpr"
        };

        return piiPatterns.Any(p => name.Contains(p) || text.Contains(p));
    }

    private bool IsConfigurationLoading(MethodDeclarationSyntax method, IMethodSymbol symbol)
    {
        var text = method.ToString();
        var name = symbol.Name.ToLowerInvariant();

        var configPatterns = new[]
        {
            "LoadConfig", "GetConfiguration", "ReadSettings",
            "IConfiguration", "ConfigurationManager", "AppSettings",
            "Environment.GetEnvironmentVariable"
        };

        return configPatterns.Any(p =>
            name.Contains(p.ToLowerInvariant()) ||
            text.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsExternalApiCall(MethodDeclarationSyntax method, SemanticModel semanticModel)
    {
        var text = method.ToString();

        // Check for HTTP client usage with external URLs
        var hasHttpClient = text.Contains("HttpClient") ||
                           text.Contains("RestClient") ||
                           text.Contains("WebRequest");

        var hasExternalUrl = text.Contains("http://") ||
                            text.Contains("https://") ||
                            text.Contains("api.");

        return hasHttpClient && hasExternalUrl;
    }

    private bool IsDataPersistence(MethodDeclarationSyntax method, SemanticModel semanticModel)
    {
        var text = method.ToString();
        var name = method.Identifier.Text.ToLowerInvariant();

        var persistencePatterns = new[]
        {
            "SaveChanges", "SaveChangesAsync",
            "Insert", "Update", "Delete", "Upsert",
            "Repository", "DbContext",
            "Add(", "Remove(", "Attach("
        };

        var persistenceNames = new[]
        {
            "save", "persist", "store", "create", "update", "delete", "remove"
        };

        return persistencePatterns.Any(p => text.Contains(p)) ||
               persistenceNames.Any(p => name.Contains(p));
    }

    private string GetPathTypeSeverity(CriticalPathType pathType)
    {
        return pathType switch
        {
            CriticalPathType.Authentication => TestIssueSeverity.Critical,
            CriticalPathType.Authorization => TestIssueSeverity.Critical,
            CriticalPathType.SqlQuery => TestIssueSeverity.Critical,
            CriticalPathType.Cryptography => TestIssueSeverity.Critical,
            CriticalPathType.Deserialization => TestIssueSeverity.Critical,
            CriticalPathType.FinancialCalculation => TestIssueSeverity.Critical,
            CriticalPathType.DataPersistence => TestIssueSeverity.High,
            CriticalPathType.PersonalDataProcessing => TestIssueSeverity.High,
            CriticalPathType.DataValidation => TestIssueSeverity.High,
            CriticalPathType.FileAccess => TestIssueSeverity.Medium,
            CriticalPathType.NetworkAccess => TestIssueSeverity.Medium,
            CriticalPathType.ErrorHandling => TestIssueSeverity.Medium,
            CriticalPathType.ConfigurationLoading => TestIssueSeverity.Medium,
            CriticalPathType.ExternalApiCall => TestIssueSeverity.Medium,
            _ => TestIssueSeverity.Low
        };
    }

    private int SeverityOrder(string severity) => severity switch
    {
        TestIssueSeverity.Critical => 0,
        TestIssueSeverity.High => 1,
        TestIssueSeverity.Medium => 2,
        TestIssueSeverity.Low => 3,
        _ => 4
    };

    private string NormalizePath(string path)
    {
        return path.Replace('\\', '/').ToLowerInvariant();
    }

    private bool IsTestFile(string? filePath)
    {
        if (string.IsNullOrEmpty(filePath))
            return false;

        var fileName = Path.GetFileNameWithoutExtension(filePath);
        return fileName.EndsWith("Tests") ||
               fileName.EndsWith("Test") ||
               fileName.EndsWith("Specs") ||
               fileName.EndsWith("Spec") ||
               filePath.Contains("Tests" + Path.DirectorySeparatorChar) ||
               filePath.Contains("Test" + Path.DirectorySeparatorChar);
    }
}
