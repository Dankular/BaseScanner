using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Security;

/// <summary>
/// Detects weak cryptographic practices: weak algorithms, hardcoded keys/IVs, insecure random.
/// </summary>
public class CryptoAnalyzer : ISecurityDetector
{
    public string Category => "Cryptography";

    private static readonly HashSet<string> WeakHashAlgorithms = new(StringComparer.OrdinalIgnoreCase)
    {
        "MD5", "MD5Cng", "MD5CryptoServiceProvider",
        "SHA1", "SHA1Cng", "SHA1CryptoServiceProvider", "SHA1Managed"
    };

    private static readonly HashSet<string> WeakEncryptionAlgorithms = new(StringComparer.OrdinalIgnoreCase)
    {
        "DES", "DESCryptoServiceProvider",
        "TripleDES", "TripleDESCryptoServiceProvider",
        "RC2", "RC2CryptoServiceProvider"
    };

    private static readonly HashSet<string> SecureHashAlgorithms = new(StringComparer.OrdinalIgnoreCase)
    {
        "SHA256", "SHA384", "SHA512", "SHA256Managed", "SHA384Managed", "SHA512Managed",
        "SHA256Cng", "SHA384Cng", "SHA512Cng"
    };

    public Task<List<SecurityVulnerability>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context)
    {
        var vulnerabilities = new List<SecurityVulnerability>();
        var filePath = document.FilePath ?? "";

        // Detect weak hash algorithms
        DetectWeakHashAlgorithms(root, semanticModel, filePath, vulnerabilities);

        // Detect weak encryption algorithms
        DetectWeakEncryption(root, semanticModel, filePath, vulnerabilities);

        // Detect hardcoded cryptographic keys
        DetectHardcodedKeys(root, semanticModel, filePath, vulnerabilities);

        // Detect static/hardcoded IVs
        DetectHardcodedIV(root, semanticModel, filePath, vulnerabilities);

        // Detect insecure random number generation
        DetectInsecureRandom(root, semanticModel, filePath, vulnerabilities);

        // Detect missing salt in password hashing
        DetectMissingSalt(root, semanticModel, filePath, vulnerabilities);

        return Task.FromResult(vulnerabilities);
    }

    private void DetectWeakHashAlgorithms(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Check for direct creation: new MD5CryptoServiceProvider()
        foreach (var creation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            var typeInfo = semanticModel.GetTypeInfo(creation);
            var typeName = typeInfo.Type?.Name ?? "";

            if (WeakHashAlgorithms.Contains(typeName))
            {
                ReportWeakHash(creation, typeName, filePath, vulnerabilities);
            }
        }

        // Check for factory method: MD5.Create(), SHA1.Create()
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
                memberAccess.Name.Identifier.Text == "Create")
            {
                var receiverType = memberAccess.Expression.ToString();
                if (WeakHashAlgorithms.Any(w => receiverType.Contains(w.Replace("CryptoServiceProvider", "").Replace("Cng", "").Replace("Managed", ""))))
                {
                    ReportWeakHash(invocation, receiverType, filePath, vulnerabilities);
                }
            }
        }

        // Check for HashAlgorithm.Create("MD5")
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
                memberAccess.Name.Identifier.Text == "Create" &&
                memberAccess.Expression.ToString().Contains("HashAlgorithm"))
            {
                if (invocation.ArgumentList.Arguments.Count > 0)
                {
                    var arg = invocation.ArgumentList.Arguments[0].Expression;
                    if (arg is LiteralExpressionSyntax literal)
                    {
                        var algName = literal.Token.ValueText;
                        if (algName.Contains("MD5") || algName.Contains("SHA1"))
                        {
                            ReportWeakHash(invocation, algName, filePath, vulnerabilities);
                        }
                    }
                }
            }
        }
    }

    private void ReportWeakHash(SyntaxNode node, string algorithm, string filePath, List<SecurityVulnerability> vulnerabilities)
    {
        var lineSpan = node.GetLocation().GetLineSpan();
        var isMd5 = algorithm.Contains("MD5");

        vulnerabilities.Add(new SecurityVulnerability
        {
            VulnerabilityType = "Weak Hash Algorithm",
            Severity = isMd5 ? "High" : "Medium",
            CweId = "CWE-328",
            FilePath = filePath,
            StartLine = lineSpan.StartLinePosition.Line + 1,
            EndLine = lineSpan.EndLinePosition.Line + 1,
            Description = $"{algorithm} is a weak hash algorithm. {(isMd5 ? "MD5 is cryptographically broken." : "SHA-1 has known weaknesses.")}",
            Recommendation = "Use SHA-256 or SHA-512 for general hashing. For passwords, use bcrypt, scrypt, or Argon2.",
            VulnerableCode = node.ToFullString().Trim(),
            SecureCode = "using var sha256 = SHA256.Create();",
            Confidence = "High"
        });
    }

    private void DetectWeakEncryption(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        foreach (var creation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            var typeInfo = semanticModel.GetTypeInfo(creation);
            var typeName = typeInfo.Type?.Name ?? "";

            if (WeakEncryptionAlgorithms.Contains(typeName))
            {
                var lineSpan = creation.GetLocation().GetLineSpan();
                vulnerabilities.Add(new SecurityVulnerability
                {
                    VulnerabilityType = "Weak Encryption Algorithm",
                    Severity = "High",
                    CweId = "CWE-327",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = $"{typeName} is a weak encryption algorithm that should not be used for sensitive data.",
                    Recommendation = "Use AES-256 with GCM mode for authenticated encryption.",
                    VulnerableCode = creation.ToFullString().Trim(),
                    SecureCode = "using var aes = Aes.Create();\naes.KeySize = 256;\naes.Mode = CipherMode.GCM; // .NET 5+",
                    Confidence = "High"
                });
            }
        }
    }

    private void DetectHardcodedKeys(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Look for Key property assignments with byte arrays
        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is MemberAccessExpressionSyntax memberAccess &&
                (memberAccess.Name.Identifier.Text == "Key" || memberAccess.Name.Identifier.Text == "KeyValue"))
            {
                // Check if right side is a hardcoded byte array
                if (IsHardcodedByteArray(assignment.Right))
                {
                    var lineSpan = assignment.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "Hardcoded Cryptographic Key",
                        Severity = "Critical",
                        CweId = "CWE-321",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = "Cryptographic key is hardcoded in source code. This compromises security if source code is leaked.",
                        Recommendation = "Load keys from secure key management (Azure Key Vault, AWS KMS, HSM) or encrypted configuration.",
                        VulnerableCode = assignment.ToFullString().Trim(),
                        SecureCode = "// Load from secure key management:\n// var key = await keyVault.GetSecretAsync(\"encryption-key\");",
                        Confidence = "High"
                    });
                }
            }
        }
    }

    private bool IsHardcodedByteArray(ExpressionSyntax expr)
    {
        // new byte[] { ... }
        if (expr is ArrayCreationExpressionSyntax arrayCreation &&
            arrayCreation.Initializer?.Expressions.Count > 0)
        {
            // Check if all elements are literals
            return arrayCreation.Initializer.Expressions.All(e =>
                e is LiteralExpressionSyntax);
        }

        // new byte[16] { ... } or { 0x00, 0x01, ... }
        if (expr is ImplicitArrayCreationExpressionSyntax implicitArray &&
            implicitArray.Initializer?.Expressions.Count > 0)
        {
            return implicitArray.Initializer.Expressions.All(e =>
                e is LiteralExpressionSyntax);
        }

        // Collection expression [0, 1, 2, ...]
        if (expr is CollectionExpressionSyntax collection &&
            collection.Elements.Count > 0)
        {
            return collection.Elements.All(e =>
                e is ExpressionElementSyntax ee && ee.Expression is LiteralExpressionSyntax);
        }

        return false;
    }

    private void DetectHardcodedIV(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is MemberAccessExpressionSyntax memberAccess &&
                memberAccess.Name.Identifier.Text == "IV")
            {
                if (IsHardcodedByteArray(assignment.Right))
                {
                    var lineSpan = assignment.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "Hardcoded IV",
                        Severity = "High",
                        CweId = "CWE-329",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = "Initialization Vector (IV) is hardcoded. Using the same IV with the same key enables cryptanalysis attacks.",
                        Recommendation = "Generate a random IV for each encryption operation. Prepend the IV to the ciphertext.",
                        VulnerableCode = assignment.ToFullString().Trim(),
                        SecureCode = "aes.GenerateIV(); // Generate random IV\n// Prepend IV to ciphertext for transmission",
                        Confidence = "High"
                    });
                }
            }
        }

        // Also check for static readonly byte array fields used as IV
        foreach (var field in root.DescendantNodes().OfType<FieldDeclarationSyntax>())
        {
            var isStatic = field.Modifiers.Any(SyntaxKind.StaticKeyword);
            if (!isStatic)
                continue;

            foreach (var variable in field.Declaration.Variables)
            {
                var name = variable.Identifier.Text.ToLowerInvariant();
                if ((name.Contains("iv") || name.Contains("vector") || name.Contains("nonce")) &&
                    variable.Initializer != null &&
                    IsHardcodedByteArray(variable.Initializer.Value))
                {
                    var lineSpan = variable.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "Static IV Field",
                        Severity = "High",
                        CweId = "CWE-329",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = "Static IV field detected. Reusing the same IV with the same key is cryptographically unsafe.",
                        Recommendation = "Generate a unique IV for each encryption operation.",
                        VulnerableCode = field.ToFullString().Trim(),
                        SecureCode = "// Generate IV per operation: aes.GenerateIV();",
                        Confidence = "High"
                    });
                }
            }
        }
    }

    private void DetectInsecureRandom(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Find usages of System.Random in security-sensitive contexts
        foreach (var creation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            var typeInfo = semanticModel.GetTypeInfo(creation);
            if (typeInfo.Type?.ToDisplayString() != "System.Random")
                continue;

            // Check if it's used in a security-sensitive context
            var containingMethod = creation.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            if (containingMethod == null)
                continue;

            var methodName = containingMethod.Identifier.Text.ToLowerInvariant();
            var isSecurityContext = methodName.Contains("token") ||
                                   methodName.Contains("password") ||
                                   methodName.Contains("key") ||
                                   methodName.Contains("secret") ||
                                   methodName.Contains("salt") ||
                                   methodName.Contains("nonce") ||
                                   methodName.Contains("random") ||
                                   methodName.Contains("generate");

            if (isSecurityContext)
            {
                var lineSpan = creation.GetLocation().GetLineSpan();
                vulnerabilities.Add(new SecurityVulnerability
                {
                    VulnerabilityType = "Insecure Random Number Generator",
                    Severity = "High",
                    CweId = "CWE-338",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = "System.Random is not cryptographically secure. It should not be used for security-sensitive operations.",
                    Recommendation = "Use System.Security.Cryptography.RandomNumberGenerator for security-sensitive random number generation.",
                    VulnerableCode = creation.ToFullString().Trim(),
                    SecureCode = "using var rng = RandomNumberGenerator.Create();\nvar bytes = new byte[32];\nrng.GetBytes(bytes);",
                    Confidence = "High"
                });
            }
        }
    }

    private void DetectMissingSalt(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Look for password hashing without salt
        // Common pattern: ComputeHash on a password string directly
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
                memberAccess.Name.Identifier.Text == "ComputeHash")
            {
                // Check if it's being used on password-related data
                var containingMethod = invocation.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
                if (containingMethod == null)
                    continue;

                var methodName = containingMethod.Identifier.Text.ToLowerInvariant();
                var isPasswordContext = methodName.Contains("password") ||
                                        methodName.Contains("hash") ||
                                        methodName.Contains("credential");

                if (isPasswordContext)
                {
                    // Check if salt is being concatenated
                    var hasSalt = containingMethod.DescendantNodes()
                        .OfType<IdentifierNameSyntax>()
                        .Any(id => id.Identifier.Text.ToLowerInvariant().Contains("salt"));

                    if (!hasSalt)
                    {
                        var lineSpan = invocation.GetLocation().GetLineSpan();
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            VulnerabilityType = "Password Hashing Without Salt",
                            Severity = "High",
                            CweId = "CWE-916",
                            FilePath = filePath,
                            StartLine = lineSpan.StartLinePosition.Line + 1,
                            EndLine = lineSpan.EndLinePosition.Line + 1,
                            Description = "Password appears to be hashed without a salt. This makes rainbow table attacks possible.",
                            Recommendation = "Use a dedicated password hashing library (bcrypt, scrypt, Argon2) that handles salting automatically.",
                            VulnerableCode = invocation.ToFullString().Trim(),
                            SecureCode = "// Use BCrypt.Net-Next:\n// var hash = BCrypt.HashPassword(password);\n// var valid = BCrypt.Verify(password, hash);",
                            Confidence = "Medium"
                        });
                    }
                }
            }
        }
    }
}
