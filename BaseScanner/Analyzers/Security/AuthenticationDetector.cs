using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Security;

/// <summary>
/// Detects authentication and authorization vulnerabilities.
/// </summary>
public class AuthenticationDetector : ISecurityDetector
{
    public string Category => "Authentication";

    private static readonly HashSet<string> AuthAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorize", "AuthorizeAttribute",
        "AllowAnonymous", "AllowAnonymousAttribute"
    };

    private static readonly HashSet<string> SensitiveControllerActions = new(StringComparer.OrdinalIgnoreCase)
    {
        "Delete", "Remove", "Update", "Edit", "Create", "Admin",
        "Manage", "Configure", "Settings", "Import", "Export"
    };

    public Task<List<SecurityVulnerability>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context)
    {
        var vulnerabilities = new List<SecurityVulnerability>();
        var filePath = document.FilePath ?? "";

        // Detect missing authorization on controllers/actions
        DetectMissingAuthorization(root, semanticModel, filePath, vulnerabilities);

        // Detect hardcoded credentials in authentication
        DetectHardcodedCredentials(root, semanticModel, filePath, vulnerabilities);

        // Detect weak password validation
        DetectWeakPasswordValidation(root, semanticModel, filePath, vulnerabilities);

        // Detect insecure session management
        DetectInsecureSessionManagement(root, semanticModel, filePath, vulnerabilities);

        // Detect missing CSRF protection
        DetectMissingCsrfProtection(root, semanticModel, filePath, vulnerabilities);

        // Detect insecure cookie settings
        DetectInsecureCookieSettings(root, semanticModel, filePath, vulnerabilities);

        // Detect JWT vulnerabilities
        DetectJwtVulnerabilities(root, semanticModel, filePath, vulnerabilities);

        return Task.FromResult(vulnerabilities);
    }

    private void DetectMissingAuthorization(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Check controller classes
        foreach (var classDecl in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
        {
            var className = classDecl.Identifier.Text;
            var isController = className.EndsWith("Controller") ||
                              HasBaseType(classDecl, semanticModel, "Controller", "ControllerBase", "ApiController");

            if (!isController)
                continue;

            var hasClassAuthorize = HasAttribute(classDecl.AttributeLists, "Authorize");
            var hasClassAllowAnonymous = HasAttribute(classDecl.AttributeLists, "AllowAnonymous");

            // Check each public method
            foreach (var method in classDecl.Members.OfType<MethodDeclarationSyntax>())
            {
                if (!method.Modifiers.Any(SyntaxKind.PublicKeyword))
                    continue;

                var methodName = method.Identifier.Text;
                var hasMethodAuthorize = HasAttribute(method.AttributeLists, "Authorize");
                var hasMethodAllowAnonymous = HasAttribute(method.AttributeLists, "AllowAnonymous");
                var isHttpMethod = HasAttribute(method.AttributeLists, "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch");

                // Skip if it's not an action or constructor
                if (methodName == className || !isHttpMethod && !IsLikelyAction(method))
                    continue;

                // Check if sensitive action lacks authorization
                var isSensitive = SensitiveControllerActions.Any(s =>
                    methodName.Contains(s, StringComparison.OrdinalIgnoreCase));

                if (isSensitive && !hasClassAuthorize && !hasMethodAuthorize && !hasMethodAllowAnonymous)
                {
                    var lineSpan = method.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "Missing Authorization",
                        Severity = "High",
                        CweId = "CWE-862",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = $"Sensitive action '{methodName}' lacks [Authorize] attribute. This may allow unauthorized access.",
                        Recommendation = "Add [Authorize] attribute with appropriate roles/policies.",
                        VulnerableCode = $"public {method.ReturnType} {methodName}(...)",
                        SecureCode = $"[Authorize(Policy = \"AdminOnly\")]\npublic {method.ReturnType} {methodName}(...)",
                        Confidence = "Medium"
                    });
                }

                // Warn about AllowAnonymous on sensitive endpoints
                if (isSensitive && hasMethodAllowAnonymous)
                {
                    var lineSpan = method.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "Sensitive Action With AllowAnonymous",
                        Severity = "High",
                        CweId = "CWE-862",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = $"Sensitive action '{methodName}' is marked [AllowAnonymous]. Verify this is intentional.",
                        Recommendation = "Review if anonymous access is truly required for this sensitive operation.",
                        VulnerableCode = $"[AllowAnonymous]\npublic {method.ReturnType} {methodName}(...)",
                        SecureCode = $"[Authorize]\npublic {method.ReturnType} {methodName}(...)",
                        Confidence = "Medium"
                    });
                }
            }
        }
    }

    private void DetectHardcodedCredentials(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Look for authentication-related string comparisons
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var methodName = memberAccess.Name.Identifier.Text;

                // Check for direct password comparison
                if (methodName is "Equals" or "Compare" or "CompareTo")
                {
                    var containingMethod = invocation.Ancestors().OfType<MethodDeclarationSyntax>().FirstOrDefault();
                    if (containingMethod == null)
                        continue;

                    var methodNameLower = containingMethod.Identifier.Text.ToLowerInvariant();
                    var isAuthContext = methodNameLower.Contains("login") ||
                                       methodNameLower.Contains("auth") ||
                                       methodNameLower.Contains("password") ||
                                       methodNameLower.Contains("validate") ||
                                       methodNameLower.Contains("verify");

                    if (isAuthContext && HasHardcodedStringArgument(invocation))
                    {
                        var lineSpan = invocation.GetLocation().GetLineSpan();
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            VulnerabilityType = "Hardcoded Authentication",
                            Severity = "Critical",
                            CweId = "CWE-798",
                            FilePath = filePath,
                            StartLine = lineSpan.StartLinePosition.Line + 1,
                            EndLine = lineSpan.EndLinePosition.Line + 1,
                            Description = "Hardcoded credential comparison detected in authentication logic.",
                            Recommendation = "Use secure credential storage and comparison (e.g., ASP.NET Identity, bcrypt).",
                            VulnerableCode = invocation.ToFullString().Trim(),
                            SecureCode = "// Use Identity framework:\n// var result = await _signInManager.PasswordSignInAsync(user, password, false, true);",
                            Confidence = "High"
                        });
                    }
                }
            }
        }

        // Look for == comparison with password variables
        foreach (var binary in root.DescendantNodes().OfType<BinaryExpressionSyntax>())
        {
            if (binary.Kind() != SyntaxKind.EqualsExpression)
                continue;

            var leftName = (binary.Left as IdentifierNameSyntax)?.Identifier.Text.ToLowerInvariant() ?? "";
            var rightName = (binary.Right as IdentifierNameSyntax)?.Identifier.Text.ToLowerInvariant() ?? "";

            var isPasswordComparison = leftName.Contains("password") || leftName.Contains("pwd") ||
                                       rightName.Contains("password") || rightName.Contains("pwd");

            if (isPasswordComparison)
            {
                var hasLiteral = binary.Left is LiteralExpressionSyntax || binary.Right is LiteralExpressionSyntax;
                if (hasLiteral)
                {
                    var lineSpan = binary.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "Hardcoded Password Comparison",
                        Severity = "Critical",
                        CweId = "CWE-798",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = "Password compared directly with hardcoded value.",
                        Recommendation = "Store password hashes and use constant-time comparison.",
                        VulnerableCode = binary.ToFullString().Trim(),
                        SecureCode = "BCrypt.Verify(inputPassword, storedHash)",
                        Confidence = "High"
                    });
                }
            }
        }
    }

    private void DetectWeakPasswordValidation(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Look for password length checks that are too short
        foreach (var binary in root.DescendantNodes().OfType<BinaryExpressionSyntax>())
        {
            if (binary.Kind() is not (SyntaxKind.LessThanExpression or
                SyntaxKind.LessThanOrEqualExpression or
                SyntaxKind.GreaterThanExpression or
                SyntaxKind.GreaterThanOrEqualExpression))
                continue;

            // Check if it's a Length check on password
            string? variableName = null;
            int? lengthValue = null;

            if (binary.Left is MemberAccessExpressionSyntax leftMember &&
                leftMember.Name.Identifier.Text == "Length")
            {
                variableName = (leftMember.Expression as IdentifierNameSyntax)?.Identifier.Text;
                lengthValue = (binary.Right as LiteralExpressionSyntax)?.Token.Value as int?;
            }
            else if (binary.Right is MemberAccessExpressionSyntax rightMember &&
                     rightMember.Name.Identifier.Text == "Length")
            {
                variableName = (rightMember.Expression as IdentifierNameSyntax)?.Identifier.Text;
                lengthValue = (binary.Left as LiteralExpressionSyntax)?.Token.Value as int?;
            }

            if (variableName == null || lengthValue == null)
                continue;

            var isPasswordVar = variableName.ToLowerInvariant().Contains("password") ||
                               variableName.ToLowerInvariant().Contains("pwd");

            if (isPasswordVar && lengthValue < 8)
            {
                var lineSpan = binary.GetLocation().GetLineSpan();
                vulnerabilities.Add(new SecurityVulnerability
                {
                    VulnerabilityType = "Weak Password Policy",
                    Severity = "Medium",
                    CweId = "CWE-521",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = $"Password length requirement of {lengthValue} is too weak. Minimum 8-12 characters recommended.",
                    Recommendation = "Enforce minimum 12 characters with complexity requirements.",
                    VulnerableCode = binary.ToFullString().Trim(),
                    SecureCode = "password.Length >= 12 && HasUppercase(password) && HasDigit(password)",
                    Confidence = "High"
                });
            }
        }
    }

    private void DetectInsecureSessionManagement(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Look for session ID in URL
        foreach (var literal in root.DescendantNodes().OfType<LiteralExpressionSyntax>())
        {
            if (!literal.IsKind(SyntaxKind.StringLiteralExpression))
                continue;

            var value = literal.Token.ValueText.ToLowerInvariant();
            if (value.Contains("sessionid=") || value.Contains("session_id=") ||
                value.Contains("jsessionid=") || value.Contains("sid="))
            {
                var lineSpan = literal.GetLocation().GetLineSpan();
                vulnerabilities.Add(new SecurityVulnerability
                {
                    VulnerabilityType = "Session ID in URL",
                    Severity = "Medium",
                    CweId = "CWE-384",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = "Session identifier appears to be passed in URL. This exposes the session to theft via referrer headers and logs.",
                    Recommendation = "Use HTTP-only, secure cookies for session management.",
                    VulnerableCode = literal.ToFullString().Trim(),
                    SecureCode = "// Use cookie-based sessions with HttpOnly and Secure flags",
                    Confidence = "Medium"
                });
            }
        }

        // Look for session timeout settings that are too long
        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is MemberAccessExpressionSyntax memberAccess)
            {
                var propName = memberAccess.Name.Identifier.Text;
                if (propName is "IdleTimeout" or "Timeout")
                {
                    // Check if the value is longer than 30 minutes
                    if (assignment.Right is InvocationExpressionSyntax invocation &&
                        invocation.Expression is MemberAccessExpressionSyntax fromMethod)
                    {
                        var methodName = fromMethod.Name.Identifier.Text;
                        if (methodName is "FromHours" or "FromDays")
                        {
                            var lineSpan = assignment.GetLocation().GetLineSpan();
                            vulnerabilities.Add(new SecurityVulnerability
                            {
                                VulnerabilityType = "Long Session Timeout",
                                Severity = "Low",
                                CweId = "CWE-613",
                                FilePath = filePath,
                                StartLine = lineSpan.StartLinePosition.Line + 1,
                                EndLine = lineSpan.EndLinePosition.Line + 1,
                                Description = "Session timeout appears to be set to hours or days. Long sessions increase risk of session hijacking.",
                                Recommendation = "Use shorter session timeouts (15-30 minutes) with secure re-authentication.",
                                VulnerableCode = assignment.ToFullString().Trim(),
                                SecureCode = "options.IdleTimeout = TimeSpan.FromMinutes(20);",
                                Confidence = "Medium"
                            });
                        }
                    }
                }
            }
        }
    }

    private void DetectMissingCsrfProtection(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Check for POST actions without ValidateAntiForgeryToken
        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            var hasHttpPost = HasAttribute(method.AttributeLists, "HttpPost", "HttpPut", "HttpDelete", "HttpPatch");
            if (!hasHttpPost)
                continue;

            var hasAntiForgery = HasAttribute(method.AttributeLists,
                "ValidateAntiForgeryToken", "AutoValidateAntiforgeryToken", "IgnoreAntiforgeryToken");

            // Check if class has it
            var classDecl = method.Ancestors().OfType<ClassDeclarationSyntax>().FirstOrDefault();
            var classHasAntiForgery = classDecl != null &&
                HasAttribute(classDecl.AttributeLists, "ValidateAntiForgeryToken", "AutoValidateAntiforgeryToken");

            if (!hasAntiForgery && !classHasAntiForgery)
            {
                // Check if it's an API controller (APIs typically use different CSRF protection)
                var isApiController = classDecl != null &&
                    (HasAttribute(classDecl.AttributeLists, "ApiController") ||
                     HasBaseType(classDecl, semanticModel, "ApiController", "ControllerBase"));

                if (!isApiController)
                {
                    var lineSpan = method.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "Missing CSRF Protection",
                        Severity = "High",
                        CweId = "CWE-352",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = $"POST/PUT/DELETE action '{method.Identifier.Text}' lacks CSRF protection.",
                        Recommendation = "Add [ValidateAntiForgeryToken] attribute or use [AutoValidateAntiforgeryToken] at controller level.",
                        VulnerableCode = $"[HttpPost]\npublic {method.ReturnType} {method.Identifier.Text}(...)",
                        SecureCode = $"[HttpPost]\n[ValidateAntiForgeryToken]\npublic {method.ReturnType} {method.Identifier.Text}(...)",
                        Confidence = "Medium"
                    });
                }
            }
        }
    }

    private void DetectInsecureCookieSettings(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Check for HttpOnly = false
        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is MemberAccessExpressionSyntax memberAccess)
            {
                var propName = memberAccess.Name.Identifier.Text;

                if (propName == "HttpOnly" && assignment.Right.ToString() == "false")
                {
                    var lineSpan = assignment.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "Cookie Without HttpOnly",
                        Severity = "Medium",
                        CweId = "CWE-1004",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = "Cookie HttpOnly flag is disabled. JavaScript can access this cookie, enabling XSS cookie theft.",
                        Recommendation = "Set HttpOnly = true for session and authentication cookies.",
                        VulnerableCode = assignment.ToFullString().Trim(),
                        SecureCode = "options.Cookie.HttpOnly = true;",
                        Confidence = "High"
                    });
                }

                if (propName == "Secure" && assignment.Right.ToString() == "false")
                {
                    var lineSpan = assignment.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "Cookie Without Secure Flag",
                        Severity = "Medium",
                        CweId = "CWE-614",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = "Cookie Secure flag is disabled. Cookie can be transmitted over unencrypted HTTP.",
                        Recommendation = "Set Secure = true to ensure cookies are only sent over HTTPS.",
                        VulnerableCode = assignment.ToFullString().Trim(),
                        SecureCode = "options.Cookie.SecurePolicy = CookieSecurePolicy.Always;",
                        Confidence = "High"
                    });
                }

                if (propName == "SameSite")
                {
                    var value = assignment.Right.ToString();
                    if (value.Contains("None"))
                    {
                        var lineSpan = assignment.GetLocation().GetLineSpan();
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            VulnerabilityType = "Cookie SameSite None",
                            Severity = "Medium",
                            CweId = "CWE-352",
                            FilePath = filePath,
                            StartLine = lineSpan.StartLinePosition.Line + 1,
                            EndLine = lineSpan.EndLinePosition.Line + 1,
                            Description = "Cookie SameSite is set to None. This allows cross-site request forgery attacks.",
                            Recommendation = "Use SameSite.Strict or SameSite.Lax unless cross-site access is required.",
                            VulnerableCode = assignment.ToFullString().Trim(),
                            SecureCode = "options.Cookie.SameSite = SameSiteMode.Strict;",
                            Confidence = "Medium"
                        });
                    }
                }
            }
        }
    }

    private void DetectJwtVulnerabilities(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Check for JWT validation disabled
        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is MemberAccessExpressionSyntax memberAccess)
            {
                var propName = memberAccess.Name.Identifier.Text;
                var value = assignment.Right.ToString();

                if (propName == "ValidateIssuer" && value == "false")
                {
                    ReportJwtValidationDisabled(assignment, "Issuer", filePath, vulnerabilities);
                }
                else if (propName == "ValidateAudience" && value == "false")
                {
                    ReportJwtValidationDisabled(assignment, "Audience", filePath, vulnerabilities);
                }
                else if (propName == "ValidateLifetime" && value == "false")
                {
                    var lineSpan = assignment.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "JWT Lifetime Validation Disabled",
                        Severity = "High",
                        CweId = "CWE-613",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = "JWT lifetime validation is disabled. Expired tokens will be accepted.",
                        Recommendation = "Enable lifetime validation to reject expired tokens.",
                        VulnerableCode = assignment.ToFullString().Trim(),
                        SecureCode = "ValidateLifetime = true",
                        Confidence = "High"
                    });
                }
                else if (propName == "RequireSignedTokens" && value == "false")
                {
                    var lineSpan = assignment.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "JWT Signature Validation Disabled",
                        Severity = "Critical",
                        CweId = "CWE-347",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = "JWT signature validation is disabled. Attackers can forge tokens.",
                        Recommendation = "Always require signed tokens in production.",
                        VulnerableCode = assignment.ToFullString().Trim(),
                        SecureCode = "RequireSignedTokens = true",
                        Confidence = "High"
                    });
                }
            }
        }

        // Check for "none" algorithm
        foreach (var literal in root.DescendantNodes().OfType<LiteralExpressionSyntax>())
        {
            if (!literal.IsKind(SyntaxKind.StringLiteralExpression))
                continue;

            var value = literal.Token.ValueText;
            if (value.Equals("none", StringComparison.OrdinalIgnoreCase) ||
                value.Equals("HS256", StringComparison.OrdinalIgnoreCase))
            {
                // Check context - is this in JWT configuration?
                var parent = literal.Parent;
                if (parent?.ToString().ToLowerInvariant().Contains("algorithm") == true ||
                    parent?.Parent?.ToString().ToLowerInvariant().Contains("algorithm") == true)
                {
                    if (value.Equals("none", StringComparison.OrdinalIgnoreCase))
                    {
                        var lineSpan = literal.GetLocation().GetLineSpan();
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            VulnerabilityType = "JWT None Algorithm",
                            Severity = "Critical",
                            CweId = "CWE-327",
                            FilePath = filePath,
                            StartLine = lineSpan.StartLinePosition.Line + 1,
                            EndLine = lineSpan.EndLinePosition.Line + 1,
                            Description = "JWT 'none' algorithm allows unsigned tokens. This is a critical vulnerability.",
                            Recommendation = "Use strong algorithms like RS256 or ES256.",
                            VulnerableCode = literal.ToFullString().Trim(),
                            SecureCode = "SecurityAlgorithms.RsaSha256",
                            Confidence = "High"
                        });
                    }
                }
            }
        }
    }

    private void ReportJwtValidationDisabled(
        AssignmentExpressionSyntax assignment,
        string validationType,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        var lineSpan = assignment.GetLocation().GetLineSpan();
        vulnerabilities.Add(new SecurityVulnerability
        {
            VulnerabilityType = $"JWT {validationType} Validation Disabled",
            Severity = "Medium",
            CweId = "CWE-287",
            FilePath = filePath,
            StartLine = lineSpan.StartLinePosition.Line + 1,
            EndLine = lineSpan.EndLinePosition.Line + 1,
            Description = $"JWT {validationType} validation is disabled. Tokens from any issuer/audience will be accepted.",
            Recommendation = $"Enable {validationType.ToLower()} validation in production.",
            VulnerableCode = assignment.ToFullString().Trim(),
            SecureCode = $"Validate{validationType} = true",
            Confidence = "Medium"
        });
    }

    private bool HasAttribute(SyntaxList<AttributeListSyntax> attributeLists, params string[] attributeNames)
    {
        foreach (var attrList in attributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                var name = attr.Name.ToString();
                if (attributeNames.Any(a => name.Equals(a, StringComparison.OrdinalIgnoreCase) ||
                                            name.Equals(a + "Attribute", StringComparison.OrdinalIgnoreCase)))
                {
                    return true;
                }
            }
        }
        return false;
    }

    private bool HasBaseType(ClassDeclarationSyntax classDecl, SemanticModel semanticModel, params string[] baseTypeNames)
    {
        if (classDecl.BaseList == null)
            return false;

        foreach (var baseType in classDecl.BaseList.Types)
        {
            var typeName = baseType.Type.ToString();
            if (baseTypeNames.Any(b => typeName.Contains(b)))
                return true;
        }
        return false;
    }

    private bool IsLikelyAction(MethodDeclarationSyntax method)
    {
        // Check if returns ActionResult or similar
        var returnType = method.ReturnType.ToString();
        return returnType.Contains("ActionResult") ||
               returnType.Contains("IActionResult") ||
               returnType.Contains("ViewResult") ||
               returnType.Contains("JsonResult") ||
               returnType.Contains("Task<");
    }

    private bool HasHardcodedStringArgument(InvocationExpressionSyntax invocation)
    {
        return invocation.ArgumentList.Arguments.Any(arg =>
            arg.Expression is LiteralExpressionSyntax literal &&
            literal.IsKind(SyntaxKind.StringLiteralExpression) &&
            literal.Token.ValueText.Length >= 4);
    }
}
