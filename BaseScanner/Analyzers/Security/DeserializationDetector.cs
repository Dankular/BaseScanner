using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Security;

/// <summary>
/// Detects unsafe deserialization patterns that can lead to remote code execution.
/// </summary>
public class DeserializationDetector : ISecurityDetector
{
    public string Category => "Deserialization";

    private static readonly HashSet<string> UnsafeDeserializers = new(StringComparer.OrdinalIgnoreCase)
    {
        "BinaryFormatter",
        "SoapFormatter",
        "NetDataContractSerializer",
        "ObjectStateFormatter",
        "LosFormatter"
    };

    private static readonly HashSet<string> RiskyDeserializers = new(StringComparer.OrdinalIgnoreCase)
    {
        "JavaScriptSerializer",
        "DataContractSerializer",
        "DataContractJsonSerializer",
        "XmlSerializer"
    };

    private static readonly HashSet<string> JsonLibraryTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Newtonsoft.Json.JsonConvert",
        "Newtonsoft.Json.JsonSerializer",
        "System.Text.Json.JsonSerializer"
    };

    public Task<List<SecurityVulnerability>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context)
    {
        var vulnerabilities = new List<SecurityVulnerability>();
        var filePath = document.FilePath ?? "";

        // Detect unsafe .NET deserializers
        DetectUnsafeDeserializers(root, semanticModel, filePath, vulnerabilities);

        // Detect risky JSON deserialization settings
        DetectUnsafeJsonSettings(root, semanticModel, filePath, vulnerabilities);

        // Detect DataContractSerializer with untrusted types
        DetectUntrustedTypeDeserialization(root, semanticModel, filePath, vulnerabilities);

        // Detect YAML deserialization issues
        DetectYamlDeserialization(root, semanticModel, filePath, vulnerabilities);

        return Task.FromResult(vulnerabilities);
    }

    private void DetectUnsafeDeserializers(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Check for instantiation of unsafe deserializers
        foreach (var creation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            var typeInfo = semanticModel.GetTypeInfo(creation);
            var typeName = typeInfo.Type?.Name ?? "";

            if (UnsafeDeserializers.Contains(typeName))
            {
                var lineSpan = creation.GetLocation().GetLineSpan();
                vulnerabilities.Add(new SecurityVulnerability
                {
                    VulnerabilityType = "Unsafe Deserialization",
                    Severity = "Critical",
                    CweId = "CWE-502",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    Description = $"{typeName} is inherently unsafe and can execute arbitrary code during deserialization of untrusted data.",
                    Recommendation = "Use safe serializers like System.Text.Json or DataContractSerializer with known types only.",
                    VulnerableCode = creation.ToFullString().Trim(),
                    SecureCode = "// Use System.Text.Json:\nvar obj = JsonSerializer.Deserialize<MyType>(json);",
                    Confidence = "High"
                });
            }
        }

        // Check for Deserialize method calls on unsafe deserializers
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
                memberAccess.Name.Identifier.Text == "Deserialize")
            {
                var receiverType = semanticModel.GetTypeInfo(memberAccess.Expression).Type;
                var typeName = receiverType?.Name ?? "";

                if (UnsafeDeserializers.Contains(typeName))
                {
                    var lineSpan = invocation.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "Unsafe Deserialization",
                        Severity = "Critical",
                        CweId = "CWE-502",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = $"Deserializing with {typeName} can execute arbitrary code if the data is from an untrusted source.",
                        Recommendation = "Replace with a safe serializer. If binary format is needed, consider MessagePack or protobuf.",
                        VulnerableCode = invocation.ToFullString().Trim(),
                        SecureCode = "// Replace with:\nvar obj = JsonSerializer.Deserialize<MyType>(json);",
                        Confidence = "High"
                    });
                }
            }
        }
    }

    private void DetectUnsafeJsonSettings(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Detect TypeNameHandling.All or TypeNameHandling.Auto in Newtonsoft.Json
        foreach (var assignment in root.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (assignment.Left is MemberAccessExpressionSyntax memberAccess &&
                memberAccess.Name.Identifier.Text == "TypeNameHandling")
            {
                var rightText = assignment.Right.ToString();
                if (rightText.Contains("All") || rightText.Contains("Auto") || rightText.Contains("Objects") || rightText.Contains("Arrays"))
                {
                    var lineSpan = assignment.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "Unsafe JSON Type Handling",
                        Severity = "Critical",
                        CweId = "CWE-502",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = $"TypeNameHandling.{rightText.Split('.').Last()} enables arbitrary type instantiation during deserialization.",
                        Recommendation = "Use TypeNameHandling.None (default) or implement a custom SerializationBinder to restrict types.",
                        VulnerableCode = assignment.ToFullString().Trim(),
                        SecureCode = "settings.TypeNameHandling = TypeNameHandling.None;\n// Or use a SerializationBinder to whitelist types",
                        Confidence = "High"
                    });
                }
            }
        }

        // Check for JsonSerializerSettings with TypeNameHandling in constructor
        foreach (var creation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            if (creation.Initializer != null)
            {
                foreach (var expr in creation.Initializer.Expressions)
                {
                    if (expr is AssignmentExpressionSyntax init &&
                        init.Left.ToString().Contains("TypeNameHandling"))
                    {
                        var rightText = init.Right.ToString();
                        if (rightText.Contains("All") || rightText.Contains("Auto"))
                        {
                            var lineSpan = creation.GetLocation().GetLineSpan();
                            vulnerabilities.Add(new SecurityVulnerability
                            {
                                VulnerabilityType = "Unsafe JSON Type Handling",
                                Severity = "Critical",
                                CweId = "CWE-502",
                                FilePath = filePath,
                                StartLine = lineSpan.StartLinePosition.Line + 1,
                                EndLine = lineSpan.EndLinePosition.Line + 1,
                                Description = "JsonSerializerSettings configured with unsafe TypeNameHandling.",
                                Recommendation = "Remove TypeNameHandling or use TypeNameHandling.None with a type binder.",
                                VulnerableCode = creation.ToFullString().Trim(),
                                SecureCode = "new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None }",
                                Confidence = "High"
                            });
                        }
                    }
                }
            }
        }
    }

    private void DetectUntrustedTypeDeserialization(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Look for XmlSerializer with Type.GetType or typeof() from user input
        foreach (var creation in root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>())
        {
            var typeInfo = semanticModel.GetTypeInfo(creation);
            if (typeInfo.Type?.Name != "XmlSerializer")
                continue;

            if (creation.ArgumentList?.Arguments.Count > 0)
            {
                var firstArg = creation.ArgumentList.Arguments[0].Expression;

                // Check if Type.GetType() is used (potentially with user input)
                if (firstArg is InvocationExpressionSyntax invocation &&
                    invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
                    memberAccess.Name.Identifier.Text == "GetType" &&
                    memberAccess.Expression.ToString() == "Type")
                {
                    var lineSpan = creation.GetLocation().GetLineSpan();
                    vulnerabilities.Add(new SecurityVulnerability
                    {
                        VulnerabilityType = "Dynamic Type Deserialization",
                        Severity = "High",
                        CweId = "CWE-502",
                        FilePath = filePath,
                        StartLine = lineSpan.StartLinePosition.Line + 1,
                        EndLine = lineSpan.EndLinePosition.Line + 1,
                        Description = "XmlSerializer created with dynamically resolved type. If type name comes from user input, this enables type confusion attacks.",
                        Recommendation = "Use a whitelist of allowed types or avoid dynamic type resolution.",
                        VulnerableCode = creation.ToFullString().Trim(),
                        SecureCode = "// Validate type against whitelist before serialization\nif (!AllowedTypes.Contains(typeName)) throw new SecurityException();",
                        Confidence = "Medium"
                    });
                }
            }
        }
    }

    private void DetectYamlDeserialization(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath,
        List<SecurityVulnerability> vulnerabilities)
    {
        // Detect YamlDotNet deserialization with unsafe settings
        foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess)
            {
                var methodName = memberAccess.Name.Identifier.Text;

                // YamlDotNet Deserialize
                if (methodName == "Deserialize")
                {
                    var symbol = semanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                    var containingType = symbol?.ContainingType?.ToDisplayString() ?? "";

                    if (containingType.Contains("YamlDotNet"))
                    {
                        // Check if using deserializer built with unsafe options
                        var lineSpan = invocation.GetLocation().GetLineSpan();
                        vulnerabilities.Add(new SecurityVulnerability
                        {
                            VulnerabilityType = "YAML Deserialization",
                            Severity = "Medium",
                            CweId = "CWE-502",
                            FilePath = filePath,
                            StartLine = lineSpan.StartLinePosition.Line + 1,
                            EndLine = lineSpan.EndLinePosition.Line + 1,
                            Description = "YAML deserialization detected. Ensure unsafe tag handling is disabled if processing untrusted input.",
                            Recommendation = "Use SafeDeserializer and disable arbitrary type instantiation.",
                            VulnerableCode = invocation.ToFullString().Trim(),
                            SecureCode = "var deserializer = new DeserializerBuilder()\n    .IgnoreUnmatchedProperties()\n    .Build();",
                            Confidence = "Low"
                        });
                    }
                }
            }
        }
    }
}
