using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Testing.Models;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Testing.Detectors;

/// <summary>
/// Detects test quality issues like weak assertions and missing edge cases.
/// Analyzes test coverage patterns to identify gaps in test thoroughness.
/// </summary>
public class TestQualityDetector : TestDetectorBase
{
    public override string Category => "TestQuality";
    public override string Description => "Identifies weak assertions and missing edge case tests";

    public override async Task<TestDetectionResult> DetectAsync(
        Project project,
        RawCoverageData? coverageData,
        CodeContext context)
    {
        var qualityIssues = new List<TestQualityIssue>();

        // First pass: collect information about tested methods
        var testedMethods = new Dictionary<string, TestMethodInfo>();

        foreach (var document in project.Documents)
        {
            if (ShouldSkipFile(document.FilePath))
                continue;

            if (!IsTestFile(document.FilePath))
                continue;

            var semanticModel = await document.GetSemanticModelAsync();
            var root = await document.GetSyntaxRootAsync();

            if (semanticModel == null || root == null)
                continue;

            // Analyze test methods
            foreach (var classDecl in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
            {
                if (!IsTestClass(classDecl))
                    continue;

                var className = classDecl.Identifier.Text;

                foreach (var method in classDecl.Members.OfType<MethodDeclarationSyntax>())
                {
                    if (!IsTestMethod(method))
                        continue;

                    // Analyze this test method for quality issues
                    var issues = AnalyzeTestQuality(method, className, document, semanticModel);
                    qualityIssues.AddRange(issues);

                    // Track what methods are being tested
                    var testedMethodsInTest = ExtractTestedMethods(method, semanticModel);
                    foreach (var tested in testedMethodsInTest)
                    {
                        if (!testedMethods.ContainsKey(tested))
                        {
                            testedMethods[tested] = new TestMethodInfo { MethodName = tested };
                        }
                        testedMethods[tested].TestMethods.Add(method.Identifier.Text);
                        testedMethods[tested].TestScenarios.AddRange(
                            ExtractTestScenarios(method, semanticModel));
                    }
                }
            }
        }

        // Second pass: identify methods that need more test coverage
        var additionalIssues = await IdentifyMissingTestScenarios(project, testedMethods);
        qualityIssues.AddRange(additionalIssues);

        return new TestDetectionResult
        {
            DetectorName = Category,
            Smells = [],
            QualityIssues = qualityIssues.OrderBy(i => TestIssueSeverity.ToSortOrder(i.Severity)).ToList(),
            CriticalPaths = [],
            UncoveredMethods = [],
            UncoveredBranches = []
        };
    }

    private List<TestQualityIssue> AnalyzeTestQuality(
        MethodDeclarationSyntax method,
        string className,
        Document document,
        SemanticModel semanticModel)
    {
        var issues = new List<TestQualityIssue>();
        var (line, _) = GetLineSpan(method);
        var methodName = method.Identifier.Text;

        // Check for weak assertions
        issues.AddRange(DetectWeakAssertions(method, className, document));

        // Check for Assert.True without message
        issues.AddRange(DetectTrueOnlyAssertions(method, className, document));

        // Check for string assertions that don't verify position
        issues.AddRange(DetectWeakStringAssertions(method, className, document));

        // Check for incomplete arrangement
        issues.AddRange(DetectIncompleteArrangement(method, className, document, semanticModel));

        // Check for missing cleanup
        issues.AddRange(DetectMissingCleanup(method, className, document, semanticModel));

        // Check for overly broad assertions
        issues.AddRange(DetectOverlyBroadAssertions(method, className, document));

        // Check for unverified side effects
        issues.AddRange(DetectUnverifiedSideEffects(method, className, document, semanticModel));

        return issues;
    }

    private List<TestQualityIssue> DetectWeakAssertions(
        MethodDeclarationSyntax method,
        string className,
        Document document)
    {
        var issues = new List<TestQualityIssue>();
        var (line, _) = GetLineSpan(method);

        foreach (var invocation in method.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var text = invocation.ToString();

            // Assert.NotNull without further verification
            if (text.Contains("Assert.NotNull") || text.Contains(".ShouldNotBeNull"))
            {
                // Check if there's a follow-up assertion
                var parent = invocation.Parent;
                var hasFollowUp = parent?.Parent?.DescendantNodes()
                    .OfType<InvocationExpressionSyntax>()
                    .Any(i => i.SpanStart > invocation.SpanStart &&
                              (i.ToString().Contains("Assert.") || i.ToString().Contains(".Should"))) ?? false;

                if (!hasFollowUp)
                {
                    issues.Add(new TestQualityIssue
                    {
                        TestMethodName = method.Identifier.Text,
                        TestClassName = className,
                        FilePath = document.FilePath ?? "",
                        Line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        IssueType = TestQualityIssueType.WeakAssertion,
                        Severity = TestIssueSeverity.Low,
                        Description = "NotNull assertion without further verification of the object's state",
                        Recommendation = "Add assertions to verify the object's properties or behavior",
                        ExpectedAssertion = "Assert property values or method behaviors"
                    });
                }
            }

            // Assert.True without meaningful condition
            if (text.Contains("Assert.True(result)") || text.Contains("Assert.True(success)"))
            {
                issues.Add(new TestQualityIssue
                {
                    TestMethodName = method.Identifier.Text,
                    TestClassName = className,
                    FilePath = document.FilePath ?? "",
                    Line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                    IssueType = TestQualityIssueType.WeakAssertion,
                    Severity = TestIssueSeverity.Medium,
                    Description = "Boolean assertion without descriptive failure message",
                    Recommendation = "Use Assert.Equal or add a failure message explaining the expected condition",
                    ExpectedAssertion = "Assert.True(condition, \"expected description\")"
                });
            }
        }

        return issues;
    }

    private List<TestQualityIssue> DetectTrueOnlyAssertions(
        MethodDeclarationSyntax method,
        string className,
        Document document)
    {
        var issues = new List<TestQualityIssue>();

        foreach (var invocation in method.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var text = invocation.ToString();

            // Check for Assert.True/Assert.False without message
            if ((text.StartsWith("Assert.True(") || text.StartsWith("Assert.False(")) &&
                !text.Contains(","))
            {
                issues.Add(new TestQualityIssue
                {
                    TestMethodName = method.Identifier.Text,
                    TestClassName = className,
                    FilePath = document.FilePath ?? "",
                    Line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                    IssueType = TestQualityIssueType.TrueOnlyAssertion,
                    Severity = TestIssueSeverity.Low,
                    Description = "Boolean assertion without failure message",
                    Recommendation = "Add a message parameter to explain what the assertion is verifying",
                    ExpectedAssertion = "Assert.True(condition, \"Explain what this checks\")"
                });
            }
        }

        return issues;
    }

    private List<TestQualityIssue> DetectWeakStringAssertions(
        MethodDeclarationSyntax method,
        string className,
        Document document)
    {
        var issues = new List<TestQualityIssue>();

        foreach (var invocation in method.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var text = invocation.ToString();

            // Contains without StartsWith/EndsWith or exact match
            if (text.Contains(".Contains(") &&
                (text.Contains("Assert") || text.Contains("Should")))
            {
                // Check if there's also a length or position check
                var hasPositionCheck = method.DescendantNodes()
                    .OfType<InvocationExpressionSyntax>()
                    .Any(i => i.ToString().Contains(".StartsWith") ||
                             i.ToString().Contains(".EndsWith") ||
                             i.ToString().Contains(".Length") ||
                             i.ToString().Contains("Assert.Equal"));

                if (!hasPositionCheck)
                {
                    issues.Add(new TestQualityIssue
                    {
                        TestMethodName = method.Identifier.Text,
                        TestClassName = className,
                        FilePath = document.FilePath ?? "",
                        Line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        IssueType = TestQualityIssueType.StringContainsWithoutPosition,
                        Severity = TestIssueSeverity.Low,
                        Description = "String Contains assertion may be too loose",
                        Recommendation = "Consider using StartsWith, EndsWith, or exact equality for more precise testing"
                    });
                }
            }
        }

        return issues;
    }

    private List<TestQualityIssue> DetectIncompleteArrangement(
        MethodDeclarationSyntax method,
        string className,
        Document document,
        SemanticModel semanticModel)
    {
        var issues = new List<TestQualityIssue>();

        // Check for mocks that are set up but some methods aren't configured
        var setupCalls = method.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(i => i.ToString().Contains(".Setup(") ||
                       i.ToString().Contains(".Returns("))
            .ToList();

        if (setupCalls.Any())
        {
            // Check if there are any throws during the test that might indicate missing setup
            var throwPatterns = method.DescendantNodes()
                .OfType<ThrowExpressionSyntax>()
                .Any();

            var hasNullCheck = method.ToString().Contains("!= null") ||
                              method.ToString().Contains("is not null");

            if (!throwPatterns && hasNullCheck && setupCalls.Count < 2)
            {
                issues.Add(new TestQualityIssue
                {
                    TestMethodName = method.Identifier.Text,
                    TestClassName = className,
                    FilePath = document.FilePath ?? "",
                    Line = GetLineSpan(method).StartLine,
                    IssueType = TestQualityIssueType.IncompleteArrangement,
                    Severity = TestIssueSeverity.Low,
                    Description = "Test may have incomplete mock setup",
                    Recommendation = "Verify all required mock methods are configured"
                });
            }
        }

        return issues;
    }

    private List<TestQualityIssue> DetectMissingCleanup(
        MethodDeclarationSyntax method,
        string className,
        Document document,
        SemanticModel semanticModel)
    {
        var issues = new List<TestQualityIssue>();
        var methodText = method.ToString();

        // Check for resource creation without cleanup
        var createsResources = methodText.Contains("new FileStream") ||
                              methodText.Contains("new StreamWriter") ||
                              methodText.Contains("new HttpClient") ||
                              methodText.Contains("new SqlConnection") ||
                              methodText.Contains("File.Create") ||
                              methodText.Contains("File.Open");

        var hasCleanup = methodText.Contains("using (") ||
                        methodText.Contains("using var") ||
                        methodText.Contains(".Dispose()") ||
                        methodText.Contains(".Close()") ||
                        methodText.Contains("finally");

        if (createsResources && !hasCleanup)
        {
            issues.Add(new TestQualityIssue
            {
                TestMethodName = method.Identifier.Text,
                TestClassName = className,
                FilePath = document.FilePath ?? "",
                Line = GetLineSpan(method).StartLine,
                IssueType = TestQualityIssueType.MissingCleanup,
                Severity = TestIssueSeverity.Medium,
                Description = "Test creates resources without cleanup",
                Recommendation = "Use 'using' statements or implement cleanup in a finally block"
            });
        }

        // Check for file/directory creation without deletion
        if ((methodText.Contains("File.WriteAll") || methodText.Contains("Directory.Create")) &&
            !methodText.Contains("File.Delete") && !methodText.Contains("Directory.Delete"))
        {
            issues.Add(new TestQualityIssue
            {
                TestMethodName = method.Identifier.Text,
                TestClassName = className,
                FilePath = document.FilePath ?? "",
                Line = GetLineSpan(method).StartLine,
                IssueType = TestQualityIssueType.MissingCleanup,
                Severity = TestIssueSeverity.Medium,
                Description = "Test creates files/directories without cleaning up",
                Recommendation = "Delete created files/directories in cleanup or use a temporary directory"
            });
        }

        return issues;
    }

    private List<TestQualityIssue> DetectOverlyBroadAssertions(
        MethodDeclarationSyntax method,
        string className,
        Document document)
    {
        var issues = new List<TestQualityIssue>();

        foreach (var invocation in method.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var text = invocation.ToString();

            // Assert.IsType<object> or similar overly broad checks
            if (text.Contains("Assert.IsType<object>") ||
                text.Contains("Assert.IsAssignableFrom<object>"))
            {
                issues.Add(new TestQualityIssue
                {
                    TestMethodName = method.Identifier.Text,
                    TestClassName = className,
                    FilePath = document.FilePath ?? "",
                    Line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                    IssueType = TestQualityIssueType.OverlyBroadAssertion,
                    Severity = TestIssueSeverity.Medium,
                    Description = "Type assertion uses overly broad type 'object'",
                    Recommendation = "Assert against the specific expected type"
                });
            }

            // Empty collection check without count verification
            if (text.Contains(".Any()") && !method.ToString().Contains(".Count"))
            {
                // Only flag if there's no other count assertion
                var hasCountCheck = method.DescendantNodes()
                    .OfType<InvocationExpressionSyntax>()
                    .Any(i => i.ToString().Contains(".Count") ||
                             i.ToString().Contains(".Length") ||
                             i.ToString().Contains("Assert.Single") ||
                             i.ToString().Contains("Assert.Empty"));

                if (!hasCountCheck)
                {
                    issues.Add(new TestQualityIssue
                    {
                        TestMethodName = method.Identifier.Text,
                        TestClassName = className,
                        FilePath = document.FilePath ?? "",
                        Line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        IssueType = TestQualityIssueType.OverlyBroadAssertion,
                        Severity = TestIssueSeverity.Low,
                        Description = "Any() check doesn't verify expected count",
                        Recommendation = "Assert the expected count for more precise testing"
                    });
                }
            }
        }

        return issues;
    }

    private List<TestQualityIssue> DetectUnverifiedSideEffects(
        MethodDeclarationSyntax method,
        string className,
        Document document,
        SemanticModel semanticModel)
    {
        var issues = new List<TestQualityIssue>();

        // Check for methods that modify state but verification is missing
        var invocations = method.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .ToList();

        foreach (var invocation in invocations)
        {
            // Look for save/update/delete operations
            var text = invocation.ToString();
            if (text.Contains(".Save") ||
                text.Contains(".Update") ||
                text.Contains(".Delete") ||
                text.Contains(".Add(") ||
                text.Contains(".Remove("))
            {
                // Check if there's a corresponding verification
                var hasVerification = invocations.Any(i =>
                {
                    var iText = i.ToString();
                    return i.SpanStart > invocation.SpanStart &&
                           (iText.Contains("Verify") ||
                            iText.Contains("Received") ||
                            iText.Contains("Assert"));
                });

                if (!hasVerification)
                {
                    issues.Add(new TestQualityIssue
                    {
                        TestMethodName = method.Identifier.Text,
                        TestClassName = className,
                        FilePath = document.FilePath ?? "",
                        Line = invocation.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
                        IssueType = TestQualityIssueType.UnverifiedSideEffects,
                        Severity = TestIssueSeverity.Medium,
                        Description = "State-modifying operation without verification",
                        Recommendation = "Add verification that the expected side effect occurred"
                    });
                }
            }
        }

        return issues;
    }

    private List<string> ExtractTestedMethods(MethodDeclarationSyntax testMethod, SemanticModel semanticModel)
    {
        var methods = new List<string>();

        foreach (var invocation in testMethod.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            var text = invocation.ToString();

            // Skip setup and assertion calls
            if (text.Contains("Mock") || text.Contains("Setup") ||
                text.Contains("Assert") || text.Contains("Should") ||
                text.Contains("Verify") || text.Contains("Returns"))
                continue;

            // Extract method name
            if (invocation.Expression is MemberAccessExpressionSyntax ma)
            {
                var methodName = ma.Name.ToString();
                methods.Add(methodName);
            }
        }

        return methods.Distinct().ToList();
    }

    private List<string> ExtractTestScenarios(MethodDeclarationSyntax testMethod, SemanticModel semanticModel)
    {
        var scenarios = new List<string>();

        // Extract from test name
        var testName = testMethod.Identifier.Text;
        if (testName.Contains("_"))
        {
            var parts = testName.Split('_');
            if (parts.Length >= 2)
                scenarios.Add(parts[1]); // Usually the scenario part
        }

        // Check for null testing
        var text = testMethod.ToString();
        if (text.Contains("null"))
            scenarios.Add("null");
        if (text.Contains("empty") || text.Contains("Empty"))
            scenarios.Add("empty");
        if (text.Contains("boundary") || text.Contains("Boundary"))
            scenarios.Add("boundary");
        if (text.Contains("negative") || text.Contains("Negative") || text.Contains("< 0"))
            scenarios.Add("negative");
        if (text.Contains("throws") || text.Contains("Throws") || text.Contains("Exception"))
            scenarios.Add("exception");

        return scenarios;
    }

    private async Task<List<TestQualityIssue>> IdentifyMissingTestScenarios(
        Project project,
        Dictionary<string, TestMethodInfo> testedMethods)
    {
        var issues = new List<TestQualityIssue>();

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

            foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                var symbol = semanticModel.GetDeclaredSymbol(method);
                if (symbol == null)
                    continue;

                var methodName = symbol.Name;

                // Skip if not tested at all (handled by CoverageGapDetector)
                if (!testedMethods.ContainsKey(methodName))
                    continue;

                var testInfo = testedMethods[methodName];
                var requiredScenarios = IdentifyRequiredScenarios(method, semanticModel);
                var missingScenarios = requiredScenarios
                    .Where(s => !testInfo.TestScenarios.Contains(s, StringComparer.OrdinalIgnoreCase))
                    .ToList();

                foreach (var scenario in missingScenarios)
                {
                    var (issueType, description, recommendation) = GetScenarioIssue(scenario);

                    issues.Add(new TestQualityIssue
                    {
                        TestMethodName = methodName,
                        TestClassName = symbol.ContainingType?.Name ?? "",
                        FilePath = document.FilePath ?? "",
                        Line = GetLineSpan(method).StartLine,
                        IssueType = issueType,
                        Severity = GetScenarioSeverity(scenario),
                        Description = description,
                        Recommendation = recommendation,
                        ExpectedAssertion = $"Test for {scenario} scenario"
                    });
                }
            }
        }

        return issues;
    }

    private List<string> IdentifyRequiredScenarios(MethodDeclarationSyntax method, SemanticModel semanticModel)
    {
        var scenarios = new List<string>();

        // Check parameters for required scenarios
        foreach (var param in method.ParameterList.Parameters)
        {
            var typeName = param.Type?.ToString() ?? "";

            // Reference types need null tests
            if (!typeName.EndsWith("?") && !IsPrimitive(typeName))
            {
                scenarios.Add("null");
            }

            // String parameters need empty tests
            if (typeName is "string" or "String")
            {
                scenarios.Add("empty");
            }

            // Numeric parameters need boundary tests
            if (typeName is "int" or "long" or "double" or "decimal" or "float")
            {
                scenarios.Add("boundary");
                scenarios.Add("negative");
            }
        }

        // Check for exception throwing
        if (method.DescendantNodes().OfType<ThrowStatementSyntax>().Any())
        {
            scenarios.Add("exception");
        }

        // Check for collections
        var hasCollectionParam = method.ParameterList.Parameters.Any(p =>
        {
            var type = p.Type?.ToString() ?? "";
            return type.Contains("List") || type.Contains("Array") ||
                   type.Contains("Collection") || type.Contains("Enumerable");
        });

        if (hasCollectionParam)
        {
            scenarios.Add("empty");
            scenarios.Add("single");
            scenarios.Add("multiple");
        }

        return scenarios.Distinct().ToList();
    }

    private (TestQualityIssueType Type, string Description, string Recommendation) GetScenarioIssue(string scenario)
    {
        return scenario.ToLowerInvariant() switch
        {
            "null" => (TestQualityIssueType.MissingNullTest,
                "Missing null parameter test",
                "Add a test that passes null to verify ArgumentNullException is thrown"),
            "empty" => (TestQualityIssueType.MissingEmptyTest,
                "Missing empty value test",
                "Add a test for empty string/collection handling"),
            "boundary" => (TestQualityIssueType.MissingBoundaryTest,
                "Missing boundary value test",
                "Add tests for min/max values and edge cases"),
            "negative" => (TestQualityIssueType.MissingNegativeTest,
                "Missing negative value test",
                "Add a test with negative numbers if applicable"),
            "exception" => (TestQualityIssueType.MissingExceptionTest,
                "Missing exception test",
                "Add tests that verify expected exceptions are thrown"),
            _ => (TestQualityIssueType.NoEdgeCases,
                $"Missing {scenario} test scenario",
                $"Add test coverage for the {scenario} case")
        };
    }

    private string GetScenarioSeverity(string scenario)
    {
        return scenario.ToLowerInvariant() switch
        {
            "null" => TestIssueSeverity.High,
            "exception" => TestIssueSeverity.High,
            "boundary" => TestIssueSeverity.Medium,
            "empty" => TestIssueSeverity.Medium,
            "negative" => TestIssueSeverity.Low,
            _ => TestIssueSeverity.Low
        };
    }

    private bool IsPrimitive(string typeName)
    {
        var primitives = new[] { "int", "long", "short", "byte", "bool", "char", "float", "double", "decimal" };
        return primitives.Contains(typeName.ToLowerInvariant());
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

    private class TestMethodInfo
    {
        public string MethodName { get; set; } = "";
        public List<string> TestMethods { get; } = new();
        public List<string> TestScenarios { get; } = new();
    }
}
