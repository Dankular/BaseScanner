using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Testing.Models;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Testing.Detectors;

/// <summary>
/// Detects test smells that indicate poor test quality.
/// Identifies patterns like empty tests, missing assertions, excessive mocking, and flaky patterns.
/// </summary>
public class TestSmellDetector : TestDetectorBase, ITestSmellDetector
{
    public override string Category => "TestSmell";
    public override string Description => "Identifies test smells that indicate poor test quality";

    public IReadOnlyList<TestSmellType> DetectableSmells => new[]
    {
        TestSmellType.EmptyTest,
        TestSmellType.NoAssertions,
        TestSmellType.ExcessiveMocking,
        TestSmellType.OnlyMockVerification,
        TestSmellType.MagicStrings,
        TestSmellType.HardcodedValues,
        TestSmellType.ThreadSleep,
        TestSmellType.DateTimeNow,
        TestSmellType.DuplicateTestLogic,
        TestSmellType.IgnoredTest,
        TestSmellType.CommentedOutCode,
        TestSmellType.LongTest,
        TestSmellType.TestNameNotDescriptive,
        TestSmellType.MissingActSection,
        TestSmellType.AssertionRoulette,
        TestSmellType.EagerTest
    };

    private const int MaxTestLineCount = 50;
    private const int MaxMocksPerTest = 5;
    private const int MaxAssertionsPerTest = 10;
    private const int MinTestNameLength = 10;

    public override async Task<TestDetectionResult> DetectAsync(
        Project project,
        RawCoverageData? coverageData,
        CodeContext context)
    {
        var smells = new List<TestSmell>();

        foreach (var document in project.Documents)
        {
            if (ShouldSkipFile(document.FilePath))
                continue;

            // Only analyze test files
            if (!IsTestFile(document.FilePath))
                continue;

            var semanticModel = await document.GetSemanticModelAsync();
            var root = await document.GetSyntaxRootAsync();

            if (semanticModel == null || root == null)
                continue;

            // Analyze test classes
            foreach (var classDecl in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
            {
                if (!IsTestClass(classDecl))
                    continue;

                var className = classDecl.Identifier.Text;

                // Track test method bodies for duplicate detection
                var methodBodies = new Dictionary<string, List<string>>();

                foreach (var method in classDecl.Members.OfType<MethodDeclarationSyntax>())
                {
                    if (!IsTestMethod(method))
                        continue;

                    var methodSmells = AnalyzeTestMethod(method, className, document, semanticModel);
                    smells.AddRange(methodSmells);

                    // Track for duplicate detection
                    var bodyHash = GetNormalizedBodyHash(method);
                    if (!string.IsNullOrEmpty(bodyHash))
                    {
                        if (!methodBodies.ContainsKey(bodyHash))
                            methodBodies[bodyHash] = new List<string>();
                        methodBodies[bodyHash].Add(method.Identifier.Text);
                    }
                }

                // Detect duplicate test logic
                foreach (var (hash, methods) in methodBodies.Where(kvp => kvp.Value.Count > 1))
                {
                    foreach (var methodName in methods)
                    {
                        var methodDecl = classDecl.Members
                            .OfType<MethodDeclarationSyntax>()
                            .FirstOrDefault(m => m.Identifier.Text == methodName);

                        if (methodDecl != null)
                        {
                            var (line, _) = GetLineSpan(methodDecl);
                            smells.Add(new TestSmell
                            {
                                TestMethodName = methodName,
                                TestClassName = className,
                                FilePath = document.FilePath ?? "",
                                Line = line,
                                SmellType = TestSmellType.DuplicateTestLogic,
                                Severity = TestIssueSeverity.Medium,
                                Description = $"Test has duplicate logic with: {string.Join(", ", methods.Where(m => m != methodName))}",
                                Recommendation = "Extract common test logic into a shared setup method or parameterized test",
                                CodeSnippet = GetCodeSnippet(methodDecl, 3)
                            });
                        }
                    }
                }
            }
        }

        return new TestDetectionResult
        {
            DetectorName = Category,
            Smells = smells.OrderBy(s => TestIssueSeverity.ToSortOrder(s.Severity)).ToList(),
            QualityIssues = [],
            CriticalPaths = [],
            UncoveredMethods = [],
            UncoveredBranches = []
        };
    }

    private List<TestSmell> AnalyzeTestMethod(
        MethodDeclarationSyntax method,
        string className,
        Document document,
        SemanticModel semanticModel)
    {
        var smells = new List<TestSmell>();
        var (line, _) = GetLineSpan(method);
        var methodName = method.Identifier.Text;

        // Check for empty test
        if (IsEmptyTest(method))
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.EmptyTest,
                TestIssueSeverity.High,
                "Test method has no implementation",
                "Implement the test or remove it if not needed"));
        }

        // Check for no assertions
        if (!HasAssertions(method))
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.NoAssertions,
                TestIssueSeverity.High,
                "Test method has no assertions",
                "Add assertions to verify expected behavior"));
        }

        // Check for only mock verification (no real assertions)
        if (HasOnlyMockVerifications(method))
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.OnlyMockVerification,
                TestIssueSeverity.Medium,
                "Test only verifies mock interactions without asserting results",
                "Add assertions to verify actual behavior, not just that methods were called"));
        }

        // Check for excessive mocking
        var mockCount = CountMocks(method);
        if (mockCount > MaxMocksPerTest)
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.ExcessiveMocking,
                TestIssueSeverity.Medium,
                $"Test uses {mockCount} mocks (max recommended: {MaxMocksPerTest})",
                "Consider using integration tests or simplifying the design"));
        }

        // Check for magic strings
        var magicStrings = FindMagicStrings(method);
        if (magicStrings.Any())
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.MagicStrings,
                TestIssueSeverity.Low,
                $"Test contains magic strings: {string.Join(", ", magicStrings.Take(3))}",
                "Use named constants or builder patterns for test data"));
        }

        // Check for hardcoded values in assertions
        var hardcodedValues = FindHardcodedValues(method);
        if (hardcodedValues.Any())
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.HardcodedValues,
                TestIssueSeverity.Low,
                "Test contains hardcoded values that may be brittle",
                "Use descriptive variable names or test data builders"));
        }

        // Check for Thread.Sleep (flaky pattern)
        if (HasThreadSleep(method))
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.ThreadSleep,
                TestIssueSeverity.High,
                "Test uses Thread.Sleep which makes it flaky and slow",
                "Use async/await with proper synchronization, or polling with timeout"));
        }

        // Check for DateTime.Now (flaky pattern)
        if (HasDateTimeNow(method))
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.DateTimeNow,
                TestIssueSeverity.Medium,
                "Test uses DateTime.Now which may cause flaky behavior",
                "Inject a time abstraction (ITimeProvider) or use fixed test dates"));
        }

        // Check for ignored test
        if (IsIgnoredTest(method))
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.IgnoredTest,
                TestIssueSeverity.Medium,
                "Test is marked as ignored/skipped",
                "Fix the test and enable it, or remove if no longer needed"));
        }

        // Check for commented out code
        if (HasCommentedOutCode(method))
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.CommentedOutCode,
                TestIssueSeverity.Low,
                "Test contains commented out code",
                "Remove commented code or restore it if needed"));
        }

        // Check for long test
        var lineCount = GetMethodLineCount(method);
        if (lineCount > MaxTestLineCount)
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.LongTest,
                TestIssueSeverity.Medium,
                $"Test is too long ({lineCount} lines, max: {MaxTestLineCount})",
                "Split into smaller, focused tests or extract helper methods"));
        }

        // Check for non-descriptive test name
        if (!IsDescriptiveTestName(methodName))
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.TestNameNotDescriptive,
                TestIssueSeverity.Low,
                "Test name is not descriptive enough",
                "Use naming convention: MethodName_Scenario_ExpectedBehavior"));
        }

        // Check for missing Act section (setup-only tests)
        if (IsMissingActSection(method))
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.MissingActSection,
                TestIssueSeverity.High,
                "Test appears to be missing the Act section (no method under test is called)",
                "Add code that exercises the method or behavior being tested"));
        }

        // Check for assertion roulette (too many unrelated assertions)
        var assertionCount = CountAssertions(method);
        if (assertionCount > MaxAssertionsPerTest)
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.AssertionRoulette,
                TestIssueSeverity.Medium,
                $"Test has too many assertions ({assertionCount})",
                "Split into multiple focused tests, each testing one behavior"));
        }

        // Check for eager test (tests multiple behaviors)
        if (IsEagerTest(method))
        {
            smells.Add(CreateSmell(method, className, document, TestSmellType.EagerTest,
                TestIssueSeverity.Medium,
                "Test appears to verify multiple unrelated behaviors",
                "Follow the 'one assertion per test' guideline or group related assertions"));
        }

        return smells;
    }

    private TestSmell CreateSmell(
        MethodDeclarationSyntax method,
        string className,
        Document document,
        TestSmellType smellType,
        string severity,
        string description,
        string recommendation)
    {
        var (line, _) = GetLineSpan(method);
        return new TestSmell
        {
            TestMethodName = method.Identifier.Text,
            TestClassName = className,
            FilePath = document.FilePath ?? "",
            Line = line,
            SmellType = smellType,
            Severity = severity,
            Description = description,
            Recommendation = recommendation,
            CodeSnippet = GetCodeSnippet(method, 5)
        };
    }

    private bool IsEmptyTest(MethodDeclarationSyntax method)
    {
        if (method.Body == null && method.ExpressionBody == null)
            return true;

        if (method.Body != null && method.Body.Statements.Count == 0)
            return true;

        // Check for only comments
        if (method.Body != null)
        {
            var hasNonTrivialStatements = method.Body.Statements
                .Any(s => !s.ToString().Trim().StartsWith("//"));
            return !hasNonTrivialStatements;
        }

        return false;
    }

    private bool HasAssertions(MethodDeclarationSyntax method)
    {
        var methodText = method.ToString();

        var assertPatterns = new[]
        {
            "Assert.", "Assert(",
            "Should", ".Should()",
            "Expect(", "Expect.",
            "That(", ".That(",
            "Must.", "Must(",
            "Verify(", ".Verify(",
            "Check(", ".Check(",
            "Has.", "Have.",
            "Be.", "Is.", "Are.",
            "Contains", "Contain"
        };

        return assertPatterns.Any(p => methodText.Contains(p));
    }

    private bool HasOnlyMockVerifications(MethodDeclarationSyntax method)
    {
        var methodText = method.ToString();

        // Check for mock verify patterns
        var mockVerifyPatterns = new[] { ".Verify(", "Received(", ".Received.", "mock.Verify" };
        var hasMockVerify = mockVerifyPatterns.Any(p => methodText.Contains(p));

        if (!hasMockVerify)
            return false;

        // Check for real assertions
        var realAssertPatterns = new[]
        {
            "Assert.Equal", "Assert.True", "Assert.False", "Assert.Null", "Assert.NotNull",
            ".ShouldBe", ".ShouldEqual", ".Should().Be", ".Should().Equal",
            "Expect(", ".To.Be", ".To.Equal"
        };

        return !realAssertPatterns.Any(p => methodText.Contains(p));
    }

    private int CountMocks(MethodDeclarationSyntax method)
    {
        var count = 0;
        var methodText = method.ToString();

        // Count Mock<T> declarations
        count += System.Text.RegularExpressions.Regex.Matches(methodText, @"new\s+Mock<").Count;
        count += System.Text.RegularExpressions.Regex.Matches(methodText, @"Substitute\.For<").Count;
        count += System.Text.RegularExpressions.Regex.Matches(methodText, @"A\.Fake<").Count;

        return count;
    }

    private List<string> FindMagicStrings(MethodDeclarationSyntax method)
    {
        var magicStrings = new List<string>();

        foreach (var literal in method.DescendantNodes().OfType<LiteralExpressionSyntax>())
        {
            if (literal.IsKind(SyntaxKind.StringLiteralExpression))
            {
                var value = literal.Token.ValueText;

                // Skip short strings, empty strings, and common test values
                if (value.Length > 10 &&
                    !IsCommonTestValue(value) &&
                    !IsInComment(literal))
                {
                    magicStrings.Add($"\"{value.Substring(0, Math.Min(20, value.Length))}...\"");
                }
            }
        }

        return magicStrings.Distinct().Take(5).ToList();
    }

    private List<string> FindHardcodedValues(MethodDeclarationSyntax method)
    {
        var hardcoded = new List<string>();

        foreach (var invocation in method.DescendantNodes().OfType<InvocationExpressionSyntax>())
        {
            // Check if this is an assertion
            var invocationText = invocation.ToString();
            if (!invocationText.Contains("Assert") && !invocationText.Contains("Should"))
                continue;

            // Check for literal arguments
            foreach (var arg in invocation.ArgumentList.Arguments)
            {
                if (arg.Expression is LiteralExpressionSyntax literal)
                {
                    if (literal.IsKind(SyntaxKind.NumericLiteralExpression) ||
                        literal.IsKind(SyntaxKind.StringLiteralExpression))
                    {
                        hardcoded.Add(literal.ToString());
                    }
                }
            }
        }

        return hardcoded.Distinct().Take(5).ToList();
    }

    private bool HasThreadSleep(MethodDeclarationSyntax method)
    {
        return method.ToString().Contains("Thread.Sleep") ||
               method.ToString().Contains("Task.Delay");
    }

    private bool HasDateTimeNow(MethodDeclarationSyntax method)
    {
        var text = method.ToString();
        return text.Contains("DateTime.Now") ||
               text.Contains("DateTime.UtcNow") ||
               text.Contains("DateTimeOffset.Now") ||
               text.Contains("DateTimeOffset.UtcNow");
    }

    private bool IsIgnoredTest(MethodDeclarationSyntax method)
    {
        foreach (var attrList in method.AttributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                var attrName = attr.Name.ToString();
                if (attrName is "Ignore" or "Skip" or "Fact(Skip" or "Theory(Skip")
                    return true;

                // Check for Skip parameter
                if (attr.ArgumentList != null)
                {
                    var args = attr.ArgumentList.ToString();
                    if (args.Contains("Skip =") || args.Contains("Skip="))
                        return true;
                }
            }
        }
        return false;
    }

    private bool HasCommentedOutCode(MethodDeclarationSyntax method)
    {
        var trivia = method.DescendantTrivia()
            .Where(t => t.IsKind(SyntaxKind.SingleLineCommentTrivia) ||
                       t.IsKind(SyntaxKind.MultiLineCommentTrivia));

        foreach (var comment in trivia)
        {
            var text = comment.ToString();
            // Check for code-like patterns in comments
            if (text.Contains(";") && (text.Contains("=") || text.Contains("(")))
                return true;
        }

        return false;
    }

    private int GetMethodLineCount(MethodDeclarationSyntax method)
    {
        var span = method.GetLocation().GetLineSpan();
        return span.EndLinePosition.Line - span.StartLinePosition.Line + 1;
    }

    private bool IsDescriptiveTestName(string name)
    {
        if (name.Length < MinTestNameLength)
            return false;

        // Should contain underscores or be camelCase with multiple words
        var hasGoodStructure = name.Contains('_') ||
                              System.Text.RegularExpressions.Regex.Matches(name, "[A-Z]").Count >= 3;

        // Should not be generic names
        var genericNames = new[] { "Test", "Test1", "Test2", "TestMethod", "MyTest", "SomeTest" };
        if (genericNames.Contains(name, StringComparer.OrdinalIgnoreCase))
            return false;

        return hasGoodStructure;
    }

    private bool IsMissingActSection(MethodDeclarationSyntax method)
    {
        if (method.Body == null)
            return false;

        // Check for method invocations (excluding setup/assertion calls)
        var invocations = method.Body.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .ToList();

        var nonSetupInvocations = invocations
            .Where(inv =>
            {
                var text = inv.ToString();
                return !text.Contains("Mock") &&
                       !text.Contains("Setup") &&
                       !text.Contains("Assert") &&
                       !text.Contains("Should") &&
                       !text.Contains("Verify") &&
                       !text.Contains("Returns");
            })
            .ToList();

        return nonSetupInvocations.Count == 0 && invocations.Any();
    }

    private int CountAssertions(MethodDeclarationSyntax method)
    {
        var count = 0;
        var text = method.ToString();

        count += System.Text.RegularExpressions.Regex.Matches(text, @"Assert\.\w+\(").Count;
        count += System.Text.RegularExpressions.Regex.Matches(text, @"\.Should\w*\(").Count;
        count += System.Text.RegularExpressions.Regex.Matches(text, @"Expect\(").Count;

        return count;
    }

    private bool IsEagerTest(MethodDeclarationSyntax method)
    {
        if (method.Body == null)
            return false;

        // Count distinct method invocations on the SUT (system under test)
        var invocations = method.Body.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(inv =>
            {
                var text = inv.ToString();
                return !text.Contains("Mock") &&
                       !text.Contains("Setup") &&
                       !text.Contains("Assert") &&
                       !text.Contains("Should") &&
                       !text.Contains("Verify");
            })
            .Select(inv =>
            {
                // Get method name being called
                if (inv.Expression is MemberAccessExpressionSyntax ma)
                    return ma.Name.ToString();
                return inv.Expression.ToString();
            })
            .Distinct()
            .ToList();

        // If testing more than 2 distinct methods, likely eager
        return invocations.Count > 2;
    }

    private string GetNormalizedBodyHash(MethodDeclarationSyntax method)
    {
        if (method.Body == null)
            return "";

        // Normalize the body by removing whitespace and variable names
        var body = method.Body.ToString();
        var normalized = System.Text.RegularExpressions.Regex.Replace(body, @"\s+", " ");
        normalized = System.Text.RegularExpressions.Regex.Replace(normalized, @"var\s+\w+", "var _");

        return normalized.GetHashCode().ToString();
    }

    private bool IsCommonTestValue(string value)
    {
        var common = new[]
        {
            "test", "example", "sample", "dummy", "foo", "bar", "hello", "world",
            "null", "true", "false", "expected", "actual", "result"
        };

        return common.Any(c => value.ToLowerInvariant().Contains(c));
    }

    private bool IsInComment(SyntaxNode node)
    {
        return node.GetLeadingTrivia().Any(t =>
            t.IsKind(SyntaxKind.SingleLineCommentTrivia) ||
            t.IsKind(SyntaxKind.MultiLineCommentTrivia));
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
