using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Logging.Models;

namespace BaseScanner.Analyzers.Logging;

/// <summary>
/// Analyzes correlation ID usage in request handling code.
/// Detects missing correlation IDs that are essential for distributed tracing.
/// </summary>
public class CorrelationAnalyzer : ILoggingDetector
{
    public string Category => "Correlation";

    // Patterns that indicate request handling code
    private static readonly HashSet<string> ControllerBaseClasses = new(StringComparer.OrdinalIgnoreCase)
    {
        "Controller", "ControllerBase", "ApiController",
        "PageModel", "RazorPage"
    };

    private static readonly HashSet<string> ControllerSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Controller", "Handler", "Endpoint"
    };

    private static readonly HashSet<string> HandlerPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        "IRequestHandler", "INotificationHandler", "ICommandHandler", "IQueryHandler",
        "IMessageHandler", "IEventHandler"
    };

    // Common correlation ID property/field/variable names
    private static readonly HashSet<string> CorrelationIdNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "correlationId", "correlation_id", "correlationid",
        "requestId", "request_id", "requestid",
        "traceId", "trace_id", "traceid",
        "spanId", "span_id", "spanid",
        "transactionId", "transaction_id", "transactionid",
        "activityId", "activity_id", "activityid",
        "x-correlation-id", "x-request-id", "x-trace-id"
    };

    // Methods that typically set up correlation context
    private static readonly HashSet<string> CorrelationSetupMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "BeginScope", "PushProperty", "ForContext", "WithProperty",
        "AddBaggage", "SetBaggage", "SetCorrelationId"
    };

    // HTTP context access patterns
    private static readonly HashSet<string> HttpContextPatterns = new(StringComparer.OrdinalIgnoreCase)
    {
        "HttpContext", "Request.Headers", "TraceIdentifier"
    };

    public Task<List<LoggingIssue>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root)
    {
        var issues = new List<LoggingIssue>();
        var filePath = document.FilePath ?? "";

        // Skip test files
        if (IsTestFile(filePath))
            return Task.FromResult(issues);

        // Find request handlers (controllers, MediatR handlers, etc.)
        var requestHandlers = FindRequestHandlers(root, semanticModel);

        foreach (var handler in requestHandlers)
        {
            AnalyzeHandlerForCorrelation(handler, semanticModel, filePath, issues);
        }

        // Check middleware classes
        var middlewareClasses = FindMiddlewareClasses(root, semanticModel);
        foreach (var middleware in middlewareClasses)
        {
            AnalyzeMiddlewareForCorrelation(middleware, semanticModel, filePath, issues);
        }

        return Task.FromResult(issues);
    }

    private bool IsTestFile(string filePath)
    {
        var lowerPath = filePath.ToLowerInvariant();
        return lowerPath.Contains("test") ||
               lowerPath.Contains("spec") ||
               lowerPath.Contains("mock") ||
               lowerPath.Contains("fake");
    }

    private List<(ClassDeclarationSyntax Class, MethodDeclarationSyntax Method)> FindRequestHandlers(
        SyntaxNode root,
        SemanticModel semanticModel)
    {
        var handlers = new List<(ClassDeclarationSyntax, MethodDeclarationSyntax)>();

        foreach (var classDecl in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
        {
            var className = classDecl.Identifier.Text;

            // Check if it's a controller
            var isController = ControllerSuffixes.Any(s => className.EndsWith(s)) ||
                              HasBaseClass(classDecl, semanticModel, ControllerBaseClasses);

            // Check if it implements a handler interface
            var isHandler = ImplementsInterface(classDecl, semanticModel, HandlerPatterns);

            if (isController || isHandler)
            {
                // Find action methods / Handle methods
                foreach (var method in classDecl.Members.OfType<MethodDeclarationSyntax>())
                {
                    if (IsActionMethod(method, isController))
                    {
                        handlers.Add((classDecl, method));
                    }
                }
            }
        }

        return handlers;
    }

    private bool HasBaseClass(ClassDeclarationSyntax classDecl, SemanticModel semanticModel, HashSet<string> baseClasses)
    {
        if (classDecl.BaseList == null)
            return false;

        foreach (var baseType in classDecl.BaseList.Types)
        {
            var typeInfo = semanticModel.GetTypeInfo(baseType.Type);
            var typeName = typeInfo.Type?.Name ?? baseType.Type.ToString();

            if (baseClasses.Contains(typeName))
                return true;

            // Check base types recursively
            var namedType = typeInfo.Type as INamedTypeSymbol;
            while (namedType?.BaseType != null)
            {
                if (baseClasses.Contains(namedType.BaseType.Name))
                    return true;
                namedType = namedType.BaseType;
            }
        }

        return false;
    }

    private bool ImplementsInterface(ClassDeclarationSyntax classDecl, SemanticModel semanticModel, HashSet<string> interfaces)
    {
        if (classDecl.BaseList == null)
            return false;

        foreach (var baseType in classDecl.BaseList.Types)
        {
            var typeInfo = semanticModel.GetTypeInfo(baseType.Type);
            var typeName = typeInfo.Type?.Name ?? baseType.Type.ToString();

            foreach (var pattern in interfaces)
            {
                if (typeName.Contains(pattern))
                    return true;
            }

            // Check interface implementations
            if (typeInfo.Type is INamedTypeSymbol namedType)
            {
                foreach (var iface in namedType.AllInterfaces)
                {
                    foreach (var pattern in interfaces)
                    {
                        if (iface.Name.Contains(pattern))
                            return true;
                    }
                }
            }
        }

        return false;
    }

    private bool IsActionMethod(MethodDeclarationSyntax method, bool isController)
    {
        // Check for HTTP method attributes
        var httpAttributes = new[] { "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "Route" };
        if (method.AttributeLists.SelectMany(a => a.Attributes)
            .Any(attr => httpAttributes.Any(h => attr.Name.ToString().Contains(h))))
        {
            return true;
        }

        // For controllers, public methods are typically actions
        if (isController && method.Modifiers.Any(SyntaxKind.PublicKeyword))
        {
            var returnType = method.ReturnType.ToString();
            if (returnType.Contains("IActionResult") ||
                returnType.Contains("ActionResult") ||
                returnType.Contains("Task"))
            {
                return true;
            }
        }

        // For handlers, look for Handle/HandleAsync methods
        var methodName = method.Identifier.Text;
        if (methodName == "Handle" || methodName == "HandleAsync")
        {
            return true;
        }

        return false;
    }

    private List<ClassDeclarationSyntax> FindMiddlewareClasses(SyntaxNode root, SemanticModel semanticModel)
    {
        var middlewareClasses = new List<ClassDeclarationSyntax>();

        foreach (var classDecl in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
        {
            var className = classDecl.Identifier.Text;

            // Check for middleware naming pattern
            if (className.EndsWith("Middleware"))
            {
                middlewareClasses.Add(classDecl);
                continue;
            }

            // Check for IMiddleware interface
            if (ImplementsInterface(classDecl, semanticModel, new HashSet<string> { "IMiddleware" }))
            {
                middlewareClasses.Add(classDecl);
            }

            // Check for InvokeAsync method pattern
            if (classDecl.Members.OfType<MethodDeclarationSyntax>()
                .Any(m => m.Identifier.Text is "Invoke" or "InvokeAsync"))
            {
                middlewareClasses.Add(classDecl);
            }
        }

        return middlewareClasses;
    }

    private void AnalyzeHandlerForCorrelation(
        (ClassDeclarationSyntax Class, MethodDeclarationSyntax Method) handler,
        SemanticModel semanticModel,
        string filePath,
        List<LoggingIssue> issues)
    {
        var (classDecl, method) = handler;

        // Check if method has any logging
        var logInvocations = FindLogInvocations(method);
        if (!logInvocations.Any())
            return; // No logging, no issue

        // Check if correlation ID is being used
        var hasCorrelationSetup = HasCorrelationSetup(method) || HasCorrelationSetup(classDecl);
        var usesCorrelationInLogging = UsesCorrelationInLogging(method, logInvocations);
        var hasCorrelationParameter = HasCorrelationParameter(method);
        var accessesHttpContextCorrelation = AccessesHttpContextCorrelation(method);

        if (!hasCorrelationSetup && !usesCorrelationInLogging &&
            !hasCorrelationParameter && !accessesHttpContextCorrelation)
        {
            var lineSpan = method.Identifier.GetLocation().GetLineSpan();

            issues.Add(new LoggingIssue
            {
                IssueType = LoggingIssueType.MissingCorrelation,
                Severity = LoggingSeverity.Medium,
                Description = $"Request handler '{method.Identifier.Text}' logs without correlation ID",
                FilePath = filePath,
                StartLine = lineSpan.StartLinePosition.Line + 1,
                EndLine = lineSpan.EndLinePosition.Line + 1,
                ProblematicCode = $"public {method.ReturnType} {method.Identifier.Text}(...)",
                Suggestion = "Add correlation ID to logging scope for distributed tracing",
                RecommendedCode = GenerateCorrelationRecommendation(method),
                Confidence = "Medium",
                Metadata = new Dictionary<string, string>
                {
                    ["ClassName"] = classDecl.Identifier.Text,
                    ["MethodName"] = method.Identifier.Text,
                    ["LogInvocationCount"] = logInvocations.Count.ToString()
                }
            });
        }
    }

    private void AnalyzeMiddlewareForCorrelation(
        ClassDeclarationSyntax middleware,
        SemanticModel semanticModel,
        string filePath,
        List<LoggingIssue> issues)
    {
        var invokeMethod = middleware.Members.OfType<MethodDeclarationSyntax>()
            .FirstOrDefault(m => m.Identifier.Text is "Invoke" or "InvokeAsync");

        if (invokeMethod == null)
            return;

        // Middleware is a good place to SET correlation IDs
        var setsCorrelationId = SetsCorrelationId(invokeMethod);
        var propagatesCorrelation = PropagatesCorrelation(invokeMethod);

        if (!setsCorrelationId && !propagatesCorrelation)
        {
            // Check if this middleware does any logging
            var logInvocations = FindLogInvocations(invokeMethod);
            if (logInvocations.Any())
            {
                var lineSpan = middleware.Identifier.GetLocation().GetLineSpan();

                issues.Add(new LoggingIssue
                {
                    IssueType = LoggingIssueType.MissingCorrelation,
                    Severity = LoggingSeverity.Low,
                    Description = $"Middleware '{middleware.Identifier.Text}' logs without correlation context",
                    FilePath = filePath,
                    StartLine = lineSpan.StartLinePosition.Line + 1,
                    EndLine = lineSpan.EndLinePosition.Line + 1,
                    ProblematicCode = $"class {middleware.Identifier.Text}",
                    Suggestion = "Consider adding correlation ID to logging context in middleware",
                    RecommendedCode = GenerateMiddlewareCorrelationCode(),
                    Confidence = "Low",
                    Metadata = new Dictionary<string, string>
                    {
                        ["MiddlewareName"] = middleware.Identifier.Text
                    }
                });
            }
        }
    }

    private List<InvocationExpressionSyntax> FindLogInvocations(SyntaxNode node)
    {
        var loggingMethods = new HashSet<string>
        {
            "Log", "LogTrace", "LogDebug", "LogInformation", "LogWarning", "LogError", "LogCritical",
            "Trace", "Debug", "Information", "Info", "Warning", "Warn", "Error", "Fatal", "Critical"
        };

        return node.DescendantNodes()
            .OfType<InvocationExpressionSyntax>()
            .Where(inv =>
            {
                if (inv.Expression is MemberAccessExpressionSyntax ma)
                {
                    return loggingMethods.Contains(ma.Name.Identifier.Text);
                }
                return false;
            })
            .ToList();
    }

    private bool HasCorrelationSetup(SyntaxNode node)
    {
        var text = node.ToString();

        return CorrelationSetupMethods.Any(m => text.Contains(m)) &&
               CorrelationIdNames.Any(n => text.Contains(n, StringComparison.OrdinalIgnoreCase));
    }

    private bool UsesCorrelationInLogging(MethodDeclarationSyntax method, List<InvocationExpressionSyntax> logInvocations)
    {
        foreach (var log in logInvocations)
        {
            var logText = log.ToString();
            if (CorrelationIdNames.Any(n => logText.Contains(n, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    private bool HasCorrelationParameter(MethodDeclarationSyntax method)
    {
        foreach (var param in method.ParameterList.Parameters)
        {
            var paramName = param.Identifier.Text;
            if (CorrelationIdNames.Any(n => paramName.Contains(n, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }
        }

        return false;
    }

    private bool AccessesHttpContextCorrelation(SyntaxNode node)
    {
        var text = node.ToString();

        // Check for HttpContext.TraceIdentifier or similar patterns
        return text.Contains("TraceIdentifier") ||
               (text.Contains("HttpContext") && CorrelationIdNames.Any(n =>
                   text.Contains(n, StringComparison.OrdinalIgnoreCase)));
    }

    private bool SetsCorrelationId(MethodDeclarationSyntax method)
    {
        var text = method.ToString();

        // Check for patterns like setting correlation ID from header or generating new one
        return text.Contains("Request.Headers") &&
               CorrelationIdNames.Any(n => text.Contains(n, StringComparison.OrdinalIgnoreCase));
    }

    private bool PropagatesCorrelation(MethodDeclarationSyntax method)
    {
        var text = method.ToString();

        // Check for patterns that propagate correlation (Activity, BeginScope, etc.)
        return text.Contains("Activity.Current") ||
               text.Contains("BeginScope") ||
               text.Contains("DiagnosticSource");
    }

    private string GenerateCorrelationRecommendation(MethodDeclarationSyntax method)
    {
        return @"// Add correlation ID to logging scope:
using (_logger.BeginScope(new Dictionary<string, object>
{
    [""CorrelationId""] = HttpContext.TraceIdentifier
}))
{
    // Your existing code here
}

// Or use Serilog:
// using (LogContext.PushProperty(""CorrelationId"", correlationId))";
    }

    private string GenerateMiddlewareCorrelationCode()
    {
        return @"// In middleware, establish correlation context:
public async Task InvokeAsync(HttpContext context)
{
    var correlationId = context.Request.Headers[""X-Correlation-ID""].FirstOrDefault()
        ?? Guid.NewGuid().ToString();

    context.Response.Headers[""X-Correlation-ID""] = correlationId;

    using (_logger.BeginScope(new Dictionary<string, object>
    {
        [""CorrelationId""] = correlationId
    }))
    {
        await _next(context);
    }
}";
    }
}
