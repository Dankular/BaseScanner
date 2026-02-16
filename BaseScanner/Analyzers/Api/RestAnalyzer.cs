using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Api.Models;

namespace BaseScanner.Analyzers.Api;

/// <summary>
/// Analyzes ASP.NET Core REST/HTTP API best practices including verb usage,
/// route consistency, response types, and status codes.
/// </summary>
public class RestAnalyzer
{
    // HTTP verbs and their expected behaviors
    private static readonly Dictionary<string, HttpVerbInfo> HttpVerbs = new()
    {
        ["HttpGet"] = new("GET", false, false, [200, 404]),
        ["HttpPost"] = new("POST", true, true, [201, 400, 409]),
        ["HttpPut"] = new("PUT", true, true, [200, 204, 400, 404]),
        ["HttpDelete"] = new("DELETE", true, false, [200, 204, 404]),
        ["HttpPatch"] = new("PATCH", true, true, [200, 204, 400, 404]),
        ["HttpHead"] = new("HEAD", false, false, [200, 404]),
        ["HttpOptions"] = new("OPTIONS", false, false, [200])
    };

    // Words that indicate state mutation
    private static readonly string[] MutationKeywords =
    [
        "create", "add", "insert", "save", "update", "modify", "edit", "change",
        "delete", "remove", "clear", "reset", "set", "assign", "increment", "decrement",
        "approve", "reject", "cancel", "submit", "process", "execute", "run", "trigger"
    ];

    // Words that indicate read operations
    private static readonly string[] ReadKeywords =
    [
        "get", "fetch", "retrieve", "find", "search", "query", "list", "read", "load",
        "check", "validate", "verify", "exists", "count", "contains"
    ];

    public async Task<List<RestEndpointIssue>> AnalyzeAsync(Project project)
    {
        var issues = new List<RestEndpointIssue>();
        var endpoints = new List<ApiEndpoint>();

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null) continue;
            if (IsGeneratedFile(document.FilePath)) continue;

            var root = await document.GetSyntaxRootAsync();
            var semanticModel = await document.GetSemanticModelAsync();
            if (root == null || semanticModel == null) continue;

            // Find controller classes
            var controllers = FindControllers(root, semanticModel);

            foreach (var controller in controllers)
            {
                var controllerEndpoints = AnalyzeController(controller, semanticModel, document.FilePath);
                endpoints.AddRange(controllerEndpoints);
            }
        }

        // Analyze each endpoint for issues
        foreach (var endpoint in endpoints)
        {
            issues.AddRange(AnalyzeEndpoint(endpoint));
        }

        // Analyze cross-endpoint consistency
        issues.AddRange(AnalyzeRouteConsistency(endpoints));
        issues.AddRange(AnalyzeNamingConsistency(endpoints));

        return issues
            .OrderByDescending(i => GetSeverityOrder(i.Severity))
            .ThenBy(i => i.FilePath)
            .ThenBy(i => i.Line)
            .ToList();
    }

    private List<ClassDeclarationSyntax> FindControllers(SyntaxNode root, SemanticModel model)
    {
        return root.DescendantNodes()
            .OfType<ClassDeclarationSyntax>()
            .Where(c => IsController(c, model))
            .ToList();
    }

    private bool IsController(ClassDeclarationSyntax classDecl, SemanticModel model)
    {
        // Check for Controller/ControllerBase inheritance
        if (classDecl.BaseList != null)
        {
            foreach (var baseType in classDecl.BaseList.Types)
            {
                var typeName = baseType.Type.ToString();
                if (typeName.Contains("Controller") || typeName.Contains("ControllerBase"))
                    return true;
            }
        }

        // Check for [ApiController] attribute
        var hasApiControllerAttr = classDecl.AttributeLists
            .SelectMany(al => al.Attributes)
            .Any(a => a.Name.ToString().Contains("ApiController"));

        if (hasApiControllerAttr) return true;

        // Check for [Controller] attribute
        var hasControllerAttr = classDecl.AttributeLists
            .SelectMany(al => al.Attributes)
            .Any(a => a.Name.ToString() == "Controller");

        return hasControllerAttr;
    }

    private List<ApiEndpoint> AnalyzeController(ClassDeclarationSyntax controller, SemanticModel model, string filePath)
    {
        var endpoints = new List<ApiEndpoint>();
        var controllerName = controller.Identifier.Text.Replace("Controller", "");

        // Get controller-level route
        var controllerRoute = GetRouteTemplate(controller.AttributeLists);

        // Analyze each action method
        foreach (var method in controller.Members.OfType<MethodDeclarationSyntax>())
        {
            if (!method.Modifiers.Any(SyntaxKind.PublicKeyword)) continue;

            var endpoint = AnalyzeAction(method, model, controllerName, controllerRoute, filePath);
            if (endpoint != null)
            {
                endpoints.Add(endpoint);
            }
        }

        return endpoints;
    }

    private ApiEndpoint? AnalyzeAction(MethodDeclarationSyntax method, SemanticModel model,
        string controllerName, string? controllerRoute, string filePath)
    {
        var httpMethod = GetHttpMethod(method.AttributeLists);
        if (httpMethod == null)
        {
            // Check for action methods without HTTP verb attributes
            // They default to GET in some cases, but we'll skip them
            return null;
        }

        var actionRoute = GetRouteTemplate(method.AttributeLists);
        var fullRoute = CombineRoutes(controllerRoute, actionRoute);

        var parameters = method.ParameterList.Parameters
            .Select(p => $"{p.Type?.ToString() ?? "?"} {p.Identifier.Text}")
            .ToList();

        var responseTypes = GetResponseTypes(method.AttributeLists);
        var statusCodes = GetStatusCodes(method.AttributeLists);
        var requiresAuth = HasAuthAttribute(method.AttributeLists) ||
                          HasAuthAttribute(((TypeDeclarationSyntax)method.Parent!).AttributeLists);

        return new ApiEndpoint
        {
            Controller = controllerName,
            Action = method.Identifier.Text,
            HttpMethod = httpMethod,
            Route = fullRoute ?? "[unknown]",
            ReturnType = method.ReturnType.ToString(),
            Parameters = parameters,
            FilePath = filePath,
            Line = method.GetLocation().GetLineSpan().StartLinePosition.Line + 1,
            ResponseTypes = responseTypes,
            StatusCodes = statusCodes,
            RequiresAuth = requiresAuth,
            Version = GetApiVersion(method.AttributeLists),
            IsDeprecated = HasDeprecatedAttribute(method.AttributeLists)
        };
    }

    private List<RestEndpointIssue> AnalyzeEndpoint(ApiEndpoint endpoint)
    {
        var issues = new List<RestEndpointIssue>();

        // Check HTTP verb matches action semantics
        var verbIssue = CheckVerbSemantics(endpoint);
        if (verbIssue != null) issues.Add(verbIssue);

        // Check for missing response types
        if (!endpoint.ResponseTypes.Any())
        {
            issues.Add(new RestEndpointIssue
            {
                HttpMethod = endpoint.HttpMethod,
                Route = endpoint.Route,
                Controller = endpoint.Controller,
                Action = endpoint.Action,
                IssueType = RestIssueType.MissingResponseType,
                Severity = "Low",
                Message = $"Action '{endpoint.Action}' lacks [ProducesResponseType] attributes",
                FilePath = endpoint.FilePath,
                Line = endpoint.Line,
                Recommendation = "Add [ProducesResponseType] attributes to document expected responses"
            });
        }

        // Check for inappropriate status codes
        var statusCodeIssues = CheckStatusCodes(endpoint);
        issues.AddRange(statusCodeIssues);

        // Check for missing authorization on sensitive endpoints
        if (IsSensitiveOperation(endpoint) && !endpoint.RequiresAuth)
        {
            issues.Add(new RestEndpointIssue
            {
                HttpMethod = endpoint.HttpMethod,
                Route = endpoint.Route,
                Controller = endpoint.Controller,
                Action = endpoint.Action,
                IssueType = RestIssueType.MissingAuthorization,
                Severity = "Medium",
                Message = $"Mutating action '{endpoint.Action}' has no [Authorize] attribute",
                FilePath = endpoint.FilePath,
                Line = endpoint.Line,
                Recommendation = "Add [Authorize] attribute or explicitly document why anonymous access is allowed"
            });
        }

        // Check for route parameter issues
        var routeParamIssues = CheckRouteParameters(endpoint);
        issues.AddRange(routeParamIssues);

        return issues;
    }

    private RestEndpointIssue? CheckVerbSemantics(ApiEndpoint endpoint)
    {
        var actionLower = endpoint.Action.ToLowerInvariant();
        var verbInfo = HttpVerbs.GetValueOrDefault(endpoint.HttpMethod);

        if (endpoint.HttpMethod == "HttpGet" || endpoint.HttpMethod == "GET")
        {
            // GET should not mutate
            if (MutationKeywords.Any(k => actionLower.Contains(k)))
            {
                return new RestEndpointIssue
                {
                    HttpMethod = endpoint.HttpMethod,
                    Route = endpoint.Route,
                    Controller = endpoint.Controller,
                    Action = endpoint.Action,
                    IssueType = RestIssueType.VerbMismatch,
                    Severity = "High",
                    Message = $"GET action '{endpoint.Action}' appears to mutate state based on its name",
                    FilePath = endpoint.FilePath,
                    Line = endpoint.Line,
                    Recommendation = "Use POST/PUT/PATCH for state-mutating operations"
                };
            }
        }
        else if (endpoint.HttpMethod is "HttpPost" or "POST" or "HttpPut" or "PUT")
        {
            // POST/PUT should typically mutate
            if (ReadKeywords.Any(k => actionLower.StartsWith(k)) &&
                !MutationKeywords.Any(k => actionLower.Contains(k)))
            {
                return new RestEndpointIssue
                {
                    HttpMethod = endpoint.HttpMethod,
                    Route = endpoint.Route,
                    Controller = endpoint.Controller,
                    Action = endpoint.Action,
                    IssueType = RestIssueType.VerbMismatch,
                    Severity = "Medium",
                    Message = $"{endpoint.HttpMethod} action '{endpoint.Action}' appears to be read-only based on its name",
                    FilePath = endpoint.FilePath,
                    Line = endpoint.Line,
                    Recommendation = "Use GET for read-only operations"
                };
            }
        }

        return null;
    }

    private List<RestEndpointIssue> CheckStatusCodes(ApiEndpoint endpoint)
    {
        var issues = new List<RestEndpointIssue>();
        var verbInfo = HttpVerbs.GetValueOrDefault(endpoint.HttpMethod);

        if (verbInfo == null || !endpoint.StatusCodes.Any()) return issues;

        // Check for unexpected status codes
        foreach (var code in endpoint.StatusCodes)
        {
            if (!verbInfo.ExpectedCodes.Contains(code) && code != 401 && code != 403 && code != 500)
            {
                issues.Add(new RestEndpointIssue
                {
                    HttpMethod = endpoint.HttpMethod,
                    Route = endpoint.Route,
                    Controller = endpoint.Controller,
                    Action = endpoint.Action,
                    IssueType = RestIssueType.InappropriateStatusCode,
                    Severity = "Low",
                    Message = $"Status code {code} is unusual for {endpoint.HttpMethod} operations",
                    FilePath = endpoint.FilePath,
                    Line = endpoint.Line,
                    Recommendation = $"Expected codes for {endpoint.HttpMethod}: {string.Join(", ", verbInfo.ExpectedCodes)}"
                });
            }
        }

        // POST should return 201 Created for resource creation
        if (endpoint.HttpMethod is "HttpPost" or "POST")
        {
            var actionLower = endpoint.Action.ToLowerInvariant();
            if ((actionLower.Contains("create") || actionLower.Contains("add")) &&
                !endpoint.StatusCodes.Contains(201))
            {
                issues.Add(new RestEndpointIssue
                {
                    HttpMethod = endpoint.HttpMethod,
                    Route = endpoint.Route,
                    Controller = endpoint.Controller,
                    Action = endpoint.Action,
                    IssueType = RestIssueType.InappropriateStatusCode,
                    Severity = "Low",
                    Message = $"POST action '{endpoint.Action}' appears to create a resource but doesn't specify 201 Created",
                    FilePath = endpoint.FilePath,
                    Line = endpoint.Line,
                    Recommendation = "Return 201 Created with Location header for resource creation"
                });
            }
        }

        return issues;
    }

    private List<RestEndpointIssue> CheckRouteParameters(ApiEndpoint endpoint)
    {
        var issues = new List<RestEndpointIssue>();

        // Extract route parameters
        var routeParams = ExtractRouteParameters(endpoint.Route);
        var methodParams = endpoint.Parameters.Select(p => p.Split(' ').Last().ToLowerInvariant()).ToList();

        // Check for route parameters not in method signature
        foreach (var routeParam in routeParams)
        {
            if (!methodParams.Contains(routeParam.ToLowerInvariant()))
            {
                issues.Add(new RestEndpointIssue
                {
                    HttpMethod = endpoint.HttpMethod,
                    Route = endpoint.Route,
                    Controller = endpoint.Controller,
                    Action = endpoint.Action,
                    IssueType = RestIssueType.InvalidRouteParameter,
                    Severity = "High",
                    Message = $"Route parameter '{routeParam}' not found in method parameters",
                    FilePath = endpoint.FilePath,
                    Line = endpoint.Line,
                    Recommendation = "Add a matching parameter to the method signature"
                });
            }
        }

        return issues;
    }

    private List<RestEndpointIssue> AnalyzeRouteConsistency(List<ApiEndpoint> endpoints)
    {
        var issues = new List<RestEndpointIssue>();

        // Group by controller
        var byController = endpoints.GroupBy(e => e.Controller);

        foreach (var controllerGroup in byController)
        {
            var controllerEndpoints = controllerGroup.ToList();

            // Check for mixed routing styles
            var hasTemplateRoutes = controllerEndpoints.Any(e => e.Route.Contains("{"));
            var hasStaticRoutes = controllerEndpoints.Any(e => !e.Route.Contains("{") && e.Route != "[unknown]");

            // Check route naming consistency
            var routePatterns = controllerEndpoints
                .Select(e => GetRouteNamingPattern(e.Route))
                .Where(p => p != null)
                .Distinct()
                .ToList();

            if (routePatterns.Count > 1)
            {
                var first = controllerEndpoints.First();
                issues.Add(new RestEndpointIssue
                {
                    HttpMethod = first.HttpMethod,
                    Route = first.Route,
                    Controller = first.Controller,
                    Action = first.Action,
                    IssueType = RestIssueType.InconsistentRoute,
                    Severity = "Medium",
                    Message = $"Controller '{first.Controller}' has inconsistent route naming patterns: {string.Join(", ", routePatterns)}",
                    FilePath = first.FilePath,
                    Line = first.Line,
                    Recommendation = "Use consistent route naming (kebab-case, camelCase, or PascalCase)"
                });
            }
        }

        // Check for duplicate routes
        var routeGroups = endpoints
            .GroupBy(e => (e.HttpMethod, e.Route.ToLowerInvariant()))
            .Where(g => g.Count() > 1);

        foreach (var group in routeGroups)
        {
            var duplicates = group.ToList();
            foreach (var dup in duplicates.Skip(1))
            {
                issues.Add(new RestEndpointIssue
                {
                    HttpMethod = dup.HttpMethod,
                    Route = dup.Route,
                    Controller = dup.Controller,
                    Action = dup.Action,
                    IssueType = RestIssueType.InconsistentRoute,
                    Severity = "High",
                    Message = $"Duplicate route '{dup.HttpMethod} {dup.Route}' - conflicts with {duplicates[0].Controller}.{duplicates[0].Action}",
                    FilePath = dup.FilePath,
                    Line = dup.Line,
                    Recommendation = "Use unique routes for each action"
                });
            }
        }

        return issues;
    }

    private List<RestEndpointIssue> AnalyzeNamingConsistency(List<ApiEndpoint> endpoints)
    {
        var issues = new List<RestEndpointIssue>();

        // Group by HTTP method
        var getEndpoints = endpoints.Where(e => e.HttpMethod is "HttpGet" or "GET").ToList();
        var postEndpoints = endpoints.Where(e => e.HttpMethod is "HttpPost" or "POST").ToList();

        // Check GET action naming patterns
        var getPatterns = getEndpoints
            .Select(e => GetActionNamingPattern(e.Action))
            .GroupBy(p => p)
            .OrderByDescending(g => g.Count())
            .ToList();

        if (getPatterns.Count > 2 && getEndpoints.Count > 3)
        {
            var dominantPattern = getPatterns.First().Key;
            var inconsistent = getEndpoints
                .Where(e => GetActionNamingPattern(e.Action) != dominantPattern)
                .Take(3)
                .ToList();

            foreach (var endpoint in inconsistent)
            {
                issues.Add(new RestEndpointIssue
                {
                    HttpMethod = endpoint.HttpMethod,
                    Route = endpoint.Route,
                    Controller = endpoint.Controller,
                    Action = endpoint.Action,
                    IssueType = RestIssueType.InconsistentNaming,
                    Severity = "Low",
                    Message = $"GET action '{endpoint.Action}' uses different naming pattern than most other GET actions",
                    FilePath = endpoint.FilePath,
                    Line = endpoint.Line,
                    Recommendation = $"Consider using consistent pattern (most common: {dominantPattern})"
                });
            }
        }

        return issues;
    }

    // Helper methods
    private string? GetHttpMethod(SyntaxList<AttributeListSyntax> attributeLists)
    {
        foreach (var attrList in attributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                var name = attr.Name.ToString();
                if (HttpVerbs.ContainsKey(name))
                    return name;
                if (name.StartsWith("Http"))
                    return name;
            }
        }
        return null;
    }

    private string? GetRouteTemplate(SyntaxList<AttributeListSyntax> attributeLists)
    {
        foreach (var attrList in attributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                var name = attr.Name.ToString();
                if (name is "Route" or "RouteAttribute" || HttpVerbs.ContainsKey(name))
                {
                    if (attr.ArgumentList?.Arguments.FirstOrDefault() is { } arg)
                    {
                        return arg.ToString().Trim('"');
                    }
                }
            }
        }
        return null;
    }

    private string? CombineRoutes(string? controllerRoute, string? actionRoute)
    {
        if (string.IsNullOrEmpty(controllerRoute) && string.IsNullOrEmpty(actionRoute))
            return null;

        if (string.IsNullOrEmpty(controllerRoute))
            return actionRoute;

        if (string.IsNullOrEmpty(actionRoute))
            return controllerRoute;

        return $"{controllerRoute.TrimEnd('/')}/{actionRoute.TrimStart('/')}";
    }

    private List<string> GetResponseTypes(SyntaxList<AttributeListSyntax> attributeLists)
    {
        var types = new List<string>();
        foreach (var attrList in attributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                if (attr.Name.ToString().Contains("ProducesResponseType"))
                {
                    types.Add(attr.ToString());
                }
            }
        }
        return types;
    }

    private List<int> GetStatusCodes(SyntaxList<AttributeListSyntax> attributeLists)
    {
        var codes = new List<int>();
        foreach (var attrList in attributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                if (attr.Name.ToString().Contains("ProducesResponseType"))
                {
                    foreach (var arg in attr.ArgumentList?.Arguments ?? [])
                    {
                        if (int.TryParse(arg.ToString(), out var code))
                        {
                            codes.Add(code);
                        }
                        else if (arg.ToString().Contains("StatusCodes.Status"))
                        {
                            var codeStr = arg.ToString()
                                .Replace("StatusCodes.Status", "")
                                .Split(new[] { '_', ' ' }, StringSplitOptions.RemoveEmptyEntries)
                                .FirstOrDefault();
                            if (int.TryParse(codeStr, out var statusCode))
                            {
                                codes.Add(statusCode);
                            }
                        }
                    }
                }
            }
        }
        return codes.Distinct().ToList();
    }

    private bool HasAuthAttribute(SyntaxList<AttributeListSyntax> attributeLists)
    {
        return attributeLists
            .SelectMany(al => al.Attributes)
            .Any(a => a.Name.ToString().Contains("Authorize"));
    }

    private bool HasDeprecatedAttribute(SyntaxList<AttributeListSyntax> attributeLists)
    {
        return attributeLists
            .SelectMany(al => al.Attributes)
            .Any(a => a.Name.ToString().Contains("Obsolete") || a.Name.ToString().Contains("Deprecated"));
    }

    private string? GetApiVersion(SyntaxList<AttributeListSyntax> attributeLists)
    {
        foreach (var attrList in attributeLists)
        {
            foreach (var attr in attrList.Attributes)
            {
                if (attr.Name.ToString().Contains("ApiVersion"))
                {
                    return attr.ArgumentList?.Arguments.FirstOrDefault()?.ToString().Trim('"');
                }
            }
        }
        return null;
    }

    private List<string> ExtractRouteParameters(string route)
    {
        var parameters = new List<string>();
        var matches = System.Text.RegularExpressions.Regex.Matches(route, @"\{([^}:?]+)");
        foreach (System.Text.RegularExpressions.Match match in matches)
        {
            parameters.Add(match.Groups[1].Value);
        }
        return parameters;
    }

    private string? GetRouteNamingPattern(string route)
    {
        if (route.Contains("-")) return "kebab-case";
        if (route.Contains("_")) return "snake_case";
        if (route.Any(char.IsUpper)) return "PascalCase";
        return "lowercase";
    }

    private string GetActionNamingPattern(string action)
    {
        if (action.StartsWith("Get")) return "GetX";
        if (action.StartsWith("Fetch")) return "FetchX";
        if (action.StartsWith("Retrieve")) return "RetrieveX";
        if (action.StartsWith("Find")) return "FindX";
        if (action.StartsWith("Create")) return "CreateX";
        if (action.StartsWith("Add")) return "AddX";
        if (action.StartsWith("Post")) return "PostX";
        if (action.StartsWith("Update")) return "UpdateX";
        if (action.StartsWith("Delete")) return "DeleteX";
        if (action.StartsWith("Remove")) return "RemoveX";
        return "Other";
    }

    private bool IsSensitiveOperation(ApiEndpoint endpoint)
    {
        return endpoint.HttpMethod is "HttpPost" or "POST" or "HttpPut" or "PUT"
               or "HttpDelete" or "DELETE" or "HttpPatch" or "PATCH";
    }

    private int GetSeverityOrder(string severity) => severity switch
    {
        "Critical" => 4,
        "High" => 3,
        "Medium" => 2,
        "Low" => 1,
        _ => 0
    };

    private bool IsGeneratedFile(string filePath)
    {
        var fileName = Path.GetFileName(filePath);
        return fileName.EndsWith(".g.cs") ||
               fileName.EndsWith(".Designer.cs") ||
               fileName.EndsWith(".generated.cs") ||
               filePath.Contains("obj" + Path.DirectorySeparatorChar);
    }

    private record HttpVerbInfo(string Method, bool MutatesState, bool HasBody, int[] ExpectedCodes);
}
