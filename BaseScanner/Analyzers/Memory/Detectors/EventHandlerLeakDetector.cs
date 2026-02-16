using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Context;

namespace BaseScanner.Analyzers.Memory.Detectors;

/// <summary>
/// Detects event handlers that are subscribed but never unsubscribed,
/// which can prevent objects from being garbage collected.
/// </summary>
public class EventHandlerLeakDetector : IMemoryLeakDetector
{
    public string Category => "EventHandlerLeak";

    public Task<List<MemoryLeak>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root,
        CodeContext context)
    {
        var leaks = new List<MemoryLeak>();
        var filePath = document.FilePath ?? "";

        // Analyze each class/struct for event subscription patterns
        foreach (var typeDecl in root.DescendantNodes().OfType<TypeDeclarationSyntax>())
        {
            var typeSymbol = semanticModel.GetDeclaredSymbol(typeDecl);
            if (typeSymbol == null) continue;

            var subscriptions = CollectEventSubscriptions(typeDecl, semanticModel);
            var unsubscriptions = CollectEventUnsubscriptions(typeDecl, semanticModel);

            // Find subscriptions without matching unsubscriptions
            foreach (var subscription in subscriptions)
            {
                if (!HasMatchingUnsubscription(subscription, unsubscriptions))
                {
                    // Check if the class implements IDisposable (potential cleanup in Dispose)
                    var implementsDisposable = typeSymbol.AllInterfaces
                        .Any(i => i.Name == "IDisposable");

                    // Check if unsubscription happens in Dispose
                    var hasDisposeUnsubscription = implementsDisposable &&
                        HasUnsubscriptionInDispose(typeDecl, subscription, semanticModel);

                    if (!hasDisposeUnsubscription)
                    {
                        var lineSpan = subscription.SubscriptionLocation.GetLineSpan();
                        var severity = DetermineSeverity(subscription, typeSymbol);

                        leaks.Add(new MemoryLeak
                        {
                            LeakType = Category,
                            Severity = severity,
                            FilePath = filePath,
                            StartLine = lineSpan.StartLinePosition.Line + 1,
                            EndLine = lineSpan.EndLinePosition.Line + 1,
                            Description = $"Event '{subscription.EventName}' is subscribed but never unsubscribed. " +
                                         $"This can prevent '{typeSymbol.Name}' instances from being garbage collected.",
                            Recommendation = implementsDisposable
                                ? $"Unsubscribe from '{subscription.EventName}' in the Dispose() method."
                                : $"Implement IDisposable and unsubscribe from '{subscription.EventName}' in Dispose(), " +
                                  $"or unsubscribe when the handler is no longer needed.",
                            ProblematicCode = subscription.EventSource,
                            SuggestedFix = GenerateSuggestedFix(subscription, implementsDisposable),
                            Confidence = "High",
                            CweId = "CWE-401",
                            IsInHotPath = IsInHotPath(subscription.SubscriptionLocation, root),
                            Details = new List<string>
                            {
                                $"Event source: {subscription.EventSource}",
                                $"Handler: {subscription.Handler}",
                                $"Containing method: {subscription.ContainingMethod}",
                                implementsDisposable ? "Class implements IDisposable" : "Class does not implement IDisposable"
                            }
                        });
                    }
                }
            }
        }

        return Task.FromResult(leaks);
    }

    private List<EventSubscriptionInfo> CollectEventSubscriptions(
        TypeDeclarationSyntax typeDecl,
        SemanticModel semanticModel)
    {
        var subscriptions = new List<EventSubscriptionInfo>();

        foreach (var assignment in typeDecl.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (!assignment.IsKind(SyntaxKind.AddAssignmentExpression))
                continue;

            // Check if left side is an event
            var leftSymbol = semanticModel.GetSymbolInfo(assignment.Left).Symbol;
            if (leftSymbol is not IEventSymbol eventSymbol)
                continue;

            var containingMethod = assignment.Ancestors()
                .OfType<MethodDeclarationSyntax>()
                .FirstOrDefault();

            var containingType = assignment.Ancestors()
                .OfType<TypeDeclarationSyntax>()
                .FirstOrDefault();

            subscriptions.Add(new EventSubscriptionInfo
            {
                EventName = eventSymbol.Name,
                EventSource = assignment.Left.ToString(),
                Handler = assignment.Right.ToString(),
                SubscriptionLocation = assignment.GetLocation(),
                ContainingMethod = containingMethod?.Identifier.Text ?? "",
                ContainingType = containingType?.Identifier.Text ?? ""
            });
        }

        return subscriptions;
    }

    private List<EventSubscriptionInfo> CollectEventUnsubscriptions(
        TypeDeclarationSyntax typeDecl,
        SemanticModel semanticModel)
    {
        var unsubscriptions = new List<EventSubscriptionInfo>();

        foreach (var assignment in typeDecl.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (!assignment.IsKind(SyntaxKind.SubtractAssignmentExpression))
                continue;

            var leftSymbol = semanticModel.GetSymbolInfo(assignment.Left).Symbol;
            if (leftSymbol is not IEventSymbol eventSymbol)
                continue;

            unsubscriptions.Add(new EventSubscriptionInfo
            {
                EventName = eventSymbol.Name,
                EventSource = assignment.Left.ToString(),
                Handler = assignment.Right.ToString(),
                SubscriptionLocation = assignment.GetLocation()
            });
        }

        return unsubscriptions;
    }

    private bool HasMatchingUnsubscription(
        EventSubscriptionInfo subscription,
        List<EventSubscriptionInfo> unsubscriptions)
    {
        return unsubscriptions.Any(unsub =>
            unsub.EventName == subscription.EventName &&
            NormalizeEventSource(unsub.EventSource) == NormalizeEventSource(subscription.EventSource) &&
            NormalizeHandler(unsub.Handler) == NormalizeHandler(subscription.Handler));
    }

    private string NormalizeEventSource(string source)
    {
        // Normalize "this.foo.Event" to "foo.Event"
        return source.Replace("this.", "").Trim();
    }

    private string NormalizeHandler(string handler)
    {
        // Normalize handler expressions for comparison
        return handler.Replace("this.", "").Trim();
    }

    private bool HasUnsubscriptionInDispose(
        TypeDeclarationSyntax typeDecl,
        EventSubscriptionInfo subscription,
        SemanticModel semanticModel)
    {
        var disposeMethod = typeDecl.Members
            .OfType<MethodDeclarationSyntax>()
            .FirstOrDefault(m => m.Identifier.Text == "Dispose");

        if (disposeMethod == null)
            return false;

        // Check for unsubscription in Dispose method
        foreach (var assignment in disposeMethod.DescendantNodes().OfType<AssignmentExpressionSyntax>())
        {
            if (!assignment.IsKind(SyntaxKind.SubtractAssignmentExpression))
                continue;

            var leftSymbol = semanticModel.GetSymbolInfo(assignment.Left).Symbol;
            if (leftSymbol is IEventSymbol eventSymbol &&
                eventSymbol.Name == subscription.EventName)
            {
                return true;
            }
        }

        return false;
    }

    private string DetermineSeverity(EventSubscriptionInfo subscription, INamedTypeSymbol containingType)
    {
        // Higher severity if subscribing to external events (not own events)
        var eventSource = subscription.EventSource;

        // If subscribing to static events, it's critical
        if (eventSource.Contains("static", StringComparison.OrdinalIgnoreCase) ||
            char.IsUpper(eventSource.Split('.').First()[0]))
        {
            return "Critical";
        }

        // If the class is not disposable and subscribes to external events
        var implementsDisposable = containingType.AllInterfaces.Any(i => i.Name == "IDisposable");
        if (!implementsDisposable)
        {
            return "High";
        }

        // If subscribing in constructor or initialization
        if (subscription.ContainingMethod is "" or "InitializeComponent" or ".ctor")
        {
            return "High";
        }

        return "Medium";
    }

    private bool IsInHotPath(Location location, SyntaxNode root)
    {
        var node = root.FindNode(location.SourceSpan);

        // Check if inside a loop
        return node.Ancestors().Any(a =>
            a is ForStatementSyntax or
                ForEachStatementSyntax or
                WhileStatementSyntax or
                DoStatementSyntax);
    }

    private string GenerateSuggestedFix(EventSubscriptionInfo subscription, bool implementsDisposable)
    {
        var unsubscribe = $"{subscription.EventSource} -= {subscription.Handler};";

        if (implementsDisposable)
        {
            return $@"// In Dispose() method:
public void Dispose()
{{
    {unsubscribe}
    // ... other cleanup
}}";
        }

        return $@"// Option 1: Implement IDisposable
public class MyClass : IDisposable
{{
    public void Dispose()
    {{
        {unsubscribe}
    }}
}}

// Option 2: Use weak event pattern
// WeakEventManager<TSource, TEventArgs>.AddHandler(source, ""EventName"", handler);

// Option 3: Unsubscribe when no longer needed
public void Cleanup()
{{
    {unsubscribe}
}}";
    }
}
