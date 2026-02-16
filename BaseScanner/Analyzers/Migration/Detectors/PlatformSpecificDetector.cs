using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Migration.Models;

namespace BaseScanner.Analyzers.Migration.Detectors;

/// <summary>
/// Detects platform-specific code that may not be portable across operating systems.
/// Identifies Windows Registry access, P/Invoke calls, COM interop, and UI framework references.
/// </summary>
public class PlatformSpecificDetector
{
    // Windows Registry patterns
    private static readonly HashSet<string> RegistryTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft.Win32.Registry",
        "Microsoft.Win32.RegistryKey",
        "Microsoft.Win32.RegistryHive",
        "Microsoft.Win32.RegistryValueKind",
        "Microsoft.Win32.RegistryView"
    };

    // P/Invoke indicators
    private static readonly HashSet<string> PInvokeAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "DllImportAttribute",
        "System.Runtime.InteropServices.DllImportAttribute",
        "LibraryImportAttribute",
        "System.Runtime.InteropServices.LibraryImportAttribute"
    };

    // COM Interop patterns
    private static readonly HashSet<string> ComInteropTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.Runtime.InteropServices.ComImportAttribute",
        "System.Runtime.InteropServices.ComVisibleAttribute",
        "System.Runtime.InteropServices.DispIdAttribute",
        "System.Runtime.InteropServices.GuidAttribute",
        "System.Runtime.InteropServices.InterfaceTypeAttribute",
        "System.Runtime.InteropServices.ClassInterfaceAttribute",
        "System.Runtime.InteropServices.ProgIdAttribute",
        "System.Runtime.InteropServices.ComSourceInterfacesAttribute",
        "System.Runtime.InteropServices.Marshal",
        "System.Runtime.InteropServices.ComTypes",
        "System.Activator"
    };

    // Windows-specific namespaces
    private static readonly HashSet<string> WindowsNamespaces = new(StringComparer.OrdinalIgnoreCase)
    {
        "System.Windows.Forms",
        "System.Drawing",
        "System.Windows.Presentation",
        "System.Windows.Media",
        "System.Windows.Controls",
        "Microsoft.Win32",
        "System.Management",
        "System.ServiceProcess",
        "System.Security.AccessControl",
        "System.Diagnostics.EventLog",
        "System.Diagnostics.PerformanceCounter",
        "System.EnterpriseServices"
    };

    // Known Windows DLLs
    private static readonly HashSet<string> WindowsDlls = new(StringComparer.OrdinalIgnoreCase)
    {
        "kernel32",
        "kernel32.dll",
        "user32",
        "user32.dll",
        "gdi32",
        "gdi32.dll",
        "advapi32",
        "advapi32.dll",
        "shell32",
        "shell32.dll",
        "ole32",
        "ole32.dll",
        "oleaut32",
        "oleaut32.dll",
        "ntdll",
        "ntdll.dll",
        "comctl32",
        "comctl32.dll",
        "comdlg32",
        "comdlg32.dll",
        "winspool.drv",
        "ws2_32",
        "ws2_32.dll",
        "secur32",
        "secur32.dll",
        "crypt32",
        "crypt32.dll",
        "version",
        "version.dll",
        "mpr",
        "mpr.dll",
        "netapi32",
        "netapi32.dll",
        "shlwapi",
        "shlwapi.dll",
        "psapi",
        "psapi.dll",
        "dbghelp",
        "dbghelp.dll"
    };

    /// <summary>
    /// Detects platform-specific code in a document.
    /// </summary>
    public async Task<List<PlatformSpecificCode>> DetectAsync(
        Document document,
        SemanticModel semanticModel,
        SyntaxNode root)
    {
        var detections = new List<PlatformSpecificCode>();
        var filePath = document.FilePath ?? "";

        // Detect different types of platform-specific code
        detections.AddRange(DetectRegistryUsage(root, semanticModel, filePath));
        detections.AddRange(DetectPInvokeCalls(root, semanticModel, filePath));
        detections.AddRange(DetectComInterop(root, semanticModel, filePath));
        detections.AddRange(DetectWindowsFormsReferences(root, semanticModel, filePath));
        detections.AddRange(DetectWpfReferences(root, semanticModel, filePath));
        detections.AddRange(DetectWindowsNamespaceUsage(root, semanticModel, filePath));
        detections.AddRange(DetectEnvironmentVariableAccess(root, semanticModel, filePath));
        detections.AddRange(DetectFilePathPatterns(root, semanticModel, filePath));

        return detections;
    }

    /// <summary>
    /// Detects platform-specific code across a project.
    /// </summary>
    public async Task<List<PlatformSpecificCode>> DetectInProjectAsync(Project project)
    {
        var allDetections = new List<PlatformSpecificCode>();

        foreach (var document in project.Documents)
        {
            if (document.FilePath == null) continue;
            if (document.FilePath.Contains(".Designer.cs")) continue;
            if (document.FilePath.Contains("\\obj\\")) continue;
            if (document.FilePath.Contains("/obj/")) continue;

            var syntaxRoot = await document.GetSyntaxRootAsync();
            var semanticModel = await document.GetSemanticModelAsync();
            if (syntaxRoot == null || semanticModel == null) continue;

            var detections = await DetectAsync(document, semanticModel, syntaxRoot);
            allDetections.AddRange(detections);
        }

        return allDetections;
    }

    private IEnumerable<PlatformSpecificCode> DetectRegistryUsage(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        // Detect Registry type usage
        var typeNodes = root.DescendantNodes().OfType<IdentifierNameSyntax>();

        foreach (var typeNode in typeNodes)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(typeNode);
            var symbol = symbolInfo.Symbol;

            if (symbol == null) continue;

            var containingType = symbol.ContainingType?.ToDisplayString() ?? "";
            var fullName = symbol.ToDisplayString();

            // Check for Registry types
            if (RegistryTypes.Any(rt => fullName.Contains(rt) || containingType.Contains(rt)))
            {
                var lineSpan = typeNode.GetLocation().GetLineSpan();

                yield return new PlatformSpecificCode
                {
                    Type = "Registry",
                    Api = fullName,
                    Platform = "Windows",
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = GetStatementSnippet(typeNode),
                    Impact = "High",
                    Description = "Windows Registry access is not available on Linux/macOS. This code will throw PlatformNotSupportedException on non-Windows platforms.",
                    Alternative = "Use configuration files (appsettings.json), environment variables, or platform checks with RuntimeInformation.IsOSPlatform().",
                    CanBeConditional = true
                };
            }
        }
    }

    private IEnumerable<PlatformSpecificCode> DetectPInvokeCalls(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        // Find methods with DllImport or LibraryImport attributes
        var methods = root.DescendantNodes().OfType<MethodDeclarationSyntax>();

        foreach (var method in methods)
        {
            var attributes = method.AttributeLists.SelectMany(al => al.Attributes);

            foreach (var attribute in attributes)
            {
                var symbolInfo = semanticModel.GetSymbolInfo(attribute);
                var attrType = symbolInfo.Symbol?.ContainingType?.ToDisplayString() ?? "";
                var attrName = attribute.Name.ToString();

                if (PInvokeAttributes.Any(pa => attrName.Contains("DllImport") || attrName.Contains("LibraryImport") ||
                                                 attrType.Contains(pa)))
                {
                    // Try to extract the DLL name
                    var dllName = ExtractDllName(attribute);
                    var isWindowsDll = dllName != null && WindowsDlls.Any(wd =>
                        dllName.Equals(wd, StringComparison.OrdinalIgnoreCase));

                    var lineSpan = method.GetLocation().GetLineSpan();
                    var impact = isWindowsDll ? "Blocking" : "High";

                    yield return new PlatformSpecificCode
                    {
                        Type = "PInvoke",
                        Api = $"{dllName ?? "unknown"}::{method.Identifier.Text}",
                        Platform = isWindowsDll ? "Windows" : "Native",
                        FilePath = filePath,
                        Line = lineSpan.StartLinePosition.Line + 1,
                        Column = lineSpan.StartLinePosition.Character + 1,
                        CodeSnippet = GetMethodSignature(method),
                        Impact = impact,
                        Description = isWindowsDll
                            ? $"P/Invoke call to Windows system DLL '{dllName}'. This will fail on non-Windows platforms."
                            : $"P/Invoke call to native library '{dllName ?? "unknown"}'. Ensure the library is available on all target platforms.",
                        Alternative = isWindowsDll
                            ? "Consider using managed alternatives or platform-specific abstractions. Wrap in RuntimeInformation.IsOSPlatform() checks."
                            : "Ensure the native library is available for all target platforms or use conditional compilation.",
                        CanBeConditional = true
                    };
                }
            }
        }
    }

    private IEnumerable<PlatformSpecificCode> DetectComInterop(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        // Detect COM-related attributes
        var attributes = root.DescendantNodes().OfType<AttributeSyntax>();

        foreach (var attribute in attributes)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(attribute);
            var attrType = symbolInfo.Symbol?.ContainingType?.ToDisplayString() ?? "";

            if (ComInteropTypes.Any(cit => attrType.Contains(cit)))
            {
                var lineSpan = attribute.GetLocation().GetLineSpan();

                yield return new PlatformSpecificCode
                {
                    Type = "COM",
                    Api = attrType,
                    Platform = "Windows",
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = GetStatementSnippet(attribute),
                    Impact = "Blocking",
                    Description = "COM interop is Windows-only. This code will not work on Linux/macOS.",
                    Alternative = "Replace COM components with managed alternatives or cross-platform libraries. Consider using REST APIs or gRPC for interprocess communication.",
                    CanBeConditional = false
                };
            }
        }

        // Detect Marshal usage for COM
        var memberAccesses = root.DescendantNodes().OfType<MemberAccessExpressionSyntax>();

        foreach (var access in memberAccesses)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(access);
            var symbol = symbolInfo.Symbol;

            if (symbol == null) continue;

            var containingType = symbol.ContainingType?.ToDisplayString() ?? "";

            // Check for COM-specific Marshal methods
            if (containingType == "System.Runtime.InteropServices.Marshal")
            {
                var methodName = symbol.Name;
                var comMethods = new[] { "GetActiveObject", "CreateWrapperOfType", "GetComObjectData",
                                         "GetIDispatchForObject", "GetIUnknownForObject", "GetObjectForIUnknown",
                                         "GetTypedObjectForIUnknown", "ReleaseComObject", "FinalReleaseComObject" };

                if (comMethods.Contains(methodName))
                {
                    var lineSpan = access.GetLocation().GetLineSpan();

                    yield return new PlatformSpecificCode
                    {
                        Type = "COM",
                        Api = $"Marshal.{methodName}",
                        Platform = "Windows",
                        FilePath = filePath,
                        Line = lineSpan.StartLinePosition.Line + 1,
                        Column = lineSpan.StartLinePosition.Character + 1,
                        CodeSnippet = GetStatementSnippet(access),
                        Impact = "Blocking",
                        Description = $"Marshal.{methodName} is a COM interop method that only works on Windows.",
                        Alternative = "Replace COM components with managed or cross-platform alternatives.",
                        CanBeConditional = false
                    };
                }
            }
        }

        // Detect dynamic COM object usage (Type.GetTypeFromProgID)
        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in invocations)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(invocation);
            var methodSymbol = symbolInfo.Symbol as IMethodSymbol;

            if (methodSymbol == null) continue;

            var methodName = methodSymbol.Name;
            var containingType = methodSymbol.ContainingType?.ToDisplayString() ?? "";

            if (containingType == "System.Type" &&
                (methodName == "InvokeMember" || methodName == "GetTypeFromProgID" || methodName == "GetTypeFromCLSID"))
            {
                var lineSpan = invocation.GetLocation().GetLineSpan();

                yield return new PlatformSpecificCode
                {
                    Type = "COM",
                    Api = $"Type.{methodName}",
                    Platform = "Windows",
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = GetStatementSnippet(invocation),
                    Impact = "Blocking",
                    Description = $"Type.{methodName} is typically used for COM interop and is Windows-specific.",
                    Alternative = "Replace COM automation with managed alternatives or platform-specific abstractions.",
                    CanBeConditional = true
                };
            }
        }
    }

    private IEnumerable<PlatformSpecificCode> DetectWindowsFormsReferences(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var usingDirectives = root.DescendantNodes().OfType<UsingDirectiveSyntax>();

        foreach (var usingDirective in usingDirectives)
        {
            var namespaceName = usingDirective.Name?.ToString() ?? "";

            if (namespaceName.StartsWith("System.Windows.Forms"))
            {
                var lineSpan = usingDirective.GetLocation().GetLineSpan();

                yield return new PlatformSpecificCode
                {
                    Type = "WinForms",
                    Api = namespaceName,
                    Platform = "Windows",
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = usingDirective.ToString().Trim(),
                    Impact = "High",
                    Description = "Windows Forms is a Windows-only UI framework. It's supported in .NET 6+ on Windows but not cross-platform.",
                    Alternative = "For cross-platform UI, consider .NET MAUI, Avalonia, or Uno Platform. For simple dialogs, use console prompts or web UI.",
                    CanBeConditional = true
                };
            }
        }

        // Also detect WinForms type usage
        var typeNodes = root.DescendantNodes().OfType<IdentifierNameSyntax>();

        foreach (var typeNode in typeNodes)
        {
            var typeInfo = semanticModel.GetTypeInfo(typeNode);
            var typeSymbol = typeInfo.Type;

            if (typeSymbol == null) continue;

            var ns = typeSymbol.ContainingNamespace?.ToDisplayString() ?? "";

            if (ns.StartsWith("System.Windows.Forms") && !IsInUsingDirective(typeNode))
            {
                var lineSpan = typeNode.GetLocation().GetLineSpan();

                yield return new PlatformSpecificCode
                {
                    Type = "WinForms",
                    Api = typeSymbol.ToDisplayString(),
                    Platform = "Windows",
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = GetStatementSnippet(typeNode),
                    Impact = "High",
                    Description = $"Windows Forms type '{typeSymbol.Name}' is Windows-only.",
                    Alternative = "Consider cross-platform alternatives like .NET MAUI, Avalonia, or Blazor.",
                    CanBeConditional = true
                };
            }
        }
    }

    private IEnumerable<PlatformSpecificCode> DetectWpfReferences(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var usingDirectives = root.DescendantNodes().OfType<UsingDirectiveSyntax>();

        foreach (var usingDirective in usingDirectives)
        {
            var namespaceName = usingDirective.Name?.ToString() ?? "";

            if (namespaceName.StartsWith("System.Windows") &&
                !namespaceName.StartsWith("System.Windows.Forms") &&
                (namespaceName.Contains("Presentation") ||
                 namespaceName.Contains("Media") ||
                 namespaceName.Contains("Controls") ||
                 namespaceName.Contains("Documents") ||
                 namespaceName.Contains("Shapes") ||
                 namespaceName.Contains("Data") ||
                 namespaceName.Contains("Input") ||
                 namespaceName == "System.Windows"))
            {
                var lineSpan = usingDirective.GetLocation().GetLineSpan();

                yield return new PlatformSpecificCode
                {
                    Type = "WPF",
                    Api = namespaceName,
                    Platform = "Windows",
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = usingDirective.ToString().Trim(),
                    Impact = "High",
                    Description = "WPF (Windows Presentation Foundation) is a Windows-only UI framework.",
                    Alternative = "For cross-platform UI, consider .NET MAUI, Avalonia (XAML-based), or Uno Platform.",
                    CanBeConditional = true
                };
            }
        }
    }

    private IEnumerable<PlatformSpecificCode> DetectWindowsNamespaceUsage(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var usingDirectives = root.DescendantNodes().OfType<UsingDirectiveSyntax>();

        foreach (var usingDirective in usingDirectives)
        {
            var namespaceName = usingDirective.Name?.ToString() ?? "";

            // Check against known Windows-specific namespaces (excluding WinForms/WPF already handled)
            if (WindowsNamespaces.Any(wn => namespaceName.StartsWith(wn)) &&
                !namespaceName.StartsWith("System.Windows.Forms") &&
                !namespaceName.StartsWith("System.Windows.Presentation"))
            {
                var lineSpan = usingDirective.GetLocation().GetLineSpan();
                var (impact, description, alternative) = GetWindowsNamespaceInfo(namespaceName);

                yield return new PlatformSpecificCode
                {
                    Type = "WindowsNamespace",
                    Api = namespaceName,
                    Platform = "Windows",
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = usingDirective.ToString().Trim(),
                    Impact = impact,
                    Description = description,
                    Alternative = alternative,
                    CanBeConditional = true
                };
            }
        }
    }

    private IEnumerable<PlatformSpecificCode> DetectEnvironmentVariableAccess(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        var invocations = root.DescendantNodes().OfType<InvocationExpressionSyntax>();

        foreach (var invocation in invocations)
        {
            var symbolInfo = semanticModel.GetSymbolInfo(invocation);
            var methodSymbol = symbolInfo.Symbol as IMethodSymbol;

            if (methodSymbol == null) continue;

            var methodName = methodSymbol.Name;
            var containingType = methodSymbol.ContainingType?.ToDisplayString() ?? "";

            // Check for Environment.GetFolderPath with Windows-specific special folders
            if (containingType == "System.Environment" && methodName == "GetFolderPath")
            {
                // Check the argument to see if it's a Windows-specific folder
                var arguments = invocation.ArgumentList.Arguments;
                if (arguments.Count > 0)
                {
                    var argText = arguments[0].ToString();
                    var windowsSpecificFolders = new[]
                    {
                        "ProgramFiles", "ProgramFilesX86", "Windows", "System",
                        "SystemX86", "SendTo", "StartMenu", "Startup", "Recent"
                    };

                    if (windowsSpecificFolders.Any(wf => argText.Contains(wf)))
                    {
                        var lineSpan = invocation.GetLocation().GetLineSpan();

                        yield return new PlatformSpecificCode
                        {
                            Type = "SpecialFolder",
                            Api = $"Environment.GetFolderPath({argText})",
                            Platform = "Windows",
                            FilePath = filePath,
                            Line = lineSpan.StartLinePosition.Line + 1,
                            Column = lineSpan.StartLinePosition.Character + 1,
                            CodeSnippet = GetStatementSnippet(invocation),
                            Impact = "Medium",
                            Description = $"The special folder {argText} may not exist or have the same meaning on non-Windows platforms.",
                            Alternative = "Use platform checks or cross-platform folder alternatives like UserProfile, ApplicationData, LocalApplicationData.",
                            CanBeConditional = true
                        };
                    }
                }
            }
        }
    }

    private IEnumerable<PlatformSpecificCode> DetectFilePathPatterns(
        SyntaxNode root,
        SemanticModel semanticModel,
        string filePath)
    {
        // Detect hardcoded Windows-style paths
        var stringLiterals = root.DescendantNodes().OfType<LiteralExpressionSyntax>()
            .Where(l => l.IsKind(SyntaxKind.StringLiteralExpression));

        foreach (var literal in stringLiterals)
        {
            var text = literal.Token.ValueText;

            // Check for Windows drive letters or UNC paths
            if ((text.Length >= 2 && text[1] == ':' && char.IsLetter(text[0])) ||
                text.StartsWith("\\\\"))
            {
                var lineSpan = literal.GetLocation().GetLineSpan();

                yield return new PlatformSpecificCode
                {
                    Type = "HardcodedPath",
                    Api = text,
                    Platform = "Windows",
                    FilePath = filePath,
                    Line = lineSpan.StartLinePosition.Line + 1,
                    Column = lineSpan.StartLinePosition.Character + 1,
                    CodeSnippet = GetStatementSnippet(literal),
                    Impact = "Medium",
                    Description = "Hardcoded Windows-style path detected. This will fail on Linux/macOS.",
                    Alternative = "Use Path.Combine() with Environment.GetFolderPath() or configuration-based paths.",
                    CanBeConditional = false
                };
            }
        }
    }

    private static string? ExtractDllName(AttributeSyntax attribute)
    {
        // Try to get the DLL name from the first argument
        var arguments = attribute.ArgumentList?.Arguments;
        if (arguments == null || arguments.Value.Count == 0) return null;

        var firstArg = arguments.Value[0];
        if (firstArg.Expression is LiteralExpressionSyntax literal &&
            literal.IsKind(SyntaxKind.StringLiteralExpression))
        {
            return literal.Token.ValueText;
        }

        return null;
    }

    private static string GetMethodSignature(MethodDeclarationSyntax method)
    {
        var modifiers = method.Modifiers.ToString();
        var returnType = method.ReturnType.ToString();
        var name = method.Identifier.Text;
        var parameters = method.ParameterList.ToString();

        return $"{modifiers} {returnType} {name}{parameters}".Trim();
    }

    private static string GetStatementSnippet(SyntaxNode node)
    {
        var statement = node.AncestorsAndSelf()
            .FirstOrDefault(n => n is StatementSyntax or MemberDeclarationSyntax or UsingDirectiveSyntax);

        var text = (statement ?? node).ToString();

        if (text.Length > 200)
        {
            text = text.Substring(0, 197) + "...";
        }

        return text.Replace("\r\n", " ").Replace("\n", " ").Trim();
    }

    private static bool IsInUsingDirective(SyntaxNode node)
    {
        return node.Ancestors().OfType<UsingDirectiveSyntax>().Any();
    }

    private static (string Impact, string Description, string Alternative) GetWindowsNamespaceInfo(string ns)
    {
        return ns switch
        {
            var n when n.StartsWith("System.Drawing") => (
                "Medium",
                "System.Drawing relies on GDI+ which is Windows-specific. System.Drawing.Common has limited cross-platform support.",
                "Use ImageSharp, SkiaSharp, or System.Drawing.Common with platform checks."
            ),
            var n when n.StartsWith("Microsoft.Win32") => (
                "High",
                "Microsoft.Win32 namespace contains Windows-specific functionality like Registry access.",
                "Use configuration files, environment variables, or platform abstractions."
            ),
            var n when n.StartsWith("System.Management") => (
                "High",
                "System.Management (WMI) is Windows-only for system management queries.",
                "Use cross-platform alternatives like /proc on Linux or platform-specific abstractions."
            ),
            var n when n.StartsWith("System.ServiceProcess") => (
                "High",
                "Windows Services are platform-specific. Linux uses different service mechanisms.",
                "Use Microsoft.Extensions.Hosting.WindowsServices for Windows or Microsoft.Extensions.Hosting.Systemd for Linux."
            ),
            var n when n.StartsWith("System.Security.AccessControl") => (
                "Medium",
                "Windows ACLs are different from Unix file permissions.",
                "Use platform checks and platform-specific permission handling."
            ),
            var n when n.StartsWith("System.Diagnostics.EventLog") => (
                "Medium",
                "Windows Event Log is not available on other platforms.",
                "Use Microsoft.Extensions.Logging with appropriate providers for each platform."
            ),
            var n when n.StartsWith("System.Diagnostics.PerformanceCounter") => (
                "Medium",
                "Windows Performance Counters are platform-specific.",
                "Use System.Diagnostics.Metrics for cross-platform metrics."
            ),
            _ => (
                "Medium",
                $"The namespace '{ns}' may contain Windows-specific functionality.",
                "Review usage and consider platform-specific alternatives."
            )
        };
    }

    /// <summary>
    /// Groups detections by type for summary reporting.
    /// </summary>
    public static Dictionary<string, List<PlatformSpecificCode>> GroupByType(List<PlatformSpecificCode> detections)
    {
        return detections.GroupBy(d => d.Type)
            .ToDictionary(g => g.Key, g => g.ToList());
    }

    /// <summary>
    /// Gets blocking issues.
    /// </summary>
    public static List<PlatformSpecificCode> GetBlockingIssues(List<PlatformSpecificCode> detections)
    {
        return detections.Where(d => d.Impact == "Blocking").ToList();
    }

    /// <summary>
    /// Gets issues that can be wrapped in conditional compilation.
    /// </summary>
    public static List<PlatformSpecificCode> GetConditionalIssues(List<PlatformSpecificCode> detections)
    {
        return detections.Where(d => d.CanBeConditional).ToList();
    }
}
