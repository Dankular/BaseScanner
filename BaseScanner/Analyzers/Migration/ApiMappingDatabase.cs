using BaseScanner.Analyzers.Migration.Models;

namespace BaseScanner.Analyzers.Migration;

/// <summary>
/// Database of API mappings from old/deprecated APIs to new/recommended APIs.
/// Used to detect deprecated API usage and suggest modern alternatives.
/// </summary>
public class ApiMappingDatabase
{
    private readonly Dictionary<string, ApiMapping> _mappings = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<ApiMapping>> _mappingsByCategory = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _securityRiskApis = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _blockingApis = new(StringComparer.OrdinalIgnoreCase);

    public ApiMappingDatabase()
    {
        InitializeMappings();
    }

    /// <summary>
    /// Gets all registered API mappings.
    /// </summary>
    public IReadOnlyDictionary<string, ApiMapping> Mappings => _mappings;

    /// <summary>
    /// Gets mappings grouped by category.
    /// </summary>
    public IReadOnlyDictionary<string, List<ApiMapping>> MappingsByCategory => _mappingsByCategory;

    /// <summary>
    /// Gets the set of APIs that pose security risks.
    /// </summary>
    public IReadOnlySet<string> SecurityRiskApis => _securityRiskApis;

    /// <summary>
    /// Gets the set of APIs that block .NET Core migration.
    /// </summary>
    public IReadOnlySet<string> BlockingApis => _blockingApis;

    /// <summary>
    /// Tries to get a mapping for the specified API.
    /// </summary>
    public bool TryGetMapping(string api, out ApiMapping? mapping)
    {
        // Try exact match first
        if (_mappings.TryGetValue(api, out mapping))
            return true;

        // Try partial match (e.g., "System.Net.WebRequest" matches "System.Net.WebRequest.Create")
        foreach (var kvp in _mappings)
        {
            if (api.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
            {
                mapping = kvp.Value;
                return true;
            }
        }

        mapping = null;
        return false;
    }

    /// <summary>
    /// Checks if the API is a known deprecated API.
    /// </summary>
    public bool IsDeprecatedApi(string api)
    {
        return _mappings.ContainsKey(api) ||
               _mappings.Keys.Any(k => api.StartsWith(k, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Checks if the API poses a security risk.
    /// </summary>
    public bool IsSecurityRisk(string api)
    {
        return _securityRiskApis.Any(s => api.Contains(s, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Checks if the API is a blocking issue for migration.
    /// </summary>
    public bool IsBlockingIssue(string api)
    {
        return _blockingApis.Any(s => api.Contains(s, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Gets mappings for a specific category.
    /// </summary>
    public IEnumerable<ApiMapping> GetMappingsForCategory(string category)
    {
        return _mappingsByCategory.TryGetValue(category, out var mappings)
            ? mappings
            : Enumerable.Empty<ApiMapping>();
    }

    /// <summary>
    /// Gets all categories.
    /// </summary>
    public IEnumerable<string> GetCategories() => _mappingsByCategory.Keys;

    private void InitializeMappings()
    {
        // ========================================
        // NETWORKING APIs
        // ========================================

        AddMapping(new ApiMapping
        {
            OldApi = "System.Net.WebRequest",
            NewApi = "System.Net.Http.HttpClient",
            Category = "Networking",
            Complexity = MigrationComplexity.Medium,
            Reason = "WebRequest is obsolete in .NET 6+. HttpClient provides better async support, connection pooling, and modern HTTP features.",
            MigrationGuide = "Replace WebRequest with HttpClient. Use IHttpClientFactory for proper lifecycle management. Convert synchronous calls to async.",
            RequiredPackages = ["Microsoft.Extensions.Http"],
            OldCodeExample = """
                var request = WebRequest.Create("https://api.example.com");
                var response = request.GetResponse();
                using var stream = response.GetResponseStream();
                """,
            NewCodeExample = """
                using var client = new HttpClient();
                var response = await client.GetAsync("https://api.example.com");
                var content = await response.Content.ReadAsStringAsync();
                """
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Net.WebClient",
            NewApi = "System.Net.Http.HttpClient",
            Category = "Networking",
            Complexity = MigrationComplexity.Low,
            Reason = "WebClient is obsolete. HttpClient is the modern, async-first HTTP client.",
            MigrationGuide = "Replace WebClient.DownloadString with HttpClient.GetStringAsync. Replace WebClient.UploadString with HttpClient.PostAsync.",
            OldCodeExample = """
                using var client = new WebClient();
                var result = client.DownloadString("https://api.example.com");
                """,
            NewCodeExample = """
                using var client = new HttpClient();
                var result = await client.GetStringAsync("https://api.example.com");
                """
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Net.HttpWebRequest",
            NewApi = "System.Net.Http.HttpClient",
            Category = "Networking",
            Complexity = MigrationComplexity.Medium,
            Reason = "HttpWebRequest is obsolete. HttpClient provides cleaner API and better resource management.",
            MigrationGuide = "Replace HttpWebRequest with HttpClient. Use HttpRequestMessage for custom headers and configuration."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Net.ServicePointManager",
            NewApi = "System.Net.Http.SocketsHttpHandler",
            Category = "Networking",
            Complexity = MigrationComplexity.Medium,
            Reason = "ServicePointManager is obsolete in .NET Core. Connection settings are configured per-handler.",
            MigrationGuide = "Configure SocketsHttpHandler or HttpClientHandler with the same settings instead of using global ServicePointManager."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Net.FtpWebRequest",
            NewApi = "FluentFTP or SSH.NET",
            Category = "Networking",
            Complexity = MigrationComplexity.High,
            Reason = "FtpWebRequest has limited functionality and is deprecated.",
            MigrationGuide = "Use FluentFTP NuGet package for FTP operations or SSH.NET for SFTP.",
            RequiredPackages = ["FluentFTP"]
        });

        // ========================================
        // COLLECTIONS APIs
        // ========================================

        AddMapping(new ApiMapping
        {
            OldApi = "System.Collections.ArrayList",
            NewApi = "System.Collections.Generic.List<T>",
            Category = "Collections",
            Complexity = MigrationComplexity.Low,
            Reason = "ArrayList is non-generic and requires boxing. List<T> provides type safety and better performance.",
            MigrationGuide = "Replace ArrayList with List<T> where T is the appropriate type. Add type casts where needed during migration.",
            OldCodeExample = """
                var list = new ArrayList();
                list.Add("item");
                var item = (string)list[0];
                """,
            NewCodeExample = """
                var list = new List<string>();
                list.Add("item");
                var item = list[0];
                """
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Collections.Hashtable",
            NewApi = "System.Collections.Generic.Dictionary<TKey, TValue>",
            Category = "Collections",
            Complexity = MigrationComplexity.Low,
            Reason = "Hashtable is non-generic and requires boxing. Dictionary<TKey, TValue> provides type safety.",
            MigrationGuide = "Replace Hashtable with Dictionary<TKey, TValue>. Determine appropriate key and value types.",
            OldCodeExample = """
                var table = new Hashtable();
                table["key"] = "value";
                var value = (string)table["key"];
                """,
            NewCodeExample = """
                var dict = new Dictionary<string, string>();
                dict["key"] = "value";
                var value = dict["key"];
                """
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Collections.SortedList",
            NewApi = "System.Collections.Generic.SortedList<TKey, TValue>",
            Category = "Collections",
            Complexity = MigrationComplexity.Low,
            Reason = "Non-generic SortedList requires boxing and lacks type safety.",
            MigrationGuide = "Replace with generic SortedList<TKey, TValue> or SortedDictionary<TKey, TValue>."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Collections.Queue",
            NewApi = "System.Collections.Generic.Queue<T>",
            Category = "Collections",
            Complexity = MigrationComplexity.Low,
            Reason = "Non-generic Queue requires boxing and lacks type safety.",
            MigrationGuide = "Replace with Queue<T> where T is the element type."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Collections.Stack",
            NewApi = "System.Collections.Generic.Stack<T>",
            Category = "Collections",
            Complexity = MigrationComplexity.Low,
            Reason = "Non-generic Stack requires boxing and lacks type safety.",
            MigrationGuide = "Replace with Stack<T> where T is the element type."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Collections.Specialized.NameValueCollection",
            NewApi = "System.Collections.Generic.Dictionary<string, string>",
            Category = "Collections",
            Complexity = MigrationComplexity.Low,
            Reason = "NameValueCollection has limited functionality compared to modern dictionary types.",
            MigrationGuide = "Replace with Dictionary<string, string> or Dictionary<string, List<string>> for multiple values per key."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Collections.Specialized.StringCollection",
            NewApi = "System.Collections.Generic.List<string>",
            Category = "Collections",
            Complexity = MigrationComplexity.Low,
            Reason = "StringCollection has no advantages over List<string>.",
            MigrationGuide = "Replace with List<string>."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Collections.Specialized.ListDictionary",
            NewApi = "System.Collections.Generic.Dictionary<TKey, TValue>",
            Category = "Collections",
            Complexity = MigrationComplexity.Low,
            Reason = "ListDictionary is optimized for small collections but lacks generics.",
            MigrationGuide = "Replace with Dictionary<TKey, TValue>."
        });

        // ========================================
        // THREADING & ASYNC APIs
        // ========================================

        AddMapping(new ApiMapping
        {
            OldApi = "System.Threading.Thread.Abort",
            NewApi = "System.Threading.CancellationToken",
            Category = "Threading",
            Complexity = MigrationComplexity.High,
            Reason = "Thread.Abort is not supported in .NET Core/.NET 5+ and can cause corruption. It throws PlatformNotSupportedException.",
            MigrationGuide = "Replace Thread.Abort with cooperative cancellation using CancellationToken. Pass tokens to long-running operations and check IsCancellationRequested periodically.",
            IsBlockingIssue = true,
            OldCodeExample = """
                var thread = new Thread(DoWork);
                thread.Start();
                // Later...
                thread.Abort();
                """,
            NewCodeExample = """
                var cts = new CancellationTokenSource();
                var task = Task.Run(() => DoWork(cts.Token), cts.Token);
                // Later...
                cts.Cancel();
                await task;
                """
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Threading.Thread.Suspend",
            NewApi = "System.Threading.ManualResetEventSlim",
            Category = "Threading",
            Complexity = MigrationComplexity.High,
            Reason = "Thread.Suspend is obsolete and not supported in .NET Core.",
            MigrationGuide = "Use synchronization primitives like ManualResetEventSlim for coordinating thread execution.",
            IsBlockingIssue = true
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Threading.Thread.Resume",
            NewApi = "System.Threading.ManualResetEventSlim",
            Category = "Threading",
            Complexity = MigrationComplexity.High,
            Reason = "Thread.Resume is obsolete and not supported in .NET Core.",
            MigrationGuide = "Use synchronization primitives like ManualResetEventSlim for coordinating thread execution.",
            IsBlockingIssue = true
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Threading.ExecutionContext.SuppressFlow",
            NewApi = "Avoid if possible or use AsyncLocal<T>",
            Category = "Threading",
            Complexity = MigrationComplexity.Medium,
            Reason = "Suppressing execution context flow can cause issues with async code and should be avoided.",
            MigrationGuide = "Review why flow suppression is needed. Consider using AsyncLocal<T> for context propagation."
        });

        // ========================================
        // SERIALIZATION APIs
        // ========================================

        AddMapping(new ApiMapping
        {
            OldApi = "System.Web.Script.Serialization.JavaScriptSerializer",
            NewApi = "System.Text.Json.JsonSerializer",
            Category = "Serialization",
            Complexity = MigrationComplexity.Medium,
            Reason = "JavaScriptSerializer is obsolete and has security vulnerabilities. System.Text.Json is the modern, high-performance alternative.",
            MigrationGuide = "Replace JavaScriptSerializer with System.Text.Json.JsonSerializer. Note that System.Text.Json has different defaults (case-sensitive, no comments by default).",
            OldCodeExample = """
                var serializer = new JavaScriptSerializer();
                var json = serializer.Serialize(obj);
                var result = serializer.Deserialize<MyType>(json);
                """,
            NewCodeExample = """
                var json = JsonSerializer.Serialize(obj);
                var result = JsonSerializer.Deserialize<MyType>(json);
                """
        });

        AddMapping(new ApiMapping
        {
            OldApi = "Newtonsoft.Json",
            NewApi = "System.Text.Json",
            Category = "Serialization",
            Complexity = MigrationComplexity.Medium,
            Reason = "System.Text.Json is built-in and offers better performance. Newtonsoft.Json is still supported but System.Text.Json is preferred for new code.",
            MigrationGuide = "Migrate to System.Text.Json. Note differences in handling: property naming, null handling, reference loops. Use [JsonPropertyName] attributes."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter",
            NewApi = "System.Text.Json or MessagePack",
            Category = "Serialization",
            Complexity = MigrationComplexity.High,
            Reason = "BinaryFormatter is a critical security risk (CVE-2020-0828) and is disabled by default in .NET 5+. It can execute arbitrary code during deserialization.",
            MigrationGuide = "Replace BinaryFormatter with a secure serializer like System.Text.Json, MessagePack, or Protocol Buffers. Never deserialize untrusted data with BinaryFormatter.",
            IsSecurityRisk = true,
            IsBlockingIssue = true,
            RequiredPackages = ["MessagePack"]
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Runtime.Serialization.Formatters.Soap.SoapFormatter",
            NewApi = "System.Text.Json or DataContractSerializer",
            Category = "Serialization",
            Complexity = MigrationComplexity.High,
            Reason = "SoapFormatter is obsolete and has security vulnerabilities similar to BinaryFormatter.",
            MigrationGuide = "Replace with DataContractSerializer for SOAP scenarios or System.Text.Json for general serialization.",
            IsSecurityRisk = true
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Runtime.Serialization.NetDataContractSerializer",
            NewApi = "System.Runtime.Serialization.DataContractSerializer",
            Category = "Serialization",
            Complexity = MigrationComplexity.Medium,
            Reason = "NetDataContractSerializer includes type information and has security risks.",
            MigrationGuide = "Use DataContractSerializer with known types for safer serialization.",
            IsSecurityRisk = true
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Xml.Serialization.XmlSerializer",
            NewApi = "System.Text.Json.JsonSerializer or DataContractSerializer",
            Category = "Serialization",
            Complexity = MigrationComplexity.Low,
            Reason = "XmlSerializer is still supported but JSON is often preferred. Consider migration for new projects.",
            MigrationGuide = "XmlSerializer is still valid if XML format is required. For new code, prefer System.Text.Json."
        });

        // ========================================
        // ASP.NET & WEB APIs
        // ========================================

        AddMapping(new ApiMapping
        {
            OldApi = "System.Web.HttpContext",
            NewApi = "Microsoft.AspNetCore.Http.HttpContext",
            Category = "ASP.NET",
            Complexity = MigrationComplexity.High,
            Reason = "System.Web is not available in .NET Core. ASP.NET Core uses a different HTTP abstraction.",
            MigrationGuide = "Inject IHttpContextAccessor to access HttpContext. Many APIs are similar but in different namespaces.",
            IsBlockingIssue = true,
            RequiredPackages = ["Microsoft.AspNetCore.Http.Abstractions"]
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Web.Mvc",
            NewApi = "Microsoft.AspNetCore.Mvc",
            Category = "ASP.NET",
            Complexity = MigrationComplexity.VeryHigh,
            Reason = "ASP.NET MVC is replaced by ASP.NET Core MVC with different architecture.",
            MigrationGuide = "Migrate to ASP.NET Core MVC. Controllers, views, and routing need updates. Use migration tools.",
            IsBlockingIssue = true,
            RequiredPackages = ["Microsoft.AspNetCore.Mvc"]
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Web.Http",
            NewApi = "Microsoft.AspNetCore.Mvc",
            Category = "ASP.NET",
            Complexity = MigrationComplexity.High,
            Reason = "Web API is now unified with MVC in ASP.NET Core.",
            MigrationGuide = "Migrate to ASP.NET Core. ApiController is replaced by ControllerBase with [ApiController] attribute.",
            IsBlockingIssue = true
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Web.HttpApplication",
            NewApi = "Microsoft.AspNetCore.Builder.WebApplication",
            Category = "ASP.NET",
            Complexity = MigrationComplexity.VeryHigh,
            Reason = "Global.asax is replaced by Program.cs and Startup.cs configuration.",
            MigrationGuide = "Move initialization logic to Program.cs. Use middleware for request pipeline configuration.",
            IsBlockingIssue = true
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Web.Caching.Cache",
            NewApi = "Microsoft.Extensions.Caching.Memory.IMemoryCache",
            Category = "ASP.NET",
            Complexity = MigrationComplexity.Medium,
            Reason = "System.Web.Caching is not available in .NET Core.",
            MigrationGuide = "Use IMemoryCache or IDistributedCache from Microsoft.Extensions.Caching.",
            IsBlockingIssue = true,
            RequiredPackages = ["Microsoft.Extensions.Caching.Memory"]
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Web.SessionState",
            NewApi = "Microsoft.AspNetCore.Http.ISession",
            Category = "ASP.NET",
            Complexity = MigrationComplexity.Medium,
            Reason = "Session handling is different in ASP.NET Core.",
            MigrationGuide = "Configure session middleware. Use HttpContext.Session. Consider distributed session for scaling.",
            IsBlockingIssue = true
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Web.Security.FormsAuthentication",
            NewApi = "Microsoft.AspNetCore.Authentication.Cookies",
            Category = "ASP.NET",
            Complexity = MigrationComplexity.High,
            Reason = "Forms authentication is replaced by cookie authentication middleware.",
            MigrationGuide = "Use AddAuthentication().AddCookie() in Startup.cs. Configure authentication options.",
            IsBlockingIssue = true
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Web.Routing",
            NewApi = "Microsoft.AspNetCore.Routing",
            Category = "ASP.NET",
            Complexity = MigrationComplexity.Medium,
            Reason = "Routing is built differently in ASP.NET Core.",
            MigrationGuide = "Use endpoint routing with app.UseRouting() and app.UseEndpoints().",
            IsBlockingIssue = true
        });

        // ========================================
        // CONFIGURATION APIs
        // ========================================

        AddMapping(new ApiMapping
        {
            OldApi = "System.Configuration.ConfigurationManager",
            NewApi = "Microsoft.Extensions.Configuration.IConfiguration",
            Category = "Configuration",
            Complexity = MigrationComplexity.Medium,
            Reason = "ConfigurationManager uses app.config/web.config. Modern .NET uses appsettings.json and IConfiguration.",
            MigrationGuide = "Move settings to appsettings.json. Inject IConfiguration where needed. Use options pattern for strongly-typed configuration.",
            RequiredPackages = ["Microsoft.Extensions.Configuration", "Microsoft.Extensions.Configuration.Json"],
            OldCodeExample = """
                var connectionString = ConfigurationManager.ConnectionStrings["Default"].ConnectionString;
                var setting = ConfigurationManager.AppSettings["MySetting"];
                """,
            NewCodeExample = """
                // In Program.cs
                builder.Configuration.AddJsonFile("appsettings.json");

                // In service
                var connectionString = configuration.GetConnectionString("Default");
                var setting = configuration["MySetting"];
                """
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Configuration.AppSettingsReader",
            NewApi = "Microsoft.Extensions.Configuration.IConfiguration",
            Category = "Configuration",
            Complexity = MigrationComplexity.Low,
            Reason = "AppSettingsReader is obsolete.",
            MigrationGuide = "Use IConfiguration to read settings from appsettings.json."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Web.Configuration.WebConfigurationManager",
            NewApi = "Microsoft.Extensions.Configuration.IConfiguration",
            Category = "Configuration",
            Complexity = MigrationComplexity.Medium,
            Reason = "Web.config is not used in ASP.NET Core for app settings.",
            MigrationGuide = "Migrate settings to appsettings.json. Use IConfiguration and options pattern.",
            IsBlockingIssue = true
        });

        // ========================================
        // REMOTING & WCF APIs
        // ========================================

        AddMapping(new ApiMapping
        {
            OldApi = "System.Runtime.Remoting",
            NewApi = "gRPC or ASP.NET Core Web API",
            Category = "Remoting",
            Complexity = MigrationComplexity.VeryHigh,
            Reason = ".NET Remoting is not supported in .NET Core. It was designed for same-machine or intranet scenarios.",
            MigrationGuide = "Replace with gRPC for high-performance RPC, or ASP.NET Core Web API for REST services.",
            IsBlockingIssue = true,
            RequiredPackages = ["Grpc.AspNetCore"]
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.ServiceModel",
            NewApi = "CoreWCF or gRPC",
            Category = "WCF",
            Complexity = MigrationComplexity.VeryHigh,
            Reason = "WCF server-side is not supported in .NET Core. CoreWCF provides partial compatibility.",
            MigrationGuide = "For WCF clients, use System.ServiceModel.* packages. For servers, migrate to CoreWCF, gRPC, or Web API.",
            IsBlockingIssue = true,
            RequiredPackages = ["CoreWCF.Primitives"]
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.EnterpriseServices",
            NewApi = "Microsoft.Extensions.DependencyInjection",
            Category = "Enterprise",
            Complexity = MigrationComplexity.VeryHigh,
            Reason = "COM+ Enterprise Services are Windows-only and not supported in .NET Core.",
            MigrationGuide = "Replace with modern patterns: DI for service locator, EF Core transactions, distributed transactions with specific providers.",
            IsBlockingIssue = true
        });

        // ========================================
        // DATA ACCESS APIs
        // ========================================

        AddMapping(new ApiMapping
        {
            OldApi = "System.Data.OleDb",
            NewApi = "Entity Framework Core or ADO.NET providers",
            Category = "Data",
            Complexity = MigrationComplexity.High,
            Reason = "OleDb is Windows-only. Cross-platform alternatives exist for specific databases.",
            MigrationGuide = "Use database-specific providers (Npgsql, MySqlConnector) or Entity Framework Core."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Data.Odbc",
            NewApi = "Database-specific ADO.NET providers",
            Category = "Data",
            Complexity = MigrationComplexity.Medium,
            Reason = "ODBC has performance overhead. Native providers are preferred.",
            MigrationGuide = "Use database-specific providers for better performance and features."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Data.Entity",
            NewApi = "Microsoft.EntityFrameworkCore",
            Category = "Data",
            Complexity = MigrationComplexity.High,
            Reason = "Entity Framework 6 is not supported in .NET Core. EF Core is the modern version.",
            MigrationGuide = "Migrate to EF Core. Note API differences: DbModelBuilder -> ModelBuilder, ObjectContext -> DbContext only.",
            RequiredPackages = ["Microsoft.EntityFrameworkCore"]
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Data.Linq",
            NewApi = "Microsoft.EntityFrameworkCore",
            Category = "Data",
            Complexity = MigrationComplexity.High,
            Reason = "LINQ to SQL is not supported in .NET Core.",
            MigrationGuide = "Migrate to Entity Framework Core. Convert DataContext to DbContext.",
            IsBlockingIssue = true
        });

        // ========================================
        // WINDOWS-SPECIFIC APIs
        // ========================================

        AddMapping(new ApiMapping
        {
            OldApi = "Microsoft.Win32.Registry",
            NewApi = "Configuration files or platform checks",
            Category = "Windows",
            Complexity = MigrationComplexity.Medium,
            Reason = "Registry is Windows-only. Available in .NET Core on Windows but not cross-platform.",
            MigrationGuide = "Use RuntimeInformation.IsOSPlatform() checks. Store settings in configuration files for cross-platform support."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Windows.Forms",
            NewApi = ".NET MAUI or Avalonia",
            Category = "Windows",
            Complexity = MigrationComplexity.VeryHigh,
            Reason = "Windows Forms is Windows-only. For cross-platform UI, use .NET MAUI or Avalonia.",
            MigrationGuide = "Windows Forms works on Windows with .NET 6+. For cross-platform, migrate to MAUI, Avalonia, or Uno Platform.",
            RequiredPackages = ["Microsoft.Maui"]
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Windows.Presentation",
            NewApi = ".NET MAUI or Avalonia",
            Category = "Windows",
            Complexity = MigrationComplexity.VeryHigh,
            Reason = "WPF is Windows-only. For cross-platform UI, consider alternatives.",
            MigrationGuide = "WPF works on Windows with .NET 6+. For cross-platform, consider MAUI, Avalonia, or Uno Platform."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Drawing",
            NewApi = "System.Drawing.Common or ImageSharp",
            Category = "Graphics",
            Complexity = MigrationComplexity.Medium,
            Reason = "System.Drawing relies on GDI+ (Windows). System.Drawing.Common works but has limitations on non-Windows.",
            MigrationGuide = "Use System.Drawing.Common NuGet package for Windows. For cross-platform, use ImageSharp or SkiaSharp.",
            RequiredPackages = ["SixLabors.ImageSharp"]
        });

        // ========================================
        // CRYPTOGRAPHY APIs
        // ========================================

        AddMapping(new ApiMapping
        {
            OldApi = "System.Security.Cryptography.RNGCryptoServiceProvider",
            NewApi = "System.Security.Cryptography.RandomNumberGenerator",
            Category = "Cryptography",
            Complexity = MigrationComplexity.Low,
            Reason = "RNGCryptoServiceProvider is obsolete. RandomNumberGenerator is the modern API.",
            MigrationGuide = "Replace with RandomNumberGenerator.Create() or static methods like RandomNumberGenerator.GetBytes().",
            OldCodeExample = """
                using var rng = new RNGCryptoServiceProvider();
                var bytes = new byte[32];
                rng.GetBytes(bytes);
                """,
            NewCodeExample = """
                var bytes = new byte[32];
                RandomNumberGenerator.Fill(bytes);
                """
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Security.Cryptography.MD5CryptoServiceProvider",
            NewApi = "System.Security.Cryptography.MD5",
            Category = "Cryptography",
            Complexity = MigrationComplexity.Low,
            Reason = "CryptoServiceProvider types are obsolete. Use the base algorithm types.",
            MigrationGuide = "Replace MD5CryptoServiceProvider with MD5.Create(). Note: MD5 is not secure for passwords or signatures."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Security.Cryptography.SHA1CryptoServiceProvider",
            NewApi = "System.Security.Cryptography.SHA1",
            Category = "Cryptography",
            Complexity = MigrationComplexity.Low,
            Reason = "CryptoServiceProvider types are obsolete.",
            MigrationGuide = "Replace SHA1CryptoServiceProvider with SHA1.Create(). Note: SHA1 is deprecated for security use."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Security.Cryptography.SHA256Managed",
            NewApi = "System.Security.Cryptography.SHA256",
            Category = "Cryptography",
            Complexity = MigrationComplexity.Low,
            Reason = "Managed implementations are obsolete. Use factory methods.",
            MigrationGuide = "Replace SHA256Managed with SHA256.Create()."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Security.Cryptography.RijndaelManaged",
            NewApi = "System.Security.Cryptography.Aes",
            Category = "Cryptography",
            Complexity = MigrationComplexity.Low,
            Reason = "RijndaelManaged is obsolete. Aes is the standard name for the algorithm.",
            MigrationGuide = "Replace RijndaelManaged with Aes.Create(). Rijndael with non-standard block sizes needs custom implementation."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Security.Cryptography.DESCryptoServiceProvider",
            NewApi = "System.Security.Cryptography.Aes",
            Category = "Cryptography",
            Complexity = MigrationComplexity.Medium,
            Reason = "DES is cryptographically weak and should not be used.",
            MigrationGuide = "Replace DES with AES for new implementations. DES should only be used for legacy compatibility.",
            IsSecurityRisk = true
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Security.Cryptography.TripleDESCryptoServiceProvider",
            NewApi = "System.Security.Cryptography.Aes",
            Category = "Cryptography",
            Complexity = MigrationComplexity.Medium,
            Reason = "3DES is deprecated. AES is more secure and faster.",
            MigrationGuide = "Replace Triple DES with AES for new implementations."
        });

        // ========================================
        // REFLECTION APIs
        // ========================================

        AddMapping(new ApiMapping
        {
            OldApi = "System.Reflection.Assembly.LoadWithPartialName",
            NewApi = "System.Reflection.Assembly.Load",
            Category = "Reflection",
            Complexity = MigrationComplexity.Medium,
            Reason = "LoadWithPartialName is obsolete and can load unexpected assembly versions.",
            MigrationGuide = "Use Assembly.Load with full assembly name or Assembly.LoadFrom with exact path."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.AppDomain.CreateDomain",
            NewApi = "AssemblyLoadContext",
            Category = "Reflection",
            Complexity = MigrationComplexity.High,
            Reason = "Multiple AppDomains are not supported in .NET Core. Only the default AppDomain exists.",
            MigrationGuide = "Use AssemblyLoadContext for assembly isolation. For process isolation, use separate processes.",
            IsBlockingIssue = true
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Reflection.Emit.AssemblyBuilder.DefineDynamicAssembly",
            NewApi = "System.Reflection.Emit with RunAndCollect",
            Category = "Reflection",
            Complexity = MigrationComplexity.Medium,
            Reason = "AssemblyBuilder API has changed. Use RunAndCollect for collectible assemblies.",
            MigrationGuide = "Use AssemblyBuilderAccess.RunAndCollect for collectible assemblies in .NET Core."
        });

        // ========================================
        // IO & FILESYSTEM APIs
        // ========================================

        AddMapping(new ApiMapping
        {
            OldApi = "System.IO.IsolatedStorage",
            NewApi = "Standard file I/O with appropriate paths",
            Category = "IO",
            Complexity = MigrationComplexity.Medium,
            Reason = "IsolatedStorage is supported but has different behavior on different platforms.",
            MigrationGuide = "Use Environment.GetFolderPath() with appropriate SpecialFolder values for cross-platform paths."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.IO.FileSystemWatcher",
            NewApi = "System.IO.FileSystemWatcher (with platform notes)",
            Category = "IO",
            Complexity = MigrationComplexity.Low,
            Reason = "FileSystemWatcher works but has platform-specific limitations (especially on Linux/macOS).",
            MigrationGuide = "Works in .NET Core but be aware of platform differences in event ordering and reliability."
        });

        // ========================================
        // MISCELLANEOUS APIs
        // ========================================

        AddMapping(new ApiMapping
        {
            OldApi = "System.Diagnostics.PerformanceCounter",
            NewApi = "System.Diagnostics.Metrics",
            Category = "Diagnostics",
            Complexity = MigrationComplexity.High,
            Reason = "Performance counters are Windows-only. .NET has a new metrics API.",
            MigrationGuide = "Use System.Diagnostics.Metrics for cross-platform metrics. Windows counters still work on Windows.",
            RequiredPackages = ["System.Diagnostics.DiagnosticSource"]
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Diagnostics.EventLog",
            NewApi = "Microsoft.Extensions.Logging",
            Category = "Diagnostics",
            Complexity = MigrationComplexity.Medium,
            Reason = "EventLog is Windows-only. Use cross-platform logging abstractions.",
            MigrationGuide = "Use Microsoft.Extensions.Logging with appropriate providers (Console, File, Application Insights).",
            RequiredPackages = ["Microsoft.Extensions.Logging"]
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.CodeDom.Compiler",
            NewApi = "Microsoft.CodeAnalysis (Roslyn)",
            Category = "CodeGeneration",
            Complexity = MigrationComplexity.High,
            Reason = "CodeDom is limited and generates less optimal code. Roslyn provides full compilation capabilities.",
            MigrationGuide = "Use Roslyn's Microsoft.CodeAnalysis for code generation and compilation.",
            RequiredPackages = ["Microsoft.CodeAnalysis.CSharp"]
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Data.DataSet",
            NewApi = "Entity Framework Core or POCOs",
            Category = "Data",
            Complexity = MigrationComplexity.Medium,
            Reason = "DataSet is still supported but is heavyweight. Modern apps prefer ORMs or POCOs.",
            MigrationGuide = "Consider using Entity Framework Core or Dapper with POCO classes for cleaner code."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.ComponentModel.BackgroundWorker",
            NewApi = "System.Threading.Tasks.Task",
            Category = "Threading",
            Complexity = MigrationComplexity.Low,
            Reason = "BackgroundWorker is outdated. async/await with Task is the modern approach.",
            MigrationGuide = "Replace BackgroundWorker with async methods and Task.Run. Use IProgress<T> for progress reporting.",
            OldCodeExample = """
                var worker = new BackgroundWorker();
                worker.DoWork += (s, e) => { /* work */ };
                worker.RunWorkerCompleted += (s, e) => { /* complete */ };
                worker.RunWorkerAsync();
                """,
            NewCodeExample = """
                var progress = new Progress<int>(p => UpdateUI(p));
                var result = await Task.Run(() => DoWork(progress));
                HandleComplete(result);
                """
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Security.Principal.WindowsIdentity.GetCurrent",
            NewApi = "Platform-specific with RuntimeInformation checks",
            Category = "Security",
            Complexity = MigrationComplexity.Medium,
            Reason = "WindowsIdentity is Windows-specific. Wrap in platform checks for cross-platform code.",
            MigrationGuide = "Use RuntimeInformation.IsOSPlatform(OSPlatform.Windows) before accessing Windows identity."
        });

        AddMapping(new ApiMapping
        {
            OldApi = "System.Security.AccessControl",
            NewApi = "Platform-specific ACL handling",
            Category = "Security",
            Complexity = MigrationComplexity.High,
            Reason = "ACLs are Windows-specific. Linux/macOS use different permission models.",
            MigrationGuide = "Windows ACLs work on Windows. For cross-platform, use Unix permissions on Linux/macOS."
        });
    }

    private void AddMapping(ApiMapping mapping)
    {
        _mappings[mapping.OldApi] = mapping;

        if (!_mappingsByCategory.ContainsKey(mapping.Category))
        {
            _mappingsByCategory[mapping.Category] = [];
        }
        _mappingsByCategory[mapping.Category].Add(mapping);

        if (mapping.IsSecurityRisk)
        {
            _securityRiskApis.Add(mapping.OldApi);
        }

        if (mapping.IsBlockingIssue)
        {
            _blockingApis.Add(mapping.OldApi);
        }
    }

    /// <summary>
    /// Gets statistics about the mapping database.
    /// </summary>
    public MappingDatabaseStatistics GetStatistics()
    {
        return new MappingDatabaseStatistics
        {
            TotalMappings = _mappings.Count,
            Categories = _mappingsByCategory.Keys.ToList(),
            MappingsPerCategory = _mappingsByCategory.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Count),
            SecurityRiskCount = _securityRiskApis.Count,
            BlockingIssueCount = _blockingApis.Count,
            ComplexityDistribution = _mappings.Values
                .GroupBy(m => m.Complexity)
                .ToDictionary(g => g.Key, g => g.Count())
        };
    }
}

/// <summary>
/// Statistics about the API mapping database.
/// </summary>
public record MappingDatabaseStatistics
{
    public int TotalMappings { get; init; }
    public List<string> Categories { get; init; } = [];
    public Dictionary<string, int> MappingsPerCategory { get; init; } = [];
    public int SecurityRiskCount { get; init; }
    public int BlockingIssueCount { get; init; }
    public Dictionary<MigrationComplexity, int> ComplexityDistribution { get; init; } = [];
}
