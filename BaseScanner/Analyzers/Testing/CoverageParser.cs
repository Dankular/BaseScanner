using System.Text.Json;
using System.Xml.Linq;
using BaseScanner.Analyzers.Testing.Models;

namespace BaseScanner.Analyzers.Testing;

/// <summary>
/// Parses coverage report files from various formats.
/// Supports OpenCover XML, Coverlet XML/JSON, dotCover XML/JSON, and Cobertura.
/// </summary>
public class CoverageParser
{
    /// <summary>
    /// Parse a coverage report file.
    /// </summary>
    /// <param name="filePath">Path to the coverage report file.</param>
    /// <returns>Parsed coverage data.</returns>
    public async Task<RawCoverageData> ParseAsync(string filePath)
    {
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"Coverage report not found: {filePath}");

        var extension = Path.GetExtension(filePath).ToLowerInvariant();
        var content = await File.ReadAllTextAsync(filePath);

        return extension switch
        {
            ".xml" => ParseXmlCoverage(content, filePath),
            ".json" => ParseJsonCoverage(content, filePath),
            _ => throw new NotSupportedException($"Unsupported coverage format: {extension}")
        };
    }

    /// <summary>
    /// Detect the format of a coverage report file.
    /// </summary>
    public CoverageReportFormat DetectFormat(string filePath)
    {
        var extension = Path.GetExtension(filePath).ToLowerInvariant();

        if (extension == ".json")
        {
            var content = File.ReadAllText(filePath);
            if (content.Contains("\"Modules\"") && content.Contains("\"Classes\""))
                return CoverageReportFormat.CoverletJson;
            if (content.Contains("\"DotCover\""))
                return CoverageReportFormat.DotCoverJson;
            return CoverageReportFormat.Unknown;
        }

        if (extension == ".xml")
        {
            var content = File.ReadAllText(filePath);
            if (content.Contains("<CoverageSession") && content.Contains("OpenCover"))
                return CoverageReportFormat.OpenCoverXml;
            if (content.Contains("<coverage") && content.Contains("line-rate"))
                return CoverageReportFormat.Cobertura;
            if (content.Contains("<coverage") && content.Contains("coverlet"))
                return CoverageReportFormat.CoverletXml;
            if (content.Contains("<Root") && content.Contains("dotCover"))
                return CoverageReportFormat.DotCoverXml;
            // Default to OpenCover format for generic XML
            if (content.Contains("<CoverageSession"))
                return CoverageReportFormat.OpenCoverXml;
        }

        return CoverageReportFormat.Unknown;
    }

    private RawCoverageData ParseXmlCoverage(string content, string filePath)
    {
        var format = DetectFormat(filePath);

        return format switch
        {
            CoverageReportFormat.OpenCoverXml => ParseOpenCoverXml(content),
            CoverageReportFormat.CoverletXml => ParseCoverletXml(content),
            CoverageReportFormat.DotCoverXml => ParseDotCoverXml(content),
            CoverageReportFormat.Cobertura => ParseCoberturaXml(content),
            _ => ParseOpenCoverXml(content) // Default fallback
        };
    }

    private RawCoverageData ParseJsonCoverage(string content, string filePath)
    {
        var format = DetectFormat(filePath);

        return format switch
        {
            CoverageReportFormat.CoverletJson => ParseCoverletJson(content),
            CoverageReportFormat.DotCoverJson => ParseDotCoverJson(content),
            _ => ParseCoverletJson(content) // Default fallback
        };
    }

    /// <summary>
    /// Parse OpenCover XML format.
    /// </summary>
    private RawCoverageData ParseOpenCoverXml(string content)
    {
        var doc = XDocument.Parse(content);
        var modules = new List<ModuleCoverageData>();
        var ns = doc.Root?.GetDefaultNamespace() ?? XNamespace.None;

        var sessionElement = doc.Root;
        if (sessionElement == null)
            return CreateEmptyResult(CoverageReportFormat.OpenCoverXml);

        foreach (var moduleElement in sessionElement.Descendants(ns + "Module"))
        {
            var moduleName = moduleElement.Element(ns + "ModuleName")?.Value ??
                            moduleElement.Attribute("ModuleName")?.Value ??
                            "Unknown";
            var modulePath = moduleElement.Element(ns + "ModulePath")?.Value ??
                            moduleElement.Attribute("ModulePath")?.Value ?? "";

            var files = new Dictionary<string, FileCoverageData>();

            // Parse files
            foreach (var fileElement in moduleElement.Descendants(ns + "File"))
            {
                var fileId = fileElement.Attribute("uid")?.Value ??
                            fileElement.Attribute("fullPath")?.Value ?? "";
                var filePath = fileElement.Attribute("fullPath")?.Value ??
                              fileElement.Value ?? "";

                if (!string.IsNullOrEmpty(filePath) && !files.ContainsKey(fileId))
                {
                    files[fileId] = new FileCoverageData
                    {
                        FilePath = filePath,
                        Classes = [],
                        LineHits = new Dictionary<int, int>()
                    };
                }
            }

            // Parse classes and methods
            foreach (var classElement in moduleElement.Descendants(ns + "Class"))
            {
                var fullName = classElement.Element(ns + "FullName")?.Value ?? "";
                if (string.IsNullOrEmpty(fullName) || fullName.StartsWith("<"))
                    continue;

                var parts = fullName.Split('.');
                var className = parts.Last();
                var namespaceName = string.Join(".", parts.Take(parts.Length - 1));

                var methods = new List<MethodCoverageData>();

                foreach (var methodElement in classElement.Descendants(ns + "Method"))
                {
                    if (methodElement.Attribute("skippedDueTo")?.Value != null)
                        continue;

                    var methodName = methodElement.Element(ns + "Name")?.Value ?? "";
                    if (methodName.StartsWith("<") || string.IsNullOrEmpty(methodName))
                        continue;

                    var seqPoints = new List<SequencePointData>();
                    var branchPoints = new List<BranchPointData>();
                    var fileRef = "";
                    var startLine = int.MaxValue;
                    var endLine = 0;

                    // Parse sequence points
                    foreach (var sp in methodElement.Descendants(ns + "SequencePoint"))
                    {
                        var line = int.Parse(sp.Attribute("sl")?.Value ?? "0");
                        var col = int.Parse(sp.Attribute("sc")?.Value ?? "0");
                        var endLn = int.Parse(sp.Attribute("el")?.Value ?? line.ToString());
                        var endCol = int.Parse(sp.Attribute("ec")?.Value ?? "0");
                        var hits = int.Parse(sp.Attribute("vc")?.Value ?? "0");
                        var fileId = sp.Attribute("fileid")?.Value ?? "";

                        if (line < startLine) startLine = line;
                        if (endLn > endLine) endLine = endLn;
                        if (string.IsNullOrEmpty(fileRef)) fileRef = fileId;

                        seqPoints.Add(new SequencePointData
                        {
                            Line = line,
                            Column = col,
                            EndLine = endLn,
                            EndColumn = endCol,
                            HitCount = hits
                        });

                        // Update line hits in file
                        if (files.TryGetValue(fileId, out var file))
                        {
                            file.LineHits[line] = hits;
                        }
                    }

                    // Parse branch points
                    foreach (var bp in methodElement.Descendants(ns + "BranchPoint"))
                    {
                        var line = int.Parse(bp.Attribute("sl")?.Value ?? "0");
                        var offset = int.Parse(bp.Attribute("offset")?.Value ?? "0");
                        var path = int.Parse(bp.Attribute("path")?.Value ?? "0");
                        var hits = int.Parse(bp.Attribute("vc")?.Value ?? "0");

                        branchPoints.Add(new BranchPointData
                        {
                            Line = line,
                            Offset = offset,
                            Path = path,
                            HitCount = hits
                        });
                    }

                    var complexity = int.Parse(methodElement.Attribute("cyclomaticComplexity")?.Value ??
                                               methodElement.Element(ns + "CyclomaticComplexity")?.Value ?? "1");

                    methods.Add(new MethodCoverageData
                    {
                        MethodName = methodName,
                        FullName = $"{fullName}.{methodName}",
                        StartLine = startLine == int.MaxValue ? 0 : startLine,
                        EndLine = endLine,
                        CyclomaticComplexity = complexity,
                        SequencePointsCovered = seqPoints.Count(sp => sp.HitCount > 0),
                        SequencePointsTotal = seqPoints.Count,
                        BranchPointsCovered = branchPoints.Count(bp => bp.HitCount > 0),
                        BranchPointsTotal = branchPoints.Count,
                        SequencePoints = seqPoints,
                        BranchPoints = branchPoints
                    });
                }

                if (methods.Any())
                {
                    // Find the file for this class
                    var firstMethodFile = files.Values.FirstOrDefault();
                    if (firstMethodFile != null)
                    {
                        firstMethodFile.Classes.Add(new ClassCoverageData
                        {
                            ClassName = className,
                            Namespace = namespaceName,
                            Methods = methods
                        });
                    }
                }
            }

            modules.Add(new ModuleCoverageData
            {
                ModuleName = moduleName,
                AssemblyPath = modulePath,
                Files = files.Values.ToList()
            });
        }

        return new RawCoverageData
        {
            Format = CoverageReportFormat.OpenCoverXml,
            GeneratedAt = DateTime.UtcNow,
            Modules = modules
        };
    }

    /// <summary>
    /// Parse Coverlet XML format.
    /// </summary>
    private RawCoverageData ParseCoverletXml(string content)
    {
        var doc = XDocument.Parse(content);
        var modules = new List<ModuleCoverageData>();

        var coverageElement = doc.Root;
        if (coverageElement == null)
            return CreateEmptyResult(CoverageReportFormat.CoverletXml);

        foreach (var packageElement in coverageElement.Descendants("package"))
        {
            var moduleName = packageElement.Attribute("name")?.Value ?? "Unknown";
            var files = new List<FileCoverageData>();

            foreach (var classElement in packageElement.Descendants("class"))
            {
                var fullName = classElement.Attribute("name")?.Value ?? "";
                var filePath = classElement.Attribute("filename")?.Value ?? "";

                if (string.IsNullOrEmpty(fullName))
                    continue;

                var parts = fullName.Split('.');
                var className = parts.Last();
                var namespaceName = string.Join(".", parts.Take(parts.Length - 1));

                var methods = new List<MethodCoverageData>();
                var lineHits = new Dictionary<int, int>();

                foreach (var methodElement in classElement.Descendants("method"))
                {
                    var methodName = methodElement.Attribute("name")?.Value ?? "";
                    var seqPoints = new List<SequencePointData>();
                    var branchPoints = new List<BranchPointData>();
                    var startLine = int.MaxValue;
                    var endLine = 0;

                    foreach (var lineElement in methodElement.Descendants("line"))
                    {
                        var line = int.Parse(lineElement.Attribute("number")?.Value ?? "0");
                        var hits = int.Parse(lineElement.Attribute("hits")?.Value ?? "0");
                        var branch = lineElement.Attribute("branch")?.Value == "true";

                        if (line < startLine) startLine = line;
                        if (line > endLine) endLine = line;

                        lineHits[line] = hits;

                        seqPoints.Add(new SequencePointData
                        {
                            Line = line,
                            Column = 0,
                            EndLine = line,
                            EndColumn = 0,
                            HitCount = hits
                        });

                        if (branch)
                        {
                            var conditionCoverage = lineElement.Attribute("condition-coverage")?.Value ?? "";
                            // Parse "50% (1/2)" format
                            if (conditionCoverage.Contains("("))
                            {
                                var match = System.Text.RegularExpressions.Regex.Match(
                                    conditionCoverage, @"\((\d+)/(\d+)\)");
                                if (match.Success)
                                {
                                    var covered = int.Parse(match.Groups[1].Value);
                                    var total = int.Parse(match.Groups[2].Value);
                                    for (int i = 0; i < total; i++)
                                    {
                                        branchPoints.Add(new BranchPointData
                                        {
                                            Line = line,
                                            Offset = 0,
                                            Path = i,
                                            HitCount = i < covered ? hits : 0
                                        });
                                    }
                                }
                            }
                        }
                    }

                    var complexity = int.Parse(methodElement.Attribute("complexity")?.Value ?? "1");

                    methods.Add(new MethodCoverageData
                    {
                        MethodName = methodName,
                        FullName = $"{fullName}.{methodName}",
                        StartLine = startLine == int.MaxValue ? 0 : startLine,
                        EndLine = endLine,
                        CyclomaticComplexity = complexity,
                        SequencePointsCovered = seqPoints.Count(sp => sp.HitCount > 0),
                        SequencePointsTotal = seqPoints.Count,
                        BranchPointsCovered = branchPoints.Count(bp => bp.HitCount > 0),
                        BranchPointsTotal = branchPoints.Count,
                        SequencePoints = seqPoints,
                        BranchPoints = branchPoints
                    });
                }

                var existingFile = files.FirstOrDefault(f => f.FilePath == filePath);
                if (existingFile != null)
                {
                    existingFile.Classes.Add(new ClassCoverageData
                    {
                        ClassName = className,
                        Namespace = namespaceName,
                        Methods = methods
                    });
                    foreach (var (line, hits) in lineHits)
                    {
                        existingFile.LineHits[line] = hits;
                    }
                }
                else
                {
                    files.Add(new FileCoverageData
                    {
                        FilePath = filePath,
                        Classes =
                        [
                            new ClassCoverageData
                            {
                                ClassName = className,
                                Namespace = namespaceName,
                                Methods = methods
                            }
                        ],
                        LineHits = lineHits
                    });
                }
            }

            modules.Add(new ModuleCoverageData
            {
                ModuleName = moduleName,
                AssemblyPath = "",
                Files = files
            });
        }

        return new RawCoverageData
        {
            Format = CoverageReportFormat.CoverletXml,
            GeneratedAt = DateTime.UtcNow,
            Modules = modules
        };
    }

    /// <summary>
    /// Parse Coverlet JSON format.
    /// </summary>
    private RawCoverageData ParseCoverletJson(string content)
    {
        var modules = new List<ModuleCoverageData>();

        using var doc = JsonDocument.Parse(content);
        var root = doc.RootElement;

        foreach (var moduleProperty in root.EnumerateObject())
        {
            var moduleName = moduleProperty.Name;
            var files = new List<FileCoverageData>();

            foreach (var fileProperty in moduleProperty.Value.EnumerateObject())
            {
                var filePath = fileProperty.Name;
                var classes = new List<ClassCoverageData>();
                var lineHits = new Dictionary<int, int>();

                foreach (var classProperty in fileProperty.Value.EnumerateObject())
                {
                    var fullClassName = classProperty.Name;
                    var parts = fullClassName.Split('.');
                    var className = parts.Last();
                    var namespaceName = string.Join(".", parts.Take(parts.Length - 1));

                    var methods = new List<MethodCoverageData>();

                    foreach (var methodProperty in classProperty.Value.EnumerateObject())
                    {
                        var methodName = methodProperty.Name;
                        var seqPoints = new List<SequencePointData>();
                        var branchPoints = new List<BranchPointData>();
                        var startLine = int.MaxValue;
                        var endLine = 0;

                        if (methodProperty.Value.ValueKind == JsonValueKind.Object)
                        {
                            // New format with Lines and Branches
                            if (methodProperty.Value.TryGetProperty("Lines", out var linesElement))
                            {
                                foreach (var lineProperty in linesElement.EnumerateObject())
                                {
                                    var line = int.Parse(lineProperty.Name);
                                    var hits = lineProperty.Value.GetInt32();

                                    if (line < startLine) startLine = line;
                                    if (line > endLine) endLine = line;
                                    lineHits[line] = hits;

                                    seqPoints.Add(new SequencePointData
                                    {
                                        Line = line,
                                        Column = 0,
                                        EndLine = line,
                                        EndColumn = 0,
                                        HitCount = hits
                                    });
                                }
                            }

                            if (methodProperty.Value.TryGetProperty("Branches", out var branchesElement))
                            {
                                foreach (var branchElement in branchesElement.EnumerateArray())
                                {
                                    var line = branchElement.GetProperty("Line").GetInt32();
                                    var offset = branchElement.GetProperty("Offset").GetInt32();
                                    var path = branchElement.GetProperty("Path").GetInt32();
                                    var hits = branchElement.GetProperty("Hits").GetInt32();

                                    branchPoints.Add(new BranchPointData
                                    {
                                        Line = line,
                                        Offset = offset,
                                        Path = path,
                                        HitCount = hits
                                    });
                                }
                            }
                        }

                        methods.Add(new MethodCoverageData
                        {
                            MethodName = methodName,
                            FullName = $"{fullClassName}.{methodName}",
                            StartLine = startLine == int.MaxValue ? 0 : startLine,
                            EndLine = endLine,
                            CyclomaticComplexity = 1,
                            SequencePointsCovered = seqPoints.Count(sp => sp.HitCount > 0),
                            SequencePointsTotal = seqPoints.Count,
                            BranchPointsCovered = branchPoints.Count(bp => bp.HitCount > 0),
                            BranchPointsTotal = branchPoints.Count,
                            SequencePoints = seqPoints,
                            BranchPoints = branchPoints
                        });
                    }

                    classes.Add(new ClassCoverageData
                    {
                        ClassName = className,
                        Namespace = namespaceName,
                        Methods = methods
                    });
                }

                files.Add(new FileCoverageData
                {
                    FilePath = filePath,
                    Classes = classes,
                    LineHits = lineHits
                });
            }

            modules.Add(new ModuleCoverageData
            {
                ModuleName = moduleName,
                AssemblyPath = "",
                Files = files
            });
        }

        return new RawCoverageData
        {
            Format = CoverageReportFormat.CoverletJson,
            GeneratedAt = DateTime.UtcNow,
            Modules = modules
        };
    }

    /// <summary>
    /// Parse dotCover XML format.
    /// </summary>
    private RawCoverageData ParseDotCoverXml(string content)
    {
        var doc = XDocument.Parse(content);
        var modules = new List<ModuleCoverageData>();

        var rootElement = doc.Root;
        if (rootElement == null)
            return CreateEmptyResult(CoverageReportFormat.DotCoverXml);

        foreach (var assemblyElement in rootElement.Descendants("Assembly"))
        {
            var moduleName = assemblyElement.Attribute("Name")?.Value ?? "Unknown";
            var files = new Dictionary<string, FileCoverageData>();

            foreach (var typeElement in assemblyElement.Descendants("Type"))
            {
                var fullName = typeElement.Attribute("Name")?.Value ?? "";
                if (string.IsNullOrEmpty(fullName))
                    continue;

                var parts = fullName.Split('.');
                var className = parts.Last();
                var namespaceName = string.Join(".", parts.Take(parts.Length - 1));

                var methods = new List<MethodCoverageData>();
                var lastFilePath = "";

                foreach (var methodElement in typeElement.Elements("Method"))
                {
                    var methodName = methodElement.Attribute("Name")?.Value ?? "";
                    var seqPoints = new List<SequencePointData>();
                    var startLine = int.MaxValue;
                    var endLine = 0;
                    var filePath = "";

                    foreach (var statementElement in methodElement.Descendants("Statement"))
                    {
                        var line = int.Parse(statementElement.Attribute("Line")?.Value ?? "0");
                        var endLn = int.Parse(statementElement.Attribute("EndLine")?.Value ?? line.ToString());
                        var covered = statementElement.Attribute("Covered")?.Value == "True";
                        var file = statementElement.Attribute("DocumentFile")?.Value ?? "";

                        if (line < startLine) startLine = line;
                        if (endLn > endLine) endLine = endLn;
                        if (string.IsNullOrEmpty(filePath))
                        {
                            filePath = file;
                            lastFilePath = file;
                        }

                        seqPoints.Add(new SequencePointData
                        {
                            Line = line,
                            Column = 0,
                            EndLine = endLn,
                            EndColumn = 0,
                            HitCount = covered ? 1 : 0
                        });

                        // Update file hits
                        if (!string.IsNullOrEmpty(file))
                        {
                            if (!files.ContainsKey(file))
                            {
                                files[file] = new FileCoverageData
                                {
                                    FilePath = file,
                                    Classes = [],
                                    LineHits = new Dictionary<int, int>()
                                };
                            }
                            files[file].LineHits[line] = covered ? 1 : 0;
                        }
                    }

                    methods.Add(new MethodCoverageData
                    {
                        MethodName = methodName,
                        FullName = $"{fullName}.{methodName}",
                        StartLine = startLine == int.MaxValue ? 0 : startLine,
                        EndLine = endLine,
                        CyclomaticComplexity = 1,
                        SequencePointsCovered = seqPoints.Count(sp => sp.HitCount > 0),
                        SequencePointsTotal = seqPoints.Count,
                        BranchPointsCovered = 0,
                        BranchPointsTotal = 0,
                        SequencePoints = seqPoints,
                        BranchPoints = []
                    });
                }

                if (methods.Any() && !string.IsNullOrEmpty(lastFilePath) && files.ContainsKey(lastFilePath))
                {
                    files[lastFilePath].Classes.Add(new ClassCoverageData
                    {
                        ClassName = className,
                        Namespace = namespaceName,
                        Methods = methods
                    });
                }
            }

            modules.Add(new ModuleCoverageData
            {
                ModuleName = moduleName,
                AssemblyPath = "",
                Files = files.Values.ToList()
            });
        }

        return new RawCoverageData
        {
            Format = CoverageReportFormat.DotCoverXml,
            GeneratedAt = DateTime.UtcNow,
            Modules = modules
        };
    }

    /// <summary>
    /// Parse dotCover JSON format.
    /// </summary>
    private RawCoverageData ParseDotCoverJson(string content)
    {
        // dotCover JSON is similar to its XML structure
        var modules = new List<ModuleCoverageData>();

        using var doc = JsonDocument.Parse(content);
        var root = doc.RootElement;

        if (root.TryGetProperty("Assemblies", out var assemblies))
        {
            foreach (var assembly in assemblies.EnumerateArray())
            {
                var moduleName = assembly.GetProperty("Name").GetString() ?? "Unknown";
                var files = new List<FileCoverageData>();

                if (assembly.TryGetProperty("Types", out var types))
                {
                    foreach (var type in types.EnumerateArray())
                    {
                        var fullName = type.GetProperty("Name").GetString() ?? "";
                        var parts = fullName.Split('.');
                        var className = parts.Last();
                        var namespaceName = string.Join(".", parts.Take(parts.Length - 1));

                        var methods = new List<MethodCoverageData>();

                        if (type.TryGetProperty("Methods", out var methodsElement))
                        {
                            foreach (var method in methodsElement.EnumerateArray())
                            {
                                var methodName = method.GetProperty("Name").GetString() ?? "";
                                var seqPoints = new List<SequencePointData>();
                                var startLine = int.MaxValue;
                                var endLine = 0;

                                if (method.TryGetProperty("Statements", out var statements))
                                {
                                    foreach (var stmt in statements.EnumerateArray())
                                    {
                                        var line = stmt.GetProperty("Line").GetInt32();
                                        var endLn = stmt.TryGetProperty("EndLine", out var el) ? el.GetInt32() : line;
                                        var covered = stmt.TryGetProperty("Covered", out var c) && c.GetBoolean();

                                        if (line < startLine) startLine = line;
                                        if (endLn > endLine) endLine = endLn;

                                        seqPoints.Add(new SequencePointData
                                        {
                                            Line = line,
                                            Column = 0,
                                            EndLine = endLn,
                                            EndColumn = 0,
                                            HitCount = covered ? 1 : 0
                                        });
                                    }
                                }

                                methods.Add(new MethodCoverageData
                                {
                                    MethodName = methodName,
                                    FullName = $"{fullName}.{methodName}",
                                    StartLine = startLine == int.MaxValue ? 0 : startLine,
                                    EndLine = endLine,
                                    CyclomaticComplexity = 1,
                                    SequencePointsCovered = seqPoints.Count(sp => sp.HitCount > 0),
                                    SequencePointsTotal = seqPoints.Count,
                                    BranchPointsCovered = 0,
                                    BranchPointsTotal = 0,
                                    SequencePoints = seqPoints,
                                    BranchPoints = []
                                });
                            }
                        }

                        // Add to a placeholder file
                        var existingFile = files.FirstOrDefault();
                        if (existingFile != null)
                        {
                            existingFile.Classes.Add(new ClassCoverageData
                            {
                                ClassName = className,
                                Namespace = namespaceName,
                                Methods = methods
                            });
                        }
                        else
                        {
                            files.Add(new FileCoverageData
                            {
                                FilePath = "",
                                Classes = [new ClassCoverageData
                                {
                                    ClassName = className,
                                    Namespace = namespaceName,
                                    Methods = methods
                                }],
                                LineHits = new Dictionary<int, int>()
                            });
                        }
                    }
                }

                modules.Add(new ModuleCoverageData
                {
                    ModuleName = moduleName,
                    AssemblyPath = "",
                    Files = files
                });
            }
        }

        return new RawCoverageData
        {
            Format = CoverageReportFormat.DotCoverJson,
            GeneratedAt = DateTime.UtcNow,
            Modules = modules
        };
    }

    /// <summary>
    /// Parse Cobertura XML format (commonly used by Azure DevOps, Jenkins).
    /// </summary>
    private RawCoverageData ParseCoberturaXml(string content)
    {
        var doc = XDocument.Parse(content);
        var modules = new List<ModuleCoverageData>();

        var coverageElement = doc.Root;
        if (coverageElement == null)
            return CreateEmptyResult(CoverageReportFormat.Cobertura);

        foreach (var packageElement in coverageElement.Descendants("package"))
        {
            var moduleName = packageElement.Attribute("name")?.Value ?? "Unknown";
            var files = new List<FileCoverageData>();

            foreach (var classElement in packageElement.Descendants("class"))
            {
                var fullName = classElement.Attribute("name")?.Value ?? "";
                var filePath = classElement.Attribute("filename")?.Value ?? "";

                if (string.IsNullOrEmpty(fullName))
                    continue;

                var parts = fullName.Split('.');
                var className = parts.Last();
                var namespaceName = string.Join(".", parts.Take(parts.Length - 1));

                var methods = new List<MethodCoverageData>();
                var lineHits = new Dictionary<int, int>();

                foreach (var methodElement in classElement.Descendants("method"))
                {
                    var methodName = methodElement.Attribute("name")?.Value ?? "";
                    var signature = methodElement.Attribute("signature")?.Value ?? "";
                    var seqPoints = new List<SequencePointData>();
                    var branchPoints = new List<BranchPointData>();
                    var startLine = int.MaxValue;
                    var endLine = 0;

                    foreach (var lineElement in methodElement.Descendants("line"))
                    {
                        var line = int.Parse(lineElement.Attribute("number")?.Value ?? "0");
                        var hits = int.Parse(lineElement.Attribute("hits")?.Value ?? "0");
                        var branch = lineElement.Attribute("branch")?.Value == "true";

                        if (line < startLine) startLine = line;
                        if (line > endLine) endLine = line;
                        lineHits[line] = hits;

                        seqPoints.Add(new SequencePointData
                        {
                            Line = line,
                            Column = 0,
                            EndLine = line,
                            EndColumn = 0,
                            HitCount = hits
                        });

                        if (branch)
                        {
                            var condCoverage = lineElement.Attribute("condition-coverage")?.Value ?? "";
                            var match = System.Text.RegularExpressions.Regex.Match(condCoverage, @"\((\d+)/(\d+)\)");
                            if (match.Success)
                            {
                                var covered = int.Parse(match.Groups[1].Value);
                                var total = int.Parse(match.Groups[2].Value);
                                for (int i = 0; i < total; i++)
                                {
                                    branchPoints.Add(new BranchPointData
                                    {
                                        Line = line,
                                        Offset = 0,
                                        Path = i,
                                        HitCount = i < covered ? hits : 0
                                    });
                                }
                            }
                        }
                    }

                    var complexity = int.Parse(methodElement.Attribute("complexity")?.Value ?? "1");

                    methods.Add(new MethodCoverageData
                    {
                        MethodName = methodName,
                        FullName = $"{fullName}.{methodName}",
                        StartLine = startLine == int.MaxValue ? 0 : startLine,
                        EndLine = endLine,
                        CyclomaticComplexity = complexity,
                        SequencePointsCovered = seqPoints.Count(sp => sp.HitCount > 0),
                        SequencePointsTotal = seqPoints.Count,
                        BranchPointsCovered = branchPoints.Count(bp => bp.HitCount > 0),
                        BranchPointsTotal = branchPoints.Count,
                        SequencePoints = seqPoints,
                        BranchPoints = branchPoints
                    });
                }

                var existingFile = files.FirstOrDefault(f => f.FilePath == filePath);
                if (existingFile != null)
                {
                    existingFile.Classes.Add(new ClassCoverageData
                    {
                        ClassName = className,
                        Namespace = namespaceName,
                        Methods = methods
                    });
                    foreach (var (line, hits) in lineHits)
                    {
                        existingFile.LineHits[line] = hits;
                    }
                }
                else
                {
                    files.Add(new FileCoverageData
                    {
                        FilePath = filePath,
                        Classes =
                        [
                            new ClassCoverageData
                            {
                                ClassName = className,
                                Namespace = namespaceName,
                                Methods = methods
                            }
                        ],
                        LineHits = lineHits
                    });
                }
            }

            modules.Add(new ModuleCoverageData
            {
                ModuleName = moduleName,
                AssemblyPath = "",
                Files = files
            });
        }

        return new RawCoverageData
        {
            Format = CoverageReportFormat.Cobertura,
            GeneratedAt = DateTime.UtcNow,
            Modules = modules
        };
    }

    private RawCoverageData CreateEmptyResult(CoverageReportFormat format)
    {
        return new RawCoverageData
        {
            Format = format,
            GeneratedAt = DateTime.UtcNow,
            Modules = []
        };
    }
}
