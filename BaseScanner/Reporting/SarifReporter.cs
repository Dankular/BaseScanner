using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using BaseScanner.Reporting.Models;

namespace BaseScanner.Reporting;

/// <summary>
/// Generates SARIF 2.1.0 format reports for static analysis results.
/// SARIF (Static Analysis Results Interchange Format) is an OASIS standard.
/// </summary>
public class SarifReporter : IReporter
{
    private const string SarifVersion = "2.1.0";
    private const string SchemaUri = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";
    private const string ToolName = "BaseScanner";
    private const string ToolVersion = "1.0.0";
    private const string ToolInformationUri = "https://github.com/basescanner/basescanner";

    /// <inheritdoc />
    public Task<string> GenerateAsync(ReportData data, ReportOptions options)
    {
        var sarif = BuildSarifLog(data, options);

        var jsonOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        };

        var json = JsonSerializer.Serialize(sarif, jsonOptions);
        return Task.FromResult(json);
    }

    /// <inheritdoc />
    public async Task WriteAsync(ReportData data, ReportOptions options, string outputPath)
    {
        var content = await GenerateAsync(data, options);
        await File.WriteAllTextAsync(outputPath, content, Encoding.UTF8);
    }

    private SarifLog BuildSarifLog(ReportData data, ReportOptions options)
    {
        var run = new SarifRun
        {
            Tool = BuildTool(data.Rules),
            Results = BuildResults(data.Issues, options),
            Invocations = BuildInvocations(data),
            Artifacts = BuildArtifacts(data.Issues),
            AutomationDetails = new RunAutomationDetails
            {
                Id = $"BaseScanner/{data.Project.Name}/{data.AnalysisTimestamp:yyyyMMddHHmmss}",
                Guid = Guid.NewGuid().ToString(),
                CorrelationGuid = data.Project.CommitHash
            }
        };

        // Add version control provenance if git info available
        if (!string.IsNullOrEmpty(data.Project.CommitHash))
        {
            run.VersionControlProvenance =
            [
                new VersionControlDetails
                {
                    RepositoryUri = data.Project.Path,
                    RevisionId = data.Project.CommitHash,
                    Branch = data.Project.Branch
                }
            ];
        }

        return new SarifLog
        {
            Schema = SchemaUri,
            Version = SarifVersion,
            Runs = [run]
        };
    }

    private SarifTool BuildTool(IEnumerable<ReportRule> rules)
    {
        return new SarifTool
        {
            Driver = new ToolComponent
            {
                Name = ToolName,
                Version = ToolVersion,
                SemanticVersion = ToolVersion,
                InformationUri = ToolInformationUri,
                Rules = rules.Select(BuildRule).ToList(),
                Notifications = [],
                SupportedTaxonomies =
                [
                    new ToolComponentReference
                    {
                        Name = "CWE",
                        Guid = "FFC64C90-42B6-44CE-8BEB-F6B7DAE649E5"
                    }
                ]
            }
        };
    }

    private ReportingDescriptor BuildRule(ReportRule rule)
    {
        var descriptor = new ReportingDescriptor
        {
            Id = rule.Id,
            Name = rule.Name,
            ShortDescription = new MultiformatMessageString { Text = rule.Name },
            FullDescription = new MultiformatMessageString { Text = rule.Description },
            Help = new MultiformatMessageString
            {
                Text = rule.HelpText,
                Markdown = rule.HelpText
            },
            HelpUri = string.IsNullOrEmpty(rule.HelpUri) ? null : rule.HelpUri,
            DefaultConfiguration = new ReportingConfiguration
            {
                Level = MapSeverityToLevel(rule.DefaultSeverity),
                Enabled = true
            },
            Properties = new PropertyBag
            {
                Tags = rule.Tags.ToList()
            }
        };

        // Add CWE taxonomy references
        if (rule.CweIds.Any())
        {
            descriptor.Relationships = rule.CweIds.Select(cwe => new ReportingDescriptorRelationship
            {
                Target = new ReportingDescriptorReference
                {
                    Id = cwe,
                    ToolComponent = new ToolComponentReference { Name = "CWE" }
                },
                Kinds = ["superset"]
            }).ToList();
        }

        return descriptor;
    }

    private List<SarifResult> BuildResults(IEnumerable<ReportIssue> issues, ReportOptions options)
    {
        return issues
            .Where(i => i.Severity >= options.MinSeverity)
            .Take(options.MaxIssues)
            .Select(issue => BuildResult(issue, options))
            .ToList();
    }

    private SarifResult BuildResult(ReportIssue issue, ReportOptions options)
    {
        var result = new SarifResult
        {
            RuleId = issue.RuleId,
            RuleIndex = 0, // Will be resolved by consumer
            Level = MapSeverityToLevel(issue.Severity),
            Kind = MapSeverityToKind(issue.Severity),
            Message = new Message { Text = issue.Message },
            Locations = [BuildLocation(issue.Location, options)],
            Fingerprints = new Dictionary<string, string>
            {
                ["primaryLocationLineHash"] = issue.Fingerprint
            },
            PartialFingerprints = new Dictionary<string, string>
            {
                ["primaryLocationLineHash/v1"] = issue.Fingerprint
            },
            Properties = new PropertyBag
            {
                Tags = issue.Tags.ToList(),
                AdditionalProperties = issue.Properties.ToDictionary(kvp => kvp.Key, kvp => (object)kvp.Value)
            }
        };

        // Add code flows for data flow issues
        if (options.IncludeCodeFlows && issue.CodeFlow.Any())
        {
            result.CodeFlows = [BuildCodeFlow(issue.CodeFlow, options)];
        }

        // Add fixes if available
        if (options.IncludeFixes && issue.Fix != null)
        {
            result.Fixes = [BuildFix(issue.Fix)];
        }

        // Add CWE taxonomy reference
        if (!string.IsNullOrEmpty(issue.CweId))
        {
            result.Taxa =
            [
                new ReportingDescriptorReference
                {
                    Id = issue.CweId,
                    ToolComponent = new ToolComponentReference { Name = "CWE" }
                }
            ];
        }

        return result;
    }

    private Location BuildLocation(IssueLocation loc, ReportOptions options)
    {
        var location = new Location
        {
            PhysicalLocation = new PhysicalLocation
            {
                ArtifactLocation = new ArtifactLocation
                {
                    Uri = loc.RelativePath.Replace('\\', '/'),
                    UriBaseId = "%SRCROOT%"
                },
                Region = new Region
                {
                    StartLine = loc.StartLine,
                    StartColumn = loc.StartColumn,
                    EndLine = loc.EndLine > 0 ? loc.EndLine : loc.StartLine,
                    EndColumn = loc.EndColumn > 0 ? loc.EndColumn : null
                }
            }
        };

        // Add snippet if enabled
        if (options.IncludeSnippets && !string.IsNullOrEmpty(loc.Snippet))
        {
            location.PhysicalLocation.Region.Snippet = new ArtifactContent
            {
                Text = loc.Snippet
            };
        }

        // Add logical location
        if (!string.IsNullOrEmpty(loc.LogicalLocation))
        {
            location.LogicalLocations =
            [
                new LogicalLocation
                {
                    FullyQualifiedName = loc.LogicalLocation,
                    Kind = "member"
                }
            ];
        }

        return location;
    }

    private CodeFlow BuildCodeFlow(IEnumerable<CodeFlowLocation> locations, ReportOptions options)
    {
        return new CodeFlow
        {
            ThreadFlows =
            [
                new ThreadFlow
                {
                    Locations = locations.Select(loc => new ThreadFlowLocation
                    {
                        Location = BuildLocation(loc.Location, options),
                        Kinds = [MapCodeFlowKind(loc.Kind)],
                        NestingLevel = 0,
                        ExecutionOrder = loc.Step
                    }).ToList()
                }
            ],
            Message = new Message { Text = "Data flow from source to sink" }
        };
    }

    private Fix BuildFix(IssueFix fix)
    {
        return new Fix
        {
            Description = new Message { Text = fix.Description },
            ArtifactChanges = fix.Replacements.Select(r => new ArtifactChange
            {
                ArtifactLocation = new ArtifactLocation
                {
                    Uri = r.Location.RelativePath.Replace('\\', '/'),
                    UriBaseId = "%SRCROOT%"
                },
                Replacements =
                [
                    new Replacement
                    {
                        DeletedRegion = new Region
                        {
                            StartLine = r.Location.StartLine,
                            StartColumn = r.Location.StartColumn,
                            EndLine = r.Location.EndLine,
                            EndColumn = r.Location.EndColumn
                        },
                        InsertedContent = new ArtifactContent { Text = r.NewText }
                    }
                ]
            }).ToList()
        };
    }

    private List<Invocation> BuildInvocations(ReportData data)
    {
        return
        [
            new Invocation
            {
                ExecutionSuccessful = true,
                StartTimeUtc = data.AnalysisTimestamp.ToString("o"),
                EndTimeUtc = data.AnalysisTimestamp
                    .AddMilliseconds(data.Summary.AnalysisDurationMs)
                    .ToString("o"),
                WorkingDirectory = new ArtifactLocation
                {
                    Uri = data.Project.Path.Replace('\\', '/')
                },
                ToolConfigurationNotifications = [],
                ToolExecutionNotifications = []
            }
        ];
    }

    private List<Artifact> BuildArtifacts(IEnumerable<ReportIssue> issues)
    {
        var files = issues
            .Select(i => i.Location.RelativePath)
            .Where(p => !string.IsNullOrEmpty(p))
            .Distinct()
            .ToList();

        return files.Select(file => new Artifact
        {
            Location = new ArtifactLocation
            {
                Uri = file.Replace('\\', '/'),
                UriBaseId = "%SRCROOT%"
            },
            Roles = ["analysisTarget"],
            MimeType = "text/x-csharp"
        }).ToList();
    }

    private static string MapSeverityToLevel(IssueSeverity severity) => severity switch
    {
        IssueSeverity.Critical => "error",
        IssueSeverity.Error => "error",
        IssueSeverity.Warning => "warning",
        IssueSeverity.Note => "note",
        _ => "none"
    };

    private static string MapSeverityToKind(IssueSeverity severity) => severity switch
    {
        IssueSeverity.Critical or IssueSeverity.Error => "fail",
        IssueSeverity.Warning => "review",
        _ => "informational"
    };

    private static string MapCodeFlowKind(CodeFlowKind kind) => kind switch
    {
        CodeFlowKind.Source => "source",
        CodeFlowKind.Sink => "sink",
        _ => "pass"
    };
}

#region SARIF 2.1.0 Model Classes

/// <summary>
/// Root SARIF log object.
/// </summary>
public class SarifLog
{
    [JsonPropertyName("$schema")]
    public string Schema { get; set; } = "";

    public string Version { get; set; } = "";
    public List<SarifRun> Runs { get; set; } = [];
}

public class SarifRun
{
    public SarifTool Tool { get; set; } = new();
    public List<SarifResult> Results { get; set; } = [];
    public List<Invocation>? Invocations { get; set; }
    public List<Artifact>? Artifacts { get; set; }
    public RunAutomationDetails? AutomationDetails { get; set; }
    public List<VersionControlDetails>? VersionControlProvenance { get; set; }
}

public class SarifTool
{
    public ToolComponent Driver { get; set; } = new();
    public List<ToolComponent>? Extensions { get; set; }
}

public class ToolComponent
{
    public string Name { get; set; } = "";
    public string? Version { get; set; }
    public string? SemanticVersion { get; set; }
    public string? InformationUri { get; set; }
    public List<ReportingDescriptor>? Rules { get; set; }
    public List<ReportingDescriptor>? Notifications { get; set; }
    public List<ToolComponentReference>? SupportedTaxonomies { get; set; }
}

public class ToolComponentReference
{
    public string? Name { get; set; }
    public string? Guid { get; set; }
    public int? Index { get; set; }
}

public class ReportingDescriptor
{
    public string Id { get; set; } = "";
    public string? Name { get; set; }
    public MultiformatMessageString? ShortDescription { get; set; }
    public MultiformatMessageString? FullDescription { get; set; }
    public MultiformatMessageString? Help { get; set; }
    public string? HelpUri { get; set; }
    public ReportingConfiguration? DefaultConfiguration { get; set; }
    public PropertyBag? Properties { get; set; }
    public List<ReportingDescriptorRelationship>? Relationships { get; set; }
}

public class ReportingDescriptorRelationship
{
    public ReportingDescriptorReference? Target { get; set; }
    public List<string>? Kinds { get; set; }
}

public class ReportingDescriptorReference
{
    public string? Id { get; set; }
    public int? Index { get; set; }
    public ToolComponentReference? ToolComponent { get; set; }
}

public class ReportingConfiguration
{
    public string? Level { get; set; }
    public bool? Enabled { get; set; }
}

public class MultiformatMessageString
{
    public string? Text { get; set; }
    public string? Markdown { get; set; }
}

public class SarifResult
{
    public string RuleId { get; set; } = "";
    public int? RuleIndex { get; set; }
    public string? Level { get; set; }
    public string? Kind { get; set; }
    public Message? Message { get; set; }
    public List<Location>? Locations { get; set; }
    public List<CodeFlow>? CodeFlows { get; set; }
    public List<Fix>? Fixes { get; set; }
    public List<ReportingDescriptorReference>? Taxa { get; set; }
    public Dictionary<string, string>? Fingerprints { get; set; }
    public Dictionary<string, string>? PartialFingerprints { get; set; }
    public PropertyBag? Properties { get; set; }
}

public class Message
{
    public string? Text { get; set; }
    public string? Markdown { get; set; }
    public string? Id { get; set; }
    public List<string>? Arguments { get; set; }
}

public class Location
{
    public PhysicalLocation? PhysicalLocation { get; set; }
    public List<LogicalLocation>? LogicalLocations { get; set; }
}

public class PhysicalLocation
{
    public ArtifactLocation? ArtifactLocation { get; set; }
    public Region? Region { get; set; }
    public Region? ContextRegion { get; set; }
}

public class ArtifactLocation
{
    public string? Uri { get; set; }
    public string? UriBaseId { get; set; }
    public int? Index { get; set; }
}

public class Region
{
    public int? StartLine { get; set; }
    public int? StartColumn { get; set; }
    public int? EndLine { get; set; }
    public int? EndColumn { get; set; }
    public int? CharOffset { get; set; }
    public int? CharLength { get; set; }
    public int? ByteOffset { get; set; }
    public int? ByteLength { get; set; }
    public ArtifactContent? Snippet { get; set; }
}

public class ArtifactContent
{
    public string? Text { get; set; }
    public string? Binary { get; set; }
    public string? Rendered { get; set; }
}

public class LogicalLocation
{
    public string? Name { get; set; }
    public string? FullyQualifiedName { get; set; }
    public string? DecoratedName { get; set; }
    public string? Kind { get; set; }
    public int? ParentIndex { get; set; }
}

public class CodeFlow
{
    public Message? Message { get; set; }
    public List<ThreadFlow>? ThreadFlows { get; set; }
}

public class ThreadFlow
{
    public string? Id { get; set; }
    public Message? Message { get; set; }
    public List<ThreadFlowLocation>? Locations { get; set; }
}

public class ThreadFlowLocation
{
    public Location? Location { get; set; }
    public int? Step { get; set; }
    public List<string>? Kinds { get; set; }
    public int? NestingLevel { get; set; }
    public int? ExecutionOrder { get; set; }
}

public class Fix
{
    public Message? Description { get; set; }
    public List<ArtifactChange>? ArtifactChanges { get; set; }
}

public class ArtifactChange
{
    public ArtifactLocation? ArtifactLocation { get; set; }
    public List<Replacement>? Replacements { get; set; }
}

public class Replacement
{
    public Region? DeletedRegion { get; set; }
    public ArtifactContent? InsertedContent { get; set; }
}

public class Invocation
{
    public bool ExecutionSuccessful { get; set; }
    public string? StartTimeUtc { get; set; }
    public string? EndTimeUtc { get; set; }
    public ArtifactLocation? WorkingDirectory { get; set; }
    public List<Notification>? ToolConfigurationNotifications { get; set; }
    public List<Notification>? ToolExecutionNotifications { get; set; }
}

public class Notification
{
    public string? Level { get; set; }
    public Message? Message { get; set; }
    public ReportingDescriptorReference? AssociatedRule { get; set; }
}

public class Artifact
{
    public ArtifactLocation? Location { get; set; }
    public List<string>? Roles { get; set; }
    public string? MimeType { get; set; }
    public int? Length { get; set; }
    public ArtifactContent? Contents { get; set; }
}

public class RunAutomationDetails
{
    public string? Id { get; set; }
    public string? Guid { get; set; }
    public string? CorrelationGuid { get; set; }
}

public class VersionControlDetails
{
    public string? RepositoryUri { get; set; }
    public string? RevisionId { get; set; }
    public string? Branch { get; set; }
    public string? RevisionTag { get; set; }
    public string? AsOfTimeUtc { get; set; }
    public ArtifactLocation? MappedTo { get; set; }
}

public class PropertyBag
{
    public List<string>? Tags { get; set; }

    [JsonExtensionData]
    public Dictionary<string, object>? AdditionalProperties { get; set; }
}

#endregion
