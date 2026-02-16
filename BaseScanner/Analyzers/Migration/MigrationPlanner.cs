using Microsoft.CodeAnalysis;
using BaseScanner.Analyzers.Migration.Models;
using BaseScanner.Analyzers.Migration.Detectors;

namespace BaseScanner.Analyzers.Migration;

/// <summary>
/// Generates comprehensive migration plans for .NET projects.
/// Analyzes complexity, creates step-by-step plans, and identifies risks.
/// </summary>
public class MigrationPlanner
{
    private readonly ApiMappingDatabase _mappingDatabase;
    private readonly DeprecatedApiDetector _deprecatedApiDetector;
    private readonly PlatformSpecificDetector _platformDetector;
    private readonly CompatibilityChecker _compatibilityChecker;

    // Effort estimates in hours per occurrence
    private static readonly Dictionary<string, double> EffortEstimates = new()
    {
        // API migration efforts
        ["WebRequest"] = 2.0,
        ["WebClient"] = 1.5,
        ["HttpWebRequest"] = 2.0,
        ["ArrayList"] = 0.25,
        ["Hashtable"] = 0.25,
        ["Thread.Abort"] = 4.0,
        ["BinaryFormatter"] = 3.0,
        ["JavaScriptSerializer"] = 1.0,
        ["ConfigurationManager"] = 1.5,

        // ASP.NET migration efforts (per usage)
        ["System.Web"] = 2.0,
        ["System.Web.Mvc"] = 3.0,
        ["System.Web.Http"] = 2.5,
        ["System.Web.HttpContext"] = 1.5,

        // Platform-specific efforts
        ["Registry"] = 2.0,
        ["PInvoke"] = 4.0,
        ["COM"] = 8.0,
        ["WinForms"] = 0.5, // Per usage, not per file
        ["WPF"] = 0.5,

        // Package migration efforts
        ["EntityFramework"] = 8.0,
        ["System.ServiceModel"] = 16.0,
        ["System.Runtime.Remoting"] = 24.0,
    };

    // Base hours for migration phases
    private static readonly Dictionary<MigrationPhase, double> PhaseBaseHours = new()
    {
        [MigrationPhase.Preparation] = 4.0,
        [MigrationPhase.CoreMigration] = 8.0,
        [MigrationPhase.ApiUpdates] = 0.0, // Calculated based on issues
        [MigrationPhase.PlatformHandling] = 0.0, // Calculated based on issues
        [MigrationPhase.Testing] = 8.0,
        [MigrationPhase.Cleanup] = 4.0,
    };

    public MigrationPlanner(ApiMappingDatabase? mappingDatabase = null)
    {
        _mappingDatabase = mappingDatabase ?? new ApiMappingDatabase();
        _deprecatedApiDetector = new DeprecatedApiDetector(_mappingDatabase);
        _platformDetector = new PlatformSpecificDetector();
        _compatibilityChecker = new CompatibilityChecker(_mappingDatabase);
    }

    /// <summary>
    /// Generates a comprehensive migration plan for a project.
    /// </summary>
    public async Task<MigrationPlan> GeneratePlanAsync(
        Project project,
        string sourceFramework = "net472",
        string targetFramework = "net8.0")
    {
        // Gather all analysis data
        var deprecatedApis = await _deprecatedApiDetector.DetectInProjectAsync(project);
        var platformIssues = await _platformDetector.DetectInProjectAsync(project);
        var compatibility = await _compatibilityChecker.CheckCompatibilityAsync(project, targetFramework);

        // Calculate blocking issues
        var blockingIssues = GetBlockingIssues(deprecatedApis, platformIssues, compatibility);

        // Estimate overall complexity
        var complexity = EstimateComplexity(deprecatedApis, platformIssues, compatibility);

        // Generate migration steps
        var steps = GenerateSteps(deprecatedApis, platformIssues, compatibility, targetFramework);

        // Generate package migrations
        var packageMigrations = GeneratePackageMigrations(compatibility);

        // Calculate total effort
        var totalHours = CalculateTotalEffort(steps, blockingIssues);

        // Assess risks
        var risks = AssessRisks(deprecatedApis, platformIssues, blockingIssues, complexity);

        // Build summary
        var summary = BuildSummary(deprecatedApis, platformIssues, blockingIssues, steps, packageMigrations);

        return new MigrationPlan
        {
            SourceFramework = sourceFramework,
            TargetFramework = targetFramework,
            ProjectName = project.Name,
            OverallComplexity = complexity,
            TotalEstimatedHours = totalHours,
            EstimateConfidence = GetEstimateConfidence(deprecatedApis.Count, platformIssues.Count),
            BlockingIssues = blockingIssues,
            Steps = steps,
            PackageMigrations = packageMigrations,
            Risks = risks,
            Summary = summary,
            GeneratedAt = DateTime.UtcNow
        };
    }

    private List<BlockingIssue> GetBlockingIssues(
        List<DeprecatedApiUsage> deprecatedApis,
        List<PlatformSpecificCode> platformIssues,
        CompatibilityResult compatibility)
    {
        var issues = new List<BlockingIssue>();

        // Blocking deprecated APIs
        var blockingApis = _deprecatedApiDetector.GetBlockingIssues(deprecatedApis);
        var groupedBlockingApis = blockingApis.GroupBy(a => a.Api);

        foreach (var group in groupedBlockingApis)
        {
            var first = group.First();
            var mapping = first.Mapping;

            issues.Add(new BlockingIssue
            {
                Type = "UnavailableAPI",
                Description = $"API '{group.Key}' is not available in target framework",
                Cause = group.Key,
                Resolution = mapping?.MigrationGuide ?? "Replace with alternative API",
                EstimatedHours = GetEffortEstimate(group.Key) * group.Count(),
                AffectedFiles = group.Select(u => u.FilePath).Distinct().ToList()
            });
        }

        // Blocking platform issues
        var blockingPlatform = PlatformSpecificDetector.GetBlockingIssues(platformIssues);
        var groupedPlatform = blockingPlatform.GroupBy(p => p.Type);

        foreach (var group in groupedPlatform)
        {
            issues.Add(new BlockingIssue
            {
                Type = $"PlatformSpecific_{group.Key}",
                Description = $"{group.Key} usage is not cross-platform",
                Cause = string.Join(", ", group.Select(p => p.Api).Distinct().Take(3)),
                Resolution = group.First().Alternative ?? "Replace with cross-platform alternative",
                EstimatedHours = GetEffortEstimate(group.Key) * group.Count(),
                AffectedFiles = group.Select(p => p.FilePath).Distinct().ToList()
            });
        }

        // Blocking package issues
        foreach (var pkg in compatibility.PackageIssues.Where(p => !p.IsCompatible && p.ReplacementPackage == null))
        {
            issues.Add(new BlockingIssue
            {
                Type = "IncompatiblePackage",
                Description = $"Package '{pkg.PackageName}' has no .NET Core equivalent",
                Cause = pkg.PackageName,
                Resolution = pkg.Notes ?? "Find alternative package or remove dependency",
                EstimatedHours = 8.0, // Significant effort for package replacement
                AffectedFiles = []
            });
        }

        return issues;
    }

    private MigrationComplexity EstimateComplexity(
        List<DeprecatedApiUsage> deprecatedApis,
        List<PlatformSpecificCode> platformIssues,
        CompatibilityResult compatibility)
    {
        var score = 0;

        // Score based on deprecated API usage
        score += deprecatedApis.Count / 10;
        score += _deprecatedApiDetector.GetBlockingIssues(deprecatedApis).Count * 5;
        score += _deprecatedApiDetector.GetSecurityRisks(deprecatedApis).Count * 3;

        // Score based on platform-specific code
        score += platformIssues.Count / 5;
        score += PlatformSpecificDetector.GetBlockingIssues(platformIssues).Count * 10;

        // Score based on package issues
        score += compatibility.PackageIssues.Count(p => !p.IsCompatible) * 5;
        score += compatibility.RequiredChanges.Count(c => c.IsRequired) * 2;

        // Score based on unavailable APIs
        score += compatibility.UnavailableApis.Sum(a => a.UsageCount) / 5;

        return score switch
        {
            < 10 => MigrationComplexity.Low,
            < 30 => MigrationComplexity.Medium,
            < 60 => MigrationComplexity.High,
            _ => MigrationComplexity.VeryHigh
        };
    }

    private List<MigrationStep> GenerateSteps(
        List<DeprecatedApiUsage> deprecatedApis,
        List<PlatformSpecificCode> platformIssues,
        CompatibilityResult compatibility,
        string targetFramework)
    {
        var steps = new List<MigrationStep>();
        var stepOrder = 1;

        // Phase 1: Preparation
        steps.Add(new MigrationStep
        {
            Order = stepOrder++,
            Phase = MigrationPhase.Preparation,
            Title = "Create backup and migration branch",
            Description = "Create a Git branch for migration work and ensure all changes are committed.",
            EstimatedHours = 0.5,
            RiskLevel = "Low",
            CanBeAutomated = true,
            Actions =
            [
                "Create new branch 'migration/net8' from main",
                "Ensure working directory is clean",
                "Create backup of current project state"
            ],
            VerificationSteps =
            [
                "Verify branch created successfully",
                "Verify all changes committed"
            ]
        });

        steps.Add(new MigrationStep
        {
            Order = stepOrder++,
            Phase = MigrationPhase.Preparation,
            Title = "Review migration analysis report",
            Description = "Review the detailed migration analysis to understand the scope of work.",
            EstimatedHours = 2.0,
            RiskLevel = "Low",
            CanBeAutomated = false,
            Actions =
            [
                "Review deprecated API usages",
                "Review platform-specific code locations",
                "Identify highest-risk changes",
                "Plan testing strategy"
            ],
            VerificationSteps =
            [
                "Team understands scope of migration",
                "Testing plan documented"
            ]
        });

        // Phase 2: Core Migration - Project File
        steps.Add(new MigrationStep
        {
            Order = stepOrder++,
            Phase = MigrationPhase.CoreMigration,
            Title = "Convert to SDK-style project format",
            Description = "Convert the project file to the modern SDK-style format required for .NET 6+.",
            EstimatedHours = 2.0,
            RiskLevel = "Medium",
            CanBeAutomated = true,
            AffectedFiles = compatibility.RequiredChanges.Any() ? ["*.csproj"] : [],
            Actions =
            [
                "Backup existing .csproj file",
                "Create new SDK-style project file",
                "Migrate PackageReference entries",
                "Remove AssemblyInfo.cs (properties now in .csproj)",
                "Update project properties"
            ],
            VerificationSteps =
            [
                "Project loads in IDE",
                "All packages restore successfully"
            ]
        });

        steps.Add(new MigrationStep
        {
            Order = stepOrder++,
            Phase = MigrationPhase.CoreMigration,
            Title = "Update target framework",
            Description = $"Change target framework to {targetFramework}.",
            EstimatedHours = 0.5,
            RiskLevel = "Low",
            CanBeAutomated = true,
            Dependencies = [stepOrder - 1],
            Actions =
            [
                $"Set <TargetFramework>{targetFramework}</TargetFramework>",
                "Enable nullable reference types",
                "Enable implicit usings"
            ],
            VerificationSteps =
            [
                "Project builds with new target framework",
                "Runtime identifier correct"
            ]
        });

        // Phase 2: Core Migration - Packages
        if (compatibility.PackageIssues.Any())
        {
            var packageActions = new List<string>();
            var packageFiles = new List<string>();

            foreach (var pkg in compatibility.PackageIssues.Where(p => !p.IsCompatible || p.MinimumCompatibleVersion != null))
            {
                if (pkg.ReplacementPackage != null)
                {
                    packageActions.Add($"Replace {pkg.PackageName} with {pkg.ReplacementPackage} {pkg.MinimumCompatibleVersion ?? "latest"}");
                }
                else if (pkg.MinimumCompatibleVersion != null)
                {
                    packageActions.Add($"Update {pkg.PackageName} to version {pkg.MinimumCompatibleVersion}");
                }
            }

            if (packageActions.Any())
            {
                steps.Add(new MigrationStep
                {
                    Order = stepOrder++,
                    Phase = MigrationPhase.CoreMigration,
                    Title = "Update NuGet packages",
                    Description = "Update or replace NuGet packages for .NET compatibility.",
                    EstimatedHours = compatibility.PackageIssues.Count * 0.5,
                    RiskLevel = "Medium",
                    CanBeAutomated = true,
                    Dependencies = [stepOrder - 1],
                    Actions = packageActions,
                    VerificationSteps =
                    [
                        "All packages restore without errors",
                        "No package version conflicts"
                    ]
                });
            }
        }

        // Phase 3: API Updates
        var apiGroups = DeprecatedApiDetector.GroupByCategory(deprecatedApis);

        foreach (var (category, usages) in apiGroups.OrderByDescending(g => g.Value.Count))
        {
            var affectedFiles = usages.Select(u => u.FilePath).Distinct().ToList();
            var actions = new List<string>();

            var mappings = usages.Where(u => u.Mapping != null)
                .Select(u => u.Mapping!)
                .DistinctBy(m => m.OldApi)
                .ToList();

            foreach (var mapping in mappings.Take(5))
            {
                actions.Add($"Replace {mapping.OldApi} with {mapping.NewApi}");
            }

            if (mappings.Count > 5)
            {
                actions.Add($"... and {mappings.Count - 5} more API replacements");
            }

            var estimatedHours = usages.Sum(u => GetEffortEstimate(u.Api));
            var hasBlockingIssues = usages.Any(u => u.Mapping?.IsBlockingIssue == true);

            steps.Add(new MigrationStep
            {
                Order = stepOrder++,
                Phase = MigrationPhase.ApiUpdates,
                Title = $"Update {category} APIs ({usages.Count} usages)",
                Description = $"Replace deprecated {category} APIs with modern alternatives.",
                EstimatedHours = Math.Max(1, estimatedHours),
                RiskLevel = hasBlockingIssues ? "High" : "Medium",
                CanBeAutomated = category is "Collections" or "Cryptography",
                AffectedFiles = affectedFiles,
                Actions = actions,
                VerificationSteps =
                [
                    $"No compiler errors related to {category}",
                    $"Unit tests for {category} functionality pass"
                ]
            });
        }

        // Phase 4: Platform-specific code handling
        var platformGroups = PlatformSpecificDetector.GroupByType(platformIssues);

        foreach (var (type, issues) in platformGroups.OrderByDescending(g => g.Value.Count))
        {
            var affectedFiles = issues.Select(i => i.FilePath).Distinct().ToList();
            var canBeConditional = issues.All(i => i.CanBeConditional);
            var isBlocking = issues.Any(i => i.Impact == "Blocking");

            var actions = new List<string>();

            if (canBeConditional)
            {
                actions.Add($"Wrap {type} code with RuntimeInformation.IsOSPlatform() checks");
                actions.Add("Add #if WINDOWS conditional compilation where appropriate");
            }
            else
            {
                actions.Add($"Replace {type} functionality with cross-platform alternatives");
            }

            foreach (var issue in issues.Take(3))
            {
                if (!string.IsNullOrEmpty(issue.Alternative))
                {
                    actions.Add($"Consider: {issue.Alternative}");
                }
            }

            steps.Add(new MigrationStep
            {
                Order = stepOrder++,
                Phase = MigrationPhase.PlatformHandling,
                Title = $"Handle {type} platform-specific code ({issues.Count} occurrences)",
                Description = $"Address {type} code that is specific to Windows.",
                EstimatedHours = issues.Sum(i => GetEffortEstimate(i.Type)),
                RiskLevel = isBlocking ? "High" : "Medium",
                CanBeAutomated = false,
                AffectedFiles = affectedFiles,
                Actions = actions,
                VerificationSteps =
                [
                    "Code compiles without Windows-specific errors",
                    canBeConditional
                        ? "Platform checks work correctly on target platforms"
                        : "Functionality works with cross-platform alternative"
                ]
            });
        }

        // Phase 5: Testing
        steps.Add(new MigrationStep
        {
            Order = stepOrder++,
            Phase = MigrationPhase.Testing,
            Title = "Update and run unit tests",
            Description = "Ensure all unit tests are updated for the new framework and pass.",
            EstimatedHours = 4.0,
            RiskLevel = "Medium",
            CanBeAutomated = true,
            Actions =
            [
                "Update test project target framework",
                "Update test packages (MSTest/NUnit/xUnit)",
                "Fix any test compilation errors",
                "Run all unit tests",
                "Fix failing tests"
            ],
            VerificationSteps =
            [
                "All tests compile",
                "Test pass rate >= 95%",
                "No regression in coverage"
            ]
        });

        steps.Add(new MigrationStep
        {
            Order = stepOrder++,
            Phase = MigrationPhase.Testing,
            Title = "Integration testing",
            Description = "Perform integration testing to verify system works end-to-end.",
            EstimatedHours = 8.0,
            RiskLevel = "High",
            CanBeAutomated = false,
            Dependencies = [stepOrder - 1],
            Actions =
            [
                "Test database connectivity",
                "Test external API integrations",
                "Test file system operations",
                "Test authentication/authorization",
                "Performance testing"
            ],
            VerificationSteps =
            [
                "All integration tests pass",
                "No performance regression > 10%",
                "All external integrations work"
            ]
        });

        // Phase 6: Cleanup
        steps.Add(new MigrationStep
        {
            Order = stepOrder++,
            Phase = MigrationPhase.Cleanup,
            Title = "Code cleanup and modernization",
            Description = "Take advantage of new C# features and clean up migration artifacts.",
            EstimatedHours = 2.0,
            RiskLevel = "Low",
            CanBeAutomated = true,
            Actions =
            [
                "Remove unnecessary using statements",
                "Apply nullable reference type annotations",
                "Use file-scoped namespaces",
                "Use primary constructors where appropriate",
                "Remove obsolete suppression pragmas"
            ],
            VerificationSteps =
            [
                "Code compiles without warnings",
                "Code analysis passes"
            ]
        });

        steps.Add(new MigrationStep
        {
            Order = stepOrder++,
            Phase = MigrationPhase.Cleanup,
            Title = "Documentation and deployment preparation",
            Description = "Update documentation and prepare for deployment.",
            EstimatedHours = 2.0,
            RiskLevel = "Low",
            CanBeAutomated = false,
            Actions =
            [
                "Update README with new requirements",
                "Update deployment scripts",
                "Update CI/CD pipelines",
                "Document any breaking changes",
                "Create migration notes"
            ],
            VerificationSteps =
            [
                "CI/CD pipeline runs successfully",
                "Deployment to staging successful",
                "Documentation reviewed"
            ]
        });

        return steps;
    }

    private List<PackageMigration> GeneratePackageMigrations(CompatibilityResult compatibility)
    {
        var migrations = new List<PackageMigration>();

        foreach (var pkg in compatibility.PackageIssues)
        {
            migrations.Add(new PackageMigration
            {
                OldPackage = pkg.PackageName,
                OldVersion = pkg.CurrentVersion,
                NewPackage = pkg.ReplacementPackage ?? pkg.PackageName,
                NewVersion = pkg.MinimumCompatibleVersion ?? "latest",
                IsVersionUpgrade = pkg.ReplacementPackage == null,
                BreakingChanges = pkg.Notes != null ? [pkg.Notes] : [],
                Notes = pkg.Notes
            });
        }

        return migrations;
    }

    private double CalculateTotalEffort(List<MigrationStep> steps, List<BlockingIssue> blockingIssues)
    {
        var stepHours = steps.Sum(s => s.EstimatedHours);
        var blockingHours = blockingIssues.Sum(b => b.EstimatedHours);

        // Add contingency based on complexity
        var contingencyFactor = steps.Count(s => s.RiskLevel == "High") * 0.1 + 0.15;

        return (stepHours + blockingHours) * (1 + contingencyFactor);
    }

    private RiskAssessment AssessRisks(
        List<DeprecatedApiUsage> deprecatedApis,
        List<PlatformSpecificCode> platformIssues,
        List<BlockingIssue> blockingIssues,
        MigrationComplexity complexity)
    {
        var technicalRisks = new List<Risk>();
        var businessRisks = new List<Risk>();
        var mitigations = new List<string>();
        var testingRecs = new List<string>();

        // Technical risks
        if (blockingIssues.Any())
        {
            technicalRisks.Add(new Risk
            {
                Description = $"{blockingIssues.Count} blocking issues require resolution before migration can complete",
                Likelihood = "High",
                Impact = "High",
                Mitigation = "Resolve blocking issues first, consider phased migration"
            });
        }

        var securityRisks = _deprecatedApiDetector.GetSecurityRisks(deprecatedApis);
        if (securityRisks.Any())
        {
            technicalRisks.Add(new Risk
            {
                Description = $"{securityRisks.Count} security-risk APIs detected (e.g., BinaryFormatter)",
                Likelihood = "High",
                Impact = "High",
                Mitigation = "Replace security-risk APIs immediately as part of migration"
            });
        }

        var platformBlocking = PlatformSpecificDetector.GetBlockingIssues(platformIssues);
        if (platformBlocking.Any())
        {
            technicalRisks.Add(new Risk
            {
                Description = "Platform-specific code may prevent cross-platform deployment",
                Likelihood = platformBlocking.Count > 5 ? "High" : "Medium",
                Impact = "Medium",
                Mitigation = "Wrap platform-specific code with OS checks or replace with abstractions"
            });
        }

        if (deprecatedApis.Count > 100)
        {
            technicalRisks.Add(new Risk
            {
                Description = "Large number of API changes increases risk of regression",
                Likelihood = "Medium",
                Impact = "Medium",
                Mitigation = "Implement comprehensive test coverage before migration"
            });
        }

        // Business risks
        businessRisks.Add(new Risk
        {
            Description = "Development velocity may decrease during migration",
            Likelihood = "High",
            Impact = "Medium",
            Mitigation = "Plan migration during lower-activity period, consider feature freeze"
        });

        if (complexity >= MigrationComplexity.High)
        {
            businessRisks.Add(new Risk
            {
                Description = "Migration timeline may exceed initial estimates",
                Likelihood = "Medium",
                Impact = "Medium",
                Mitigation = "Build in buffer time, communicate uncertainties to stakeholders"
            });
        }

        // Mitigation strategies
        mitigations.Add("Create comprehensive backup before starting migration");
        mitigations.Add("Use version control with frequent commits to track changes");
        mitigations.Add("Implement feature flags for gradual rollout");
        mitigations.Add("Maintain parallel environments during transition");

        if (blockingIssues.Any())
        {
            mitigations.Add("Address blocking issues before other migration work");
        }

        // Testing recommendations
        testingRecs.Add("Run full regression test suite after each phase");
        testingRecs.Add("Perform load testing to verify performance");
        testingRecs.Add("Test on all target deployment platforms");

        if (platformIssues.Any())
        {
            testingRecs.Add("Test on Windows, Linux, and macOS (if cross-platform)");
        }

        testingRecs.Add("Verify all external integrations");
        testingRecs.Add("Test with production-like data volumes");

        var overallRisk = (complexity, blockingIssues.Count) switch
        {
            (MigrationComplexity.VeryHigh, _) => "Critical",
            (MigrationComplexity.High, > 3) => "Critical",
            (MigrationComplexity.High, _) => "High",
            (MigrationComplexity.Medium, > 5) => "High",
            (MigrationComplexity.Medium, _) => "Medium",
            _ => "Low"
        };

        return new RiskAssessment
        {
            OverallRisk = overallRisk,
            TechnicalRisks = technicalRisks,
            BusinessRisks = businessRisks,
            MitigationStrategies = mitigations,
            TestingRecommendations = testingRecs
        };
    }

    private MigrationSummary BuildSummary(
        List<DeprecatedApiUsage> deprecatedApis,
        List<PlatformSpecificCode> platformIssues,
        List<BlockingIssue> blockingIssues,
        List<MigrationStep> steps,
        List<PackageMigration> packageMigrations)
    {
        var affectedFiles = deprecatedApis.Select(a => a.FilePath)
            .Concat(platformIssues.Select(p => p.FilePath))
            .Distinct()
            .Count();

        var totalFiles = deprecatedApis.Select(a => a.FilePath)
            .Concat(platformIssues.Select(p => p.FilePath))
            .Distinct()
            .Count() + 10; // Estimate for other files

        var issuesByCategory = DeprecatedApiDetector.GroupByCategory(deprecatedApis)
            .ToDictionary(g => g.Key, g => g.Value.Count);

        var hoursByPhase = steps.GroupBy(s => s.Phase)
            .ToDictionary(g => g.Key, g => g.Sum(s => s.EstimatedHours));

        return new MigrationSummary
        {
            TotalFiles = totalFiles,
            FilesRequiringChanges = affectedFiles,
            DeprecatedApiUsages = deprecatedApis.Count,
            PlatformSpecificIssues = platformIssues.Count,
            BlockingIssueCount = blockingIssues.Count,
            PackagesToMigrate = packageMigrations.Count,
            TotalSteps = steps.Count,
            IssuesByCategory = issuesByCategory,
            HoursByPhase = hoursByPhase
        };
    }

    private static double GetEffortEstimate(string key)
    {
        foreach (var (pattern, hours) in EffortEstimates)
        {
            if (key.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                return hours;
            }
        }

        return 0.5; // Default effort per occurrence
    }

    private static string GetEstimateConfidence(int deprecatedApiCount, int platformIssueCount)
    {
        var total = deprecatedApiCount + platformIssueCount;

        return total switch
        {
            < 20 => "High",
            < 100 => "Medium",
            _ => "Low"
        };
    }

    /// <summary>
    /// Gets a human-readable migration plan summary.
    /// </summary>
    public string GetPlanSummary(MigrationPlan plan)
    {
        var summary = new System.Text.StringBuilder();

        summary.AppendLine($"Migration Plan: {plan.ProjectName}");
        summary.AppendLine($"From: {plan.SourceFramework} -> To: {plan.TargetFramework}");
        summary.AppendLine(new string('=', 60));
        summary.AppendLine();

        summary.AppendLine($"Overall Complexity: {plan.OverallComplexity}");
        summary.AppendLine($"Estimated Effort: {plan.TotalEstimatedHours:F1} hours");
        summary.AppendLine($"Estimate Confidence: {plan.EstimateConfidence}");
        summary.AppendLine($"Risk Level: {plan.Risks.OverallRisk}");
        summary.AppendLine();

        if (plan.BlockingIssues.Any())
        {
            summary.AppendLine($"BLOCKING ISSUES ({plan.BlockingIssues.Count}):");
            foreach (var issue in plan.BlockingIssues.Take(5))
            {
                summary.AppendLine($"  - {issue.Type}: {issue.Description}");
                summary.AppendLine($"    Resolution: {issue.Resolution}");
            }
            summary.AppendLine();
        }

        summary.AppendLine($"MIGRATION STEPS ({plan.Steps.Count} total):");
        var phases = plan.Steps.GroupBy(s => s.Phase);
        foreach (var phase in phases)
        {
            var phaseHours = phase.Sum(s => s.EstimatedHours);
            summary.AppendLine($"\n  {phase.Key} ({phaseHours:F1} hours):");
            foreach (var step in phase)
            {
                summary.AppendLine($"    {step.Order}. {step.Title} ({step.EstimatedHours:F1}h, Risk: {step.RiskLevel})");
            }
        }

        summary.AppendLine();
        summary.AppendLine("SUMMARY:");
        summary.AppendLine($"  Files requiring changes: {plan.Summary.FilesRequiringChanges}");
        summary.AppendLine($"  Deprecated API usages: {plan.Summary.DeprecatedApiUsages}");
        summary.AppendLine($"  Platform-specific issues: {plan.Summary.PlatformSpecificIssues}");
        summary.AppendLine($"  Packages to migrate: {plan.Summary.PackagesToMigrate}");

        return summary.ToString();
    }
}
