# BaseScanner

A comprehensive C# code analysis platform providing deep insights into code quality, security vulnerabilities, performance issues, thread safety, technical debt, and refactoring opportunities. Features include semantic analysis, memory leak detection, clone detection, incremental analysis, and interactive TUI. Works as a CLI tool, Language Server (LSP), and MCP server for Claude Code integration.

## Features

### Analysis Modes

| Flag | Description |
|------|-------------|
| `--deep` | Usage counting, deprecated code detection, dead code analysis |
| `--sentiment` | Code quality scoring, complexity metrics, duplicate detection |
| `--perf` | Async issues, performance anti-patterns, blocking calls |
| `--exceptions` | Exception handling issues, empty catches, swallowed exceptions |
| `--resources` | Resource leaks, IDisposable issues, event handler leaks |
| `--deps` | Circular dependencies, coupling metrics (Ce, Ca, Instability) |
| `--magic` | Magic numbers and strings detection |
| `--git` | Git churn analysis, hotspot detection |
| `--refactor` | Long methods, god classes, feature envy, parameter smells |
| `--arch` | Architecture analysis, API surface, call graph, inheritance |
| `--safety` | Null safety, immutability opportunities, logging gaps |
| `--optimize` | Optimization opportunities with code suggestions |
| `--security` | Security vulnerability analysis with CWE references |
| `--dashboard` | Project health metrics dashboard |
| `--trends` | Trend analysis using git history |
| `--thread-safety` | Thread safety, race conditions, async patterns, deadlock risks |
| `--tech-debt` | Technical debt calculation with time estimates and quick wins |
| `--memory-leaks` | Memory leak detection (event handlers, closures, disposables) |
| `--documentation` | Documentation quality, coverage, naming quality |
| `--naming` | Naming convention compliance, semantic analysis |
| `--logging` | Logging quality, sensitive data exposure, structured logging |
| `--clones` | Semantic code clone detection with extraction opportunities |
| `--impact` | Change impact analysis, blast radius, dependency graph |
| `--configuration` | Hardcoded values, config validation, environment detection |
| `--contracts` | Preconditions, side effects, invariant violations |
| `--migration` | Framework migration assistant with deprecation detection |
| `--api-design` | API consistency, breaking changes, REST best practices |
| `--vuln-scan` | NuGet vulnerability scanner (CVE/GHSA) |
| `--concurrency` | Concurrency issues (floating tasks, locks, reentrancy) |
| `--aspnet` | ASP.NET Core security (auth, CORS, CSRF, mass assignment) |
| `--ef` | Entity Framework issues (N+1, tracking, lazy loading) |
| `--quality` | Code quality, cognitive complexity, testability |
| `--incremental` | Enable incremental analysis with caching |
| `--tui` | Launch interactive terminal UI |
| `--lsp` | Start Language Server Protocol server |
| `--all` | Run all analyses |

### Transformation Options

| Flag | Description |
|------|-------------|
| `--apply` | Apply optimizations to the codebase (creates backup) |
| `--preview` | Preview transformations without applying |
| `--category=X` | Filter by category: performance, readability, modernization |
| `--confidence=X` | Minimum confidence: high, medium, low (default: high) |
| `--rollback` | Rollback to previous backup |
| `--list-backups` | List available transformation backups |

### Refactoring Optimizer

| Flag | Description |
|------|-------------|
| `--refactor-analyze` | Analyze refactoring opportunities with LCOM4 metrics |
| `--refactor-preview` | Compare multiple strategies using virtual workspace |
| `--refactor-apply` | Apply best refactoring strategy with backup |
| `--refactor-chain` | Apply a chain of strategies (godclass, longmethod, testability) |
| `--severity=X` | Filter by severity: critical, high, medium, low |

### Framework-Aware Analysis

BaseScanner intelligently detects your project's target framework and C# language version:

- **C# 6+**: Null-conditional operator (`?.`)
- **C# 7+**: Pattern matching (`is T variable`)
- **C# 8+**: Switch expressions, null-coalescing assignment (`??=`)
- **C# 9+**: Target-typed `new()`
- **.NET 6+**: `MinBy()`/`MaxBy()` LINQ methods

Suggestions are filtered to only show what's available for your project.

## Installation

### Prerequisites

- .NET 9.0 SDK
- Visual Studio 2022 (for MSBuild)

### Build

```bash
dotnet build
```

## Usage

### CLI Mode

```bash
# Analyze a project with all checks
dotnet run -- "path/to/project.csproj" --all

# Quick scan
dotnet run -- "path/to/project" --deep --perf

# Security analysis
dotnet run -- "path/to/project" --security --vuln-scan

# Thread safety and concurrency
dotnet run -- "path/to/project" --thread-safety --concurrency

# Technical debt analysis
dotnet run -- "path/to/project" --tech-debt

# Memory leak detection
dotnet run -- "path/to/project" --memory-leaks

# Documentation quality
dotnet run -- "path/to/project" --documentation --naming

# Code clones
dotnet run -- "path/to/project" --clones --min-lines=6

# Change impact analysis
dotnet run -- "path/to/project" --impact --symbol="MyNamespace.MyClass.MyMethod"

# Framework migration
dotnet run -- "path/to/project" --migration --target=net9.0

# API design analysis
dotnet run -- "path/to/project" --api-design --aspnet

# Optimization suggestions
dotnet run -- "path/to/project" --optimize

# Preview and apply transformations
dotnet run -- "path/to/project" --preview --confidence=high
dotnet run -- "path/to/project" --apply --category=performance

# Rollback changes
dotnet run -- "path/to/project" --rollback

# Refactoring optimizer
dotnet run -- "path/to/project" --refactor-analyze --severity=critical
dotnet run -- "path/to/project" --refactor-preview --file=MyClass.cs --target=MyClass
dotnet run -- "path/to/project" --refactor-apply --file=MyClass.cs --target=MyClass
dotnet run -- "path/to/project" --refactor-chain --file=MyClass.cs --target=MyClass --chain=godclass

# Incremental analysis (uses caching)
dotnet run -- "path/to/project" --incremental --all

# Interactive TUI mode
dotnet run -- "path/to/project" --tui

# Language Server mode (for IDE integration)
dotnet run -- "path/to/project" --lsp
```

### MCP Server Mode (Claude Code Integration)

```bash
# Add to Claude Code
claude mcp add --transport stdio basescanner -- dotnet run --project "path/to/BaseScanner" -- --mcp
```

Available MCP tools (40+ tools):

### Core Analysis
| Tool | Description |
|------|-------------|
| `QuickProjectScan` | Fast health check with top issues |
| `AnalyzeCsharpProject` | Full analysis with configurable options |
| `ListAnalysisTypes` | Show available analysis types |
| `RunFullAnalysis` | Comprehensive analysis (security, concurrency, frameworks, quality) |
| `RunComprehensiveAnalysis` | All Phase 1-4 analyzers in parallel |

### Security & Vulnerabilities
| Tool | Description |
|------|-------------|
| `AnalyzeSecurity` | Security vulnerability analysis with CWE references |
| `ScanVulnerabilities` | NuGet dependency CVE/GHSA scanner |
| `AnalyzeTaintFlow` | Track tainted data from sources to sinks |
| `AnalyzeAspNetCore` | ASP.NET Core security (auth, CORS, CSRF) |
| `AnalyzeConfiguration` | Hardcoded values, config validation |

### Code Quality & Complexity
| Tool | Description |
|------|-------------|
| `AnalyzeCodeQuality` | Cognitive complexity, code smells, testability |
| `AnalyzeCognitiveComplexity` | Sonar cognitive complexity analysis |
| `GetProjectDashboard` | Project health metrics dashboard |
| `CalculateTechnicalDebt` | Debt rating, time estimates, quick wins |
| `AnalyzeDocumentation` | Documentation quality and coverage |
| `AnalyzeNamingConventions` | Naming compliance and semantic analysis |

### Concurrency & Threading
| Tool | Description |
|------|-------------|
| `AnalyzeConcurrency` | Floating tasks, async void, lock patterns |
| `AnalyzeThreadSafety` | Race conditions, shared state, deadlock risks |

### Performance & Optimization
| Tool | Description |
|------|-------------|
| `AnalyzeOptimizations` | Find optimization opportunities |
| `CompareOptimizationStrategies` | Compare strategies in virtual workspace |
| `PreviewTransformations` | Preview code transformations |
| `ApplyTransformations` | Apply transformations with backup |
| `RollbackTransformations` | Restore from backup |
| `ListTransformationBackups` | List available backups |

### Memory & Resources
| Tool | Description |
|------|-------------|
| `DetectMemoryLeaks` | Event handlers, closures, disposables |
| `AnalyzeLoggingQuality` | Log levels, sensitive data, structured logging |

### Code Duplication
| Tool | Description |
|------|-------------|
| `DetectCodeClones` | Semantic clone detection with extraction opportunities |

### Dependencies & Impact
| Tool | Description |
|------|-------------|
| `AnalyzeChangeImpact` | Blast radius, dependency graph, risk assessment |
| `AnalyzeEntityFramework` | EF Core N+1, tracking, lazy loading issues |

### Refactoring
| Tool | Description |
|------|-------------|
| `AnalyzeRefactoringOpportunities` | God classes, LCOM4 metrics |
| `PreviewRefactoring` | Compare refactoring strategies |
| `ApplyRefactoring` | Apply best strategy with backup |
| `ApplyRefactoringChain` | Apply strategy sequences |
| `AnalyzeCohesion` | Class cohesion and method clusters |
| `GetRefactoringChains` | Pre-built strategy chains |
| `ListRefactoringStrategies` | List available strategies |

### Contracts & Architecture
| Tool | Description |
|------|-------------|
| `AnalyzeContracts` | Preconditions, side effects, invariants |
| `AnalyzeApiDesign` | API consistency, breaking changes, REST |

### Migration & Trends
| Tool | Description |
|------|-------------|
| `AssistMigration` | Framework migration with deprecation detection |
| `AnalyzeTrends` | Analyze trends over git history |

## Analysis Details

### Security Analysis

Detects security vulnerabilities with CWE references:

| Category | Description | CWE |
|----------|-------------|-----|
| SQL Injection | User input in SQL commands | CWE-89 |
| Command Injection | User input in Process.Start | CWE-78 |
| Path Traversal | Unsafe file path handling | CWE-22 |
| Hardcoded Secrets | API keys, passwords in code | CWE-798 |
| Weak Cryptography | MD5, SHA1, DES usage | CWE-327, CWE-328 |
| Unsafe Deserialization | BinaryFormatter, unsafe JSON | CWE-502 |
| Missing Authorization | Unprotected endpoints | CWE-862 |
| CSRF Vulnerabilities | Missing anti-forgery tokens | CWE-352 |

### Optimization Detectors

**Performance:**
- LINQ optimizations (Count() > 0 → Any(), OrderBy+First → MinBy/MaxBy)
- Collection optimizations (List → HashSet for lookups, capacity hints)
- Async patterns (async void → Task, .Result → await)
- String optimizations (concatenation → StringBuilder, Format → interpolation)
- Memory optimizations (ArrayPool, stackalloc, avoiding boxing)
- Caching opportunities (repeated calls, compiled regex)

**Modernization:**
- Null-conditional operators
- Pattern matching
- Switch expressions
- Target-typed new
- Null-coalescing assignment

### Dead Code Detection

Finds unused classes, methods, and fields by analyzing symbol references across the entire project.

### Code Sentiment Analysis

Scores code quality based on:
- Cyclomatic complexity
- Nesting depth
- Method length
- Parameter count
- Duplicate detection (exact and structural)

### Performance Analysis

Detects:
- `async void` methods (exception handling issues)
- `.GetAwaiter().GetResult()` (deadlock risk)
- String concatenation in loops
- LINQ in loops
- Missing `ConfigureAwait(false)`

### Refactoring Opportunities

Identifies:
- **God Classes**: High LCOM (Lack of Cohesion), many methods/fields
- **Long Methods**: With extract method suggestions
- **Feature Envy**: Methods that use other classes more than their own
- **Parameter Smells**: Long parameter lists, primitive obsession

### Refactoring Optimizer

A comprehensive refactoring system that uses an in-memory virtual workspace to safely compare and apply refactorings without breaking functionality.

**Virtual Workspace:**

The Virtual Workspace enables safe, non-destructive refactoring by:

- **In-Memory Branches**: Each refactoring strategy runs in an isolated in-memory branch, leaving your files untouched until you approve
- **Parallel Comparison**: Multiple strategies execute simultaneously, allowing side-by-side comparison of different approaches
- **Semantic Validation**: Each transformation is validated for compilation and public API preservation before scoring
- **Diff Generation**: Unified diffs show exactly what changes each strategy would make
- **Rollback Safety**: Automatic backups are created before any file modifications

```
┌─────────────────────────────────────────────────────────────┐
│                    Virtual Workspace                         │
├─────────────────────────────────────────────────────────────┤
│  Original Solution                                           │
│       │                                                      │
│       ├──► Branch: ExtractMethod ──► Score: 72 ──► Diff     │
│       ├──► Branch: ExtractClass  ──► Score: 85 ──► Diff     │
│       ├──► Branch: SplitGodClass ──► Score: 91 ──► Diff  ◄──┤ Best
│       └──► Branch: ExtractInterface ──► Score: 68 ──► Diff  │
│                                                              │
│  Compare → Select Best → Apply to Disk (with backup)        │
└─────────────────────────────────────────────────────────────┘
```

**Strategies:**

| Strategy | Description |
|----------|-------------|
| `SimplifyMethod` | Guard clauses, early returns, flatten nesting |
| `ExtractMethod` | Extract cohesive code blocks into methods |
| `ExtractClass` | Extract method clusters to new classes |
| `SplitGodClass` | Split by responsibility boundaries |
| `ExtractInterface` | Create interfaces from public members |
| `ReplaceConditional` | Replace switch-on-type with polymorphism |

**Strategy Chains:**

Pre-built chains for comprehensive remediation:

```
GodClass Chain:     SimplifyMethod → ExtractMethod → SplitGodClass → ExtractInterface
LongMethod Chain:   SimplifyMethod → ExtractMethod
Testability Chain:  ExtractInterface → ExtractClass → ReplaceConditional
Complexity Chain:   SimplifyMethod → ReplaceConditional → ExtractMethod
```

**Scoring Metrics:**

| Metric | Weight | Description |
|--------|--------|-------------|
| Cohesion | 40% | LCOM4 improvement |
| Complexity | 30% | Cyclomatic complexity reduction |
| Maintainability | 20% | Code maintainability improvement |
| Naming | 10% | Naming quality of generated code |

### Architecture Analysis

- Public API surface analysis
- Entry points and dead ends in call graph
- Deep inheritance hierarchies
- Composition over inheritance candidates

### Thread Safety & Concurrency Analysis

Detects concurrency issues and threading problems:

| Category | Description |
|----------|-------------|
| Race Conditions | Shared mutable state without proper synchronization |
| Lock Issues | Deadlock risks, lock ordering violations, excessive locking |
| Async Patterns | Async void, floating tasks, missing ConfigureAwait |
| Atomicity Violations | Non-atomic read-modify-write operations |
| Reentrancy Issues | Async reentrancy in non-reentrant code |

### Technical Debt Analysis

Calculates technical debt with actionable metrics:

- **Debt Rating**: A-E rating based on total debt
- **Time Estimates**: Minutes/hours/days to fix each issue
- **Quick Wins**: High-payoff, low-effort improvements
- **Major Projects**: High-impact items requiring significant effort
- **File Hotspots**: Files with highest debt concentration
- **Trend Analysis**: Improving vs worsening files
- **Payoff Plans**: Optimized debt reduction strategies within time budgets

### Memory Leak Detection

Identifies memory leak patterns:

- Unsubscribed event handlers (UI, domain events, weak events)
- Closure captures of disposable/large objects
- Static/singleton collection growth
- IDisposable leaks and missing using statements
- Timer/callback leaks
- Estimated memory impact per leak

### Documentation Quality

Analyzes documentation completeness and quality:

- XML documentation coverage percentage
- Missing public API documentation
- Stale/TODO comments (TODO, FIXME, HACK)
- Naming quality analysis
- Misleading parameter names
- Documentation debt scoring

### Naming Conventions

Comprehensive naming analysis:

- PascalCase/camelCase compliance
- Semantic naming issues (async methods, boolean fields)
- Misleading names (return type mismatches, boolean logic)
- Term inconsistencies across codebase
- Abbreviation consistency
- Context-aware suggestions

### Logging Quality

Evaluates logging practices:

- Log level appropriateness (exceptions, control flow)
- Sensitive data exposure (PII, credentials, tokens)
- Structured logging usage
- Missing correlation IDs
- Exception logging patterns
- Framework detection (ILogger, Serilog, NLog, log4net)

### Code Clone Detection

Semantic clone detection beyond textual duplicates:

- **Type-1**: Exact clones (whitespace/comments differ)
- **Type-2**: Renamed clones (identifiers differ)
- **Type-3**: Gapped clones (statements added/removed)
- Clone coverage metrics
- Extraction opportunities with suggested method names
- Estimated lines saved by refactoring

### Change Impact Analysis

Analyzes blast radius of code changes:

- Direct and transitive dependency impact
- Affected file counts and paths
- Risk scoring (low/medium/high/critical)
- Public API impact assessment
- Breaking change detection
- Mitigation strategies
- Dependency graph statistics

### Configuration Analysis

Detects configuration issues:

- Hardcoded configuration values
- Environment-specific code
- Config key validation against config files
- Missing/unused configuration keys
- Schema validation
- Type mismatch detection

### Contract Analysis

Analyzes implicit contracts in code:

- Missing preconditions (null checks, range validation)
- Hidden side effects in pure-looking methods
- Invariant violations
- Guard clause suggestions
- Method purity analysis

### Migration Assistant

Assists with .NET framework migrations:

- Deprecated API detection
- Modern replacement suggestions
- Platform-specific code identification
- Compatibility analysis
- Migration plan generation
- Blocking issue identification

### API Design Analysis

Evaluates API design quality:

- Consistency across endpoints
- Breaking change detection
- REST/HTTP best practices
- Versioning strategy issues
- Controller action analysis
- Route pattern validation

### Dashboard Metrics

- **Health Score**: Overall project quality (0-100)
- **Cyclomatic Complexity**: Average and maximum
- **Maintainability Index**: Code maintainability score
- **Technical Debt**: Estimated remediation time
- **Hotspots**: Files with most issues

## Advanced Features

### Interactive Terminal UI (TUI)

Launch an interactive terminal interface for exploring analysis results:

- **Filter Panel**: Filter issues by severity, category, file
- **Issue Detail View**: Drill down into specific issues with code context
- **Diff Preview**: Preview transformations before applying
- **Navigation**: Keyboard shortcuts for efficient browsing
- **Real-time Updates**: Watch mode for continuous analysis

```bash
dotnet run -- "path/to/project" --tui
```

### Language Server Protocol (LSP)

IDE integration via Language Server Protocol:

- **Diagnostics**: Real-time issue detection as you type
- **Code Actions**: Quick fixes and refactoring suggestions
- **Hover Information**: Detailed issue descriptions on hover
- **Code Lens**: Inline metrics and complexity indicators

Supported in VS Code, Visual Studio, and other LSP-compatible editors.

### Incremental Analysis

Cache-based incremental analysis for faster repeated scans:

- **Change Detection**: Only analyzes modified files
- **Dependency Tracking**: Re-analyzes affected dependents
- **Cache Invalidation**: Smart cache invalidation on config changes
- **Performance**: 10-100x faster on unchanged codebases

The cache is stored in `.basescanner/` directory.

### Reporting & Integration

Multiple output formats for CI/CD integration:

| Format | Description | Use Case |
|--------|-------------|----------|
| **SARIF** | Static Analysis Results Interchange Format | Universal, GitHub integration |
| **HTML** | Rich interactive HTML report | Human review, dashboards |
| **JUnit XML** | JUnit-compatible test results | CI/CD test reporting |
| **GitHub Annotations** | GitHub Actions workflow annotations | PR comments, check runs |
| **Azure DevOps** | Azure Pipelines integration | Azure DevOps builds |

```bash
dotnet run -- "path/to/project" --all --report=sarif --output=results.sarif
```

### Git Hooks

Automatic git hook generation and installation:

- **Pre-commit**: Block commits with critical issues
- **Pre-push**: Run full analysis before push
- **Commit-msg**: Validate commit message format
- **Custom Hooks**: Define custom quality gates

```bash
dotnet run -- --install-hooks "path/to/repo"
```

### ML-Powered Confidence Scoring

Machine learning-based confidence scoring for suggestions:

- **Feature Extraction**: Analyzes code context, patterns
- **Pattern Learning**: Learns from accepted/rejected suggestions
- **Feedback Loop**: Improves accuracy over time
- **Confidence Levels**: High/Medium/Low confidence ratings

## Output Example

```
=== PROJECT HEALTH DASHBOARD ===

  Health Score: 78/100

  CODE SIZE:
    Files:            45
    Lines of Code:    12,450
    Classes:          89
    Methods:          523

  COMPLEXITY:
    Avg Cyclomatic:   4.2
    Max Cyclomatic:   28
    Methods > 10 CC:  12

  MAINTAINABILITY:
    Index:            65.3
    Technical Debt:   8.5 hours (1.1 days)

=== SECURITY VULNERABILITY ANALYSIS ===

  CRITICAL: 2
  HIGH: 5
  MEDIUM: 12

  SQL Injection (2):
    DataAccess.cs:45 [Critical] CWE-89 User input concatenated in SQL query
      Fix: Use parameterized queries instead of string concatenation

  Hardcoded Secrets (3):
    Config.cs:12 [High] CWE-798 Potential API key detected
      Fix: Move secrets to environment variables or secure vault
```

## Project Structure

```
BaseScanner/
├── Analyzers/
│   ├── ArchitectureAnalyzer.cs
│   ├── OptimizationAnalyzer.cs
│   ├── Api/                           # API design analysis
│   │   ├── ApiDesignAnalyzer.cs
│   │   ├── BreakingChangeDetector.cs
│   │   ├── ConsistencyAnalyzer.cs
│   │   ├── RestAnalyzer.cs
│   │   └── VersioningAnalyzer.cs
│   ├── Clones/                        # Semantic clone detection
│   │   ├── CloneAnalysisEngine.cs
│   │   ├── CloneClassifier.cs
│   │   ├── SemanticCloneDetector.cs
│   │   ├── SemanticHasher.cs
│   │   └── SyntaxNormalizer.cs
│   ├── Concurrency/                   # Thread safety analysis
│   │   ├── ConcurrencyAnalyzer.cs
│   │   ├── ThreadSafetyAnalyzer.cs
│   │   └── Detectors/
│   │       ├── AsyncReentrancyDetector.cs
│   │       ├── AtomicityDetector.cs
│   │       ├── LockAnalyzer.cs
│   │       ├── RaceConditionDetector.cs
│   │       └── SharedStateDetector.cs
│   ├── Configuration/                 # Configuration analysis
│   │   ├── ConfigurationAnalyzer.cs
│   │   ├── ConfigSchemaValidator.cs
│   │   ├── ConfigUsageAnalyzer.cs
│   │   ├── EnvironmentCodeDetector.cs
│   │   └── HardcodedValueDetector.cs
│   ├── Contracts/                     # Contract analysis
│   │   └── ContractAnalyzer.cs
│   ├── Debt/                          # Technical debt
│   │   └── TechnicalDebtScorer.cs
│   ├── Dependencies/                  # Dependency analysis
│   │   └── VulnerabilityScanner.cs
│   ├── Documentation/                 # Documentation quality
│   │   ├── DocumentationAnalyzer.cs
│   │   └── Detectors/
│   ├── Impact/                        # Change impact analysis
│   │   └── ChangeImpactAnalyzer.cs
│   ├── Logging/                       # Logging quality
│   │   └── LoggingQualityAnalyzer.cs
│   ├── Memory/                        # Memory leak detection
│   │   ├── MemoryLeakDetector.cs
│   │   └── Detectors/
│   ├── Migration/                     # Framework migration
│   │   ├── MigrationAssistant.cs
│   │   └── Detectors/
│   ├── Naming/                        # Naming conventions
│   │   └── NamingConventionAnalyzer.cs
│   ├── Testing/                       # Test quality analysis
│   │   └── Detectors/
│   ├── Frameworks/
│   │   ├── AspNetCoreAnalyzer.cs
│   │   └── EntityFrameworkAnalyzer.cs
│   ├── Optimizations/
│   │   ├── AsyncPatternDetector.cs
│   │   ├── CachingOptimizationDetector.cs
│   │   ├── CollectionOptimizationDetector.cs
│   │   ├── LazyInitDetector.cs
│   │   ├── LinqOptimizationDetector.cs
│   │   ├── MemoryOptimizationDetector.cs
│   │   ├── ModernCSharpDetector.cs
│   │   └── StringOptimizationDetector.cs
│   ├── Quality/
│   │   └── CodeQualityAnalyzer.cs
│   └── Security/
│       ├── AuthenticationDetector.cs
│       ├── CryptoAnalyzer.cs
│       ├── DeserializationDetector.cs
│       ├── InjectionDetector.cs
│       ├── PathTraversalDetector.cs
│       ├── SecretDetector.cs
│       └── SecurityAnalyzer.cs
├── Analysis/
│   ├── AnalysisCache.cs              # Incremental analysis cache
│   ├── ChangeDetector.cs             # File change detection
│   ├── DataFlowEngine.cs
│   ├── DependencyTracker.cs          # Dependency tracking
│   ├── IncrementalAnalysisEngine.cs  # Incremental engine
│   ├── MetricsDashboard.cs
│   ├── TaintTracker.cs
│   └── TrendAnalyzer.cs
├── Context/
│   ├── CodeContext.cs
│   └── ContextCache.cs
├── Hooks/                             # Git hooks system
│   ├── HookConfigLoader.cs
│   ├── HookGenerator.cs
│   ├── HookInstaller.cs
│   └── HookTemplates.cs
├── ML/                                # Machine learning
│   ├── ConfidenceScorer.cs
│   ├── FeatureExtractor.cs
│   ├── FeedbackStore.cs
│   └── PatternLearner.cs
├── Refactoring/
│   ├── RefactoringOrchestrator.cs
│   ├── Analysis/
│   │   └── CohesionAnalyzer.cs
│   ├── Composition/
│   │   └── StrategyComposer.cs
│   ├── Models/
│   │   └── RefactoringModels.cs
│   ├── Scoring/
│   │   └── RefactoringScorer.cs
│   └── Strategies/
│       ├── IRefactoringStrategy.cs
│       ├── ExtractClassStrategy.cs
│       ├── ExtractInterfaceStrategy.cs
│       ├── ExtractMethodStrategy.cs
│       ├── ReplaceConditionalStrategy.cs
│       ├── SimplifyMethodStrategy.cs
│       └── SplitGodClassStrategy.cs
├── Reporting/                         # Multi-format reporting
│   ├── AzureDevOpsReporter.cs
│   ├── GithubAnnotationReporter.cs
│   ├── HtmlReporter.cs
│   ├── JUnitReporter.cs
│   └── SarifReporter.cs
├── Rules/                             # Rule engine
├── Server/                            # Language Server (LSP)
│   ├── CodeActionProvider.cs
│   ├── CodeLensProvider.cs
│   ├── DiagnosticsProvider.cs
│   ├── HoverProvider.cs
│   └── LanguageServer.cs
├── Services/
│   ├── AnalysisService.cs
│   ├── AnalysisResult.cs
│   └── BackupService.cs
├── Transformers/
│   ├── TransformationService.cs
│   └── Optimizations/
│       ├── AsyncTransformer.cs
│       ├── CollectionTransformer.cs
│       ├── LinqTransformer.cs
│       ├── ModernCSharpTransformer.cs
│       └── StringTransformer.cs
├── Tui/                               # Terminal UI
│   ├── DiffPreviewView.cs
│   ├── FilterPanel.cs
│   ├── InteractiveMode.cs
│   └── IssueDetailView.cs
├── VirtualWorkspace/
│   ├── VirtualWorkspaceManager.cs
│   ├── SolutionBranchManager.cs
│   ├── TransformationScorer.cs
│   ├── DiffEngine.cs
│   └── Models.cs
├── Tools/
│   ├── AnalyzerTools.cs              # 40+ MCP tools
│   └── RefactoringTools.cs
└── Program.cs
```

## License

MIT

## Contributing

Contributions welcome! Please open an issue or PR.
