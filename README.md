# BaseScanner

A powerful C# code analysis tool that provides deep insights into code quality, performance issues, security vulnerabilities, and refactoring opportunities. Works as both a CLI tool and an MCP (Model Context Protocol) server for Claude Code integration.

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

# Optimization suggestions only
dotnet run -- "path/to/project" --optimize

# Security vulnerability scan
dotnet run -- "path/to/project" --security

# Project health dashboard
dotnet run -- "path/to/project" --dashboard

# Preview and apply transformations
dotnet run -- "path/to/project" --preview --confidence=high
dotnet run -- "path/to/project" --apply --category=performance

# Rollback changes
dotnet run -- "path/to/project" --rollback
```

### MCP Server Mode (Claude Code Integration)

```bash
# Add to Claude Code
claude mcp add --transport stdio basescanner -- dotnet run --project "path/to/BaseScanner" -- --mcp
```

Available MCP tools:

| Tool | Description |
|------|-------------|
| `QuickProjectScan` | Fast health check with top issues |
| `AnalyzeCsharpProject` | Full analysis with configurable options |
| `ListAnalysisTypes` | Show available analysis types |
| `AnalyzeOptimizations` | Find optimization opportunities with code suggestions |
| `AnalyzeSecurity` | Security vulnerability analysis with CWE references |
| `GetProjectDashboard` | Project health metrics (score, complexity, debt) |
| `PreviewTransformations` | Preview code transformations before applying |
| `ApplyTransformations` | Apply transformations with automatic backup |
| `RollbackTransformations` | Restore from backup |
| `ListTransformationBackups` | List available backups |
| `AnalyzeTaintFlow` | Track tainted data from sources to sinks |
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

### Architecture Analysis

- Public API surface analysis
- Entry points and dead ends in call graph
- Deep inheritance hierarchies
- Composition over inheritance candidates

### Dashboard Metrics

- **Health Score**: Overall project quality (0-100)
- **Cyclomatic Complexity**: Average and maximum
- **Maintainability Index**: Code maintainability score
- **Technical Debt**: Estimated remediation time
- **Hotspots**: Files with most issues

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
│   ├── Optimizations/
│   │   ├── AsyncPatternDetector.cs
│   │   ├── CachingOptimizationDetector.cs
│   │   ├── CollectionOptimizationDetector.cs
│   │   ├── LazyInitDetector.cs
│   │   ├── LinqOptimizationDetector.cs
│   │   ├── MemoryOptimizationDetector.cs
│   │   ├── ModernCSharpDetector.cs
│   │   └── StringOptimizationDetector.cs
│   └── Security/
│       ├── AuthenticationDetector.cs
│       ├── CryptoAnalyzer.cs
│       ├── DeserializationDetector.cs
│       ├── InjectionDetector.cs
│       ├── ISecurityDetector.cs
│       ├── PathTraversalDetector.cs
│       ├── SecretDetector.cs
│       └── SecurityAnalyzer.cs
├── Analysis/
│   ├── DataFlowEngine.cs
│   ├── MetricsDashboard.cs
│   ├── TaintTracker.cs
│   └── TrendAnalyzer.cs
├── Context/
│   ├── CodeContext.cs
│   └── ContextCache.cs
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
├── Tools/
│   └── AnalyzerTools.cs
└── Program.cs
```

## License

MIT

## Contributing

Contributions welcome! Please open an issue or PR.
