using System.Collections.Concurrent;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using BaseScanner.Analyzers.Naming.Models;

namespace BaseScanner.Analyzers.Naming;

/// <summary>
/// Main coordinator for naming convention analysis.
/// Orchestrates convention validation, semantic analysis, and terminology consistency checks.
/// </summary>
public class NamingConventionAnalyzer
{
    private readonly ConventionRules _conventionRules;
    private readonly NameAnalyzer _nameAnalyzer;
    private readonly TerminologyConsistency _terminologyConsistency;
    private readonly NamingConfiguration _configuration;

    public NamingConventionAnalyzer() : this(ConventionRules.CreateDefaultConfiguration())
    {
    }

    public NamingConventionAnalyzer(NamingConfiguration configuration)
    {
        _configuration = configuration;
        _conventionRules = new ConventionRules(configuration);
        _nameAnalyzer = new NameAnalyzer(_conventionRules);
        _terminologyConsistency = new TerminologyConsistency(_conventionRules);
    }

    /// <summary>
    /// Analyzes a project for naming convention issues.
    /// </summary>
    public async Task<NamingAnalysisResult> AnalyzeAsync(Project project)
    {
        var violations = new ConcurrentBag<NamingViolation>();
        var semanticIssues = new ConcurrentBag<SemanticNameAnalysis>();
        var totalSymbols = 0;

        // Clear previous terminology data
        _terminologyConsistency.Clear();

        // Analyze each document in parallel
        await Parallel.ForEachAsync(
            project.Documents,
            new ParallelOptions { MaxDegreeOfParallelism = 4 },
            async (document, ct) =>
            {
                if (document.FilePath == null ||
                    document.FilePath.Contains(".Designer.cs") ||
                    document.FilePath.Contains(".g.cs") ||
                    document.FilePath.Contains(".Generated.cs"))
                    return;

                var semanticModel = await document.GetSemanticModelAsync(ct);
                var root = await document.GetSyntaxRootAsync(ct);

                if (semanticModel == null || root == null)
                    return;

                var (docViolations, docSemanticIssues, symbolCount) =
                    AnalyzeDocument(document.FilePath, root, semanticModel);

                foreach (var violation in docViolations)
                    violations.Add(violation);

                foreach (var issue in docSemanticIssues)
                    semanticIssues.Add(issue);

                Interlocked.Add(ref totalSymbols, symbolCount);
            });

        // Analyze terminology consistency across the project
        var termInconsistencies = _terminologyConsistency.FindInconsistencies();
        var abbreviationIssues = _terminologyConsistency.FindAbbreviationIssues();

        // Build result
        var violationList = violations.ToList();
        var semanticIssueList = semanticIssues.Where(s => s.Issues.Count > 0).ToList();

        return new NamingAnalysisResult
        {
            ProjectPath = project.FilePath ?? project.Name,
            AnalyzedAt = DateTime.UtcNow,
            TotalSymbolsAnalyzed = totalSymbols,
            Violations = violationList,
            SemanticIssues = semanticIssueList,
            TermInconsistencies = termInconsistencies,
            AbbreviationIssues = abbreviationIssues,
            Summary = BuildSummary(violationList, semanticIssueList, termInconsistencies, abbreviationIssues, totalSymbols)
        };
    }

    /// <summary>
    /// Analyzes a single document for naming issues.
    /// </summary>
    private (List<NamingViolation>, List<SemanticNameAnalysis>, int) AnalyzeDocument(
        string filePath,
        SyntaxNode root,
        SemanticModel semanticModel)
    {
        var violations = new List<NamingViolation>();
        var semanticIssues = new List<SemanticNameAnalysis>();
        var symbolCount = 0;

        // Analyze classes
        foreach (var classDecl in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
        {
            symbolCount++;
            var violation = AnalyzeTypeDeclaration(classDecl, SymbolCategory.Class, filePath);
            if (violation != null)
                violations.Add(violation);

            // Record for terminology analysis
            _terminologyConsistency.RecordSymbol(
                classDecl.Identifier.Text,
                SymbolCategory.Class,
                filePath,
                classDecl.Identifier.GetLocation().GetLineSpan().StartLinePosition.Line + 1);
        }

        // Analyze interfaces
        foreach (var interfaceDecl in root.DescendantNodes().OfType<InterfaceDeclarationSyntax>())
        {
            symbolCount++;
            var violation = AnalyzeInterfaceDeclaration(interfaceDecl, filePath);
            if (violation != null)
                violations.Add(violation);

            _terminologyConsistency.RecordSymbol(
                interfaceDecl.Identifier.Text,
                SymbolCategory.Interface,
                filePath,
                interfaceDecl.Identifier.GetLocation().GetLineSpan().StartLinePosition.Line + 1);
        }

        // Analyze structs
        foreach (var structDecl in root.DescendantNodes().OfType<StructDeclarationSyntax>())
        {
            symbolCount++;
            var violation = AnalyzeTypeDeclaration(structDecl, SymbolCategory.Struct, filePath);
            if (violation != null)
                violations.Add(violation);

            _terminologyConsistency.RecordSymbol(
                structDecl.Identifier.Text,
                SymbolCategory.Struct,
                filePath,
                structDecl.Identifier.GetLocation().GetLineSpan().StartLinePosition.Line + 1);
        }

        // Analyze records
        foreach (var recordDecl in root.DescendantNodes().OfType<RecordDeclarationSyntax>())
        {
            symbolCount++;
            var violation = AnalyzeTypeDeclaration(recordDecl, SymbolCategory.Record, filePath);
            if (violation != null)
                violations.Add(violation);

            _terminologyConsistency.RecordSymbol(
                recordDecl.Identifier.Text,
                SymbolCategory.Record,
                filePath,
                recordDecl.Identifier.GetLocation().GetLineSpan().StartLinePosition.Line + 1);
        }

        // Analyze enums
        foreach (var enumDecl in root.DescendantNodes().OfType<EnumDeclarationSyntax>())
        {
            symbolCount++;
            var lineSpan = enumDecl.Identifier.GetLocation().GetLineSpan();
            var violation = _conventionRules.ValidateName(
                enumDecl.Identifier.Text,
                SymbolCategory.Enum,
                filePath,
                lineSpan.StartLinePosition.Line + 1,
                lineSpan.StartLinePosition.Character + 1);

            if (violation != null)
                violations.Add(violation);

            // Analyze enum members
            foreach (var member in enumDecl.Members)
            {
                symbolCount++;
                var memberLineSpan = member.Identifier.GetLocation().GetLineSpan();
                var memberViolation = _conventionRules.ValidateName(
                    member.Identifier.Text,
                    SymbolCategory.EnumMember,
                    filePath,
                    memberLineSpan.StartLinePosition.Line + 1,
                    memberLineSpan.StartLinePosition.Character + 1,
                    enumDecl.Identifier.Text);

                if (memberViolation != null)
                    violations.Add(memberViolation);
            }

            _terminologyConsistency.RecordSymbol(
                enumDecl.Identifier.Text,
                SymbolCategory.Enum,
                filePath,
                lineSpan.StartLinePosition.Line + 1);
        }

        // Analyze methods
        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            symbolCount++;
            var containingType = method.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault();
            var containingTypeName = containingType?.Identifier.Text;

            // Convention validation
            var lineSpan = method.Identifier.GetLocation().GetLineSpan();
            var violation = _conventionRules.ValidateName(
                method.Identifier.Text,
                SymbolCategory.Method,
                filePath,
                lineSpan.StartLinePosition.Line + 1,
                lineSpan.StartLinePosition.Character + 1,
                containingTypeName);

            if (violation != null)
                violations.Add(violation);

            // Semantic analysis
            if (_configuration.EnforceSemanticNaming)
            {
                var semanticAnalysis = _nameAnalyzer.AnalyzeMethod(method, semanticModel, filePath);
                if (semanticAnalysis.Issues.Count > 0)
                    semanticIssues.Add(semanticAnalysis);
            }

            // Analyze parameters
            foreach (var param in method.ParameterList.Parameters)
            {
                symbolCount++;
                var (paramViolation, _) = AnalyzeParameter(param, filePath, containingTypeName);
                if (paramViolation != null)
                    violations.Add(paramViolation);
            }

            _terminologyConsistency.RecordSymbol(
                method.Identifier.Text,
                SymbolCategory.Method,
                filePath,
                lineSpan.StartLinePosition.Line + 1,
                containingTypeName);
        }

        // Analyze properties
        foreach (var property in root.DescendantNodes().OfType<PropertyDeclarationSyntax>())
        {
            symbolCount++;
            var containingType = property.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault();
            var containingTypeName = containingType?.Identifier.Text;

            var lineSpan = property.Identifier.GetLocation().GetLineSpan();
            var violation = _conventionRules.ValidateName(
                property.Identifier.Text,
                SymbolCategory.Property,
                filePath,
                lineSpan.StartLinePosition.Line + 1,
                lineSpan.StartLinePosition.Character + 1,
                containingTypeName);

            if (violation != null)
                violations.Add(violation);

            // Semantic analysis for properties
            if (_configuration.EnforceSemanticNaming)
            {
                var semanticAnalysis = _nameAnalyzer.AnalyzeProperty(property, semanticModel, filePath);
                if (semanticAnalysis.Issues.Count > 0)
                    semanticIssues.Add(semanticAnalysis);
            }

            _terminologyConsistency.RecordSymbol(
                property.Identifier.Text,
                SymbolCategory.Property,
                filePath,
                lineSpan.StartLinePosition.Line + 1,
                containingTypeName);
        }

        // Analyze fields
        foreach (var fieldDecl in root.DescendantNodes().OfType<FieldDeclarationSyntax>())
        {
            var containingType = fieldDecl.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault();
            var containingTypeName = containingType?.Identifier.Text;

            foreach (var variable in fieldDecl.Declaration.Variables)
            {
                symbolCount++;
                var fieldViolation = AnalyzeField(fieldDecl, variable, filePath, containingTypeName);
                if (fieldViolation != null)
                    violations.Add(fieldViolation);

                var lineSpan = variable.Identifier.GetLocation().GetLineSpan();
                _terminologyConsistency.RecordSymbol(
                    variable.Identifier.Text,
                    GetFieldCategory(fieldDecl),
                    filePath,
                    lineSpan.StartLinePosition.Line + 1,
                    containingTypeName);
            }
        }

        // Analyze local variables
        foreach (var localDecl in root.DescendantNodes().OfType<LocalDeclarationStatementSyntax>())
        {
            foreach (var variable in localDecl.Declaration.Variables)
            {
                symbolCount++;
                var lineSpan = variable.Identifier.GetLocation().GetLineSpan();

                // Check if it's a constant
                var isConstant = localDecl.Modifiers.Any(SyntaxKind.ConstKeyword);

                NamingViolation? violation;
                if (isConstant)
                {
                    violation = _conventionRules.ValidateConstantName(
                        variable.Identifier.Text,
                        filePath,
                        lineSpan.StartLinePosition.Line + 1,
                        lineSpan.StartLinePosition.Character + 1);
                }
                else
                {
                    violation = _conventionRules.ValidateName(
                        variable.Identifier.Text,
                        SymbolCategory.LocalVariable,
                        filePath,
                        lineSpan.StartLinePosition.Line + 1,
                        lineSpan.StartLinePosition.Character + 1);
                }

                if (violation != null)
                    violations.Add(violation);
            }
        }

        // Analyze type parameters
        foreach (var typeParam in root.DescendantNodes().OfType<TypeParameterSyntax>())
        {
            symbolCount++;
            var lineSpan = typeParam.Identifier.GetLocation().GetLineSpan();
            var violation = _conventionRules.ValidateName(
                typeParam.Identifier.Text,
                SymbolCategory.TypeParameter,
                filePath,
                lineSpan.StartLinePosition.Line + 1,
                lineSpan.StartLinePosition.Character + 1);

            if (violation != null)
                violations.Add(violation);
        }

        // Analyze events
        foreach (var eventDecl in root.DescendantNodes().OfType<EventDeclarationSyntax>())
        {
            symbolCount++;
            var containingType = eventDecl.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault();
            var lineSpan = eventDecl.Identifier.GetLocation().GetLineSpan();
            var violation = _conventionRules.ValidateName(
                eventDecl.Identifier.Text,
                SymbolCategory.Event,
                filePath,
                lineSpan.StartLinePosition.Line + 1,
                lineSpan.StartLinePosition.Character + 1,
                containingType?.Identifier.Text);

            if (violation != null)
                violations.Add(violation);
        }

        // Analyze event fields
        foreach (var eventFieldDecl in root.DescendantNodes().OfType<EventFieldDeclarationSyntax>())
        {
            var containingType = eventFieldDecl.Ancestors().OfType<TypeDeclarationSyntax>().FirstOrDefault();

            foreach (var variable in eventFieldDecl.Declaration.Variables)
            {
                symbolCount++;
                var lineSpan = variable.Identifier.GetLocation().GetLineSpan();
                var violation = _conventionRules.ValidateName(
                    variable.Identifier.Text,
                    SymbolCategory.Event,
                    filePath,
                    lineSpan.StartLinePosition.Line + 1,
                    lineSpan.StartLinePosition.Character + 1,
                    containingType?.Identifier.Text);

                if (violation != null)
                    violations.Add(violation);
            }
        }

        // Analyze delegates
        foreach (var delegateDecl in root.DescendantNodes().OfType<DelegateDeclarationSyntax>())
        {
            symbolCount++;
            var lineSpan = delegateDecl.Identifier.GetLocation().GetLineSpan();
            var violation = _conventionRules.ValidateName(
                delegateDecl.Identifier.Text,
                SymbolCategory.Delegate,
                filePath,
                lineSpan.StartLinePosition.Line + 1,
                lineSpan.StartLinePosition.Character + 1);

            if (violation != null)
                violations.Add(violation);
        }

        return (violations, semanticIssues, symbolCount);
    }

    private NamingViolation? AnalyzeTypeDeclaration(TypeDeclarationSyntax typeDecl, SymbolCategory category, string filePath)
    {
        var lineSpan = typeDecl.Identifier.GetLocation().GetLineSpan();
        return _conventionRules.ValidateName(
            typeDecl.Identifier.Text,
            category,
            filePath,
            lineSpan.StartLinePosition.Line + 1,
            lineSpan.StartLinePosition.Character + 1);
    }

    private NamingViolation? AnalyzeInterfaceDeclaration(InterfaceDeclarationSyntax interfaceDecl, string filePath)
    {
        var lineSpan = interfaceDecl.Identifier.GetLocation().GetLineSpan();
        return _conventionRules.ValidateName(
            interfaceDecl.Identifier.Text,
            SymbolCategory.Interface,
            filePath,
            lineSpan.StartLinePosition.Line + 1,
            lineSpan.StartLinePosition.Character + 1);
    }

    private (NamingViolation?, SymbolCategory) AnalyzeParameter(
        ParameterSyntax param,
        string filePath,
        string? containingTypeName)
    {
        var lineSpan = param.Identifier.GetLocation().GetLineSpan();
        var violation = _conventionRules.ValidateName(
            param.Identifier.Text,
            SymbolCategory.Parameter,
            filePath,
            lineSpan.StartLinePosition.Line + 1,
            lineSpan.StartLinePosition.Character + 1,
            containingTypeName);

        return (violation, SymbolCategory.Parameter);
    }

    private NamingViolation? AnalyzeField(
        FieldDeclarationSyntax fieldDecl,
        VariableDeclaratorSyntax variable,
        string filePath,
        string? containingTypeName)
    {
        var lineSpan = variable.Identifier.GetLocation().GetLineSpan();
        var isConst = fieldDecl.Modifiers.Any(SyntaxKind.ConstKeyword);
        var isReadonly = fieldDecl.Modifiers.Any(SyntaxKind.ReadOnlyKeyword);

        // Check for constants
        if (isConst || (isReadonly && fieldDecl.Modifiers.Any(SyntaxKind.StaticKeyword)))
        {
            return _conventionRules.ValidateConstantName(
                variable.Identifier.Text,
                filePath,
                lineSpan.StartLinePosition.Line + 1,
                lineSpan.StartLinePosition.Character + 1,
                containingTypeName);
        }

        var category = GetFieldCategory(fieldDecl);

        return _conventionRules.ValidateName(
            variable.Identifier.Text,
            category,
            filePath,
            lineSpan.StartLinePosition.Line + 1,
            lineSpan.StartLinePosition.Character + 1,
            containingTypeName);
    }

    private static SymbolCategory GetFieldCategory(FieldDeclarationSyntax fieldDecl)
    {
        if (fieldDecl.Modifiers.Any(SyntaxKind.ConstKeyword))
            return SymbolCategory.Constant;

        if (fieldDecl.Modifiers.Any(SyntaxKind.PublicKeyword))
            return SymbolCategory.PublicField;

        if (fieldDecl.Modifiers.Any(SyntaxKind.ProtectedKeyword))
            return SymbolCategory.ProtectedField;

        if (fieldDecl.Modifiers.Any(SyntaxKind.InternalKeyword))
            return SymbolCategory.InternalField;

        return SymbolCategory.PrivateField;
    }

    private NamingAnalysisSummary BuildSummary(
        List<NamingViolation> violations,
        List<SemanticNameAnalysis> semanticIssues,
        List<TermInconsistency> termInconsistencies,
        List<AbbreviationUsage> abbreviationIssues,
        int totalSymbols)
    {
        var violationsByCategory = violations
            .GroupBy(v => v.SymbolCategory)
            .ToDictionary(g => g.Key, g => g.Count());

        var violationsByRule = violations
            .GroupBy(v => v.RuleId)
            .ToDictionary(g => g.Key, g => g.Count());

        var errorCount = violations.Count(v => v.Severity == NamingViolationSeverity.Error);
        var warningCount = violations.Count(v => v.Severity == NamingViolationSeverity.Warning);
        var suggestionCount = violations.Count(v => v.Severity == NamingViolationSeverity.Suggestion);
        var infoCount = violations.Count(v => v.Severity == NamingViolationSeverity.Info);

        // Calculate naming quality score (0-100)
        var qualityScore = CalculateQualityScore(
            totalSymbols,
            violations.Count,
            semanticIssues.Sum(s => s.Issues.Count),
            termInconsistencies.Count,
            abbreviationIssues.Count);

        // Identify top issues
        var topIssues = new List<string>();

        if (errorCount > 0)
            topIssues.Add($"{errorCount} critical naming violations");

        if (warningCount > 10)
            topIssues.Add($"{warningCount} naming convention warnings");

        if (termInconsistencies.Count > 0)
            topIssues.Add($"{termInconsistencies.Count} terminology inconsistencies");

        var asyncIssues = semanticIssues.Count(s => s.Issues.Any(i => i.IssueType.Contains("Async")));
        if (asyncIssues > 0)
            topIssues.Add($"{asyncIssues} async naming issues");

        var boolIssues = semanticIssues.Count(s => s.Issues.Any(i => i.IssueType.Contains("Boolean")));
        if (boolIssues > 0)
            topIssues.Add($"{boolIssues} boolean naming issues");

        return new NamingAnalysisSummary
        {
            TotalViolations = violations.Count,
            ErrorCount = errorCount,
            WarningCount = warningCount,
            SuggestionCount = suggestionCount,
            InfoCount = infoCount,
            ViolationsByCategory = violationsByCategory,
            ViolationsByRule = violationsByRule,
            SemanticIssueCount = semanticIssues.Sum(s => s.Issues.Count),
            TermInconsistencyCount = termInconsistencies.Count,
            AbbreviationIssueCount = abbreviationIssues.Count,
            NamingQualityScore = qualityScore,
            TopIssues = topIssues
        };
    }

    private static double CalculateQualityScore(
        int totalSymbols,
        int violations,
        int semanticIssues,
        int termInconsistencies,
        int abbreviationIssues)
    {
        if (totalSymbols == 0)
            return 100;

        // Base score starts at 100
        var score = 100.0;

        // Deduct for violations (weighted by severity)
        var violationPenalty = (violations * 2.0 / totalSymbols) * 100;
        score -= Math.Min(30, violationPenalty);

        // Deduct for semantic issues
        var semanticPenalty = (semanticIssues * 1.5 / totalSymbols) * 100;
        score -= Math.Min(20, semanticPenalty);

        // Deduct for terminology inconsistencies
        var termPenalty = termInconsistencies * 3;
        score -= Math.Min(15, termPenalty);

        // Deduct for abbreviation issues
        var abbrPenalty = abbreviationIssues * 2;
        score -= Math.Min(10, abbrPenalty);

        return Math.Max(0, Math.Min(100, score));
    }
}
