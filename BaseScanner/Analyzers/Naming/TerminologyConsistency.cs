using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Microsoft.CodeAnalysis;
using BaseScanner.Analyzers.Naming.Models;

namespace BaseScanner.Analyzers.Naming;

/// <summary>
/// Analyzes terminology consistency across a codebase.
/// Detects inconsistent term usage (Customer vs Client vs User)
/// and flags abbreviation inconsistencies.
/// </summary>
public class TerminologyConsistency
{
    private readonly ConventionRules _rules;
    private readonly ConcurrentDictionary<string, List<TermUsage>> _termUsages;
    private readonly ConcurrentDictionary<string, List<TermUsage>> _abbreviationUsages;

    // Known domain concept synonyms that often cause inconsistency
    private static readonly Dictionary<string, List<string>> DomainConceptSynonyms = new(StringComparer.OrdinalIgnoreCase)
    {
        // User/identity concepts
        ["user"] = new() { "customer", "client", "member", "account", "person", "contact", "profile" },
        ["customer"] = new() { "user", "client", "member", "account", "buyer", "consumer" },
        ["client"] = new() { "user", "customer", "consumer" },

        // CRUD operations
        ["create"] = new() { "add", "insert", "new", "make", "build", "generate" },
        ["read"] = new() { "get", "fetch", "load", "retrieve", "find", "query" },
        ["update"] = new() { "modify", "change", "edit", "alter", "set", "patch" },
        ["delete"] = new() { "remove", "destroy", "erase", "drop", "clear" },

        // Data concepts
        ["data"] = new() { "info", "information", "record", "entry", "item" },
        ["list"] = new() { "collection", "array", "set", "items", "entries" },
        ["id"] = new() { "identifier", "key", "code", "number" },

        // Configuration
        ["config"] = new() { "configuration", "settings", "options", "preferences", "params" },
        ["setting"] = new() { "option", "preference", "parameter", "config" },

        // State concepts
        ["status"] = new() { "state", "condition", "phase" },
        ["error"] = new() { "exception", "fault", "failure", "issue", "problem" },

        // Communication
        ["message"] = new() { "notification", "alert", "notice", "event" },
        ["request"] = new() { "query", "command", "call", "action" },
        ["response"] = new() { "result", "reply", "answer", "output" },

        // Time concepts
        ["date"] = new() { "time", "timestamp", "datetime" },
        ["start"] = new() { "begin", "init", "open", "launch" },
        ["end"] = new() { "finish", "complete", "close", "stop", "terminate" }
    };

    // Common abbreviations and their expansions
    private static readonly Dictionary<string, string> CommonAbbreviations = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Id"] = "Identifier",
        ["Db"] = "Database",
        ["Ctx"] = "Context",
        ["Req"] = "Request",
        ["Res"] = "Response",
        ["Msg"] = "Message",
        ["Cfg"] = "Configuration",
        ["Mgr"] = "Manager",
        ["Svc"] = "Service",
        ["Repo"] = "Repository",
        ["Impl"] = "Implementation",
        ["Auth"] = "Authentication",
        ["Authz"] = "Authorization",
        ["Btn"] = "Button",
        ["Lbl"] = "Label",
        ["Txt"] = "Text",
        ["Num"] = "Number",
        ["Str"] = "String",
        ["Val"] = "Value",
        ["Cnt"] = "Count",
        ["Len"] = "Length",
        ["Idx"] = "Index",
        ["Pos"] = "Position",
        ["Src"] = "Source",
        ["Dst"] = "Destination",
        ["Dir"] = "Directory",
        ["Tmp"] = "Temporary",
        ["Env"] = "Environment",
        ["Proc"] = "Process",
        ["Func"] = "Function",
        ["Param"] = "Parameter",
        ["Arg"] = "Argument",
        ["Attr"] = "Attribute",
        ["Prop"] = "Property",
        ["Elem"] = "Element",
        ["Doc"] = "Document",
        ["Desc"] = "Description",
        ["Info"] = "Information",
        ["Util"] = "Utility",
        ["Ext"] = "Extension",
        ["Prev"] = "Previous",
        ["Curr"] = "Current",
        ["Max"] = "Maximum",
        ["Min"] = "Minimum",
        ["Avg"] = "Average"
    };

    public TerminologyConsistency() : this(new ConventionRules())
    {
    }

    public TerminologyConsistency(ConventionRules rules)
    {
        _rules = rules;
        _termUsages = new ConcurrentDictionary<string, List<TermUsage>>(StringComparer.OrdinalIgnoreCase);
        _abbreviationUsages = new ConcurrentDictionary<string, List<TermUsage>>(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Clears all collected term usages for a new analysis.
    /// </summary>
    public void Clear()
    {
        _termUsages.Clear();
        _abbreviationUsages.Clear();
    }

    /// <summary>
    /// Records a symbol name for terminology analysis.
    /// </summary>
    public void RecordSymbol(
        string symbolName,
        SymbolCategory category,
        string filePath,
        int line,
        string? context = null)
    {
        var words = _rules.SplitIntoWords(symbolName);

        foreach (var word in words)
        {
            var normalizedWord = word.ToLowerInvariant();

            // Skip very short words
            if (normalizedWord.Length < 2)
                continue;

            // Record term usage
            var usage = new TermUsage
            {
                Term = word,
                NormalizedTerm = normalizedWord,
                Context = context ?? category.ToString(),
                FilePath = filePath,
                Line = line,
                SymbolName = symbolName,
                SymbolCategory = category
            };

            _termUsages.AddOrUpdate(
                normalizedWord,
                _ => new List<TermUsage> { usage },
                (_, list) => { list.Add(usage); return list; });

            // Check if it's an abbreviation
            if (CommonAbbreviations.ContainsKey(word))
            {
                _abbreviationUsages.AddOrUpdate(
                    word,
                    _ => new List<TermUsage> { usage },
                    (_, list) => { list.Add(usage); return list; });
            }
        }
    }

    /// <summary>
    /// Analyzes collected terms for inconsistencies.
    /// </summary>
    public List<TermInconsistency> FindInconsistencies()
    {
        var inconsistencies = new List<TermInconsistency>();
        var processedConcepts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (term, usages) in _termUsages)
        {
            // Skip if we've already processed this concept
            if (processedConcepts.Contains(term))
                continue;

            // Find related terms (synonyms that are also used in the codebase)
            var relatedTerms = FindRelatedTermsInUsage(term);

            if (relatedTerms.Count > 0)
            {
                // Mark all related terms as processed
                processedConcepts.Add(term);
                foreach (var related in relatedTerms)
                    processedConcepts.Add(related);

                // Build list of all variant terms
                var allTerms = new List<string> { term };
                allTerms.AddRange(relatedTerms);

                // Collect all usages for these terms
                var allUsages = new List<TermUsage>();
                foreach (var t in allTerms)
                {
                    if (_termUsages.TryGetValue(t, out var termUsages))
                    {
                        allUsages.AddRange(termUsages);
                    }
                }

                if (allUsages.Count > 0)
                {
                    inconsistencies.Add(new TermInconsistency
                    {
                        Concept = InferConceptName(allTerms),
                        VariantTerms = allTerms.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                        Usages = allUsages,
                        TotalOccurrences = allUsages.Count,
                        RecommendedTerm = RecommendPreferredTerm(allTerms, allUsages),
                        Explanation = BuildInconsistencyExplanation(allTerms, allUsages)
                    });
                }
            }
        }

        return inconsistencies;
    }

    /// <summary>
    /// Analyzes abbreviation usage for consistency.
    /// </summary>
    public List<AbbreviationUsage> FindAbbreviationIssues()
    {
        var issues = new List<AbbreviationUsage>();

        foreach (var (abbr, usages) in _abbreviationUsages)
        {
            var expandedForm = CommonAbbreviations.GetValueOrDefault(abbr);

            // Check if the expanded form is also used
            var expandedUsages = new List<TermUsage>();
            if (expandedForm != null && _termUsages.TryGetValue(expandedForm.ToLowerInvariant(), out var expanded))
            {
                expandedUsages = expanded;
            }

            var inconsistentForms = new List<string>();
            var isConsistent = true;

            if (expandedUsages.Count > 0)
            {
                // Both abbreviated and expanded forms are used - inconsistent
                isConsistent = false;
                inconsistentForms.Add($"{abbr} (abbreviated, {usages.Count} uses)");
                inconsistentForms.Add($"{expandedForm} (expanded, {expandedUsages.Count} uses)");
            }

            issues.Add(new AbbreviationUsage
            {
                Abbreviation = abbr,
                ExpandedForm = expandedForm,
                Usages = usages,
                IsConsistentlyUsed = isConsistent,
                InconsistentForms = inconsistentForms
            });
        }

        // Only return issues where there's actual inconsistency
        return issues.Where(i => !i.IsConsistentlyUsed).ToList();
    }

    /// <summary>
    /// Gets term usage statistics.
    /// </summary>
    public Dictionary<string, int> GetTermFrequencies()
    {
        return _termUsages.ToDictionary(
            kvp => kvp.Key,
            kvp => kvp.Value.Count,
            StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Finds terms that might refer to the same concept.
    /// </summary>
    public List<string> FindPotentialSynonyms(string term)
    {
        var normalizedTerm = term.ToLowerInvariant();
        var synonyms = new List<string>();

        // Check if this term is in our synonym dictionary
        if (DomainConceptSynonyms.TryGetValue(normalizedTerm, out var knownSynonyms))
        {
            foreach (var synonym in knownSynonyms)
            {
                if (_termUsages.ContainsKey(synonym))
                {
                    synonyms.Add(synonym);
                }
            }
        }

        // Check if this term is a synonym of another term
        foreach (var (concept, conceptSynonyms) in DomainConceptSynonyms)
        {
            if (conceptSynonyms.Contains(normalizedTerm, StringComparer.OrdinalIgnoreCase))
            {
                if (_termUsages.ContainsKey(concept))
                {
                    synonyms.Add(concept);
                }
                foreach (var syn in conceptSynonyms)
                {
                    if (!syn.Equals(normalizedTerm, StringComparison.OrdinalIgnoreCase) &&
                        _termUsages.ContainsKey(syn))
                    {
                        synonyms.Add(syn);
                    }
                }
            }
        }

        return synonyms.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// Analyzes a namespace for term consistency.
    /// </summary>
    public List<TermInconsistency> AnalyzeNamespaceConsistency(IEnumerable<TermUsage> usages)
    {
        var namespaceTerms = new Dictionary<string, List<TermUsage>>(StringComparer.OrdinalIgnoreCase);

        foreach (var usage in usages)
        {
            var words = _rules.SplitIntoWords(usage.SymbolName);
            foreach (var word in words)
            {
                var normalized = word.ToLowerInvariant();
                if (!namespaceTerms.ContainsKey(normalized))
                {
                    namespaceTerms[normalized] = new List<TermUsage>();
                }
                namespaceTerms[normalized].Add(usage);
            }
        }

        var inconsistencies = new List<TermInconsistency>();
        var processed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (term, termUsages) in namespaceTerms)
        {
            if (processed.Contains(term))
                continue;

            var related = FindRelatedTermsInDictionary(term, namespaceTerms);
            if (related.Count > 0)
            {
                processed.Add(term);
                foreach (var r in related)
                    processed.Add(r);

                var allTerms = new List<string> { term };
                allTerms.AddRange(related);

                var allUsages = new List<TermUsage>();
                foreach (var t in allTerms)
                {
                    if (namespaceTerms.TryGetValue(t, out var tUsages))
                    {
                        allUsages.AddRange(tUsages);
                    }
                }

                inconsistencies.Add(new TermInconsistency
                {
                    Concept = InferConceptName(allTerms),
                    VariantTerms = allTerms.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                    Usages = allUsages,
                    TotalOccurrences = allUsages.Count,
                    RecommendedTerm = RecommendPreferredTerm(allTerms, allUsages),
                    Explanation = $"Inconsistent terminology within related symbols"
                });
            }
        }

        return inconsistencies;
    }

    private List<string> FindRelatedTermsInUsage(string term)
    {
        var related = new List<string>();
        var normalizedTerm = term.ToLowerInvariant();

        // Check direct synonyms
        if (DomainConceptSynonyms.TryGetValue(normalizedTerm, out var synonyms))
        {
            foreach (var syn in synonyms)
            {
                if (_termUsages.ContainsKey(syn))
                {
                    related.Add(syn);
                }
            }
        }

        // Check reverse mappings
        foreach (var (concept, conceptSynonyms) in DomainConceptSynonyms)
        {
            if (conceptSynonyms.Contains(normalizedTerm, StringComparer.OrdinalIgnoreCase))
            {
                if (!concept.Equals(normalizedTerm, StringComparison.OrdinalIgnoreCase) &&
                    _termUsages.ContainsKey(concept))
                {
                    related.Add(concept);
                }

                foreach (var syn in conceptSynonyms)
                {
                    if (!syn.Equals(normalizedTerm, StringComparison.OrdinalIgnoreCase) &&
                        _termUsages.ContainsKey(syn))
                    {
                        related.Add(syn);
                    }
                }
            }
        }

        return related.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private List<string> FindRelatedTermsInDictionary(
        string term,
        Dictionary<string, List<TermUsage>> termDict)
    {
        var related = new List<string>();
        var normalizedTerm = term.ToLowerInvariant();

        if (DomainConceptSynonyms.TryGetValue(normalizedTerm, out var synonyms))
        {
            foreach (var syn in synonyms)
            {
                if (termDict.ContainsKey(syn))
                {
                    related.Add(syn);
                }
            }
        }

        foreach (var (concept, conceptSynonyms) in DomainConceptSynonyms)
        {
            if (conceptSynonyms.Contains(normalizedTerm, StringComparer.OrdinalIgnoreCase))
            {
                if (!concept.Equals(normalizedTerm, StringComparison.OrdinalIgnoreCase) &&
                    termDict.ContainsKey(concept))
                {
                    related.Add(concept);
                }

                foreach (var syn in conceptSynonyms)
                {
                    if (!syn.Equals(normalizedTerm, StringComparison.OrdinalIgnoreCase) &&
                        termDict.ContainsKey(syn))
                    {
                        related.Add(syn);
                    }
                }
            }
        }

        return related.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private string InferConceptName(List<string> terms)
    {
        // Find the most common term as the concept name
        var mostCommon = terms
            .Select(t => (term: t, count: _termUsages.TryGetValue(t, out var usages) ? usages.Count : 0))
            .OrderByDescending(x => x.count)
            .First().term;

        return char.ToUpperInvariant(mostCommon[0]) + mostCommon.Substring(1).ToLowerInvariant();
    }

    private string? RecommendPreferredTerm(List<string> terms, List<TermUsage> usages)
    {
        // Strategy 1: Check if there's a configured preferred term
        var config = _rules.GetConfiguration();
        foreach (var equiv in config.TermEquivalences)
        {
            if (terms.Contains(equiv.PreferredTerm, StringComparer.OrdinalIgnoreCase))
            {
                return equiv.PreferredTerm;
            }

            foreach (var alt in equiv.AlternativeTerms)
            {
                if (terms.Contains(alt, StringComparer.OrdinalIgnoreCase))
                {
                    return equiv.PreferredTerm;
                }
            }
        }

        // Strategy 2: Recommend the most commonly used term
        var termCounts = terms
            .Select(t => (term: t, count: usages.Count(u => u.NormalizedTerm.Equals(t, StringComparison.OrdinalIgnoreCase))))
            .OrderByDescending(x => x.count)
            .ToList();

        if (termCounts.Count > 0 && termCounts[0].count > 0)
        {
            var preferred = termCounts[0].term;
            // Return in proper casing
            return char.ToUpperInvariant(preferred[0]) + preferred.Substring(1).ToLowerInvariant();
        }

        return null;
    }

    private string BuildInconsistencyExplanation(List<string> terms, List<TermUsage> usages)
    {
        var termStats = terms
            .Select(t => (
                term: t,
                count: usages.Count(u => u.NormalizedTerm.Equals(t, StringComparison.OrdinalIgnoreCase)),
                files: usages.Where(u => u.NormalizedTerm.Equals(t, StringComparison.OrdinalIgnoreCase))
                    .Select(u => u.FilePath)
                    .Distinct()
                    .Count()
            ))
            .Where(x => x.count > 0)
            .OrderByDescending(x => x.count)
            .ToList();

        if (termStats.Count <= 1)
            return "Terms may refer to the same concept";

        var parts = termStats.Select(s => $"'{s.term}' ({s.count} uses in {s.files} files)");
        return $"Multiple terms used for same concept: {string.Join(", ", parts)}";
    }
}
