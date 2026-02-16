using System.Text;
using System.Web;
using BaseScanner.Reporting.Models;

namespace BaseScanner.Reporting;

/// <summary>
/// Generates comprehensive HTML reports with interactive dashboards for analysis results.
/// Includes summary metrics, issue breakdowns, file-by-file analysis, and trend charts.
/// </summary>
public class HtmlReporter : IReporter
{
    /// <inheritdoc />
    public Task<string> GenerateAsync(ReportData data, ReportOptions options)
    {
        var sb = new StringBuilder();

        AppendHtmlHeader(sb, data, options);
        AppendNavigation(sb);
        AppendSummaryDashboard(sb, data);
        AppendSeverityBreakdown(sb, data);
        AppendCategoryBreakdown(sb, data);
        AppendFileBreakdown(sb, data, options);
        AppendIssueDetails(sb, data, options);

        if (options.IncludeHistory && data.History.Any())
        {
            AppendTrendCharts(sb, data);
        }

        AppendFooter(sb, data);
        AppendHtmlFooter(sb);

        return Task.FromResult(sb.ToString());
    }

    /// <inheritdoc />
    public async Task WriteAsync(ReportData data, ReportOptions options, string outputPath)
    {
        var content = await GenerateAsync(data, options);
        await File.WriteAllTextAsync(outputPath, content, Encoding.UTF8);
    }

    private void AppendHtmlHeader(StringBuilder sb, ReportData data, ReportOptions options)
    {
        var title = HttpUtility.HtmlEncode(options.Title);
        var projectName = HttpUtility.HtmlEncode(data.Project.Name);

        sb.AppendLine(@"<!DOCTYPE html>
<html lang=""en"">
<head>
    <meta charset=""UTF-8"">
    <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"">");
        sb.AppendLine($@"    <title>{title} - {projectName}</title>");
        sb.AppendLine(@"    <style>
        :root {
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --bg-card: #0f3460;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #e94560;
            --success: #00d26a;
            --warning: #ffc107;
            --error: #ff6b6b;
            --info: #17a2b8;
            --critical: #dc3545;
            --border: #333;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        header {
            background: var(--bg-secondary);
            padding: 20px;
            border-bottom: 2px solid var(--accent);
            margin-bottom: 30px;
        }

        header h1 {
            color: var(--accent);
            font-size: 2rem;
            margin-bottom: 5px;
        }

        header .subtitle {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        nav {
            background: var(--bg-secondary);
            padding: 10px 20px;
            position: sticky;
            top: 0;
            z-index: 100;
            border-bottom: 1px solid var(--border);
        }

        nav a {
            color: var(--text-primary);
            text-decoration: none;
            padding: 8px 16px;
            margin-right: 5px;
            border-radius: 4px;
            transition: background 0.2s;
        }

        nav a:hover {
            background: var(--bg-card);
        }

        section {
            margin-bottom: 40px;
            scroll-margin-top: 60px;
        }

        section h2 {
            color: var(--accent);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border);
        }

        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .metric-card {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            transition: transform 0.2s;
        }

        .metric-card:hover {
            transform: translateY(-5px);
        }

        .metric-card .value {
            font-size: 2.5rem;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .metric-card .label {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }

        .metric-card.error .value { color: var(--error); }
        .metric-card.warning .value { color: var(--warning); }
        .metric-card.success .value { color: var(--success); }
        .metric-card.info .value { color: var(--info); }

        .score-ring {
            width: 120px;
            height: 120px;
            margin: 0 auto 10px;
            position: relative;
        }

        .score-ring svg {
            transform: rotate(-90deg);
        }

        .score-ring circle {
            fill: none;
            stroke-width: 10;
        }

        .score-ring .bg {
            stroke: var(--border);
        }

        .score-ring .progress {
            stroke-linecap: round;
            transition: stroke-dashoffset 1s ease-out;
        }

        .score-ring .score-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 1.5rem;
            font-weight: bold;
        }

        .chart-container {
            background: var(--bg-card);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }

        .bar-chart {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .bar-row {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .bar-label {
            width: 150px;
            font-size: 0.9rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .bar-track {
            flex: 1;
            height: 25px;
            background: var(--border);
            border-radius: 4px;
            overflow: hidden;
        }

        .bar-fill {
            height: 100%;
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 10px;
            font-size: 0.8rem;
            font-weight: bold;
            transition: width 0.5s ease-out;
        }

        .bar-fill.critical { background: var(--critical); }
        .bar-fill.error { background: var(--error); }
        .bar-fill.warning { background: var(--warning); }
        .bar-fill.info { background: var(--info); }
        .bar-fill.default { background: var(--accent); }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-card);
            border-radius: 10px;
            overflow: hidden;
        }

        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }

        th {
            background: var(--bg-secondary);
            color: var(--accent);
            font-weight: 600;
        }

        tr:hover {
            background: rgba(233, 69, 96, 0.1);
        }

        .severity-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }

        .severity-critical { background: var(--critical); color: white; }
        .severity-error { background: var(--error); color: white; }
        .severity-warning { background: var(--warning); color: black; }
        .severity-note { background: var(--info); color: white; }

        .issue-card {
            background: var(--bg-card);
            border-radius: 10px;
            margin-bottom: 15px;
            overflow: hidden;
            border-left: 4px solid var(--border);
        }

        .issue-card.critical { border-left-color: var(--critical); }
        .issue-card.error { border-left-color: var(--error); }
        .issue-card.warning { border-left-color: var(--warning); }
        .issue-card.note { border-left-color: var(--info); }

        .issue-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            cursor: pointer;
            background: var(--bg-secondary);
        }

        .issue-header:hover {
            background: rgba(233, 69, 96, 0.1);
        }

        .issue-title {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .issue-location {
            color: var(--text-secondary);
            font-size: 0.85rem;
        }

        .issue-body {
            padding: 15px;
            display: none;
        }

        .issue-body.expanded {
            display: block;
        }

        .code-snippet {
            background: #0d0d0d;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9rem;
            margin: 10px 0;
        }

        .code-snippet .line-number {
            color: var(--text-secondary);
            margin-right: 15px;
            user-select: none;
        }

        .code-snippet .highlight {
            background: rgba(233, 69, 96, 0.3);
            display: inline-block;
            width: 100%;
        }

        .fix-suggestion {
            background: rgba(0, 210, 106, 0.1);
            border: 1px solid var(--success);
            border-radius: 5px;
            padding: 15px;
            margin-top: 15px;
        }

        .fix-suggestion h4 {
            color: var(--success);
            margin-bottom: 10px;
        }

        .data-flow {
            margin-top: 15px;
        }

        .data-flow-step {
            display: flex;
            align-items: flex-start;
            gap: 15px;
            padding: 10px;
            border-left: 2px solid var(--border);
            margin-left: 10px;
        }

        .data-flow-step .step-number {
            background: var(--accent);
            color: white;
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
            flex-shrink: 0;
        }

        .trend-chart {
            height: 200px;
            display: flex;
            align-items: flex-end;
            justify-content: space-around;
            gap: 5px;
            padding: 20px;
        }

        .trend-bar {
            width: 30px;
            background: var(--accent);
            border-radius: 4px 4px 0 0;
            transition: height 0.5s ease-out;
            position: relative;
        }

        .trend-bar:hover::after {
            content: attr(data-value);
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: var(--bg-secondary);
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            white-space: nowrap;
        }

        footer {
            background: var(--bg-secondary);
            padding: 20px;
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 40px;
        }

        .toggle-btn {
            background: var(--accent);
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: background 0.2s;
        }

        .toggle-btn:hover {
            background: #c73e54;
        }

        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: repeat(2, 1fr);
            }

            nav {
                overflow-x: auto;
                white-space: nowrap;
            }

            .bar-label {
                width: 100px;
            }
        }
    </style>
</head>
<body>");
    }

    private void AppendNavigation(StringBuilder sb)
    {
        sb.AppendLine(@"
    <nav>
        <div class=""container"">
            <a href=""#summary"">Summary</a>
            <a href=""#severity"">By Severity</a>
            <a href=""#category"">By Category</a>
            <a href=""#files"">By File</a>
            <a href=""#issues"">All Issues</a>
            <a href=""#trends"">Trends</a>
        </div>
    </nav>");
    }

    private void AppendSummaryDashboard(StringBuilder sb, ReportData data)
    {
        var qualityColor = data.Summary.QualityScore >= 80 ? "success" :
                           data.Summary.QualityScore >= 60 ? "warning" : "error";
        var securityColor = data.Summary.SecurityScore >= 80 ? "success" :
                            data.Summary.SecurityScore >= 60 ? "warning" : "error";

        sb.AppendLine(@"
    <header>
        <div class=""container"">");
        sb.AppendLine($@"            <h1>{HttpUtility.HtmlEncode(data.Project.Name)} - Code Analysis Report</h1>
            <p class=""subtitle"">Generated on {data.AnalysisTimestamp:MMMM dd, yyyy 'at' HH:mm:ss} UTC</p>");
        sb.AppendLine(@"        </div>
    </header>

    <div class=""container"">
        <section id=""summary"">
            <h2>Summary Dashboard</h2>
            <div class=""dashboard"">");

        // Quality Score
        sb.AppendLine($@"
                <div class=""metric-card {qualityColor}"">
                    <div class=""score-ring"">
                        <svg width=""120"" height=""120"">
                            <circle class=""bg"" cx=""60"" cy=""60"" r=""50""></circle>
                            <circle class=""progress"" cx=""60"" cy=""60"" r=""50""
                                stroke=""var(--{qualityColor})""
                                stroke-dasharray=""{data.Summary.QualityScore * 3.14:F0} 314""
                            ></circle>
                        </svg>
                        <span class=""score-text"">{data.Summary.QualityScore:F0}</span>
                    </div>
                    <div class=""label"">Quality Score</div>
                </div>");

        // Security Score
        sb.AppendLine($@"
                <div class=""metric-card {securityColor}"">
                    <div class=""score-ring"">
                        <svg width=""120"" height=""120"">
                            <circle class=""bg"" cx=""60"" cy=""60"" r=""50""></circle>
                            <circle class=""progress"" cx=""60"" cy=""60"" r=""50""
                                stroke=""var(--{securityColor})""
                                stroke-dasharray=""{data.Summary.SecurityScore * 3.14:F0} 314""
                            ></circle>
                        </svg>
                        <span class=""score-text"">{data.Summary.SecurityScore:F0}</span>
                    </div>
                    <div class=""label"">Security Score</div>
                </div>");

        // Other metrics
        sb.AppendLine($@"
                <div class=""metric-card"">
                    <div class=""value"">{data.Summary.TotalIssues}</div>
                    <div class=""label"">Total Issues</div>
                </div>

                <div class=""metric-card error"">
                    <div class=""value"">{data.Summary.ErrorCount}</div>
                    <div class=""label"">Errors</div>
                </div>

                <div class=""metric-card warning"">
                    <div class=""value"">{data.Summary.WarningCount}</div>
                    <div class=""label"">Warnings</div>
                </div>

                <div class=""metric-card info"">
                    <div class=""value"">{data.Summary.FilesAnalyzed}</div>
                    <div class=""label"">Files Analyzed</div>
                </div>

                <div class=""metric-card"">
                    <div class=""value"">{data.Summary.FilesWithIssues}</div>
                    <div class=""label"">Files with Issues</div>
                </div>

                <div class=""metric-card"">
                    <div class=""value"">{data.Summary.AnalysisDurationMs}ms</div>
                    <div class=""label"">Analysis Duration</div>
                </div>
            </div>
        </section>");
    }

    private void AppendSeverityBreakdown(StringBuilder sb, ReportData data)
    {
        var total = Math.Max(1, data.Summary.TotalIssues);

        sb.AppendLine(@"
        <section id=""severity"">
            <h2>Issues by Severity</h2>
            <div class=""chart-container"">
                <div class=""bar-chart"">");

        var severityCounts = new[]
        {
            ("Critical", data.Issues.Count(i => i.Severity == IssueSeverity.Critical), "critical"),
            ("Error", data.Issues.Count(i => i.Severity == IssueSeverity.Error), "error"),
            ("Warning", data.Issues.Count(i => i.Severity == IssueSeverity.Warning), "warning"),
            ("Note", data.Issues.Count(i => i.Severity == IssueSeverity.Note), "info")
        };

        foreach (var (label, count, cssClass) in severityCounts)
        {
            var percentage = (int)(100.0 * count / total);
            sb.AppendLine($@"
                    <div class=""bar-row"">
                        <span class=""bar-label"">{label}</span>
                        <div class=""bar-track"">
                            <div class=""bar-fill {cssClass}"" style=""width: {percentage}%"">{count}</div>
                        </div>
                    </div>");
        }

        sb.AppendLine(@"
                </div>
            </div>
        </section>");
    }

    private void AppendCategoryBreakdown(StringBuilder sb, ReportData data)
    {
        if (!data.Summary.IssuesByCategory.Any())
        {
            return;
        }

        var maxCount = data.Summary.IssuesByCategory.Values.Max();
        var sortedCategories = data.Summary.IssuesByCategory
            .OrderByDescending(c => c.Value)
            .Take(10);

        sb.AppendLine(@"
        <section id=""category"">
            <h2>Issues by Category</h2>
            <div class=""chart-container"">
                <div class=""bar-chart"">");

        foreach (var category in sortedCategories)
        {
            var percentage = (int)(100.0 * category.Value / maxCount);
            sb.AppendLine($@"
                    <div class=""bar-row"">
                        <span class=""bar-label"">{HttpUtility.HtmlEncode(category.Key)}</span>
                        <div class=""bar-track"">
                            <div class=""bar-fill default"" style=""width: {percentage}%"">{category.Value}</div>
                        </div>
                    </div>");
        }

        sb.AppendLine(@"
                </div>
            </div>
        </section>");
    }

    private void AppendFileBreakdown(StringBuilder sb, ReportData data, ReportOptions options)
    {
        var topFiles = data.Summary.IssuesByFile
            .OrderByDescending(f => f.Value)
            .Take(20)
            .ToList();

        if (!topFiles.Any())
        {
            return;
        }

        sb.AppendLine(@"
        <section id=""files"">
            <h2>Files with Most Issues</h2>
            <table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Issues</th>
                        <th>Errors</th>
                        <th>Warnings</th>
                    </tr>
                </thead>
                <tbody>");

        foreach (var file in topFiles)
        {
            var fileIssues = data.Issues.Where(i => i.Location.RelativePath == file.Key).ToList();
            var errors = fileIssues.Count(i => i.Severity >= IssueSeverity.Error);
            var warnings = fileIssues.Count(i => i.Severity == IssueSeverity.Warning);

            sb.AppendLine($@"
                    <tr>
                        <td><code>{HttpUtility.HtmlEncode(file.Key)}</code></td>
                        <td>{file.Value}</td>
                        <td><span class=""severity-badge severity-error"">{errors}</span></td>
                        <td><span class=""severity-badge severity-warning"">{warnings}</span></td>
                    </tr>");
        }

        sb.AppendLine(@"
                </tbody>
            </table>
        </section>");
    }

    private void AppendIssueDetails(StringBuilder sb, ReportData data, ReportOptions options)
    {
        var issues = data.Issues
            .Where(i => i.Severity >= options.MinSeverity)
            .OrderByDescending(i => i.Severity)
            .ThenBy(i => i.Location.FilePath)
            .Take(options.MaxIssues)
            .ToList();

        sb.AppendLine(@"
        <section id=""issues"">
            <h2>All Issues</h2>");

        var issueId = 0;
        foreach (var issue in issues)
        {
            var severityClass = issue.Severity.ToString().ToLower();
            var severityBadgeClass = $"severity-{severityClass}";
            var fileName = Path.GetFileName(issue.Location.FilePath);

            sb.AppendLine($@"
            <div class=""issue-card {severityClass}"">
                <div class=""issue-header"" onclick=""toggleIssue({issueId})"">
                    <div class=""issue-title"">
                        <span class=""severity-badge {severityBadgeClass}"">{issue.Severity}</span>
                        <strong>{HttpUtility.HtmlEncode(issue.RuleId)}</strong>
                        <span>{HttpUtility.HtmlEncode(issue.Message)}</span>
                    </div>
                    <div class=""issue-location"">
                        {HttpUtility.HtmlEncode(fileName)}:{issue.Location.StartLine}
                    </div>
                </div>
                <div class=""issue-body"" id=""issue-{issueId}"">");

            // Description
            if (!string.IsNullOrEmpty(issue.Description))
            {
                sb.AppendLine($@"
                    <p>{HttpUtility.HtmlEncode(issue.Description)}</p>");
            }

            // CWE reference
            if (!string.IsNullOrEmpty(issue.CweId))
            {
                sb.AppendLine($@"
                    <p><strong>CWE:</strong> <a href=""https://cwe.mitre.org/data/definitions/{issue.CweId.Replace("CWE-", "")}.html"" target=""_blank"">{issue.CweId}</a></p>");
            }

            // Code snippet
            if (options.IncludeSnippets && !string.IsNullOrEmpty(issue.Location.Snippet))
            {
                sb.AppendLine($@"
                    <div class=""code-snippet"">
                        <span class=""line-number"">{issue.Location.StartLine}</span><span class=""highlight"">{HttpUtility.HtmlEncode(issue.Location.Snippet)}</span>
                    </div>");
            }

            // Data flow
            if (options.IncludeCodeFlows && issue.CodeFlow.Any())
            {
                sb.AppendLine(@"
                    <div class=""data-flow"">
                        <h4>Data Flow</h4>");

                foreach (var step in issue.CodeFlow)
                {
                    sb.AppendLine($@"
                        <div class=""data-flow-step"">
                            <span class=""step-number"">{step.Step}</span>
                            <div>
                                <strong>{step.Kind}</strong>: {HttpUtility.HtmlEncode(step.Message)}<br>
                                <small>{HttpUtility.HtmlEncode(Path.GetFileName(step.Location.FilePath))}:{step.Location.StartLine}</small>
                            </div>
                        </div>");
                }

                sb.AppendLine(@"
                    </div>");
            }

            // Fix suggestion
            if (options.IncludeFixes && issue.Fix != null)
            {
                sb.AppendLine($@"
                    <div class=""fix-suggestion"">
                        <h4>Suggested Fix</h4>
                        <p>{HttpUtility.HtmlEncode(issue.Fix.Description)}</p>
                    </div>");
            }

            sb.AppendLine(@"
                </div>
            </div>");

            issueId++;
        }

        sb.AppendLine(@"
        </section>");
    }

    private void AppendTrendCharts(StringBuilder sb, ReportData data)
    {
        if (!data.History.Any())
        {
            return;
        }

        var recentHistory = data.History
            .OrderBy(h => h.Timestamp)
            .TakeLast(10)
            .ToList();

        var maxIssues = recentHistory.Max(h => h.Summary.TotalIssues);
        maxIssues = Math.Max(maxIssues, 1);

        sb.AppendLine(@"
        <section id=""trends"">
            <h2>Issue Trends</h2>
            <div class=""chart-container"">
                <div class=""trend-chart"">");

        foreach (var snapshot in recentHistory)
        {
            var height = (int)(180.0 * snapshot.Summary.TotalIssues / maxIssues);
            var label = snapshot.Timestamp.ToString("MM/dd");
            sb.AppendLine($@"
                    <div class=""trend-bar"" style=""height: {height}px"" data-value=""{snapshot.Summary.TotalIssues} issues on {label}"" title=""{label}: {snapshot.Summary.TotalIssues} issues""></div>");
        }

        sb.AppendLine(@"
                </div>
            </div>
        </section>");
    }

    private void AppendFooter(StringBuilder sb, ReportData data)
    {
        sb.AppendLine($@"
    </div>

    <footer>
        <p>Generated by <strong>BaseScanner</strong> v1.0.0</p>
        <p>Project: {HttpUtility.HtmlEncode(data.Project.Name)} | Commit: {data.Project.CommitHash} | Branch: {data.Project.Branch}</p>
        <p>{data.AnalysisTimestamp:yyyy-MM-dd HH:mm:ss} UTC</p>
    </footer>");
    }

    private void AppendHtmlFooter(StringBuilder sb)
    {
        sb.AppendLine(@"
    <script>
        function toggleIssue(id) {
            const body = document.getElementById('issue-' + id);
            body.classList.toggle('expanded');
        }

        // Animate score rings on load
        document.addEventListener('DOMContentLoaded', function() {
            const progressCircles = document.querySelectorAll('.score-ring .progress');
            progressCircles.forEach(circle => {
                const value = circle.getAttribute('stroke-dasharray').split(' ')[0];
                circle.style.strokeDashoffset = 314;
                setTimeout(() => {
                    circle.style.strokeDashoffset = 314 - parseFloat(value);
                }, 100);
            });

            // Animate bars
            const bars = document.querySelectorAll('.bar-fill');
            bars.forEach(bar => {
                const width = bar.style.width;
                bar.style.width = '0';
                setTimeout(() => {
                    bar.style.width = width;
                }, 100);
            });
        });
    </script>
</body>
</html>");
    }
}
