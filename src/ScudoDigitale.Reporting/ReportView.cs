// ╔═══════════════════════════════════════════════════════════════╗
// ║   ███████╗ ██████╗██╗   ██╗██████╗  ██████╗                   ║
// ║   ██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗                  ║
// ║   ███████╗██║     ██║   ██║██║  ██║██║   ██║                  ║
// ║   ╚════██║██║     ██║   ██║██║  ██║██║   ██║                  ║
// ║   ███████║╚██████╗╚██████╔╝██████╔╝╚██████╔╝  D I G I T A L E ║
// ║   ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝                   ║
// ║   Security check: network, Wi-Fi, websites, email, Bluetooth, ║
// ║   GDPR and NIS2.   © 2026 Gaetano Cardinale — gcardinale.it   ║
// ╠═══════════════════════════════════════════════════════════════╣
// ║ SPDX-License-Identifier: AGPL-3.0-or-later                    ║
// ║ Attribution required (AGPL sec. 7(b)): see NOTICE file        ║
// ╚═══════════════════════════════════════════════════════════════╝

using ScudoDigitale.Core;
using ScudoDigitale.Reporting.Resources;

namespace ScudoDigitale.Reporting;

/// <summary>
/// What the HTML and the PDF show, already translated and formatted: both formats are drawn from the
/// same view, so they cannot say different things. The texts are plain: each format escapes them its
/// own way.
/// </summary>
/// <param name="Language">Culture name of the report, for the <c>lang</c> attribute.</param>
/// <param name="Title">Title of the report.</param>
/// <param name="Disclaimer">What the tool is not.</param>
/// <param name="Facts">Declaration, profile, targets, date and CVE database, as label and value.</param>
/// <param name="NotesHeading">Heading of the notes.</param>
/// <param name="Notes">Notes for the reader; may be empty.</param>
/// <param name="Summary">The summary.</param>
/// <param name="Sections">One per area and target.</param>
/// <param name="Footer">The attribution, on every page.</param>
/// <param name="PageNumber">"Page {0} of {1}", for the PDF.</param>
internal sealed record ReportView(
    string Language,
    string Title,
    string Disclaimer,
    IReadOnlyList<ViewFact> Facts,
    string NotesHeading,
    IReadOnlyList<string> Notes,
    ViewSummary Summary,
    IReadOnlyList<ViewSection> Sections,
    string Footer,
    string PageNumber)
{
    /// <summary>Builds the view of a document.</summary>
    /// <param name="document">The report.</param>
    /// <returns>The view, in the language of the report.</returns>
    public static ReportView Of(ReportDocument document)
    {
        var l = ReportLabels.For(document);
        var summary = ReportSummary.Of(document);
        var declaration = document.Declaration;

        ViewFact[] facts =
        [
            new(string.Empty, l.Format(nameof(Strings.DeclaredBy), declaration.OperatorName, l.Role(declaration.OperatorRole), l.Date(declaration.DeclaredAt))),
            new(l.Get(nameof(Strings.ProfileLabel)), l.Profile(document.Profile)),
            new(l.Get(nameof(Strings.TargetsLabel)), l.Targets(declaration)),
            new(string.Empty, l.Format(nameof(Strings.GeneratedOn), l.Date(document.GeneratedAt))),
            new(string.Empty, l.VulnerabilityDatabase(document)),
        ];

        var viewSummary = new ViewSummary(
            l.Get(nameof(Strings.SummaryHeading)),
            l.Get(nameof(Strings.FindingsBySeverity)),
            Enum.GetValues<Severity>().OrderDescending().Select(s => new ViewCount(l.Severity(s), summary.BySeverity[s], ReportLabels.SeverityClass(s))).ToArray(),
            l.Get(nameof(Strings.FindingsByArea)),
            summary.ByArea.Select(a => new ViewCount(l.Area(a.Area), a.Findings, string.Empty)).ToArray(),
            l.Format(nameof(Strings.ChecksCounts), summary.Passed, summary.Skipped, summary.Failed),
            l.Get(nameof(Strings.ActionsHeading)),
            summary.Actions.Select(f => new ViewAction(l.Severity(f.EffectiveSeverity), ReportLabels.SeverityClass(f.EffectiveSeverity), f.Title, f.Target, f.Fix)).ToArray(),
            l.Get(nameof(Strings.NoActions)));

        return new ReportView(
            document.Language,
            l.Get(nameof(Strings.ReportTitle)),
            l.Get(nameof(Strings.Disclaimer)),
            facts,
            l.Get(nameof(Strings.NotesHeading)),
            document.Notes,
            viewSummary,
            document.Sections.Select(s => Section(s, l)).ToArray(),
            Attribution.ReportFooter(document.ProgramVersion, l.Culture),
            l.Get(nameof(Strings.PageNumber)));
    }

    private static ViewSection Section(ReportSection section, ReportLabels l)
    {
        ViewList[] lists =
        [
            new(l.Get(nameof(Strings.ChecksPassed)), "passed", section.Passed),
            new(l.Get(nameof(Strings.ChecksSkipped)), "skipped", section.Skipped),
            new(l.Get(nameof(Strings.ChecksFailed)), "failed", section.Failed),
        ];

        return new ViewSection(
            l.SectionHeading(section),
            ReportLabels.SaysNoProblems(section) ? l.Get(nameof(Strings.NoProblems)) : null,
            l.Get(nameof(Strings.ProblemsFound)),
            section.Findings.Select(f => Finding(f, l)).ToArray(),
            lists.Where(x => x.Items.Count > 0).ToArray());
    }

    private static ViewFinding Finding(ReportFinding f, ReportLabels l)
    {
        var details = new List<ViewFact>();
        void Add(string label, string? value)
        {
            if (!string.IsNullOrWhiteSpace(value))
            {
                details.Add(new ViewFact(l.Get(label), value));
            }
        }

        Add(nameof(Strings.EvidenceLabel), f.Evidence);
        Add(nameof(Strings.RiskLabel), f.Risk);
        Add(nameof(Strings.FixLabel), f.Fix);
        Add(nameof(Strings.ConfidenceLabel), l.Confidence(f.Confidence));
        Add(nameof(Strings.CveLabel), string.Join(", ", f.Cve));
        Add(nameof(Strings.CvssLabel), f.Cvss?.ToString("0.0", l.Culture));
        Add(nameof(Strings.EpssLabel), f.Epss?.ToString("0.###", l.Culture));
        Add(nameof(Strings.ReferencesLabel), string.Join(", ", f.References));

        var notes = new List<string>();
        if (f.Kev)
        {
            notes.Add(l.Get(nameof(Strings.KevNote)));
        }

        if (f.Severity != f.EffectiveSeverity)
        {
            notes.Add(l.Format(nameof(Strings.SeverityRaised), l.Severity(f.Severity)));
        }

        return new ViewFinding(l.Severity(f.EffectiveSeverity), ReportLabels.SeverityClass(f.EffectiveSeverity), f.Id, f.Title, f.Target, details, notes);
    }
}

/// <summary>A label and its value; the label may be empty for a sentence that stands alone.</summary>
/// <param name="Label">The label.</param>
/// <param name="Value">The value.</param>
internal sealed record ViewFact(string Label, string Value);

/// <summary>The summary, translated.</summary>
/// <param name="Heading">Heading of the summary.</param>
/// <param name="SeverityHeading">Heading of the counts by severity.</param>
/// <param name="Severities">Counts by severity, Critical to Info.</param>
/// <param name="AreaHeading">Heading of the counts by area.</param>
/// <param name="Areas">Counts by area.</param>
/// <param name="Checks">Checks passed, skipped and failed, in one sentence.</param>
/// <param name="ActionsHeading">Heading of the most urgent actions.</param>
/// <param name="Actions">The most urgent actions; may be empty.</param>
/// <param name="NoActions">What to say when there is no action.</param>
internal sealed record ViewSummary(
    string Heading,
    string SeverityHeading,
    IReadOnlyList<ViewCount> Severities,
    string AreaHeading,
    IReadOnlyList<ViewCount> Areas,
    string Checks,
    string ActionsHeading,
    IReadOnlyList<ViewAction> Actions,
    string NoActions);

/// <summary>A count with its label.</summary>
/// <param name="Label">The label.</param>
/// <param name="Count">The number.</param>
/// <param name="Class">CSS class of a severity, or empty.</param>
internal sealed record ViewCount(string Label, int Count, string Class);

/// <summary>One of the most urgent actions.</summary>
/// <param name="Severity">Label of the effective severity.</param>
/// <param name="Class">CSS class of the severity.</param>
/// <param name="Title">Title of the finding.</param>
/// <param name="Target">What it refers to.</param>
/// <param name="Fix">How to fix it, if known.</param>
internal sealed record ViewAction(string Severity, string Class, string Title, string Target, string? Fix);

/// <summary>A section, translated.</summary>
/// <param name="Heading">Area, and target when there is one.</param>
/// <param name="NoProblems">"No problems found", only when something was checked; otherwise <see langword="null"/>.</param>
/// <param name="ProblemsHeading">Heading of the findings.</param>
/// <param name="Findings">The findings, most urgent first.</param>
/// <param name="Lists">Checks passed, skipped and failed; empty lists are left out.</param>
internal sealed record ViewSection(string Heading, string? NoProblems, string ProblemsHeading, IReadOnlyList<ViewFinding> Findings, IReadOnlyList<ViewList> Lists);

/// <summary>A finding, translated.</summary>
/// <param name="Severity">Label of the effective severity.</param>
/// <param name="Class">CSS class of the severity.</param>
/// <param name="Id">Check id.</param>
/// <param name="Title">Title.</param>
/// <param name="Target">What it refers to.</param>
/// <param name="Details">Evidence, risk, fix, confidence, CVE, CVSS, EPSS, references; empty ones left out.</param>
/// <param name="Notes">KEV and raised severity, when they apply.</param>
internal sealed record ViewFinding(string Severity, string Class, string Id, string Title, string Target, IReadOnlyList<ViewFact> Details, IReadOnlyList<string> Notes);

/// <summary>A list of checks that produced no findings.</summary>
/// <param name="Heading">Passed, skipped or failed.</param>
/// <param name="Kind"><c>passed</c>, <c>skipped</c> or <c>failed</c>, used as CSS class.</param>
/// <param name="Items">The checks.</param>
internal sealed record ViewList(string Heading, string Kind, IReadOnlyList<ReportCheck> Items);
