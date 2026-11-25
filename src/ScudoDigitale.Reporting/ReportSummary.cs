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

namespace ScudoDigitale.Reporting;

/// <summary>
/// The summary at the top of the report (spec §4): findings by severity and by area, checks passed,
/// skipped and failed, and the most urgent actions. Computed from the document, never stored in it,
/// so it cannot disagree with the sections.
/// </summary>
public sealed record ReportSummary
{
    /// <summary>How many actions the summary lists at most.</summary>
    public const int MaxActions = 5;

    private ReportSummary(
        IReadOnlyDictionary<Severity, int> bySeverity,
        IReadOnlyList<(CheckArea Area, int Findings)> byArea,
        int passed,
        int skipped,
        int failed,
        IReadOnlyList<ReportFinding> actions)
    {
        BySeverity = bySeverity;
        ByArea = byArea;
        Passed = passed;
        Skipped = skipped;
        Failed = failed;
        Actions = actions;
    }

    /// <summary>Number of findings for every severity, Critical to Info; a severity with no findings has 0.</summary>
    public IReadOnlyDictionary<Severity, int> BySeverity { get; }

    /// <summary>Number of findings in every area present in the report, in the order of the sections.</summary>
    public IReadOnlyList<(CheckArea Area, int Findings)> ByArea { get; }

    /// <summary>Checks or questions that raised no problem.</summary>
    public int Passed { get; }

    /// <summary>Checks that could not run here.</summary>
    public int Skipped { get; }

    /// <summary>Checks that failed.</summary>
    public int Failed { get; }

    /// <summary>
    /// The most urgent findings of the whole report, at most <see cref="MaxActions"/>, most urgent first.
    /// Informational findings are not actions and never appear here.
    /// </summary>
    public IReadOnlyList<ReportFinding> Actions { get; }

    /// <summary>Total number of findings.</summary>
    public int Findings => BySeverity.Values.Sum();

    /// <summary>Computes the summary of a document.</summary>
    /// <param name="document">The report.</param>
    /// <returns>The summary.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="document"/> is <see langword="null"/>.</exception>
    public static ReportSummary Of(ReportDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        var findings = document.Sections.SelectMany(s => s.Findings).ToArray();
        var bySeverity = Enum.GetValues<Severity>()
            .OrderDescending()
            .ToDictionary(s => s, s => findings.Count(f => f.EffectiveSeverity == s));
        var byArea = document.Sections
            .GroupBy(s => s.Area)
            .Select(g => (g.Key, g.Sum(s => s.Findings.Count)))
            .ToArray();

        // The same total order as FindingPrioritizer, which sorted every section.
        var actions = findings
            .Where(f => f.EffectiveSeverity > Severity.Info)
            .OrderByDescending(f => f.Kev)
            .ThenByDescending(f => f.EffectiveSeverity)
            .ThenByDescending(f => f.Epss ?? -1.0)
            .ThenByDescending(f => f.Confidence)
            .ThenBy(f => f.Id, StringComparer.Ordinal)
            .ThenBy(f => f.Target, StringComparer.Ordinal)
            .Take(MaxActions)
            .ToArray();

        return new ReportSummary(
            bySeverity,
            byArea,
            document.Sections.Sum(s => s.Passed.Count),
            document.Sections.Sum(s => s.Skipped.Count),
            document.Sections.Sum(s => s.Failed.Count),
            actions);
    }
}
