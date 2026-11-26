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

using System.Globalization;
using ScudoDigitale.Core;

namespace ScudoDigitale.Reporting;

/// <summary>
/// Turns what the engine and the questionnaires returned into a <see cref="ReportDocument"/>:
/// one section per area and target, findings most urgent first (<see cref="FindingPrioritizer"/>),
/// and every check that passed, was skipped or failed, so that nothing is left out silently.
/// </summary>
public static class ReportBuilder
{
    /// <summary>Builds the report of an assessment.</summary>
    /// <param name="scope">The declaration: operator, role, date and targets (their order is the order of the sections).</param>
    /// <param name="profile">Who the assessment is for.</param>
    /// <param name="runs">What the engine returned.</param>
    /// <param name="programVersion">Version of the program, for example <c>0.1.0</c>.</param>
    /// <param name="generatedAt">When the report is generated.</param>
    /// <param name="notes">Things the reader must know to interpret the results; blank notes are ignored.</param>
    /// <param name="questionnaires">Sections made by <see cref="QuestionnaireSection"/>, if any.</param>
    /// <returns>The report, in the current UI language.</returns>
    /// <exception cref="ArgumentNullException">An argument or an item of a list is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="programVersion"/> is empty or blank.</exception>
    public static ReportDocument Build(
        ScopeDeclaration scope,
        Profile profile,
        IEnumerable<CheckRun> runs,
        string programVersion,
        DateTimeOffset generatedAt,
        IEnumerable<string>? notes = null,
        IEnumerable<ReportSection>? questionnaires = null)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(runs);
        ArgumentException.ThrowIfNullOrWhiteSpace(programVersion);
        var runList = NotNull(runs, nameof(runs));
        var extra = NotNull(questionnaires ?? [], nameof(questionnaires));

        var order = scope.Targets.Select((target, index) => (target, index)).ToDictionary(p => p.target, p => p.index);
        var technical = runList
            .GroupBy(r => (r.Area, r.Target))
            .OrderBy(g => g.Key.Area)
            .ThenBy(g => order.GetValueOrDefault(g.Key.Target, int.MaxValue))
            .Select(g => Section(g.Key.Area, g.Key.Target.Value, g.ToArray()));

        // OrderBy is stable: in the same area the technical sections stay before the questionnaires.
        var sections = technical.Concat(extra).OrderBy(s => s.Area).ToArray();

        return new ReportDocument
        {
            ProgramVersion = programVersion.Trim(),
            GeneratedAt = generatedAt,
            Language = LanguageOf(CultureInfo.CurrentUICulture),
            Declaration = new ReportDeclaration
            {
                OperatorName = scope.OperatorName,
                OperatorRole = scope.OperatorRole,
                DeclaredAt = scope.DeclaredAt,
                Targets = scope.Targets.Select(t => new ReportTarget(t.Kind, t.Value)).ToArray(),
            },
            Profile = new ReportProfile
            {
                Kind = profile.Kind,
                CompanyName = profile.CompanyName,
                VatNumber = profile.VatNumber,
                AtecoCode = profile.AtecoCode,
                Employees = profile.Employees,
                AnnualTurnoverEur = profile.AnnualTurnoverEur,
            },
            Notes = (notes ?? []).Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()).ToArray(),
            Sections = sections,
        };
    }

    /// <summary>
    /// The section of a questionnaire: its findings most urgent first, and the questions whose answer
    /// raised no problem.
    /// </summary>
    /// <param name="area">The area of the questionnaire, for example <see cref="CheckArea.Gdpr"/>.</param>
    /// <param name="findings">The findings of the answers.</param>
    /// <param name="passed">The questions answered without problems, with the id and text of each.</param>
    /// <returns>The section, with no target.</returns>
    /// <exception cref="ArgumentNullException">A list or one of its items is <see langword="null"/>.</exception>
    public static ReportSection QuestionnaireSection(CheckArea area, IEnumerable<Finding> findings, IEnumerable<ReportCheck> passed)
    {
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(passed);
        return new ReportSection
        {
            Area = area,
            Findings = Prioritized(NotNull(findings, nameof(findings))),
            Passed = NotNull(passed, nameof(passed)),
        };
    }

    /// <summary>
    /// The culture name written in the report. The invariant culture has no name and becomes
    /// <c>en</c>, the language of the texts in the program.
    /// </summary>
    /// <param name="culture">The culture.</param>
    /// <returns>Its name, or <c>en</c>.</returns>
    internal static string LanguageOf(CultureInfo culture) => culture.Name.Length == 0 ? "en" : culture.Name;

    private static ReportSection Section(CheckArea area, string target, CheckRun[] runs) => new()
    {
        Area = area,
        Target = target,
        Findings = Prioritized(runs.Select(r => r.Result).OfType<CheckResult.Executed>().SelectMany(r => r.Findings)),
        Passed = runs.Where(r => r.Result is CheckResult.Executed { Findings.Count: 0 }).Select(r => new ReportCheck(r.CheckId, r.CheckTitle)).ToArray(),
        Skipped = runs.Where(r => r.Result is CheckResult.Skipped).Select(r => new ReportCheck(r.CheckId, r.CheckTitle, ((CheckResult.Skipped)r.Result).Reason)).ToArray(),
        Failed = runs.Where(r => r.Result is CheckResult.Failed).Select(r => new ReportCheck(r.CheckId, r.CheckTitle, ((CheckResult.Failed)r.Result).Error)).ToArray(),
    };

    private static ReportFinding[] Prioritized(IEnumerable<Finding> findings) =>
        FindingPrioritizer.Prioritize(findings).Select(p => new ReportFinding
        {
            Id = p.Finding.Id,
            Area = p.Finding.Area,
            Title = p.Finding.Title,
            Severity = p.Finding.Severity,
            EffectiveSeverity = p.EffectiveSeverity,
            Confidence = p.Finding.Confidence,
            Target = p.Finding.Target,
            Evidence = p.Finding.Evidence,
            Cve = p.Finding.Cve,
            Cvss = p.Finding.Cvss,
            Epss = p.Finding.Epss,
            Kev = p.Finding.Kev,
            Risk = p.Finding.Risk,
            Fix = p.Finding.Fix,
            References = p.Finding.References,
        }).ToArray();

    private static T[] NotNull<T>(IEnumerable<T> items, string name)
        where T : class
    {
        var list = items.ToArray();
        return list.Any(i => i is null) ? throw new ArgumentNullException(name, "An item is null.") : list;
    }
}
