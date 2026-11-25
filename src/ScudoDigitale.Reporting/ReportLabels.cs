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
using ScudoDigitale.Reporting.Resources;

namespace ScudoDigitale.Reporting;

/// <summary>
/// The labels of a report in the language of its <see cref="ReportDocument.Language"/>, whatever the
/// language of the computer that renders it: the findings were written in that language, and the
/// headings must match them.
/// </summary>
internal sealed class ReportLabels
{
    private ReportLabels(CultureInfo culture) => Culture = culture;

    /// <summary>The culture of the report, also used for dates and numbers.</summary>
    public CultureInfo Culture { get; }

    /// <summary>The labels for a document.</summary>
    /// <param name="document">The report.</param>
    /// <returns>Labels in its language; English when the language is unknown to the platform.</returns>
    public static ReportLabels For(ReportDocument document)
    {
        try
        {
            return new ReportLabels(CultureInfo.GetCultureInfo(document.Language));
        }
        catch (CultureNotFoundException)
        {
            return new ReportLabels(CultureInfo.GetCultureInfo("en"));
        }
    }

    /// <summary>A label.</summary>
    /// <param name="name">Name of the resource, for example <c>nameof(Strings.RiskLabel)</c>.</param>
    /// <returns>The text in the language of the report.</returns>
    public string Get(string name) => Strings.ResourceManager.GetString(name, Culture) ?? name;

    /// <summary>A label with placeholders, filled with values formatted in the culture of the report.</summary>
    /// <param name="name">Name of the resource.</param>
    /// <param name="arguments">The values.</param>
    /// <returns>The text.</returns>
    public string Format(string name, params object?[] arguments) => string.Format(Culture, Get(name), arguments);

    /// <summary>A date and time, short form.</summary>
    /// <param name="value">The moment.</param>
    /// <returns>For example <c>25/11/2026 10:30</c> in Italian.</returns>
    public string Date(DateTimeOffset value) => value.ToString("g", Culture);

    /// <summary>Name of a severity.</summary>
    /// <param name="severity">The severity.</param>
    /// <returns>The label.</returns>
    public string Severity(Severity severity) => Get("Severity" + severity);

    /// <summary>Name of a confidence.</summary>
    /// <param name="confidence">The confidence.</param>
    /// <returns>The label.</returns>
    public string Confidence(Confidence confidence) => Get("Confidence" + confidence);

    /// <summary>Name of a role.</summary>
    /// <param name="role">The role.</param>
    /// <returns>The label.</returns>
    public string Role(OperatorRole role) => Get("Role" + role);

    /// <summary>Name of an area.</summary>
    /// <param name="area">The area.</param>
    /// <returns>The label.</returns>
    public string Area(CheckArea area) => Get("Area" + area);

    /// <summary>Name of a kind of target.</summary>
    /// <param name="kind">The kind.</param>
    /// <returns>The label.</returns>
    public string TargetKind(TargetKind kind) => Get("Target" + kind);

    /// <summary>Heading of a section: the area, and the target when there is one.</summary>
    /// <param name="section">The section.</param>
    /// <returns>For example <c>Email — example.com</c>.</returns>
    public string SectionHeading(ReportSection section) =>
        section.Target is null ? Area(section.Area) : $"{Area(section.Area)} — {section.Target}";

    /// <summary>Who the assessment is for, on one line.</summary>
    /// <param name="profile">The profile.</param>
    /// <returns>The text.</returns>
    public string Profile(ReportProfile profile)
    {
        if (profile.Kind == ProfileKind.Individual)
        {
            return Get(nameof(Strings.ProfileIndividual));
        }

        var notGiven = Get(nameof(Strings.NotGiven));
        var details = Format(
            nameof(Strings.ProfileCompanyDetails),
            profile.Employees?.ToString("N0", Culture) ?? notGiven,
            profile.AnnualTurnoverEur is { } turnover ? turnover.ToString("N0", Culture) + " €" : notGiven,
            profile.VatNumber ?? notGiven,
            profile.AtecoCode ?? notGiven);
        return $"{profile.CompanyName ?? notGiven} ({details})";
    }

    /// <summary>What was checked, on one line.</summary>
    /// <param name="declaration">The declaration.</param>
    /// <returns>For example <c>example.com (domain), example.com (website)</c>.</returns>
    public string Targets(ReportDeclaration declaration) =>
        declaration.Targets.Count == 0
            ? Get(nameof(Strings.NoTargets))
            : string.Join(", ", declaration.Targets.Select(t => $"{t.Value} ({TargetKind(t.Kind)})"));

    /// <summary>The line about the CVE database.</summary>
    /// <param name="document">The report.</param>
    /// <returns>The text.</returns>
    public string VulnerabilityDatabase(ReportDocument document) =>
        document.VulnerabilityDatabaseVersion is { } version
            ? Format(nameof(Strings.VulnerabilityDatabase), version)
            : Get(nameof(Strings.NoVulnerabilityDatabase));

    /// <summary>
    /// Whether a section can say "no problems found": only when something was actually checked,
    /// never above a list of checks that could not run.
    /// </summary>
    /// <param name="section">The section.</param>
    /// <returns><see langword="true"/> when the section has no findings and at least one check passed.</returns>
    public static bool SaysNoProblems(ReportSection section) => section.Findings.Count == 0 && section.Passed.Count > 0;

    /// <summary>The CSS class of a severity, used by the HTML.</summary>
    /// <param name="severity">The severity.</param>
    /// <returns>For example <c>sev-high</c>.</returns>
    public static string SeverityClass(Severity severity) => "sev-" + severity.ToString().ToLowerInvariant();
}
