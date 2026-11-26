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

namespace ScudoDigitale.Reporting.Tests;

/// <summary>Sets the culture and UI culture for the current async flow and restores it on dispose.</summary>
internal sealed class UiCulture : IDisposable
{
    private readonly CultureInfo previous = CultureInfo.CurrentCulture;
    private readonly CultureInfo previousUi = CultureInfo.CurrentUICulture;

    public UiCulture(string name)
    {
        CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name);
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name);
    }

    public void Dispose()
    {
        CultureInfo.CurrentCulture = previous;
        CultureInfo.CurrentUICulture = previousUi;
    }
}

/// <summary>Builders for valid test objects.</summary>
internal static class Make
{
    public static readonly DateTimeOffset DeclaredAt = new(2026, 11, 25, 10, 30, 0, TimeSpan.FromHours(1));

    public static readonly DateTimeOffset GeneratedAt = new(2026, 11, 25, 10, 31, 5, TimeSpan.FromHours(1));

    public static readonly Target Mail = new(TargetKind.Domain, "example.com");

    public static readonly Target Site = new(TargetKind.Website, "www.example.com");

    public static ScopeDeclaration Scope(params Target[] targets) =>
        new("Mario Rossi", OperatorRole.SecurityOfficer, targets, DeclaredAt);

    public static Finding Finding(
        string id,
        Severity severity,
        CheckArea area = CheckArea.Email,
        string target = "example.com",
        Confidence confidence = Confidence.Certain) =>
        new(id, area, "Title of " + id, severity, confidence, target)
        {
            Evidence = "evidence of " + id,
            Risk = "risk of " + id,
            Fix = "fix of " + id,
            References = ["RFC 7489"],
        };

    public static CheckRun Executed(Target target, string id, params Finding[] findings) =>
        new(id, "Check " + id, AreaOf(target), target, new CheckResult.Executed(findings));

    public static CheckRun Skipped(Target target, string id, string reason) =>
        new(id, "Check " + id, AreaOf(target), target, new CheckResult.Skipped(reason));

    public static CheckRun Failed(Target target, string id, string error) =>
        new(id, "Check " + id, AreaOf(target), target, new CheckResult.Failed(error));

    public static CheckArea AreaOf(Target target) => target.Kind == TargetKind.Website ? CheckArea.Web : CheckArea.Email;

    /// <summary>A report with two areas, every kind of result, a KEV finding, a questionnaire and a note.</summary>
    public static ReportDocument Document()
    {
        var kev = new Finding("WEB-CMS-001", CheckArea.Web, "Outdated CMS", Severity.Low, Confidence.Probable, "www.example.com")
        {
            Evidence = "generator: WordPress 5.0",
            Cve = ["CVE-2019-8942"],
            Cvss = 8.8,
            Epss = 0.97,
            Kev = true,
            Fix = "Update WordPress.",
            References = ["CISA KEV"],
        };

        CheckRun[] runs =
        [
            Executed(Mail, "MAIL-DMARC-001", Finding("MAIL-DMARC-001", Severity.Medium)),
            Executed(Mail, "MAIL-SPF-001"),
            Skipped(Mail, "MAIL-DKIM-002", "no key to look at"),
            Failed(Mail, "MAIL-MX-001", "DNS timeout"),
            Executed(Site, "WEB-CMS-001", kev),
            Executed(Site, "WEB-HSTS-001", Finding("WEB-HSTS-001", Severity.Info, CheckArea.Web, "www.example.com")),
        ];

        var gdpr = ReportBuilder.QuestionnaireSection(
            CheckArea.Gdpr,
            [Finding("GDPR-ART30-001", Severity.High, CheckArea.Gdpr, "Rossi SRL")],
            [new ReportCheck("GDPR-ART32-001", "Security measures")]);

        return ReportBuilder.Build(
            Scope(Mail, Site),
            Profile.Company("Rossi SRL", employees: 12, annualTurnoverEur: 1_500_000m, vatNumber: "IT01234567890"),
            runs,
            "0.1.0",
            GeneratedAt,
            ["The site is reached through a proxy."],
            [gdpr]);
    }
}
