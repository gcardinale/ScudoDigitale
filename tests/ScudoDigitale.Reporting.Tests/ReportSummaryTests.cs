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

namespace ScudoDigitale.Reporting.Tests;

public sealed class ReportSummaryTests
{
    [Fact]
    public void Of_WhenDocumentHasFindings_ShouldCountThemBySeverityIncludingZeros()
    {
        var summary = ReportSummary.Of(Make.Document());

        Assert.Equal(1, summary.BySeverity[Severity.Critical]);
        Assert.Equal(1, summary.BySeverity[Severity.High]);
        Assert.Equal(1, summary.BySeverity[Severity.Medium]);
        Assert.Equal(0, summary.BySeverity[Severity.Low]);
        Assert.Equal(1, summary.BySeverity[Severity.Info]);
        Assert.Equal(4, summary.Findings);
    }

    [Fact]
    public void Of_WhenDocumentHasSections_ShouldCountByAreaInSectionOrderAndTotalTheChecks()
    {
        var summary = ReportSummary.Of(Make.Document());

        Assert.Equal([(CheckArea.Web, 2), (CheckArea.Email, 1), (CheckArea.Gdpr, 1)], summary.ByArea);
        Assert.Equal(2, summary.Passed);
        Assert.Equal(1, summary.Skipped);
        Assert.Equal(1, summary.Failed);
    }

    [Fact]
    public void Of_WhenTwoSectionsShareAnArea_ShouldAddThemUp()
    {
        var other = new Target(TargetKind.Domain, "other.example");
        var document = ReportBuilder.Build(
            Make.Scope(Make.Mail, other),
            Profile.Individual(),
            [Make.Executed(Make.Mail, "MAIL-SPF-001", Make.Finding("MAIL-SPF-001", Severity.High)), Make.Executed(other, "MAIL-SPF-001", Make.Finding("MAIL-SPF-001", Severity.High, target: "other.example"))],
            "0.1.0",
            Make.GeneratedAt);

        Assert.Equal([(CheckArea.Email, 2)], ReportSummary.Of(document).ByArea);
    }

    [Fact]
    public void Of_WhenThereAreManyFindings_ShouldListAtMostFiveActionsInPriorityOrderWithoutInfo()
    {
        var kev = new Finding("MAIL-ZZZ-001", CheckArea.Email, "Exploited", Severity.Medium, Confidence.Certain, "example.com") { Kev = true };
        var epss = new Finding("MAIL-YYY-001", CheckArea.Email, "Likely exploited", Severity.High, Confidence.Certain, "example.com") { Epss = 0.05 };
        Finding[] findings =
        [
            Make.Finding("MAIL-AAA-001", Severity.Info),
            Make.Finding("MAIL-BBB-001", Severity.Low),
            Make.Finding("MAIL-CCC-001", Severity.High, confidence: Confidence.ToBeVerified),
            Make.Finding("MAIL-DDD-001", Severity.High),
            Make.Finding("MAIL-EEE-001", Severity.Medium),
            Make.Finding("MAIL-FFF-001", Severity.Medium),
            epss,
            kev,
        ];
        var document = ReportBuilder.Build(Make.Scope(Make.Mail), Profile.Individual(), [Make.Executed(Make.Mail, "MAIL-AAA-001", findings)], "0.1.0", Make.GeneratedAt);

        var actions = ReportSummary.Of(document).Actions;

        // KEV first, then severity, EPSS, confidence and id: the same order as the sections.
        Assert.Equal(["MAIL-ZZZ-001", "MAIL-YYY-001", "MAIL-DDD-001", "MAIL-CCC-001", "MAIL-EEE-001"], actions.Select(a => a.Id));
        Assert.Equal(ReportSummary.MaxActions, actions.Count);
    }

    [Fact]
    public void Of_WhenOnlyInfoFindings_ShouldHaveNoActions()
    {
        var document = ReportBuilder.Build(
            Make.Scope(Make.Mail),
            Profile.Individual(),
            [Make.Executed(Make.Mail, "MAIL-AAA-001", Make.Finding("MAIL-AAA-001", Severity.Info))],
            "0.1.0",
            Make.GeneratedAt);

        Assert.Empty(ReportSummary.Of(document).Actions);
    }

    [Fact]
    public void Of_WhenFindingsTieOnEverythingButTarget_ShouldSortByTarget()
    {
        var document = ReportBuilder.Build(
            Make.Scope(Make.Mail),
            Profile.Individual(),
            [Make.Executed(Make.Mail, "MAIL-AAA-001", Make.Finding("MAIL-AAA-001", Severity.High, target: "b.example"), Make.Finding("MAIL-AAA-001", Severity.High, target: "a.example"))],
            "0.1.0",
            Make.GeneratedAt);

        Assert.Equal(["a.example", "b.example"], ReportSummary.Of(document).Actions.Select(a => a.Target));
    }

    [Fact]
    public void Of_WhenDocumentIsNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => ReportSummary.Of(null!));
    }
}
