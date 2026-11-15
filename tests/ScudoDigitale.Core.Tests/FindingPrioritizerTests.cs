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

namespace ScudoDigitale.Core.Tests;

public class FindingPrioritizerTests
{
    [Theory]
    [InlineData(0.0, Severity.Info)]
    [InlineData(0.1, Severity.Low)]
    [InlineData(3.9, Severity.Low)]
    [InlineData(4.0, Severity.Medium)]
    [InlineData(6.9, Severity.Medium)]
    [InlineData(7.0, Severity.High)]
    [InlineData(8.9, Severity.High)]
    [InlineData(9.0, Severity.Critical)]
    [InlineData(10.0, Severity.Critical)]
    public void FromCvss_WhenScoreIsOnABoundary_ShouldReturnTheQualitativeRating(double score, Severity expected)
    {
        Assert.Equal(expected, FindingPrioritizer.FromCvss(score));
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(10.1)]
    [InlineData(double.NaN)]
    public void FromCvss_WhenScoreIsOutOfRange_ShouldThrow(double score)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => FindingPrioritizer.FromCvss(score));
    }

    [Fact]
    public void EffectiveSeverity_WhenKev_ShouldAlwaysBeCritical()
    {
        var finding = Make.Finding(severity: Severity.Low) with { Kev = true, Cvss = 2.0, Epss = 0.0 };

        Assert.Equal(Severity.Critical, FindingPrioritizer.EffectiveSeverity(finding));
    }

    [Fact]
    public void EffectiveSeverity_WhenCvssPresent_ShouldReplaceTheCheckSeverity()
    {
        var finding = Make.Finding(severity: Severity.Critical) with { Cvss = 5.0 };

        Assert.Equal(Severity.Medium, FindingPrioritizer.EffectiveSeverity(finding));
    }

    [Fact]
    public void EffectiveSeverity_WhenNoCvss_ShouldKeepTheCheckSeverity()
    {
        Assert.Equal(Severity.High, FindingPrioritizer.EffectiveSeverity(Make.Finding(severity: Severity.High)));
    }

    [Fact]
    public void EffectiveSeverity_WhenEpssIsAtTheThreshold_ShouldRaiseByOneLevel()
    {
        var finding = Make.Finding() with { Cvss = 5.0, Epss = FindingPrioritizer.EpssRaiseThreshold };

        Assert.Equal(Severity.High, FindingPrioritizer.EffectiveSeverity(finding));
    }

    [Fact]
    public void EffectiveSeverity_WhenEpssIsJustBelowTheThreshold_ShouldNotRaise()
    {
        var finding = Make.Finding() with { Cvss = 5.0, Epss = 0.0999 };

        Assert.Equal(Severity.Medium, FindingPrioritizer.EffectiveSeverity(finding));
    }

    [Fact]
    public void EffectiveSeverity_WhenAlreadyCriticalAndHighEpss_ShouldStayCritical()
    {
        var finding = Make.Finding() with { Cvss = 9.8, Epss = 0.9 };

        Assert.Equal(Severity.Critical, FindingPrioritizer.EffectiveSeverity(finding));
    }

    [Fact]
    public void EffectiveSeverity_WhenFindingIsNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => FindingPrioritizer.EffectiveSeverity(null!));
    }

    [Fact]
    public void Prioritize_WhenMixed_ShouldPutKevFirstThenSeverityThenEpssThenConfidence()
    {
        var kevLow = Make.Finding("NET-SMB-001", Severity.Low) with { Kev = true };
        var criticalByCvss = Make.Finding("NET-RDP-001", Severity.Low) with { Cvss = 9.5 };
        var highEpssLow = Make.Finding("WEB-CMS-001", Severity.High) with { Epss = 0.05 };
        var highEpssHigh = Make.Finding("WEB-CMS-002", Severity.High) with { Epss = 0.09 };
        var highNoEpssCertain = Make.Finding("MAIL-SPF-001", Severity.High, Confidence.Certain);
        var highNoEpssProbable = Make.Finding("MAIL-SPF-002", Severity.High, Confidence.Probable);
        var info = Make.Finding("MAIL-BIMI-001", Severity.Info);

        var sorted = FindingPrioritizer.Prioritize(
            [info, highNoEpssProbable, highEpssLow, criticalByCvss, highNoEpssCertain, kevLow, highEpssHigh]);

        Assert.Equal(
            ["NET-SMB-001", "NET-RDP-001", "WEB-CMS-002", "WEB-CMS-001", "MAIL-SPF-001", "MAIL-SPF-002", "MAIL-BIMI-001"],
            sorted.Select(p => p.Finding.Id));
        Assert.Equal(Severity.Critical, sorted[0].EffectiveSeverity);
        Assert.Equal(Severity.Critical, sorted[1].EffectiveSeverity);
    }

    [Fact]
    public void Prioritize_WhenKevAndCriticalTie_ShouldPutKevFirst()
    {
        var critical = Make.Finding("AAA-CRIT-001") with { Cvss = 10.0, Epss = 1.0 };
        var kev = Make.Finding("ZZZ-KEV-001") with { Kev = true };

        var sorted = FindingPrioritizer.Prioritize([critical, kev]);

        Assert.Equal(["ZZZ-KEV-001", "AAA-CRIT-001"], sorted.Select(p => p.Finding.Id));
    }

    [Fact]
    public void Prioritize_WhenEverythingElseTies_ShouldOrderByIdThenTargetForARepeatableResult()
    {
        var b2 = Make.Finding("MAIL-SPF-002", target: "b.com");
        var a2 = Make.Finding("MAIL-SPF-002", target: "a.com");
        var a1 = Make.Finding("MAIL-SPF-001", target: "z.com");

        var first = FindingPrioritizer.Prioritize([b2, a2, a1]);
        var second = FindingPrioritizer.Prioritize([a1, b2, a2]);

        Assert.Equal(["z.com", "a.com", "b.com"], first.Select(p => p.Finding.Target));
        Assert.Equal(first, second);
    }

    [Fact]
    public void Prioritize_WhenCalled_ShouldReturnEffectiveSeverityWithoutChangingTheInput()
    {
        var original = Make.Finding(severity: Severity.Low) with { Cvss = 9.9 };

        var sorted = FindingPrioritizer.Prioritize([original]);

        Assert.Equal(Severity.Critical, sorted[0].EffectiveSeverity);
        Assert.Equal(Severity.Low, sorted[0].Finding.Severity);
    }

    [Fact]
    public void Prioritize_WhenAppliedAgainToItsOwnOutput_ShouldNotRaiseTheSeverityAgain()
    {
        // Reporting may prioritize per area and then globally: EPSS must raise the severity once only.
        var finding = Make.Finding(severity: Severity.Medium) with { Epss = 0.5 };

        var once = FindingPrioritizer.Prioritize([finding]);
        var twice = FindingPrioritizer.Prioritize(once.Select(p => p.Finding));

        Assert.Equal(Severity.High, once[0].EffectiveSeverity);
        Assert.Equal(Severity.High, twice[0].EffectiveSeverity);
        Assert.Equal(once, twice);
    }

    [Fact]
    public void Prioritize_WhenEmpty_ShouldReturnEmpty()
    {
        Assert.Empty(FindingPrioritizer.Prioritize([]));
    }

    [Fact]
    public void Prioritize_WhenNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => FindingPrioritizer.Prioritize(null!));
    }

    [Fact]
    public void Prioritize_WhenAFindingIsNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => FindingPrioritizer.Prioritize([Make.Finding(), null!]));
    }
}
