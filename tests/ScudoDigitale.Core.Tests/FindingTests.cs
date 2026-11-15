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

public class FindingTests
{
    [Fact]
    public void Constructor_WhenValid_ShouldKeepValuesAndDefaultTheRest()
    {
        var finding = new Finding("MAIL-DMARC-001", CheckArea.Email, "DMARC in monitoring mode", Severity.Medium, Confidence.Certain, "example.com");

        Assert.Equal("MAIL-DMARC-001", finding.Id);
        Assert.Equal(CheckArea.Email, finding.Area);
        Assert.Equal("DMARC in monitoring mode", finding.Title);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(Confidence.Certain, finding.Confidence);
        Assert.Equal("example.com", finding.Target);
        Assert.Null(finding.Evidence);
        Assert.Empty(finding.Cve);
        Assert.Null(finding.Cvss);
        Assert.Null(finding.Epss);
        Assert.False(finding.Kev);
        Assert.Null(finding.Risk);
        Assert.Null(finding.Fix);
        Assert.Empty(finding.References);
    }

    [Fact]
    public void Init_WhenOptionalValuesGiven_ShouldKeepThem()
    {
        var finding = Make.Finding() with
        {
            Evidence = "v=DMARC1; p=none",
            Cve = ["CVE-2024-0001"],
            Cvss = 7.5,
            Epss = 0.42,
            Kev = true,
            Risk = "Spoofing",
            Fix = "Use p=reject",
            References = ["RFC 7489"],
        };

        Assert.Equal("v=DMARC1; p=none", finding.Evidence);
        Assert.Equal(["CVE-2024-0001"], finding.Cve);
        Assert.Equal(7.5, finding.Cvss);
        Assert.Equal(0.42, finding.Epss);
        Assert.True(finding.Kev);
        Assert.Equal("Spoofing", finding.Risk);
        Assert.Equal("Use p=reject", finding.Fix);
        Assert.Equal(["RFC 7489"], finding.References);
    }

    [Fact]
    public void Init_WhenListsChangeLater_ShouldNotBeAffected()
    {
        var cve = new List<string> { "CVE-2024-0001" };
        var references = new List<string> { "RFC 7489" };
        var finding = Make.Finding() with { Cve = cve, References = references };

        cve.Clear();
        references.Clear();

        Assert.Single(finding.Cve);
        Assert.Single(finding.References);
    }

    [Theory]
    [InlineData("MAIL-DMARC-001")]
    [InlineData("NIS2-SCOPE-010")]
    [InlineData("WEB-TLS10-999")]
    public void Constructor_WhenIdIsWellFormed_ShouldAcceptIt(string id)
    {
        Assert.Equal(id, Make.Finding(id).Id);
    }

    [Theory]
    [InlineData("MAIL-DMARC-001\n")]
    [InlineData("mail-dmarc-001")]
    [InlineData("MAIL-DMARC-01")]
    [InlineData("MAIL-DMARC-0001")]
    [InlineData("MAIL_DMARC_001")]
    [InlineData("MAIL-001")]
    [InlineData(" MAIL-DMARC-001")]
    [InlineData("1MAIL-DMARC-001")]
    public void Constructor_WhenIdIsMalformed_ShouldThrow(string id)
    {
        Assert.Throws<ArgumentException>(() => Make.Finding(id));
    }

    [Fact]
    public void Constructor_WhenTitleIsBlank_ShouldThrow()
    {
        Assert.Throws<ArgumentException>(() => new Finding("MAIL-DMARC-001", CheckArea.Email, " ", Severity.Low, Confidence.Certain, "example.com"));
    }

    [Fact]
    public void Constructor_WhenTargetIsBlank_ShouldThrow()
    {
        Assert.Throws<ArgumentException>(() => Make.Finding(target: ""));
    }

    [Fact]
    public void Constructor_WhenIdIsBlank_ShouldThrow()
    {
        Assert.Throws<ArgumentException>(() => Make.Finding(" "));
    }

    [Fact]
    public void Constructor_WhenAreaIsUndefined_ShouldThrow()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Finding("MAIL-DMARC-001", (CheckArea)99, "t", Severity.Low, Confidence.Certain, "x"));
    }

    [Fact]
    public void Constructor_WhenSeverityIsUndefined_ShouldThrow()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Make.Finding(severity: (Severity)99));
    }

    [Fact]
    public void Constructor_WhenConfidenceIsUndefined_ShouldThrow()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Make.Finding(confidence: (Confidence)99));
    }

    [Theory]
    [InlineData(0.0)]
    [InlineData(10.0)]
    public void Cvss_WhenAtTheBounds_ShouldAcceptIt(double value)
    {
        Assert.Equal(value, (Make.Finding() with { Cvss = value }).Cvss);
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(10.1)]
    [InlineData(double.NaN)]
    public void Cvss_WhenOutOfRange_ShouldThrow(double value)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Make.Finding() with { Cvss = value });
    }

    [Theory]
    [InlineData(0.0)]
    [InlineData(1.0)]
    public void Epss_WhenAtTheBounds_ShouldAcceptIt(double value)
    {
        Assert.Equal(value, (Make.Finding() with { Epss = value }).Epss);
    }

    [Theory]
    [InlineData(-0.01)]
    [InlineData(1.01)]
    [InlineData(double.NaN)]
    public void Epss_WhenOutOfRange_ShouldThrow(double value)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Make.Finding() with { Epss = value });
    }

    [Fact]
    public void Cve_WhenSetToNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => Make.Finding() with { Cve = null! });
    }

    [Fact]
    public void References_WhenSetToNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => Make.Finding() with { References = null! });
    }
}
