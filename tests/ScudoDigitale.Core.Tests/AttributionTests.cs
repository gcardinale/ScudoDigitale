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

public class AttributionTests
{
    [Fact]
    public void Notice_WhenRead_ShouldBeTheExactAttributionRequiredByNotice()
    {
        Assert.Equal("Scudo Digitale — © Gaetano Cardinale — https://gcardinale.it", Attribution.Notice);
    }

    [Fact]
    public void Constants_WhenRead_ShouldMatchTheLicenseTerms()
    {
        Assert.Equal("Scudo Digitale", Attribution.ProductName);
        Assert.Equal("Gaetano Cardinale", Attribution.Author);
        Assert.Equal("https://gcardinale.it", Attribution.Website);
        Assert.Equal("AGPL-3.0-or-later", Attribution.License);
    }

    [Fact]
    public void Banner_WhenRead_ShouldEndWithTheNotice()
    {
        Assert.EndsWith("\n" + Attribution.Notice, Attribution.Banner, StringComparison.Ordinal);
        Assert.Contains("D I G I T A L E", Attribution.Banner, StringComparison.Ordinal);
    }

    [Fact]
    public void ReportFooter_WhenCultureIsEnglish_ShouldContainVersionAndFullAttribution()
    {
        using var _ = new UiCulture("en-US");

        var footer = Attribution.ReportFooter(" 1.0 ");

        Assert.Equal(
            "Report generated with Scudo Digitale v1.0 — © Gaetano Cardinale — https://gcardinale.it — AGPL-3.0-or-later",
            footer);
    }

    [Fact]
    public void ReportFooter_WhenCultureIsItalian_ShouldTranslateOnlyTheLeadingWords()
    {
        using var _ = new UiCulture("it-IT");

        var footer = Attribution.ReportFooter("1.0");

        Assert.Equal(
            "Report generato con Scudo Digitale v1.0 — © Gaetano Cardinale — https://gcardinale.it — AGPL-3.0-or-later",
            footer);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void ReportFooter_WhenVersionIsBlank_ShouldThrow(string version)
    {
        Assert.Throws<ArgumentException>(() => Attribution.ReportFooter(version));
    }
}
