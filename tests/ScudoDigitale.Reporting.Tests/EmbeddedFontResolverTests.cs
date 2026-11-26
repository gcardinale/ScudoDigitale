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

using PdfSharp.Fonts;

namespace ScudoDigitale.Reporting.Tests;

public sealed class EmbeddedFontResolverTests
{
    [Theory]
    [InlineData("Arial", false, false, EmbeddedFontResolver.RegularFace, false)]
    [InlineData(EmbeddedFontResolver.Family, true, false, EmbeddedFontResolver.BoldFace, false)]
    [InlineData("Courier New", false, true, EmbeddedFontResolver.RegularFace, true)]
    [InlineData("Courier New", true, true, EmbeddedFontResolver.BoldFace, true)]
    public void ResolveTypeface_WhenAnyFamilyIsAsked_ShouldGiveDejaVuAndSimulateItalic(string family, bool bold, bool italic, string face, bool simulatedItalic)
    {
        var info = new EmbeddedFontResolver().ResolveTypeface(family, bold, italic);

        Assert.Equal(face, info.FaceName);
        Assert.False(info.MustSimulateBold);
        Assert.Equal(simulatedItalic, info.MustSimulateItalic);
    }

    [Theory]
    [InlineData(EmbeddedFontResolver.RegularFace)]
    [InlineData(EmbeddedFontResolver.BoldFace)]
    public void GetFont_WhenFaceIsIncluded_ShouldReturnATrueTypeFont(string face)
    {
        var bytes = new EmbeddedFontResolver().GetFont(face);

        Assert.NotNull(bytes);
        Assert.True(bytes.Length > 100_000);
        Assert.Equal(new byte[] { 0x00, 0x01, 0x00, 0x00 }, bytes[..4]);
    }

    [Fact]
    public void GetFont_WhenFaceIsNotIncluded_ShouldReturnNull()
    {
        Assert.Null(new EmbeddedFontResolver().GetFont("Arial"));
    }

    [Fact]
    public void Install_WhenCalledTwice_ShouldKeepOneResolver()
    {
        EmbeddedFontResolver.Install();
        var first = GlobalFontSettings.FontResolver;

        EmbeddedFontResolver.Install();

        Assert.IsType<EmbeddedFontResolver>(first);
        Assert.Same(first, GlobalFontSettings.FontResolver);
    }
}
