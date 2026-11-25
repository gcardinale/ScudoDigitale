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

public sealed class ReportJsonTests
{
    [Fact]
    public void Write_WhenDocumentIsComplete_ShouldProduceTheVersion1Format()
    {
        using var _ = new UiCulture("en-US");

        var json = ReportJson.Write(Make.Document());

        // The format is public (ADR-005): this test changes only together with SchemaVersion.
        Assert.Equal(GoldenJson.Version1, json);
    }

    [Fact]
    public void Read_WhenJsonWasWrittenByWrite_ShouldGiveBackTheSameDocument()
    {
        var original = Make.Document();

        var read = ReportJson.Read(ReportJson.Write(original));

        Assert.Equal(ReportJson.Write(original), ReportJson.Write(read));
        Assert.Equal(original.Declaration.Targets, read.Declaration.Targets);
        Assert.Equal(original.Profile, read.Profile);
        Assert.Equal(original.Sections.Count, read.Sections.Count);
        var kev = read.Sections.Single(s => s.Area == CheckArea.Web).Findings[0];
        Assert.True(kev.Kev);
        Assert.Equal(Severity.Critical, kev.EffectiveSeverity);
        Assert.Equal(["CVE-2019-8942"], kev.Cve);
        Assert.Equal(original.GeneratedAt, read.GeneratedAt);
        Assert.Equal(original.GeneratedAt.Offset, read.GeneratedAt.Offset);
    }

    [Fact]
    public void Write_WhenTextHasAccents_ShouldKeepThemReadableWithLfLineEndings()
    {
        var document = Make.Document() with { Notes = ["Affidabilità <alta> & \"certa\""] };

        var json = ReportJson.Write(document);

        Assert.Contains("\"Affidabilità <alta> & \\\"certa\\\"\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain('\r', json);
    }

    [Theory]
    [InlineData("""{"schemaVersion": 2}""")]
    [InlineData("""{"schemaVersion": "1"}""")]
    [InlineData("""{"programVersion": "0.1.0"}""")]
    [InlineData("""[1, 2]""")]
    [InlineData("""null""")]
    [InlineData("""not json""")]
    public void Read_WhenSchemaVersionIsNotSupported_ShouldThrowInvalidData(string json)
    {
        Assert.Throws<InvalidDataException>(() => ReportJson.Read(json));
    }

    [Theory]
    [InlineData("\"programVersion\": \"0.1.0\",", "")]
    [InlineData("\"cve\": [\n            \"CVE-2019-8942\"\n          ]", "\"cve\": null")]
    [InlineData("\"effectiveSeverity\": \"Critical\"", "\"effectiveSeverity\": 4")]
    [InlineData("\"effectiveSeverity\": \"Critical\"", "\"effectiveSeverity\": \"Catastrophic\"")]
    [InlineData("\"id\": \"MAIL-SPF-001\",", "")]
    public void Read_WhenAValueIsMissingOrInvalid_ShouldThrowInvalidData(string valid, string broken)
    {
        var json = ReportJson.Write(Make.Document());
        Assert.Contains(valid, json, StringComparison.Ordinal);

        Assert.Throws<InvalidDataException>(() => ReportJson.Read(json.Replace(valid, broken, StringComparison.Ordinal)));
    }

    [Fact]
    public void Read_WhenJsonHasUnknownProperties_ShouldIgnoreThem()
    {
        var json = ReportJson.Write(Make.Document()).Replace("\"schemaVersion\": 1,", "\"schemaVersion\": 1, \"futureField\": true,", StringComparison.Ordinal);

        Assert.Equal("0.1.0", ReportJson.Read(json).ProgramVersion);
    }

    [Fact]
    public void WriteAndRead_WhenArgumentIsNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => ReportJson.Write(null!));
        Assert.Throws<ArgumentNullException>(() => ReportJson.Read(null!));
    }
}
