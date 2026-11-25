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

using System.Text;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Fields;
using MigraDoc.DocumentObjectModel.Tables;
using PdfSharp.Pdf.IO;
using ScudoDigitale.Core;

namespace ScudoDigitale.Reporting.Tests;

public sealed class PdfReportTests
{
    [Fact]
    public void Render_WhenCalled_ShouldProduceAPdfThatOpens()
    {
        using var _ = new UiCulture("en-US");

        var bytes = PdfReport.Render(Make.Document());

        Assert.Equal("%PDF-", Encoding.ASCII.GetString(bytes, 0, 5));
        using var pdf = PdfReader.Open(new MemoryStream(bytes), PdfDocumentOpenMode.Import);
        Assert.True(pdf.PageCount >= 1);
        Assert.Equal("Security self-assessment report", pdf.Info.Title);
        Assert.Equal(Attribution.Notice, pdf.Info.Author);
    }

    [Fact]
    public void Render_WhenReportIsLong_ShouldSpanSeveralPages()
    {
        var findings = Enumerable.Range(100, 40).Select(i => Make.Finding($"MAIL-LONG-{i}", Severity.Medium)).ToArray();
        var document = ReportBuilder.Build(Make.Scope(Make.Mail), Profile.Individual(), [Make.Executed(Make.Mail, "MAIL-LONG-100", findings)], "0.1.0", Make.GeneratedAt);

        using var pdf = PdfReader.Open(new MemoryStream(PdfReport.Render(document)), PdfDocumentOpenMode.Import);

        Assert.True(pdf.PageCount > 3, $"{pdf.PageCount} pages");
    }

    [Fact]
    public void Build_WhenCalled_ShouldPutAttributionAndPageNumberInTheFooterOfEveryPage()
    {
        using var _ = new UiCulture("en-US");
        var view = ReportView.Of(Make.Document());

        var document = PdfReport.Build(view);

        var section = Assert.Single(document.Sections.Cast<Section>());
        Assert.False(section.PageSetup.DifferentFirstPageHeaderFooter);
        Assert.False(section.PageSetup.OddAndEvenPagesHeaderFooter);
        Assert.Empty(section.Footers.FirstPage.Elements);
        Assert.Empty(section.Footers.EvenPage.Elements);
        var paragraphs = section.Footers.Primary.Elements.Cast<Paragraph>().ToArray();
        Assert.Equal(Attribution.ReportFooter("0.1.0"), TextOf(paragraphs[0]));
        Assert.Equal("Page [page] of [pages]", TextOf(paragraphs[1]));
        Assert.Equal(PageFormat.A4, section.PageSetup.PageFormat);
    }

    [Theory]
    [InlineData("p. {0}", "p. [page]")]
    [InlineData("{1}/{0}", "[pages]/[page]")]
    [InlineData("{0}", "[page]")]
    public void Build_WhenPageFormatChanges_ShouldPlaceEachFieldWhereItsPlaceholderIs(string format, string expected)
    {
        var view = ReportView.Of(Make.Document()) with { PageNumber = format };

        var footer = Assert.Single(PdfReport.Build(view).Sections.Cast<Section>()).Footers.Primary;

        Assert.Equal(expected, TextOf(footer.Elements.Cast<Paragraph>().Last()));
    }

    [Fact]
    public void Build_WhenCalled_ShouldContainEverythingTheHtmlShows()
    {
        using var _ = new UiCulture("en-US");

        var text = TextOf(PdfReport.Build(ReportView.Of(Make.Document())));

        foreach (var expected in new[]
        {
            "Security self-assessment report",
            "does not replace a penetration test",
            "Declared by Mario Rossi (security officer)",
            "For: Rossi SRL",
            "Checked: example.com (domain), www.example.com (website)",
            "CVE database: not used in this version",
            "The site is reached through a proxy.",
            "1 Critical",
            "0 Low",
            "Websites: 2 · Email: 1 · GDPR: 1",
            "1 checks passed, 1 skipped, 1 could not run. 1 questions answered without problems.",
            "1. [CRITICAL] Outdated CMS (www.example.com)",
            "Websites — www.example.com",
            "Evidence: generator: WordPress 5.0",
            "CVSS: 8.8",
            "In the CISA catalog of vulnerabilities exploited in the wild.",
            "Severity given by the check: Low.",
            "✓ MAIL-SPF-001 Check MAIL-SPF-001",
            "– MAIL-DKIM-002 Check MAIL-DKIM-002: no key to look at",
            "! MAIL-MX-001 Check MAIL-MX-001: DNS timeout",
            "[HIGH] Title of GDPR-ART30-001 GDPR-ART30-001",
        })
        {
            Assert.Contains(expected, text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Build_WhenNothingIsUrgentAndNothingFound_ShouldSaySo()
    {
        using var _ = new UiCulture("en-US");
        var document = ReportBuilder.Build(Make.Scope(), Profile.Individual(), [], "0.1.0", Make.GeneratedAt, questionnaires: [ReportBuilder.QuestionnaireSection(CheckArea.Gdpr, [], [new ReportCheck("GDPR-BACKUP-001", "Backups")])]);

        var text = TextOf(PdfReport.Build(ReportView.Of(document)));

        Assert.Contains("No urgent action.", text, StringComparison.Ordinal);
        Assert.Contains("No problems found.", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Notes", text, StringComparison.Ordinal);
    }

    [Fact]
    public void SeverityColor_WhenCalled_ShouldGiveEachSeverityItsOwnColour()
    {
        var colours = Enum.GetValues<Severity>().Select(s => PdfReport.SeverityColor(ReportLabels.SeverityClass(s)).Argb).ToArray();

        Assert.Equal(colours.Length, colours.Distinct().Count());
    }

    [Fact]
    public void Render_WhenDocumentIsNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => PdfReport.Render(null!));
    }

    private static string TextOf(Document document)
    {
        var text = new StringBuilder();
        foreach (var section in document.Sections.Cast<Section>())
        {
            Append(text, section.Elements);
        }

        return text.ToString();
    }

    private static string TextOf(Paragraph paragraph)
    {
        var text = new StringBuilder();
        Append(text, paragraph.Elements);
        return text.ToString();
    }

    private static void Append(StringBuilder text, DocumentObjectCollection elements)
    {
        foreach (var element in elements)
        {
            switch (element)
            {
                case Paragraph p:
                    Append(text, p.Elements);
                    text.Append('\n');
                    break;
                case Table t:
                    foreach (var row in t.Rows.Cast<Row>())
                    {
                        for (var i = 0; i < t.Columns.Count; i++)
                        {
                            Append(text, row.Cells[i].Elements);
                        }
                    }

                    break;
                case FormattedText f:
                    Append(text, f.Elements);
                    break;
                case Text t:
                    text.Append(t.Content);
                    break;
                case Character { SymbolName: SymbolName.LineBreak }:
                    text.Append('\n');
                    break;
                case PageField:
                    text.Append("[page]");
                    break;
                case NumPagesField:
                    text.Append("[pages]");
                    break;
            }
        }
    }
}
