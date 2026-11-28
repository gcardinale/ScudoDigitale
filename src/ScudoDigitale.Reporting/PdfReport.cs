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

using System.Text.RegularExpressions;
using MigraDoc.DocumentObjectModel;
using MigraDoc.Rendering;
using PdfSharp;
using ScudoDigitale.Core;

namespace ScudoDigitale.Reporting;

/// <summary>
/// The PDF report (MigraDoc, AGPL): the same content as the HTML, on A4 pages, with the attribution
/// and the page number at the foot of every page.
/// </summary>
public static class PdfReport
{
    private static readonly Color Brand = Color.FromRgb(0x1e, 0x3a, 0x5f);
    private static readonly Color Muted = Color.FromRgb(0x6b, 0x72, 0x80);
    private static readonly Color Line = Color.FromRgb(0xe5, 0xe7, 0xeb);
    private static readonly Color Good = Color.FromRgb(0x15, 0x80, 0x3d);
    private static readonly Color Warning = Color.FromRgb(0x92, 0x40, 0x0e);

    /// <summary>
    /// PDFsharp 6.5 and later refuses to render until a license is chosen: Scudo Digitale is AGPL, so it
    /// uses PDFsharp under the AGPL (AGPL-3.0-only) too, once per process, before the first PDF. A paid
    /// edition would load a commercial license here instead.
    /// </summary>
    static PdfReport() => PdfSharpLicense.SetAgplLicense();

    /// <summary>Renders a document as PDF.</summary>
    /// <param name="document">The report.</param>
    /// <returns>The bytes of the PDF file.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="document"/> is <see langword="null"/>.</exception>
    public static byte[] Render(ReportDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        EmbeddedFontResolver.Install();

        var view = ReportView.Of(document);
        var renderer = new PdfDocumentRenderer { Document = Build(view) };
        renderer.RenderDocument();
        renderer.PdfDocument.Info.Title = view.Title;
        renderer.PdfDocument.Info.Author = Attribution.Notice;
        renderer.PdfDocument.Info.Creator = Attribution.ProductName;

        using var output = new MemoryStream();
        renderer.PdfDocument.Save(output, closeStream: false);
        return output.ToArray();
    }

    /// <summary>The MigraDoc document of a view, before rendering.</summary>
    /// <param name="view">The view.</param>
    /// <returns>The document, one section, A4.</returns>
    internal static Document Build(ReportView view)
    {
        var document = new Document();
        document.Info.Title = view.Title;
        DefineStyles(document);

        var section = document.AddSection();
        section.PageSetup = document.DefaultPageSetup.Clone();
        section.PageSetup.PageFormat = PageFormat.A4;
        section.PageSetup.TopMargin = Unit.FromCentimeter(2);
        section.PageSetup.BottomMargin = Unit.FromCentimeter(2.5);
        section.PageSetup.LeftMargin = Unit.FromCentimeter(2);
        section.PageSetup.RightMargin = Unit.FromCentimeter(2);
        section.PageSetup.FooterDistance = Unit.FromCentimeter(1);
        AddFooter(section, view);

        section.AddParagraph(view.Title, StyleNames.Heading1);
        Small(section.AddParagraph(view.Disclaimer), Muted);
        foreach (var fact in view.Facts)
        {
            Labelled(section.AddParagraph(), fact.Label, fact.Value);
        }

        if (view.Notes.Count > 0)
        {
            var heading = section.AddParagraph(view.NotesHeading, StyleNames.Heading3);
            heading.Format.Font.Color = Warning;
            foreach (var note in view.Notes)
            {
                section.AddParagraph(note);
            }
        }

        AddSummary(section, view.Summary);
        foreach (var area in view.Sections)
        {
            AddSection(section, area);
        }

        return document;
    }

    /// <summary>The background colour of a severity, as in the HTML.</summary>
    /// <param name="cssClass">The CSS class of the severity, for example <c>sev-high</c>.</param>
    /// <returns>The colour.</returns>
    internal static Color SeverityColor(string cssClass) => cssClass switch
    {
        "sev-critical" => Color.FromRgb(0x7f, 0x1d, 0x1d),
        "sev-high" => Color.FromRgb(0xb9, 0x1c, 0x1c),
        "sev-medium" => Color.FromRgb(0xc2, 0x41, 0x0c),
        "sev-low" => Color.FromRgb(0xa1, 0x62, 0x07),
        _ => Color.FromRgb(0x47, 0x55, 0x69),
    };

    private static void DefineStyles(Document document)
    {
        var normal = document.Styles[StyleNames.Normal]!;
        normal.Font.Name = EmbeddedFontResolver.Family;
        normal.Font.Size = 9.5;
        normal.ParagraphFormat.SpaceAfter = Unit.FromPoint(3);

        var h1 = document.Styles[StyleNames.Heading1]!;
        h1.Font.Size = 18;
        h1.Font.Bold = true;
        h1.Font.Color = Brand;
        h1.ParagraphFormat.SpaceAfter = Unit.FromPoint(6);

        var h2 = document.Styles[StyleNames.Heading2]!;
        h2.Font.Size = 14;
        h2.Font.Bold = true;
        h2.Font.Color = Brand;
        h2.ParagraphFormat.SpaceBefore = Unit.FromPoint(16);
        h2.ParagraphFormat.SpaceAfter = Unit.FromPoint(6);
        h2.ParagraphFormat.KeepWithNext = true;
        h2.ParagraphFormat.Borders.Bottom.Width = 0.5;
        h2.ParagraphFormat.Borders.Bottom.Color = Line;

        var h3 = document.Styles[StyleNames.Heading3]!;
        h3.Font.Size = 11;
        h3.Font.Bold = true;
        h3.ParagraphFormat.SpaceBefore = Unit.FromPoint(8);
        h3.ParagraphFormat.SpaceAfter = Unit.FromPoint(3);
        h3.ParagraphFormat.KeepWithNext = true;

        var footer = document.Styles[StyleNames.Footer]!;
        footer.Font.Size = 7.5;
        footer.Font.Color = Muted;
        footer.ParagraphFormat.Alignment = ParagraphAlignment.Center;
    }

    private static void AddFooter(Section section, ReportView view)
    {
        // The attribution is a license term (AGPL 7(b)): it must be on every page, so it lives in the
        // primary footer of the only section, and no first-page or even-page footer replaces it.
        section.PageSetup.DifferentFirstPageHeaderFooter = false;
        section.PageSetup.OddAndEvenPagesHeaderFooter = false;
        var footer = section.Footers.Primary;
        footer.AddParagraph(view.Footer);

        // "Page {0} of {1}": {0} becomes the page number and {1} the number of pages, wherever the language puts them.
        var page = footer.AddParagraph();
        foreach (var part in Regex.Split(view.PageNumber, @"(\{0\}|\{1\})"))
        {
            switch (part)
            {
                case "{0}":
                    page.AddPageField();
                    break;
                case "{1}":
                    page.AddNumPagesField();
                    break;
                case "":
                    break;
                default:
                    page.AddText(part);
                    break;
            }
        }
    }

    private static void AddSummary(Section section, ViewSummary summary)
    {
        section.AddParagraph(summary.Heading, StyleNames.Heading2);
        section.AddParagraph(summary.SeverityHeading, StyleNames.Heading3);
        var table = section.AddTable();
        table.Borders.Width = 0;
        foreach (var _ in summary.Severities)
        {
            table.AddColumn(Unit.FromCentimeter(3.4));
        }

        var row = table.AddRow();
        for (var i = 0; i < summary.Severities.Count; i++)
        {
            var count = summary.Severities[i];
            var cell = row.Cells[i];
            cell.Shading.Color = SeverityColor(count.Class);
            cell.Format.Font.Color = Colors.White;
            var p = cell.AddParagraph();
            p.Format.SpaceBefore = Unit.FromPoint(3);
            p.Format.SpaceAfter = Unit.FromPoint(3);
            p.Format.Alignment = ParagraphAlignment.Center;
            p.AddFormattedText(count.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) + " ", TextFormat.Bold);
            p.AddText(count.Label);
        }

        if (summary.Areas.Count > 0)
        {
            section.AddParagraph(summary.AreaHeading, StyleNames.Heading3);
            section.AddParagraph(string.Join(" · ", summary.Areas.Select(a => $"{a.Label}: {a.Count}")));
        }

        section.AddParagraph(summary.Checks);
        section.AddParagraph(summary.ActionsHeading, StyleNames.Heading3);
        if (summary.Actions.Count == 0)
        {
            Small(section.AddParagraph(summary.NoActions), Good).Format.Font.Bold = true;
            return;
        }

        var number = 1;
        foreach (var action in summary.Actions)
        {
            var p = section.AddParagraph();
            p.Format.LeftIndent = Unit.FromCentimeter(0.6);
            p.Format.FirstLineIndent = Unit.FromCentimeter(-0.6);
            p.Format.KeepTogether = true;
            p.AddText($"{number++}. ");
            Badge(p, action.Severity, action.Class);
            p.AddFormattedText(" " + action.Title, TextFormat.Bold);
            p.AddFormattedText($" ({action.Target})", new Font { Color = Muted });
            if (action.Fix is not null)
            {
                p.AddLineBreak();
                p.AddText(action.Fix);
            }
        }
    }

    private static void AddSection(Section section, ViewSection area)
    {
        section.AddParagraph(area.Heading, StyleNames.Heading2);
        if (area.NoProblems is not null)
        {
            Small(section.AddParagraph(area.NoProblems), Good).Format.Font.Bold = true;
        }

        if (area.Findings.Count > 0)
        {
            section.AddParagraph(area.ProblemsHeading, StyleNames.Heading3);
            foreach (var finding in area.Findings)
            {
                AddFinding(section, finding);
            }
        }

        foreach (var list in area.Lists)
        {
            section.AddParagraph(list.Heading, StyleNames.Heading3);
            var mark = list.Kind switch { "passed" => "✓", "failed" => "!", _ => "–" };
            foreach (var check in list.Items)
            {
                var p = section.AddParagraph();
                p.Format.LeftIndent = Unit.FromCentimeter(0.5);
                p.Format.FirstLineIndent = Unit.FromCentimeter(-0.5);
                p.AddText(mark + " ");
                p.AddFormattedText(check.Id, new Font { Color = Muted, Size = 8 });
                p.AddText(" " + check.Title);
                if (check.Detail is not null)
                {
                    p.AddFormattedText(": " + check.Detail, new Font { Color = Muted });
                }
            }
        }
    }

    private static void AddFinding(Section section, ViewFinding finding)
    {
        // One table cell per finding: a border around it, and it is not split across pages when it fits on one.
        var table = section.AddTable();
        table.Borders.Color = Line;
        table.Borders.Width = 0.5;
        table.AddColumn(Unit.FromCentimeter(17));
        var row = table.AddRow();
        var cell = row.Cells[0];
        cell.Format.LeftIndent = Unit.FromPoint(4);
        cell.Format.RightIndent = Unit.FromPoint(4);

        var title = cell.AddParagraph();
        title.Format.SpaceBefore = Unit.FromPoint(4);
        Badge(title, finding.Severity, finding.Class);
        title.AddFormattedText(" " + finding.Title + " ", TextFormat.Bold);
        title.AddFormattedText(finding.Id, new Font { Color = Muted, Size = 8 });
        Small(cell.AddParagraph(finding.Target), Muted);

        foreach (var detail in finding.Details)
        {
            Labelled(cell.AddParagraph(), detail.Label, detail.Value);
        }

        foreach (var note in finding.Notes)
        {
            Small(cell.AddParagraph(note), Warning);
        }

        section.AddParagraph().Format.SpaceAfter = Unit.FromPoint(2);
    }

    private static void Badge(Paragraph paragraph, string label, string cssClass)
    {
        // MigraDoc has no background for a run of text: the severity is shown in its colour instead.
        var text = paragraph.AddFormattedText($"[{label.ToUpperInvariant()}]", TextFormat.Bold);
        text.Font.Color = SeverityColor(cssClass);
        text.Font.Size = 8.5;
    }

    private static void Labelled(Paragraph paragraph, string label, string value)
    {
        if (label.Length > 0)
        {
            paragraph.AddFormattedText(label + ": ", TextFormat.Bold);
        }

        paragraph.AddText(value);
    }

    private static Paragraph Small(Paragraph paragraph, Color color)
    {
        paragraph.Format.Font.Color = color;
        return paragraph;
    }
}
