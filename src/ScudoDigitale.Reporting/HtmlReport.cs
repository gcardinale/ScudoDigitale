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

using System.Text.Encodings.Web;
using System.Text.Unicode;
using Scriban;
using Scriban.Runtime;

namespace ScudoDigitale.Reporting;

/// <summary>
/// The HTML report: one file with no external resources (no fonts, scripts or images to download),
/// readable on screen and printable, with the attribution at the foot of every printed page.
/// </summary>
public static class HtmlReport
{
    private const string TemplateResource = "ScudoDigitale.Reporting.Templates.report.html.sbn";

    // Accents stay readable; <, >, &, quotes and everything else that could become markup are escaped.
    private static readonly HtmlEncoder Encoder = HtmlEncoder.Create(UnicodeRanges.All);

    private static readonly Lazy<Template> Template = new(LoadTemplate);

    /// <summary>Renders a document as HTML.</summary>
    /// <param name="document">The report.</param>
    /// <returns>The HTML page, with LF line endings.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="document"/> is <see langword="null"/>.</exception>
    public static string Render(ReportDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        // Every text is escaped here, before the template sees it: findings quote what remote sites and
        // DNS servers returned, and the template must not be able to forget an escape.
        var view = Encode(ReportView.Of(document));

        var globals = new ScriptObject();
        globals.Import(view);
        var context = new TemplateContext { StrictVariables = true };
        context.PushGlobal(globals);
        return Template.Value.Render(context).ReplaceLineEndings("\n");
    }

    private static Template LoadTemplate()
    {
        using var stream = typeof(HtmlReport).Assembly.GetManifestResourceStream(TemplateResource)
            ?? throw new InvalidOperationException($"Missing resource {TemplateResource}.");
        using var reader = new StreamReader(stream);
        var template = Scriban.Template.Parse(reader.ReadToEnd(), TemplateResource);
        return template.HasErrors
            ? throw new InvalidOperationException($"The report template is not valid: {string.Join("; ", template.Messages)}")
            : template;
    }

    private static ReportView Encode(ReportView v) => v with
    {
        Language = E(v.Language),
        Title = E(v.Title),
        Disclaimer = E(v.Disclaimer),
        Facts = v.Facts.Select(Encode).ToArray(),
        NotesHeading = E(v.NotesHeading),
        Notes = v.Notes.Select(E).ToArray(),
        Summary = v.Summary with
        {
            Heading = E(v.Summary.Heading),
            SeverityHeading = E(v.Summary.SeverityHeading),
            Severities = v.Summary.Severities.Select(Encode).ToArray(),
            AreaHeading = E(v.Summary.AreaHeading),
            Areas = v.Summary.Areas.Select(Encode).ToArray(),
            Checks = E(v.Summary.Checks),
            ActionsHeading = E(v.Summary.ActionsHeading),
            Actions = v.Summary.Actions.Select(a => new ViewAction(E(a.Severity), E(a.Class), E(a.Title), E(a.Target), EOrNull(a.Fix))).ToArray(),
            NoActions = E(v.Summary.NoActions),
        },
        Sections = v.Sections.Select(s => new ViewSection(
            E(s.Heading),
            EOrNull(s.NoProblems),
            E(s.ProblemsHeading),
            s.Findings.Select(f => new ViewFinding(E(f.Severity), E(f.Class), E(f.Id), E(f.Title), E(f.Target), f.Details.Select(Encode).ToArray(), f.Notes.Select(E).ToArray())).ToArray(),
            s.Lists.Select(l => new ViewList(E(l.Heading), E(l.Kind), l.Items.Select(i => new ReportCheck(E(i.Id), E(i.Title), EOrNull(i.Detail))).ToArray())).ToArray())).ToArray(),
        Footer = E(v.Footer),
    };

    private static ViewFact Encode(ViewFact fact) => new(E(fact.Label), E(fact.Value));

    private static ViewCount Encode(ViewCount count) => count with { Label = E(count.Label), Class = E(count.Class) };

    private static string E(string text) => Encoder.Encode(text);

    private static string? EOrNull(string? text) => text is null ? null : Encoder.Encode(text);
}
