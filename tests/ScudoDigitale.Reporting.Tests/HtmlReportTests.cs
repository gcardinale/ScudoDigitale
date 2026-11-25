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

public sealed class HtmlReportTests
{
    [Fact]
    public void Render_WhenCalled_ShouldBeOneFileWithNoExternalResources()
    {
        var html = HtmlReport.Render(Make.Document());

        Assert.StartsWith("<!DOCTYPE html>", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<link", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("src=", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("url(", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("@import", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain('\r', html);
    }

    [Fact]
    public void Render_WhenFindingsQuoteMarkup_ShouldEscapeEveryText()
    {
        const string Attack = "<script>alert(1)</script>\"><img src=x onerror=alert(2)>";
        var hostile = new Finding("WEB-CSP-001", CheckArea.Web, Attack, Severity.High, Confidence.Certain, Attack)
        {
            Evidence = Attack,
            Risk = Attack,
            Fix = Attack,
            References = [Attack],
        };
        var target = new Target(TargetKind.Website, "evil.example");
        var document = ReportBuilder.Build(
            new ScopeDeclaration(Attack, OperatorRole.Owner, [target], Make.DeclaredAt),
            Profile.Company(Attack),
            [Make.Executed(target, "WEB-CSP-001", hostile), Make.Skipped(target, "WEB-HSTS-001", Attack)],
            "0.1.0",
            Make.GeneratedAt,
            [Attack]);

        var html = HtmlReport.Render(document);

        Assert.DoesNotContain("<script", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("<img", html, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("\"><img", html, StringComparison.Ordinal);

        // Title, target, evidence, risk, fix, references, operator, company, note, skip reason, and the
        // title, target and fix of the action: every one of them is there, escaped.
        const string Escaped = "&lt;script&gt;alert(1)&lt;/script&gt;&quot;&gt;&lt;img src=x onerror=alert(2)&gt;";
        Assert.Equal(13, html.Split(Escaped).Length - 1);
    }

    [Fact]
    public void Render_WhenLanguageComesFromAHostileJson_ShouldEscapeTheLangAttribute()
    {
        var document = Make.Document() with { Language = "x\" onmouseover=\"alert(1)" };

        var html = HtmlReport.Render(document);

        Assert.Contains("<html lang=\"x&quot; onmouseover=&quot;alert(1)\">", html, StringComparison.Ordinal);
        Assert.DoesNotContain("onmouseover=\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_WhenPrinted_ShouldKeepFreeTheSpaceOfTheFooterOnEveryPage()
    {
        var html = HtmlReport.Render(Make.Document());

        // The content sits in a table whose footer row, repeated by the browser on every printed page,
        // is taller than the fixed attribution: nothing is drawn under it (checked with Chrome).
        var spacer = html.IndexOf("<tfoot><tr><td><div class=\"footer-space\"></div></td></tr></tfoot>", StringComparison.Ordinal);
        var content = html.IndexOf("<tbody><tr><td>\n<main>", StringComparison.Ordinal);
        var end = html.IndexOf("</main>\n</td></tr></tbody>\n</table>\n<footer class=\"attribution\">", StringComparison.Ordinal);
        Assert.True(spacer > 0 && content > spacer && end > content, html);
        Assert.Contains(".footer-space { height: 16mm; }", html, StringComparison.Ordinal);
        Assert.Contains("footer.attribution { position: fixed; bottom: 0; left: 0; right: 0; height: 12mm;", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_WhenCalled_ShouldEndWithTheAttributionRepeatedOnEveryPrintedPage()
    {
        using var _ = new UiCulture("en-US");

        var html = HtmlReport.Render(Make.Document());

        var footer = $"<footer class=\"attribution\">{Attribution.ReportFooter("0.1.0")}</footer>";
        Assert.Contains(footer, html, StringComparison.Ordinal);
        Assert.Contains("footer.attribution { position: fixed; bottom: 0;", html, StringComparison.Ordinal);
        Assert.EndsWith("</html>\n", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_WhenDocumentIsItalianAndThreadIsEnglish_ShouldUseItalianLabelsAndKeepAccents()
    {
        ReportDocument document;
        using (new UiCulture("it-IT"))
        {
            document = Make.Document();
        }

        using var _ = new UiCulture("en-US");
        var html = HtmlReport.Render(document);

        Assert.Contains("<html lang=\"it-IT\">", html, StringComparison.Ordinal);
        Assert.Contains("<h1>Rapporto di autovalutazione della sicurezza</h1>", html, StringComparison.Ordinal);
        Assert.Contains("<dt>Affidabilità</dt>", html, StringComparison.Ordinal);
        Assert.Contains("Report generato con Scudo Digitale v0.1.0", html, StringComparison.Ordinal);
        // The date format belongs to the platform: ICU (Linux, macOS) and Windows may differ.
        var date = Make.DeclaredAt.ToString("g", System.Globalization.CultureInfo.GetCultureInfo("it-IT"));
        Assert.Contains($"Dichiarato da Mario Rossi (responsabile della sicurezza) il {date}.", html, StringComparison.Ordinal);
        Assert.Contains("25/11/2026", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_WhenCalled_ShouldShowSummaryActionsAndSectionsInOrder()
    {
        using var _ = new UiCulture("en-US");

        var html = HtmlReport.Render(Make.Document());

        Assert.Contains("<li class=\"sev-critical\"><strong>1</strong>Critical</li>", html, StringComparison.Ordinal);
        Assert.Contains("<li class=\"sev-low\"><strong>0</strong>Low</li>", html, StringComparison.Ordinal);
        Assert.Contains("<li><strong>2</strong>Websites</li>", html, StringComparison.Ordinal);
        Assert.Contains("<p>1 checks passed, 1 skipped, 1 could not run. 1 questions answered without problems.</p>", html, StringComparison.Ordinal);
        Assert.Contains("<li><span class=\"badge sev-critical\">Critical</span> <strong>Outdated CMS</strong> <span class=\"target\">(www.example.com)</span><br>Update WordPress.</li>", html, StringComparison.Ordinal);
        Assert.Contains("<section class=\"notes\" aria-label=\"Notes\">", html, StringComparison.Ordinal);

        var web = html.IndexOf("<h2>Websites — www.example.com</h2>", StringComparison.Ordinal);
        var email = html.IndexOf("<h2>Email — example.com</h2>", StringComparison.Ordinal);
        var gdpr = html.IndexOf("<h2>GDPR</h2>", StringComparison.Ordinal);
        Assert.True(web > 0 && email > web && gdpr > email, html);
    }

    [Fact]
    public void Render_WhenFindingIsKevAndRaised_ShouldSayBoth()
    {
        using var _ = new UiCulture("en-US");

        var html = HtmlReport.Render(Make.Document());

        Assert.Contains("<p class=\"finding-note\">In the CISA catalog of vulnerabilities exploited in the wild.</p>", html, StringComparison.Ordinal);
        Assert.Contains("<p class=\"finding-note\">Severity given by the check: Low.</p>", html, StringComparison.Ordinal);
        Assert.Contains("<dt>CVSS</dt><dd>8.8</dd>", html, StringComparison.Ordinal);
        Assert.Contains("<dt>EPSS</dt><dd>0.97</dd>", html, StringComparison.Ordinal);
        Assert.Contains("<li><span class=\"id\">MAIL-DKIM-002</span> Check MAIL-DKIM-002: <span class=\"detail\">no key to look at</span></li>", html, StringComparison.Ordinal);
        Assert.Contains("<li><span class=\"id\">MAIL-SPF-001</span> Check MAIL-SPF-001</li>", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_WhenEveryCheckWasSkipped_ShouldNotSayNoProblems()
    {
        using var _ = new UiCulture("en-US");
        var skippedOnly = ReportBuilder.Build(Make.Scope(Make.Mail), Profile.Individual(), [Make.Skipped(Make.Mail, "MAIL-SPF-001", "offline")], "0.1.0", Make.GeneratedAt);
        var passedOnly = ReportBuilder.Build(Make.Scope(Make.Mail), Profile.Individual(), [Make.Executed(Make.Mail, "MAIL-SPF-001")], "0.1.0", Make.GeneratedAt);

        Assert.DoesNotContain("No problems found.", HtmlReport.Render(skippedOnly), StringComparison.Ordinal);
        var html = HtmlReport.Render(passedOnly);
        Assert.Contains("<p class=\"none\">No problems found.</p>", html, StringComparison.Ordinal);
        Assert.Contains("<p class=\"none\">No urgent action.</p>", html, StringComparison.Ordinal);
        Assert.DoesNotContain("class=\"notes\"", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_WhenAssessmentIsQuestionnaireOnly_ShouldHaveNoAreaCounts()
    {
        using var _ = new UiCulture("en-US");
        var document = ReportBuilder.Build(Make.Scope(), Profile.Individual(), [], "0.1.0", Make.GeneratedAt);

        var html = HtmlReport.Render(document);

        Assert.DoesNotContain("Problems by area", html, StringComparison.Ordinal);
        Assert.Contains("<dt>Checked</dt><dd>no system: questionnaires only</dd>", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Render_WhenDocumentIsNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => HtmlReport.Render(null!));
    }
}
