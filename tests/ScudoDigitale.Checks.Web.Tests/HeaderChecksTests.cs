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

namespace ScudoDigitale.Checks.Web.Tests;

public sealed class HstsTests
{
    [Theory]
    [InlineData("max-age=31536000", 31536000L)]
    [InlineData("includeSubDomains; MAX-AGE = \"600\" ; preload", 600L)]
    [InlineData("max-age=0", 0L)]
    [InlineData("max-age=1; max-age=2", 1L)]
    [InlineData("includeSubDomains", null)]
    [InlineData("max-age", null)]
    [InlineData("max-age=abc", null)]
    [InlineData("max-age=-5", null)]
    [InlineData("", null)]
    public void MaxAge_WhenCalled_ShouldReadTheFirstValidDirective(string value, long? expected)
    {
        Assert.Equal(expected, Hsts.MaxAge(value));
    }

    [Fact]
    public async Task Check_WhenHeaderIsMissing_ShouldReportMediumNamingThePage()
    {
        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(Site.Good().WithHeader("Strict-Transport-Security"), HeaderChecks.HstsId);

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("HSTS not enabled", finding.Title);
        Assert.Equal("The response of https://example.com/ has no Strict-Transport-Security header.", finding.Evidence);
    }

    [Theory]
    [InlineData("includeSubDomains", Severity.Medium, "HSTS header not valid (no max-age)")]
    [InlineData("max-age=0", Severity.Medium, "HSTS switched off (max-age=0)")]
    [InlineData("max-age=15551999", Severity.Low, "HSTS with a short duration (less than 6 months)")]
    public async Task Check_WhenHeaderIsWeak_ShouldReportWithTheValue(string value, Severity severity, string title)
    {
        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(Site.Good().WithHeader("Strict-Transport-Security", value), HeaderChecks.HstsId);

        Assert.Equal(severity, finding.Severity);
        Assert.Equal(title, finding.Title);
        Assert.Equal("Strict-Transport-Security: " + value, finding.Evidence);
    }

    [Fact]
    public async Task Check_WhenMaxAgeIsExactlySixMonths_ShouldFindNothing()
    {
        Assert.Empty(await Make.FindingsAsync(Site.Good().WithHeader("strict-transport-security", "max-age=15552000"), HeaderChecks.HstsId));
    }

    [Fact]
    public async Task Check_WhenHeaderIsSentTwice_ShouldUseOnlyTheFirst()
    {
        var visit = Site.Good().WithHeader("Strict-Transport-Security", "max-age=0", "max-age=31536000");

        Assert.Single(await Make.FindingsAsync(visit, HeaderChecks.HstsId));
    }
}

public sealed class ContentSecurityPolicyTests
{
    [Theory]
    [InlineData("default-src 'self'", true)]
    [InlineData("script-src 'self' https://cdn.example.net; default-src *", true)]
    [InlineData("SCRIPT-SRC 'NONE'", true)]
    [InlineData("script-src 'nonce-abc' 'unsafe-inline'", true)]
    [InlineData("script-src 'sha256-abc' 'unsafe-inline'", true)]
    [InlineData("script-src 'strict-dynamic' 'nonce-abc' https: 'unsafe-inline'", true)]
    [InlineData("script-src 'self' 'unsafe-inline'", false)]
    [InlineData("script-src 'self' 'unsafe-eval'", false)]
    [InlineData("script-src 'strict-dynamic' 'unsafe-eval'", false)]
    [InlineData("script-src 'nonce-abc' https:", false)]
    [InlineData("script-src *", false)]
    [InlineData("script-src data:", false)]
    [InlineData("script-src http:", false)]
    [InlineData("default-src 'self' 'unsafe-inline'", false)]
    [InlineData("script-src 'self'; script-src *", true)]
    [InlineData("img-src 'self'; frame-ancestors 'none'", false)]
    public void RestrictsScripts_WhenCalled_ShouldSayWhetherThePolicyLimitsScripts(string text, bool expected)
    {
        Assert.Equal(expected, Assert.Single(ContentSecurityPolicy.Parse([text])).RestrictsScripts());
    }

    [Fact]
    public void Parse_WhenValuesListSeveralPoliciesOrNone_ShouldSplitThemAndDropTheEmptyOnes()
    {
        var policies = ContentSecurityPolicy.Parse(["default-src 'self', frame-ancestors 'none' ; ;", " ; ", ""]);

        Assert.Equal(2, policies.Count);
        Assert.Equal(["'self'"], policies[0].Sources("default-src"));
        Assert.Null(policies[0].Sources("frame-ancestors"));
        Assert.Equal(["'none'"], policies[1].Sources("frame-ancestors"));
        Assert.All(policies, p => Assert.False(p.IsEmpty));
    }

    [Fact]
    public async Task Check_WhenThereIsNoPolicy_ShouldReportMedium()
    {
        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(Site.Good().WithHeader("Content-Security-Policy"), HeaderChecks.CspId);

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("No Content-Security-Policy", finding.Title);
    }

    [Fact]
    public async Task Check_WhenPolicyIsOnlyReported_ShouldReportLowWithTheHeader()
    {
        var visit = Site.Good().WithPageHeaders(("Content-Security-Policy-Report-Only", "default-src 'self'"));

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, HeaderChecks.CspId);

        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal("Content-Security-Policy in report-only mode", finding.Title);
        Assert.Equal("Content-Security-Policy-Report-Only: default-src 'self'", finding.Evidence);
    }

    [Fact]
    public async Task Check_WhenPolicyDoesNotLimitScripts_ShouldReportLowWithThePolicy()
    {
        var visit = Site.Good().WithHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'");

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, HeaderChecks.CspId);

        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal("Content-Security-Policy that does not limit scripts", finding.Title);
        Assert.Equal("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'", finding.Evidence);
    }

    [Fact]
    public async Task Check_WhenOneOfTwoPoliciesLimitsScripts_ShouldFindNothing()
    {
        var visit = Site.Good().WithHeader("Content-Security-Policy", "script-src * 'unsafe-inline'", "script-src 'self'");

        Assert.Empty(await Make.FindingsAsync(visit, HeaderChecks.CspId));
    }

    [Fact]
    public async Task Check_WhenPolicyIsInAMetaElement_ShouldCountIt()
    {
        var visit = Site.Good().WithHeader("Content-Security-Policy")
            .WithBody("""<html><head><meta http-equiv="Content-Security-Policy" content="default-src &#39;self&#39;"></head></html>""");

        Assert.Empty(await Make.FindingsAsync(visit, HeaderChecks.CspId));
    }

    [Fact]
    public async Task Check_WhenPolicyIsVeryLong_ShouldShortenTheEvidence()
    {
        var policy = "script-src 'unsafe-inline' " + string.Join(' ', Enumerable.Range(0, 60).Select(i => $"https://cdn{i}.example.net"));

        var finding = await Make.SingleFindingAsync(Site.Good().WithHeader("Content-Security-Policy", policy), HeaderChecks.CspId);

        Assert.Equal("Content-Security-Policy: ".Length + WebFinding.MaxEvidenceLength + 1, finding.Evidence!.Length);
        Assert.EndsWith("…", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void Header_WhenValueIsExactlyAtTheLimit_ShouldNotShortenIt()
    {
        var value = new string('x', WebFinding.MaxEvidenceLength);

        Assert.Equal("H: " + value, WebFinding.Header("H", value));
    }
}

public sealed class HtmlMetaTests
{
    [Fact]
    public void Contents_WhenPageHasMatchingMetaElements_ShouldReturnTheirDecodedContentInOrder()
    {
        const string Html = """
            <html><head>
            <META NAME='Referrer' CONTENT='no-referrer'>
            <meta content="strict-origin" name=referrer />
            <meta name="viewport" content="width=device-width">
            <meta name="referrer">
            <meta http-equiv="Content-Security-Policy" content="default-src &#39;self&#39;; img-src *">
            </head></html>
            """;

        Assert.Equal(["no-referrer", "strict-origin"], HtmlMeta.Contents(Html, "name", "referrer"));
        Assert.Equal(["default-src 'self'; img-src *"], HtmlMeta.Contents(Html, "http-equiv", "content-security-policy"));
        Assert.Empty(HtmlMeta.Contents(Html, "name", "robots"));
    }

    [Fact]
    public void Contents_WhenPageWasNotRead_ShouldReturnNothing()
    {
        Assert.Empty(HtmlMeta.Contents(null, "name", "referrer"));
    }
}

public sealed class OtherHeaderChecksTests
{
    [Fact]
    public async Task Frame_WhenNeitherHeaderNorFrameAncestors_ShouldReportMedium()
    {
        var visit = Site.Good().WithPageHeaders(("Content-Security-Policy", "default-src 'self'"));

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, HeaderChecks.FrameId);

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("The response of https://example.com/ has no X-Frame-Options header.", finding.Evidence);
    }

    [Theory]
    [InlineData("deny")]
    [InlineData(" SAMEORIGIN ")]
    [InlineData("DENY, DENY")]
    public async Task Frame_WhenXFrameOptionsIsValid_ShouldFindNothing(string value)
    {
        var visit = Site.Good().WithPageHeaders(("X-Frame-Options", value));

        Assert.Empty(await Make.FindingsAsync(visit, HeaderChecks.FrameId));
    }

    [Theory]
    [InlineData("ALLOW-FROM https://partner.example")]
    [InlineData("ALLOWALL")]
    [InlineData("DENY, SAMEORIGIN, nonsense")]
    public async Task Frame_WhenXFrameOptionsHasAValueBrowsersIgnore_ShouldReportMediumLikeAMissingHeader(string value)
    {
        var visit = Site.Good().WithPageHeaders(("X-Frame-Options", value));

        var finding = await Make.SingleFindingAsync(visit, HeaderChecks.FrameId);

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("X-Frame-Options: " + value, finding.Evidence);
    }

    [Fact]
    public async Task Frame_WhenPolicyHasFrameAncestors_ShouldFindNothingWhateverXFrameOptionsSays()
    {
        var visit = Site.Good().WithPageHeaders(("Content-Security-Policy", "frame-ancestors 'self'"), ("X-Frame-Options", "ALLOWALL"));

        Assert.Empty(await Make.FindingsAsync(visit, HeaderChecks.FrameId));
    }

    [Theory]
    [InlineData("frame-ancestors *")]
    [InlineData("frame-ancestors 'self' https:")]
    [InlineData("frame-ancestors http:")]
    public async Task Frame_WhenFrameAncestorsAllowsAnySite_ShouldNotCountItAsProtection(string policy)
    {
        var visit = Site.Good().WithPageHeaders(("Content-Security-Policy", policy));

        Assert.Equal(Severity.Medium, (await Make.SingleFindingAsync(visit, HeaderChecks.FrameId)).Severity);
    }

    [Fact]
    public async Task Frame_WhenFrameAncestorsIsOnlyInAMetaElement_ShouldNotCountIt()
    {
        var visit = Site.Good().WithPageHeaders()
            .WithBody("""<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none'">""");

        Assert.Single(await Make.FindingsAsync(visit, HeaderChecks.FrameId));
    }

    [Fact]
    public async Task Nosniff_WhenHeaderIsMissing_ShouldReportLow()
    {
        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(Site.Good().WithHeader("X-Content-Type-Options"), HeaderChecks.NosniffId);

        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal("No X-Content-Type-Options", finding.Title);
    }

    [Fact]
    public async Task Nosniff_WhenValueIsNotNosniff_ShouldReportLowWithTheValue()
    {
        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(Site.Good().WithHeader("X-Content-Type-Options", "sniff"), HeaderChecks.NosniffId);

        Assert.Equal("X-Content-Type-Options is not nosniff", finding.Title);
        Assert.Equal("X-Content-Type-Options: sniff", finding.Evidence);
    }

    [Fact]
    public async Task Nosniff_WhenValueIsNosniffInAnyCase_ShouldFindNothing()
    {
        Assert.Empty(await Make.FindingsAsync(Site.Good().WithHeader("X-Content-Type-Options", " NoSniff "), HeaderChecks.NosniffId));
    }

    [Fact]
    public async Task Nosniff_WhenSeveralValuesAreSent_ShouldJudgeTheFirstAsBrowsersDo()
    {
        var joined = Site.Good().WithHeader("X-Content-Type-Options", "nosniff, nosniff");
        var twice = Site.Good().WithHeader("X-Content-Type-Options", "nosniff", "sniff");
        var wrongFirst = Site.Good().WithHeader("X-Content-Type-Options", "sniff, nosniff");

        Assert.Empty(await Make.FindingsAsync(joined, HeaderChecks.NosniffId));
        Assert.Empty(await Make.FindingsAsync(twice, HeaderChecks.NosniffId));
        Assert.Equal("X-Content-Type-Options: sniff, nosniff", (await Make.SingleFindingAsync(wrongFirst, HeaderChecks.NosniffId)).Evidence);
    }

    [Fact]
    public async Task Checks_WhenTheAddressOfThePageCarriesASessionIdentifier_ShouldNotShowItInTheEvidence()
    {
        // A site that receives no cookie may move the session into the address of its first redirect.
        var visit = Site.Good() with
        {
            Https = Site.Response(
                Site.RedirectHop("https://example.com/", "/app/;jsessionid=5EC2E7"),
                Site.Hop("https://example.com/app/;jsessionid=5EC2E7?token=abc")),
        };

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, HeaderChecks.HstsId);

        Assert.Equal("The response of https://example.com/app/;…?… has no Strict-Transport-Security header.", finding.Evidence);
    }

    [Theory]
    [InlineData("https://example.com/", "https://example.com/")]
    [InlineData("https://example.com/a/b.html#top", "https://example.com/a/b.html")]
    [InlineData("https://user:pass@example.com:8443/a?x=1&sid=SECRET", "https://example.com:8443/a?…")]
    [InlineData("http://example.com/app/;jsessionid=SECRET/next?y", "http://example.com/app/;…?…")]
    public void Show_WhenCalled_ShouldDropPathParametersQueryFragmentAndUserInformation(string url, string expected)
    {
        Assert.Equal(expected, SafeUrl.Show(new Uri(url)));
    }

    [Fact]
    public async Task Referrer_WhenThereIsNoPolicy_ShouldReportLowNamingThePage()
    {
        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(Site.Good().WithHeader("Referrer-Policy"), HeaderChecks.ReferrerId);

        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal("No Referrer-Policy", finding.Title);
        Assert.Equal("The response of https://example.com/ has no Referrer-Policy header.", finding.Evidence);
    }

    [Fact]
    public async Task Referrer_WhenValueIsNotAKnownPolicy_ShouldReportItAsMissingWithTheValue()
    {
        var finding = await Make.SingleFindingAsync(Site.Good().WithHeader("Referrer-Policy", "always"), HeaderChecks.ReferrerId);

        Assert.Equal("Referrer-Policy: always", finding.Evidence);
    }

    [Theory]
    [InlineData("unsafe-url")]
    [InlineData("No-Referrer-When-Downgrade")]
    [InlineData("no-referrer, unsafe-url, made-up-policy")]
    public async Task Referrer_WhenEffectivePolicySendsTheFullAddress_ShouldReportLow(string value)
    {
        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(Site.Good().WithHeader("Referrer-Policy", value), HeaderChecks.ReferrerId);

        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal("Referrer-Policy that sends the full address to other sites", finding.Title);
    }

    [Theory]
    [InlineData("no-referrer")]
    [InlineData("unsafe-url, strict-origin-when-cross-origin")]
    [InlineData("same-origin")]
    public async Task Referrer_WhenEffectivePolicyIsStrict_ShouldFindNothing(string value)
    {
        Assert.Empty(await Make.FindingsAsync(Site.Good().WithHeader("Referrer-Policy", value), HeaderChecks.ReferrerId));
    }

    [Theory]
    [InlineData("Always", 1)]
    [InlineData("default", 1)]
    [InlineData("never", 0)]
    [InlineData("origin-when-crossorigin", 0)]
    public async Task Referrer_WhenMetaElementUsesAnOldValue_ShouldReadItAsBrowsersDo(string content, int findings)
    {
        var visit = Site.Good().WithHeader("Referrer-Policy").WithBody($"<meta name=\"referrer\" content=\"{content}\">");

        Assert.Equal(findings, (await Make.FindingsAsync(visit, HeaderChecks.ReferrerId)).Count);
    }

    [Fact]
    public async Task Referrer_WhenHeaderUsesAnOldMetaValue_ShouldNotAcceptIt()
    {
        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(Site.Good().WithHeader("Referrer-Policy", "never"), HeaderChecks.ReferrerId);

        Assert.Equal("No Referrer-Policy", finding.Title);
    }

    [Fact]
    public async Task Referrer_WhenPolicyIsInAMetaElement_ShouldCountIt()
    {
        var visit = Site.Good().WithHeader("Referrer-Policy").WithBody("""<meta name="referrer" content="no-referrer">""");

        Assert.Empty(await Make.FindingsAsync(visit, HeaderChecks.ReferrerId));
    }

    [Fact]
    public async Task Permissions_WhenHeaderIsMissing_ShouldReportInfo()
    {
        using var culture = new UiCulture("it-IT");
        var finding = await Make.SingleFindingAsync(Site.Good().WithHeader("Permissions-Policy"), HeaderChecks.PermissionsId);

        Assert.Equal(Severity.Info, finding.Severity);
        Assert.Equal("Permissions-Policy assente", finding.Title);
        Assert.Equal("La risposta di https://example.com/ non ha l'intestazione Permissions-Policy.", finding.Evidence);
    }
}
