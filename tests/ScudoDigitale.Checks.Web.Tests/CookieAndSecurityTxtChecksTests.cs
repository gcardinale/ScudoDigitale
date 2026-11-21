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

public sealed class SetCookieTests
{
    [Fact]
    public void TryParse_WhenCookieHasEveryAttribute_ShouldReadThemWithoutKeepingTheValue()
    {
        var cookie = SetCookie.TryParse("SID=s3cr3t-value; Path=/; secure; HTTPONLY; SameSite=Strict; Max-Age=3600");

        Assert.NotNull(cookie);
        Assert.Equal("SID", cookie.Name);
        Assert.True(cookie.Secure);
        Assert.True(cookie.HttpOnly);
        Assert.Equal("strict", cookie.SameSite);
        Assert.Equal("SID=…; Path=/; secure; HTTPONLY; SameSite=Strict; Max-Age=3600", cookie.Display);
        Assert.DoesNotContain("s3cr3t", cookie.Display, StringComparison.Ordinal);
    }

    [Fact]
    public void TryParse_WhenCookieHasNoAttributes_ShouldHaveNone()
    {
        var cookie = SetCookie.TryParse("lang=it");

        Assert.Equal(new { Secure = false, HttpOnly = false, SameSite = (string?)null }, new { cookie!.Secure, cookie.HttpOnly, cookie.SameSite });
        Assert.Equal("lang=…", cookie.Display);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ; ")]
    [InlineData("novalue")]
    [InlineData("=orphan; Secure")]
    public void TryParse_WhenHeaderHasNoCookieName_ShouldReturnNull(string header)
    {
        Assert.Null(SetCookie.TryParse(header));
    }

    [Theory]
    [InlineData("PHPSESSID", true)]
    [InlineData("JSESSIONID", true)]
    [InlineData("connect.sid", true)]
    [InlineData("auth_token", true)]
    [InlineData("wordpress_logged_in_login", true)]
    [InlineData("csrftoken", false)]
    [InlineData("XSRF-TOKEN", false)]
    [InlineData("lang", false)]
    [InlineData("cookie_consent", false)]
    public void LooksLikeSession_WhenCalled_ShouldRecogniseSessionNamesButNotAntiForgeryTokens(string name, bool expected)
    {
        Assert.Equal(expected, SetCookie.TryParse(name + "=x")!.LooksLikeSession);
    }
}

public sealed class CookieChecksTests
{
    [Theory]
    [InlineData(CookieChecks.SecureId)]
    [InlineData(CookieChecks.HttpOnlyId)]
    [InlineData(CookieChecks.SameSiteId)]
    public async Task Checks_WhenSiteSetsNoCookies_ShouldBeSkippedSayingSo(string id)
    {
        var visit = Site.Good().WithHeader("Set-Cookie", "not-a-cookie");

        using var culture = new UiCulture("en-US");
        var skipped = Assert.IsType<CheckResult.Skipped>(await Make.RunAsync(visit, id));

        Assert.Equal("Skipped: the site sets no cookies on a first visit.", skipped.Reason);
    }

    [Fact]
    public async Task Secure_WhenCookieHasNoSecure_ShouldReportMediumWithoutTheValue()
    {
        var visit = Site.Good().WithHeader("Set-Cookie", "session=t0ps3cret; Path=/; HttpOnly; SameSite=Lax", "lang=it; Secure");

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, CookieChecks.SecureId);

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(Confidence.Certain, finding.Confidence);
        Assert.Equal("Cookie without Secure (session)", finding.Title);
        Assert.Equal("session=…; Path=/; HttpOnly; SameSite=Lax", finding.Evidence);
    }

    [Theory]
    [InlineData("PHPSESSID=abc; Secure", Severity.Medium)]
    [InlineData("lang=it; Secure", Severity.Low)]
    public async Task HttpOnly_WhenCookieHasNoHttpOnly_ShouldReportProbableAndHigherForSessionNames(string header, Severity expected)
    {
        var finding = await Make.SingleFindingAsync(Site.Good().WithHeader("Set-Cookie", header), CookieChecks.HttpOnlyId);

        Assert.Equal(expected, finding.Severity);
        Assert.Equal(Confidence.Probable, finding.Confidence);
    }

    [Theory]
    [InlineData("a=1; Secure; SameSite=None", null)]
    [InlineData("a=1; SameSite=STRICT", null)]
    [InlineData("a=1; SameSite=None", Severity.Medium)]
    [InlineData("a=1; Secure", Severity.Low)]
    [InlineData("a=1; Secure; SameSite=Sometimes", Severity.Low)]
    public async Task SameSite_WhenCalled_ShouldReportMissingValuesAndNoneWithoutSecure(string header, Severity? expected)
    {
        var findings = await Make.FindingsAsync(Site.Good().WithHeader("Set-Cookie", header), CookieChecks.SameSiteId);

        Assert.Equal(expected, findings.SingleOrDefault()?.Severity);
    }

    [Fact]
    public async Task Checks_WhenRedirectsSetCookiesToo_ShouldEvaluateThemAndKeepTheLastOfEachName()
    {
        var visit = Site.Good() with
        {
            Https = Site.Response(
                Site.Hop("https://example.com/", 302, null, ("Location", "https://www.example.com/"), ("Set-Cookie", "first=1"), ("Set-Cookie", "twice=1")),
                Site.Hop("https://www.example.com/", 200, null, ("Set-Cookie", "twice=2; Secure"))),
        };

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, CookieChecks.SecureId);

        Assert.Equal("Cookie without Secure (first)", finding.Title);
    }
}

public sealed class SecurityTxtChecksTests
{
    private const string Id = SecurityTxtChecks.FileId;

    [Fact]
    public async Task File_WhenHttpsDoesNotAnswer_ShouldBeSkipped()
    {
        var visit = Site.Good() with { Https = Trail.Failed("https://example.com/: refused"), Certificates = [], SecurityTxt = null };

        Assert.IsType<CheckResult.Skipped>(await Make.RunAsync(visit, Id));
    }

    [Fact]
    public async Task File_WhenRequestFails_ShouldFailWithTheError()
    {
        var visit = Site.Good() with { SecurityTxt = Trail.Failed("timeout") };

        using var culture = new UiCulture("en-US");
        Assert.Equal("The request for security.txt failed: timeout", Assert.IsType<CheckResult.Failed>(await Make.RunAsync(visit, Id)).Error);
    }

    [Fact]
    public async Task File_WhenItRedirectsWithoutEnd_ShouldFail()
    {
        var visit = Site.Good() with
        {
            SecurityTxt = Site.Stopped(TrailEnd.TooManyRedirects, "https://example.com/x", Site.RedirectHop("https://example.com/.well-known/security.txt", "/x")),
        };

        Assert.IsType<CheckResult.Failed>(await Make.RunAsync(visit, Id));
    }

    [Theory]
    [InlineData(TrailEnd.LeftSite, "https://vendor.example/security.txt")]
    [InlineData(TrailEnd.ChangedScheme, "http://example.com/security.txt")]
    internal async Task File_WhenItRedirectsElsewhere_ShouldReportInfoToBeVerifiedWithoutFollowing(TrailEnd end, string next)
    {
        var visit = Site.Good() with
        {
            SecurityTxt = Site.Stopped(end, next, Site.RedirectHop("https://example.com/.well-known/security.txt", next)),
        };

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, Id);

        Assert.Equal(Severity.Info, finding.Severity);
        Assert.Equal(Confidence.ToBeVerified, finding.Confidence);
        Assert.Equal("security.txt redirects to another address, not followed", finding.Title);
        Assert.Equal("https://example.com/.well-known/security.txt → " + next, finding.Evidence);
    }

    [Fact]
    public async Task File_WhenThereIsNone_ShouldReportInfoWithAddressAndStatus()
    {
        var visit = Site.Good() with { SecurityTxt = Site.Response(Site.Hop("https://example.com/.well-known/security.txt", 404)) };

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, Id);

        Assert.Equal(Severity.Info, finding.Severity);
        Assert.Equal(Confidence.Certain, finding.Confidence);
        Assert.Equal("No security.txt file at https://example.com/.well-known/security.txt (HTTP 404).", finding.Evidence);
    }

    [Fact]
    public async Task File_WhenContactIsMissing_ShouldReportLow()
    {
        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(Site.Good().WithSecurityTxt("Contact:\nExpires: 2027-01-01T00:00:00Z"), Id);

        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal("security.txt without a contact", finding.Title);
    }

    [Theory]
    [InlineData("Contact: mailto:a@example.com\n")]
    [InlineData("Contact: mailto:a@example.com\nExpires: soon\n")]
    public async Task File_WhenExpiresIsMissingOrUnreadable_ShouldReportLow(string text)
    {
        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(Site.Good().WithSecurityTxt(text), Id);

        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal("security.txt without a valid expiry date", finding.Title);
    }

    [Fact]
    public async Task File_WhenExpired_ShouldReportLowWithTheDate()
    {
        var text = "CONTACT: https://example.com/report\r\nexpires: 2026-11-21T09:59:59Z\r\n";

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(Site.Good().WithSecurityTxt(text), Id);

        Assert.Equal("security.txt expired", finding.Title);
        Assert.Equal("https://example.com/.well-known/security.txt — Expires: 2026-11-21T09:59:59Z", finding.Evidence);
    }

    [Fact]
    public async Task File_WhenItExpiresExactlyNow_ShouldFindNothing()
    {
        Assert.Empty(await Make.FindingsAsync(Site.Good().WithSecurityTxt("Contact: mailto:a@example.com\nExpires: 2026-11-21T10:00:00Z"), Id));
    }

    [Fact]
    public async Task File_WhenItHasNoFieldAtAll_ShouldReportBothGaps()
    {
        var findings = await Make.FindingsAsync(Site.Good().WithSecurityTxt("# nothing here\n\nhello"), Id);

        Assert.Equal(2, findings.Count);
    }

    [Fact]
    public void Fields_WhenFileHasCommentsAndSignature_ShouldReturnOnlyTheFieldsWithAValue()
    {
        var fields = SecurityTxtChecks.Fields("-----BEGIN PGP SIGNED MESSAGE-----\n# Contact: commented@example.com\n\nContact: mailto:a@example.com\nPreferred-Languages: it, en\nEmpty:\n");

        Assert.Equal([("contact", "mailto:a@example.com"), ("preferred-languages", "it, en")], fields);
    }
}
