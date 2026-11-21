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

using System.Collections.Concurrent;
using System.Net;

namespace ScudoDigitale.Checks.Web.Tests;

/// <summary>The real fetcher against a local server: real connections, real TLS, no network.</summary>
public sealed class HttpSiteFetcherTests(TestPki pki) : IClassFixture<TestPki>
{
    private const string Host = TestSite.Host;

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenSiteIsWellConfigured_ShouldMakeOnlyTheRequestsOfAFirstVisit()
    {
        await using var site = new TestSite(pki);

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(Host, visit.Host);
        Assert.InRange(visit.VisitedAt, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.Equal(TrailEnd.ChangedScheme, visit.Http.End);
        Assert.Equal("http://site.test/ → https://site.test/", visit.Http.Path);
        Assert.Equal(301, Assert.Single(visit.Http.Hops).Status);

        Assert.Equal(TrailEnd.Response, visit.Https.End);
        var page = Assert.Single(visit.Https.Hops);
        Assert.Equal(200, page.Status);
        Assert.Contains("<title>Home</title>", page.Body, StringComparison.Ordinal);
        Assert.Equal("max-age=31536000; includeSubDomains", Assert.Single(page.Values("strict-transport-security")));
        Assert.Equal("default-src 'self'; frame-ancestors 'none'", Assert.Single(page.Values("Content-Security-Policy")));
        Assert.Equal("text/html; charset=utf-8", Assert.Single(page.Values("Content-Type")));

        Assert.NotNull(visit.SecurityTxt);
        Assert.StartsWith("Contact: mailto:security@site.test", visit.SecurityTxt.Hops[^1].Body, StringComparison.Ordinal);

        Assert.Equal(
            ["http /", "https /", "https /.well-known/security.txt"],
            site.Requests.Select(r => $"{(r.Secure ? "https" : "http")} {r.Path}").Order());
        Assert.All(site.Requests, r =>
        {
            Assert.Equal(Host, r.Host);
            Assert.Equal(HttpSiteFetcher.UserAgent, r.Headers["User-Agent"]);
            Assert.False(r.Headers.ContainsKey("Cookie"));
        });
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenCertificateIsIssuedByTheTrustedRoot_ShouldDescribeItAsTrustedAndMatching()
    {
        await using var site = new TestSite(pki);

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        var certificate = Assert.Single(visit.Certificates);
        Assert.Equal(Host, certificate.Host);
        Assert.Equal(["site.test", "www.site.test"], certificate.Names);
        Assert.True(certificate.NameMatches);
        Assert.Equal(ChainState.Trusted, certificate.Chain);
        Assert.Equal("NoError", certificate.ChainDetail);
        Assert.InRange(certificate.NotAfter, DateTimeOffset.UtcNow.AddDays(79), DateTimeOffset.UtcNow.AddDays(81));
        Assert.InRange(certificate.NotBefore, DateTimeOffset.UtcNow.AddDays(-11), DateTimeOffset.UtcNow.AddDays(-9));
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenCertificateIsExpired_ShouldStillReadThePageAndLeaveTheDatesToTheirOwnCheck()
    {
        await using var site = new TestSite(pki, pki.Expired);

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        var certificate = Assert.Single(visit.Certificates);
        Assert.True(certificate.NotAfter < DateTimeOffset.UtcNow);
        Assert.Equal(ChainState.Trusted, certificate.Chain);
        Assert.Equal(200, visit.Https.Hops[^1].Status);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenCertificateIsForAnotherName_ShouldSayTheNameDoesNotMatch()
    {
        await using var site = new TestSite(pki, pki.WrongName);

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        var certificate = Assert.Single(visit.Certificates);
        Assert.False(certificate.NameMatches);
        Assert.Equal(["other.test"], certificate.Names);
        Assert.Equal(ChainState.Trusted, certificate.Chain);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenCertificateIsSelfSigned_ShouldDescribeTheChainAsUntrusted()
    {
        await using var site = new TestSite(pki, pki.SelfSigned);

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        var certificate = Assert.Single(visit.Certificates);
        Assert.Equal(ChainState.Untrusted, certificate.Chain);
        Assert.Contains("UntrustedRoot", certificate.ChainDetail, StringComparison.Ordinal);
        Assert.Equal(200, visit.Https.Hops[^1].Status);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenServerDoesNotSendTheIssuer_ShouldDescribeTheChainAsIncompleteWithoutDownloadingIt()
    {
        await using var site = new TestSite(pki, pki.MissingIssuer);

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        var certificate = Assert.Single(visit.Certificates);
        Assert.Equal(ChainState.Incomplete, certificate.Chain);
        Assert.Equal("PartialChain", certificate.ChainDetail);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenOnlyTheSystemAuthoritiesAreTrusted_ShouldNotTrustTheTestRoot()
    {
        await using var site = new TestSite(pki);
        var options = site.Options() with { TrustedRoots = null };

        var visit = await new HttpSiteFetcher(options).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.NotEqual(ChainState.Trusted, Assert.Single(visit.Certificates).Chain);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenSiteRedirectsToItsWwwName_ShouldFollowAndRecordBothCertificatesDeclaredHostFirst()
    {
        await using var site = new TestSite(pki)
        {
            Override = r => r.Secure && r.Host == Host && r.Path == "/" ? FakeResponse.Redirect("https://www.site.test/", 302) : null,
        };

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Response, visit.Https.End);
        Assert.Equal("https://site.test/ → https://www.site.test/", visit.Https.Path);
        Assert.Equal([302, 200], visit.Https.Hops.Select(h => h.Status));
        Assert.Equal(["site.test", "www.site.test"], visit.Certificates.Select(c => c.Host));
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenSiteRedirectsToAnotherDomain_ShouldStopWithoutContactingIt()
    {
        await using var site = new TestSite(pki)
        {
            Override = r => r.Secure && r.Path == "/" ? FakeResponse.Redirect("https://elsewhere.example/landing", 307) : null,
        };

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.LeftSite, visit.Https.End);
        Assert.Equal(new Uri("https://elsewhere.example/landing"), visit.Https.Next);
        Assert.DoesNotContain(site.Requests, r => r.Host != Host);
        Assert.Equal(Host, Assert.Single(visit.Certificates).Host);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenHttpsRedirectsBackToHttp_ShouldStopAtTheChangeOfScheme()
    {
        await using var site = new TestSite(pki)
        {
            HttpRedirects = false,
            Override = r => r.Secure && r.Path == "/" ? FakeResponse.Redirect("http://site.test/", 308) : null,
        };

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.ChangedScheme, visit.Https.End);
        Assert.Equal("https://site.test/ → http://site.test/", visit.Https.Path);
        Assert.Equal(TrailEnd.Response, visit.Http.End);
        Assert.Equal(200, visit.Http.Hops[^1].Status);
        Assert.Null(visit.Http.Hops[^1].Body);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenHttpRedirectsThroughAnotherAddressInClear_ShouldFollowItUntilHttps()
    {
        await using var site = new TestSite(pki)
        {
            Override = r => !r.Secure && r.Host == Host ? FakeResponse.Redirect("http://www.site.test/", 303) : null,
        };

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.ChangedScheme, visit.Http.End);
        Assert.Equal("http://site.test/ → http://www.site.test/ → https://www.site.test/", visit.Http.Path);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenRedirectsNeverEnd_ShouldGiveUpAfterTheLimit()
    {
        var step = 0;
        await using var site = new TestSite(pki)
        {
            Override = r => r.Secure && !r.Path.Contains("security.txt", StringComparison.Ordinal)
                ? FakeResponse.Redirect("/loop" + Interlocked.Increment(ref step), 302)
                : null,
        };

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.TooManyRedirects, visit.Https.End);
        Assert.Equal(HttpSiteFetcher.MaxRedirects + 1, visit.Https.Hops.Count);
        Assert.Equal(new Uri("https://site.test/loop6"), visit.Https.Next);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenNothingListensOnHttps_ShouldReportTheErrorAndNotAskForSecurityTxt()
    {
        await using var site = new TestSite(pki) { HttpsListens = false, HttpRedirects = false };

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Error, visit.Https.End);
        Assert.StartsWith("https://site.test/: ", visit.Https.Error, StringComparison.Ordinal);
        Assert.Empty(visit.Https.Hops);
        Assert.Null(visit.SecurityTxt);
        Assert.Empty(visit.Certificates);
        Assert.Equal(TrailEnd.Response, visit.Http.End);
        Assert.Equal("http /", Assert.Single(site.Requests.Select(r => $"{(r.Secure ? "https" : "http")} {r.Path}")));
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenServerNeverAnswers_ShouldGiveUpAfterTheRequestTimeout()
    {
        await using var site = new TestSite(pki) { Silent = _ => true };

        using var culture = new UiCulture("en-US");
        var visit = await new HttpSiteFetcher(site.Options(TimeSpan.FromMilliseconds(500))).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Error, visit.Http.End);
        Assert.Equal("http://site.test/: no answer within 0.5 seconds", visit.Http.Error);
        Assert.Equal("https://site.test/: no answer within 0.5 seconds", visit.Https.Error);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenCallerCancels_ShouldThrow()
    {
        await using var site = new TestSite(pki) { Silent = _ => true };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(200));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new HttpSiteFetcher(site.Options()).VisitAsync(Host, cts.Token));
    }

    [Fact]
    public async Task VisitAsync_WhenAlreadyCancelled_ShouldThrowWithoutARequest()
    {
        await using var site = new TestSite(pki);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new HttpSiteFetcher(site.Options()).VisitAsync(Host, new CancellationToken(true)));
        Assert.Empty(site.Requests);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenSecurityTxtIsOnlyAtTheTopLevel_ShouldFallBackToIt()
    {
        await using var site = new TestSite(pki)
        {
            SecurityTxt = null,
            Override = r => r.Path == "/security.txt" ? new FakeResponse(200, "Text/Plain; charset=utf-8", "Contact: mailto:legacy@site.test") : null,
        };

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        var file = Assert.Single(visit.SecurityTxt!.Hops);
        Assert.Equal("https://site.test/security.txt", file.Url.AbsoluteUri);
        Assert.Equal("Contact: mailto:legacy@site.test", file.Body);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenThereIsNoSecurityTxtAnywhere_ShouldKeepTheAnswerOfTheWellKnownAddress()
    {
        await using var site = new TestSite(pki)
        {
            // A page that answers 200 with HTML for any address is not a security.txt file.
            Override = r => r.Path.EndsWith("security.txt", StringComparison.Ordinal) ? new FakeResponse(200, "text/html", "<html>Oops</html>") : null,
        };

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        var file = Assert.Single(visit.SecurityTxt!.Hops);
        Assert.Equal("https://site.test/.well-known/security.txt", file.Url.AbsoluteUri);
        Assert.Null(file.Body);
        Assert.Equal(2, site.Requests.Count(r => r.Path.EndsWith("security.txt", StringComparison.Ordinal)));
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenSecurityTxtRedirectsElsewhere_ShouldNotTryTheTopLevelAddress()
    {
        await using var site = new TestSite(pki)
        {
            Override = r => r.Path == "/.well-known/security.txt" ? FakeResponse.Redirect("https://vendor.example/security.txt") : null,
        };

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.LeftSite, visit.SecurityTxt!.End);
        Assert.DoesNotContain(site.Requests, r => r.Path == "/security.txt");
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenPageIsHuge_ShouldReadOnlyTheFirstPart()
    {
        var huge = new string('x', HttpSiteFetcher.MaxBodyBytes + 100_000);
        await using var site = new TestSite(pki)
        {
            Override = r => r.Secure && r.Path == "/" ? new FakeResponse(200, "text/html", huge) : null,
        };

        var visit = await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(HttpSiteFetcher.MaxBodyBytes, visit.Https.Hops[^1].Body!.Length);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenPageIsNotHtmlOrNotFound_ShouldNotReadItsBody()
    {
        await using var site = new TestSite(pki)
        {
            Override = r => r.Secure && r.Path == "/" ? new FakeResponse(404, "text/html", "<html>gone</html>") : null,
        };
        await using var pdf = new TestSite(pki)
        {
            Override = r => r.Secure && r.Path == "/" ? new FakeResponse(200, "application/pdf", "%PDF") : null,
        };
        await using var untyped = new TestSite(pki)
        {
            Override = r => r.Secure && r.Path == "/" ? new FakeResponse(200, null, "raw") : null,
        };

        Assert.Null((await new HttpSiteFetcher(site.Options()).VisitAsync(Host, TestContext.Current.CancellationToken)).Https.Hops[^1].Body);
        Assert.Null((await new HttpSiteFetcher(pdf.Options()).VisitAsync(Host, TestContext.Current.CancellationToken)).Https.Hops[^1].Body);
        Assert.Null((await new HttpSiteFetcher(untyped.Options()).VisitAsync(Host, TestContext.Current.CancellationToken)).Https.Hops[^1].Body);
    }

    [Theory]
    [InlineData(301, "https://example.com/a", "https://example.com/a")]
    [InlineData(302, "/b?x=1", "http://example.com/b?x=1")]
    [InlineData(303, " //cdn.example.net/c ", "http://cdn.example.net/c")]
    [InlineData(307, "d", "http://example.com/d")]
    [InlineData(308, "HTTPS://EXAMPLE.COM", "https://example.com/")]
    [InlineData(200, "https://example.com/a", null)]
    [InlineData(300, "https://example.com/a", null)]
    [InlineData(304, "https://example.com/a", null)]
    [InlineData(301, null, null)]
    [InlineData(301, "mailto:someone@example.com", null)]
    [InlineData(301, "javascript:alert(1)", null)]
    [InlineData(301, "http://exa mple.com:bad/", null)]
    public void Redirect_WhenCalled_ShouldFollowOnlyRedirectStatusesWithAnHttpAddress(int status, string? location, string? expected)
    {
        var hop = location is null
            ? Site.Hop("http://example.com/", status)
            : Site.Hop("http://example.com/", status, null, ("location", location));

        Assert.Equal(expected, HttpSiteFetcher.Redirect(hop)?.AbsoluteUri);
    }

    [Fact]
    public void UserAgent_WhenRead_ShouldDeclareTheProgramAndWhereToReadAboutIt()
    {
        Assert.Matches(@"\AMozilla/5\.0 \(compatible; ScudoDigitale/\d+\.\d+; \+https://gcardinale\.it\)\z", HttpSiteFetcher.UserAgent);
    }

    [Fact]
    public void CreateHandler_WhenCalled_ShouldNotFollowRedirectsByItselfNorKeepCookies()
    {
        using var handler = new HttpSiteFetcher(new WebCheckOptions { RequestTimeout = TimeSpan.FromSeconds(3) })
            .CreateHandler(new ConcurrentDictionary<string, CertificateInfo>());

        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.Equal(TimeSpan.FromSeconds(3), handler.ConnectTimeout);
        Assert.Equal(DecompressionMethods.All, handler.AutomaticDecompression);
        var policy = handler.SslOptions.CertificateChainPolicy!;
        Assert.True(policy.DisableCertificateDownloads);
        Assert.Equal(System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck, policy.RevocationMode);
        Assert.Equal(System.Security.Cryptography.X509Certificates.X509ChainTrustMode.System, policy.TrustMode);
    }
}
