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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Web.Tests;

public sealed class HttpsChecksTests
{
    [Fact]
    public async Task Available_WhenHttpsDoesNotAnswerButHttpDoes_ShouldReportHighWithTheError()
    {
        var visit = Site.Good() with
        {
            Http = Site.Response(Site.Hop("http://example.com/")),
            Https = Trail.Failed("https://example.com/: connection refused", refused: true),
            Certificates = [],
            SecurityTxt = null,
        };

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, HttpsChecks.AvailableId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(Confidence.Certain, finding.Confidence);
        Assert.Equal("The site does not answer over HTTPS", finding.Title);
        Assert.Equal("https://example.com/: connection refused", finding.Evidence);
    }

    [Fact]
    public async Task Available_WhenHttpsFailsForAnotherReasonThanAClosedPort_ShouldNotClaimThatThereIsNoHttps()
    {
        var visit = Site.Good() with
        {
            Http = Site.Response(Site.Hop("http://example.com/")),
            Https = Trail.Failed("https://example.com/: no answer within 10 seconds"),
            Certificates = [],
            SecurityTxt = null,
        };

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, HttpsChecks.AvailableId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(Confidence.ToBeVerified, finding.Confidence);
        Assert.Equal("The site could not be reached over HTTPS", finding.Title);
        Assert.Equal("https://example.com/: no answer within 10 seconds", finding.Evidence);
    }

    [Fact]
    public async Task Available_WhenHttpsRedirectsBackToHttp_ShouldReportHighWithThePath()
    {
        var visit = Site.Good() with
        {
            Https = Site.Stopped(TrailEnd.ChangedScheme, "http://example.com/", Site.RedirectHop("https://example.com/", "http://example.com/")),
        };

        using var culture = new UiCulture("it-IT");
        var finding = await Make.SingleFindingAsync(visit, HttpsChecks.AvailableId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("Il sito in HTTPS rimanda i visitatori a HTTP", finding.Title);
        Assert.Equal("https://example.com/ → http://example.com/", finding.Evidence);
    }

    [Theory]
    [InlineData(TrailEnd.Response)]
    [InlineData(TrailEnd.LeftSite)]
    [InlineData(TrailEnd.TooManyRedirects)]
    internal async Task Available_WhenHttpsAnswers_ShouldFindNothing(TrailEnd end)
    {
        var visit = Site.Good() with { Https = new Trail([Site.Hop("https://example.com/")], end, new Uri("https://other.example/")) };

        Assert.Empty(await Make.FindingsAsync(visit, HttpsChecks.AvailableId));
    }

    [Fact]
    public async Task Redirect_WhenHttpServesThePage_ShouldReportMedium()
    {
        var visit = Site.Good() with { Http = Site.Response(Site.Hop("http://example.com/")) };

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, HttpsChecks.RedirectId);

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("The site is also served over HTTP, without redirecting to HTTPS", finding.Title);
        Assert.Equal("http://example.com/ answered HTTP 200 without redirecting to HTTPS.", finding.Evidence);
    }

    [Theory]
    [InlineData(399, 1)]
    [InlineData(400, 0)]
    [InlineData(404, 0)]
    public async Task Redirect_WhenHttpAnswersWithoutRedirecting_ShouldReportOnlyBelow400(int status, int findings)
    {
        var visit = Site.Good() with { Http = Site.Response(Site.Hop("http://example.com/", status)) };

        Assert.Equal(findings, (await Make.FindingsAsync(visit, HttpsChecks.RedirectId)).Count);
    }

    [Fact]
    public async Task Redirect_WhenNothingAnswersOverHttp_ShouldFindNothing()
    {
        var visit = Site.Good() with { Http = Trail.Failed("http://example.com/: connection refused") };

        Assert.Empty(await Make.FindingsAsync(visit, HttpsChecks.RedirectId));
    }

    [Fact]
    public async Task Redirect_WhenHttpsIsReachedThroughAnotherAddressInClear_ShouldReportLowWithThePath()
    {
        var visit = Site.Good() with
        {
            Http = Site.Stopped(
                TrailEnd.ChangedScheme,
                "https://www.example.com/",
                Site.RedirectHop("http://example.com/", "http://www.example.com/"),
                Site.RedirectHop("http://www.example.com/", "https://www.example.com/")),
        };

        var finding = await Make.SingleFindingAsync(visit, HttpsChecks.RedirectId);

        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal("http://example.com/ → http://www.example.com/ → https://www.example.com/", finding.Evidence);
    }

    [Fact]
    public async Task Redirect_WhenHttpSendsVisitorsToAnotherSiteInClear_ShouldReportLow()
    {
        var visit = Site.Good() with
        {
            Http = Site.Stopped(TrailEnd.LeftSite, "http://other.example/", Site.RedirectHop("http://example.com/", "http://other.example/")),
        };

        Assert.Equal(Severity.Low, (await Make.SingleFindingAsync(visit, HttpsChecks.RedirectId)).Severity);
    }

    [Fact]
    public async Task Redirect_WhenHttpRedirectsWithoutEnd_ShouldFail()
    {
        var visit = Site.Good() with
        {
            Http = Site.Stopped(TrailEnd.TooManyRedirects, "http://example.com/b", Site.RedirectHop("http://example.com/", "/b")),
        };

        Assert.IsType<CheckResult.Failed>(await Make.RunAsync(visit, HttpsChecks.RedirectId));
    }
}

public sealed class CertificateChecksTests
{
    [Theory]
    [InlineData(CertificateChecks.ExpiryId)]
    [InlineData(CertificateChecks.ChainId)]
    [InlineData(CertificateChecks.NameId)]
    public async Task Checks_WhenNoCertificateWasSeen_ShouldBeSkippedPointingToTheHttpsCheck(string id)
    {
        var visit = Site.Good() with
        {
            Http = Site.Response(Site.Hop("http://example.com/")),
            Https = Trail.Failed("https://example.com/: connection refused"),
            Certificates = [],
        };

        using var culture = new UiCulture("en-US");
        var skipped = Assert.IsType<CheckResult.Skipped>(await Make.RunAsync(visit, id));

        Assert.Equal("Skipped: the site does not answer over HTTPS (see WEB-HTTPS-001).", skipped.Reason);
    }

    [Theory]
    [InlineData(CertificateChecks.ExpiryId)]
    [InlineData(CertificateChecks.ChainId)]
    [InlineData(CertificateChecks.NameId)]
    public async Task Checks_WhenHttpsAnswersButItsCertificateCouldNotBeRead_ShouldFailSayingSo(string id)
    {
        var visit = Site.Good() with { Certificates = [] };

        using var culture = new UiCulture("it-IT");
        var failed = Assert.IsType<CheckResult.Failed>(await Make.RunAsync(visit, id));

        Assert.Equal("Non è stato possibile leggere il certificato del sito.", failed.Error);
    }

    [Theory]
    [InlineData(31, null)]
    [InlineData(30, Severity.Low)]
    [InlineData(14, Severity.Low)]
    [InlineData(13, Severity.Medium)]
    [InlineData(0, Severity.Medium)]
    public async Task Expiry_WhenCertificateIsStillValid_ShouldReportBySeverityOfTheDaysLeft(int daysLeft, Severity? expected)
    {
        var visit = Site.Good() with { Certificates = [Site.Certificate(daysLeft: daysLeft)] };

        using var culture = new UiCulture("en-US");
        var findings = await Make.FindingsAsync(visit, CertificateChecks.ExpiryId);

        Assert.Equal(expected, findings.SingleOrDefault()?.Severity);
        if (expected is not null)
        {
            Assert.Equal($"Certificate expiring in {daysLeft} days (example.com)", findings[0].Title);
        }
    }

    [Fact]
    public async Task Expiry_WhenCertificateIsExpired_ShouldReportHighWithTheDates()
    {
        var visit = Site.Good() with { Certificates = [Site.Certificate(daysLeft: -1)] };

        using var culture = new UiCulture("it-IT");
        var finding = await Make.SingleFindingAsync(visit, CertificateChecks.ExpiryId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("Certificato scaduto (example.com)", finding.Title);
        Assert.Equal("example.com: valido dal 22/10/2026 al 20/11/2026.", finding.Evidence);
    }

    [Fact]
    public async Task Expiry_WhenCertificateIsNotYetValid_ShouldReportHigh()
    {
        var future = Site.Certificate() with { NotBefore = Site.Now.AddMinutes(1) };

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(Site.Good() with { Certificates = [future] }, CertificateChecks.ExpiryId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("Certificate not yet valid (example.com)", finding.Title);
    }

    [Fact]
    public async Task Expiry_WhenValidityStartsOrEndsExactlyNow_ShouldNotCallItExpired()
    {
        var edge = Site.Certificate() with { NotBefore = Site.Now, NotAfter = Site.Now };

        var finding = await Make.SingleFindingAsync(Site.Good() with { Certificates = [edge] }, CertificateChecks.ExpiryId);

        Assert.Equal(Severity.Medium, finding.Severity);
    }

    [Fact]
    public async Task Chain_WhenAuthorityIsNotRecognized_ShouldReportHighCertainWithTheFlags()
    {
        var visit = Site.Good() with { Certificates = [Site.Certificate(chain: ChainState.Untrusted, detail: "UntrustedRoot")] };

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, CertificateChecks.ChainId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(Confidence.Certain, finding.Confidence);
        Assert.Equal("Certificate not issued by a recognized authority (example.com)", finding.Title);
        Assert.Equal("example.com: UntrustedRoot", finding.Evidence);
    }

    [Fact]
    public async Task Chain_WhenIssuerIsMissing_ShouldReportMediumProbable()
    {
        var visit = Site.Good() with { Certificates = [Site.Certificate(chain: ChainState.Incomplete, detail: "PartialChain")] };

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, CertificateChecks.ChainId);

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(Confidence.Probable, finding.Confidence);
        Assert.Equal("Incomplete certificate chain (example.com)", finding.Title);
    }

    [Fact]
    public async Task Name_WhenCertificateIsForAnotherName_ShouldReportHighListingItsNames()
    {
        var visit = Site.Good() with { Certificates = [Site.Certificate(nameMatches: false)] };

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(visit, CertificateChecks.NameId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("example.com: the certificate is issued for example.com, www.example.com.", finding.Evidence);
    }

    [Fact]
    public async Task Checks_WhenTwoHostsWereContacted_ShouldReportEachCertificateUnderItsHost()
    {
        var visit = Site.Good() with
        {
            Certificates = [Site.Certificate(), Site.Certificate("www.example.com", daysLeft: -5, nameMatches: false, chain: ChainState.Untrusted)],
        };

        using var culture = new UiCulture("en-US");
        Assert.Equal("Certificate expired (www.example.com)", (await Make.SingleFindingAsync(visit, CertificateChecks.ExpiryId)).Title);
        Assert.Contains("(www.example.com)", (await Make.SingleFindingAsync(visit, CertificateChecks.ChainId)).Title, StringComparison.Ordinal);
        Assert.Contains("(www.example.com)", (await Make.SingleFindingAsync(visit, CertificateChecks.NameId)).Title, StringComparison.Ordinal);
    }
}

public sealed class CertificateInspectorTests
{
    [Theory]
    [InlineData(X509ChainStatusFlags.NoError, ChainState.Trusted)]
    [InlineData(X509ChainStatusFlags.PartialChain, ChainState.Incomplete)]
    [InlineData(X509ChainStatusFlags.UntrustedRoot, ChainState.Untrusted)]
    [InlineData(X509ChainStatusFlags.PartialChain | X509ChainStatusFlags.NotSignatureValid, ChainState.Untrusted)]
    [InlineData(X509ChainStatusFlags.NotTimeValid, ChainState.Untrusted)]
    [InlineData(X509ChainStatusFlags.Revoked, ChainState.Untrusted)]
    internal void Classify_WhenCalled_ShouldTrustOnlyAChainWithoutFlags(X509ChainStatusFlags flags, ChainState expected)
    {
        Assert.Equal(expected, CertificateInspector.Classify(flags));
    }

    [Fact]
    public void Names_WhenCertificateHasNoAlternativeNames_ShouldFallBackToItsCommonName()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var certificate = new CertificateRequest("CN=old.example.com, O=Example", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        Assert.Equal(["old.example.com"], CertificateInspector.Names(certificate));
    }

    [Fact]
    public void Describe_WhenTheAuthorityItselfIsExpired_ShouldNotTrustTheChain()
    {
        // An expired certificate alone is left to the expiry check; an expired issuer is a broken chain.
        var now = DateTimeOffset.UtcNow;
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=Expired Test Root", rootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var root = rootRequest.CreateSelfSigned(now.AddYears(-2), now.AddDays(-1));
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var leaf = new CertificateRequest("CN=site.test", leafKey, HashAlgorithmName.SHA256).Create(root, now.AddYears(-1), now.AddDays(-2), [7]);
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.Build(leaf);

        var info = CertificateInspector.Describe("site.test", leaf, chain, System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors);

        Assert.Equal(ChainState.Untrusted, info.Chain);
        Assert.Contains("NotTimeValid", info.ChainDetail, StringComparison.Ordinal);
        Assert.True(info.NameMatches);
        Assert.Equal(["site.test"], info.Names);
    }
}
