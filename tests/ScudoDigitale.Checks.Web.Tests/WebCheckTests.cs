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

/// <summary>Behaviour shared by every website check: target validation, unreachable sites, errors, cancellation.</summary>
public sealed class WebCheckTests
{
    public static TheoryData<string> AllIds => [.. WebChecks.Create().Select(c => c.Id)];

    [Theory]
    [MemberData(nameof(AllIds))]
    public async Task RunAsync_WhenTargetIsNotAWebsiteName_ShouldFailWithoutVisiting(string id)
    {
        var fetcher = new FakeSiteFetcher();

        using var culture = new UiCulture("en-US");
        var result = await Make.Check(fetcher, id).RunAsync(Make.Context("not a site"), TestContext.Current.CancellationToken);

        Assert.Equal("'not a site' is not a valid website address: use a domain name such as example.com.", Assert.IsType<CheckResult.Failed>(result).Error);
        Assert.Equal(0, fetcher.Visits);
    }

    [Fact]
    public async Task RunAsync_WhenTargetIsNotOfKindWebsite_ShouldFail()
    {
        var fetcher = new FakeSiteFetcher();

        var result = await Make.Check(fetcher, HttpsChecks.AvailableId).RunAsync(Make.Context("example.com", TargetKind.Domain), TestContext.Current.CancellationToken);

        Assert.IsType<CheckResult.Failed>(result);
        Assert.Equal(0, fetcher.Visits);
    }

    [Theory]
    [MemberData(nameof(AllIds))]
    public async Task RunAsync_WhenSiteAnswersNeitherOverHttpNorHttps_ShouldFailInsteadOfReportingProblems(string id)
    {
        var visit = Site.Good() with
        {
            Http = Trail.Failed("http://example.com/: connection refused"),
            Https = Trail.Failed("https://example.com/: no such host"),
            Certificates = [],
            SecurityTxt = null,
        };

        using var culture = new UiCulture("it-IT");
        var result = await Make.RunAsync(visit, id);

        Assert.Equal("Il sito example.com non è raggiungibile: https://example.com/: no such host", Assert.IsType<CheckResult.Failed>(result).Error);
    }

    [Theory]
    [MemberData(nameof(AllIds))]
    public async Task RunAsync_WhenSiteIsWellConfigured_ShouldFindNothing(string id)
    {
        Assert.Empty(await Make.FindingsAsync(Site.Good(), id));
    }

    [Fact]
    public async Task RunAsync_WhenTargetIsAUrlOrAnInternationalName_ShouldVisitItsHost()
    {
        var fetcher = new FakeSiteFetcher();
        var check = Make.Check(fetcher, HttpsChecks.AvailableId);

        Assert.IsType<CheckResult.Executed>(await check.RunAsync(Make.Context("https://Example.com/some/page"), TestContext.Current.CancellationToken));
        Assert.IsType<CheckResult.Executed>(await check.RunAsync(Make.Context("caffè.it"), TestContext.Current.CancellationToken));
        Assert.Equal(2, fetcher.Visits);
    }

    [Theory]
    [MemberData(nameof(AllIds))]
    public async Task RunAsync_WhenFetcherThrows_ShouldFailInsteadOfThrowing(string id)
    {
        var fetcher = new FakeSiteFetcher { Throws = new InvalidOperationException("fetcher exploded") };

        using var culture = new UiCulture("en-US");
        var result = await Make.Check(fetcher, id).RunAsync(Make.Context(), TestContext.Current.CancellationToken);

        Assert.Equal("Unexpected error: fetcher exploded", Assert.IsType<CheckResult.Failed>(result).Error);
    }

    [Theory(Timeout = 10_000)]
    [MemberData(nameof(AllIds))]
    public async Task RunAsync_WhenFetcherHangsAndTokenIsCancelled_ShouldThrowOperationCanceled(string id)
    {
        var fetcher = new FakeSiteFetcher { Hangs = true };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Make.Check(fetcher, id).RunAsync(Make.Context(), cts.Token));
    }

    [Fact(Timeout = 10_000)]
    public async Task RunAsync_WhenVisitGoesOverItsTimeBudget_ShouldFailSayingSoEvenIfTheFetcherIgnoresTheToken()
    {
        var fetcher = new FakeSiteFetcher { Hangs = true };
        var options = new WebCheckOptions { VisitBudget = TimeSpan.FromMilliseconds(200) };

        using var culture = new UiCulture("en-US");
        var result = await Make.Check(fetcher, HeaderChecks.HstsId, options).RunAsync(Make.Context(), TestContext.Current.CancellationToken);

        Assert.Equal("The visit to example.com did not end within 0.2 seconds.", Assert.IsType<CheckResult.Failed>(result).Error);
    }

    [Fact]
    public async Task RunAsync_WhenAlreadyCancelled_ShouldThrowWithoutVisiting()
    {
        var fetcher = new FakeSiteFetcher();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Make.Check(fetcher, HttpsChecks.AvailableId).RunAsync(Make.Context(), new CancellationToken(true)));
        Assert.Equal(0, fetcher.Visits);
    }

    [Fact]
    public async Task RunAsync_WhenEveryCheckRuns_ShouldVisitTheSiteOnlyOnce()
    {
        var fetcher = new FakeSiteFetcher();
        var checks = WebChecks.Create(fetcher, new WebCheckOptions());

        foreach (var check in checks)
        {
            await check.RunAsync(Make.Context(), TestContext.Current.CancellationToken);
        }

        Assert.Equal(1, fetcher.Visits);
    }

    [Fact(Timeout = 10_000)]
    public async Task RunAsync_WhenChecksStartAtTheSameTimeOnDifferentThreads_ShouldStillVisitTheSiteOnlyOnce()
    {
        // The engine runs four checks at once: the second must wait for the visit the first started.
        var fetcher = new FakeSiteFetcher { Blocks = TimeSpan.FromMilliseconds(300) };
        var checks = WebChecks.Create(fetcher, new WebCheckOptions());
        using var start = new Barrier(4);

        var results = await Task.WhenAll(checks.Take(4).Select(check => Task.Run(
            () =>
            {
                start.SignalAndWait(TestContext.Current.CancellationToken);
                return check.RunAsync(Make.Context(), TestContext.Current.CancellationToken);
            },
            TestContext.Current.CancellationToken)));

        Assert.All(results, result => Assert.IsType<CheckResult.Executed>(result));
        Assert.Equal(1, fetcher.Visits);
    }

    [Fact(Timeout = 10_000)]
    public async Task RunAsync_WhenOneCheckIsCancelled_ShouldNotCancelTheSharedVisitForTheOthers()
    {
        var gate = new TaskCompletionSource();
        var fetcher = new FakeSiteFetcher { Release = gate.Task };
        var checks = WebChecks.Create(fetcher, new WebCheckOptions());
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);

        var cancelled = checks[0].RunAsync(Make.Context(), cts.Token);
        var waiting = checks[1].RunAsync(Make.Context(), TestContext.Current.CancellationToken);
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        gate.SetResult();

        Assert.Empty(Assert.IsType<CheckResult.Executed>(await waiting).Findings);
        Assert.Equal(1, fetcher.Visits);
    }

    [Fact(Timeout = 10_000)]
    public async Task EngineTimeout_WhenFetcherHangs_ShouldReportFailedAndReturn()
    {
        var fetcher = new FakeSiteFetcher { Hangs = true };
        var engine = new CheckEngine(new DenyAll(), new CheckEngineOptions { CheckTimeout = TimeSpan.FromMilliseconds(200) });

        var runs = await engine.RunAsync(
            [Make.Check(fetcher, HttpsChecks.AvailableId)],
            Profile.Individual(),
            Make.Context().Scope,
            TestContext.Current.CancellationToken);

        Assert.IsType<CheckResult.Failed>(Assert.Single(runs).Result);
    }

    [Theory]
    [InlineData(HeaderChecks.HstsId)]
    [InlineData(HeaderChecks.CspId)]
    [InlineData(HeaderChecks.FrameId)]
    [InlineData(HeaderChecks.NosniffId)]
    [InlineData(HeaderChecks.ReferrerId)]
    [InlineData(HeaderChecks.PermissionsId)]
    [InlineData(CookieChecks.SecureId)]
    [InlineData(CookieChecks.HttpOnlyId)]
    [InlineData(CookieChecks.SameSiteId)]
    public async Task PageChecks_WhenThereIsNoHomePageToEvaluate_ShouldSayWhyInsteadOfReportingMissingHeaders(string id)
    {
        var noHttps = Site.Good() with { Https = Trail.Failed("https://example.com/: connection refused"), Certificates = [], SecurityTxt = null };
        var backToHttp = Site.Good() with { Https = Site.Stopped(TrailEnd.ChangedScheme, "http://example.com/", Site.RedirectHop("https://example.com/", "http://example.com/")) };
        var elsewhere = Site.Good() with { Https = Site.Stopped(TrailEnd.LeftSite, "https://other.example/", Site.RedirectHop("https://example.com/", "https://other.example/")) };
        var loop = Site.Good() with { Https = Site.Stopped(TrailEnd.TooManyRedirects, "https://example.com/a", Site.RedirectHop("https://example.com/", "/a")) };
        var forbidden = Site.Good() with { Https = Site.Response(Site.Hop("https://example.com/", 403)) };

        using var culture = new UiCulture("en-US");
        Assert.Contains("WEB-HTTPS-001", Assert.IsType<CheckResult.Skipped>(await Make.RunAsync(noHttps, id)).Reason, StringComparison.Ordinal);
        Assert.Contains("back to HTTP (see WEB-HTTPS-001)", Assert.IsType<CheckResult.Skipped>(await Make.RunAsync(backToHttp, id)).Reason, StringComparison.Ordinal);
        Assert.Equal(
            "Skipped: the site redirects to other.example, outside the declared domain. Run the check on that domain.",
            Assert.IsType<CheckResult.Skipped>(await Make.RunAsync(elsewhere, id)).Reason);
        Assert.Equal(
            "The site redirects more than 5 times: https://example.com/ → https://example.com/a",
            Assert.IsType<CheckResult.Failed>(await Make.RunAsync(loop, id)).Error);
        Assert.Equal(
            "The home page https://example.com/ answered HTTP 403, so its headers and cookies were not evaluated.",
            Assert.IsType<CheckResult.Failed>(await Make.RunAsync(forbidden, id)).Error);
    }

    [Fact]
    public async Task PageChecks_WhenHomePageAnswers399_ShouldStillEvaluateIt()
    {
        var visit = Site.Good() with { Https = Site.Response(Site.Hop("https://example.com/", 399, null, Site.GoodHeaders)) };

        Assert.Empty(await Make.FindingsAsync(visit, HeaderChecks.HstsId));
    }

    private sealed class DenyAll : IScopeGuard
    {
        public Task<bool> IsAuthorizedAsync(Target target, CancellationToken cancellationToken) => Task.FromResult(false);
    }
}
