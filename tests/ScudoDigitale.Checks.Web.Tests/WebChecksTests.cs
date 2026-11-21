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

using System.Collections;
using System.Globalization;
using System.Resources;
using ScudoDigitale.Checks.Web.Resources;
using ScudoDigitale.Core;

using System.Net;
using ScudoDigitale.Core.Dns;

namespace ScudoDigitale.Checks.Web.Tests;

public sealed class WebChecksTests
{
    private static readonly string[] ExpectedIds =
    [
        "WEB-HTTPS-001", "WEB-HTTPS-002",
        "WEB-CERT-001", "WEB-CERT-002", "WEB-CERT-003",
        "WEB-HSTS-001",
        "WEB-HDR-001", "WEB-HDR-002", "WEB-HDR-003", "WEB-HDR-004", "WEB-HDR-005",
        "WEB-COOKIE-001", "WEB-COOKIE-002", "WEB-COOKIE-003",
        "WEB-SECTXT-001",
    ];

    [Fact]
    public void Create_WhenCalled_ShouldReturnThePassiveWebsiteChecksInReportOrder()
    {
        var checks = WebChecks.Create();

        Assert.Equal(ExpectedIds, checks.Select(c => c.Id));
        Assert.All(checks, c =>
        {
            Assert.True(Finding.IsCheckId(c.Id));
            Assert.Equal(CheckArea.Web, c.Area);
            Assert.Equal(TargetKind.Website, c.AppliesTo);
            Assert.Equal(ScopeRequirement.Passive, c.Scope);
        });
    }

    [Fact]
    public void Create_WhenOptionsAreGiven_ShouldBuildTheSameChecks()
    {
        var checks = WebChecks.Create(new WebCheckOptions { RequestTimeout = TimeSpan.FromSeconds(3) });

        Assert.Equal(ExpectedIds, checks.Select(c => c.Id));
    }

    [Theory]
    [InlineData("en-US", "Site reachable over HTTPS", "security.txt file")]
    [InlineData("it-IT", "Sito raggiungibile in HTTPS", "File security.txt")]
    public void Title_WhenUiLanguageChanges_ShouldFollowIt(string culture, string first, string last)
    {
        var checks = WebChecks.Create();

        using var ui = new UiCulture(culture);
        Assert.Equal(first, checks[0].Title);
        Assert.Equal(last, checks[^1].Title);
        Assert.All(checks, c => Assert.False(string.IsNullOrWhiteSpace(c.Title)));
        Assert.Equal(checks.Count, checks.Select(c => c.Title).Distinct().Count());
    }

    [Fact]
    public void Resources_WhenComparingLanguages_ShouldHaveTheSameKeysAndPlaceholders()
    {
        var english = Read(CultureInfo.InvariantCulture);
        var italian = Read(CultureInfo.GetCultureInfo("it"));

        Assert.Equal(english.Keys.Order(), italian.Keys.Order());
        foreach (var (key, text) in english)
        {
            Assert.False(string.IsNullOrWhiteSpace(text), key);
            Assert.NotEqual(text, italian[key]);
            Assert.Equal(Placeholders(text), Placeholders(italian[key]));
        }
    }

    [Fact]
    public void Options_WhenCreated_ShouldBeCautiousAndWithinBounds()
    {
        var options = new WebCheckOptions();

        Assert.Equal(TimeSpan.FromSeconds(10), options.RequestTimeout);
        Assert.Equal(TimeSpan.FromSeconds(40), options.VisitBudget);
        Assert.True(options.VisitBudget < new CheckEngineOptions().CheckTimeout);
        Assert.Null(options.TrustedRoots);
        Assert.InRange(options.Clock(), DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
        var endpoint = new System.Net.DnsEndPoint("example.com", 443);
        Assert.Same(endpoint, options.Route(endpoint));
    }

    [Fact]
    public void DnsSource_WhenSet_ShouldDefaultToThePublicResolversAndAcceptOnlyDefinedValues()
    {
        Assert.Equal(DnsSource.Public, new WebCheckOptions().DnsSource);
        Assert.Equal(DnsSource.System, new WebCheckOptions { DnsSource = DnsSource.System }.DnsSource);
        Assert.Throws<ArgumentOutOfRangeException>(() => new WebCheckOptions { DnsSource = (DnsSource)9 });
    }

    [Fact]
    public void Create_WhenOnlyTheDnsOfTheComputerIsAsked_ShouldBuildTheSameChecks()
    {
        Assert.Equal(ExpectedIds, WebChecks.Create(new WebCheckOptions { DnsSource = DnsSource.System }).Select(c => c.Id));
    }

    [Fact]
    public void ProxyFor_WhenAProxyIsConfigured_ShouldReturnItsHostAndPortWithoutCredentials()
    {
        var proxy = new WebProxy(new Uri("http://mario:secret@proxy.lan:8080"));

        Assert.Equal("proxy.lan:8080", WebChecks.ProxyFor("example.com", proxy));
    }

    [Fact]
    public void ProxyFor_WhenTheSiteIsBypassed_ShouldReturnNull()
    {
        var proxy = new WebProxy(new Uri("http://proxy.lan:8080"), BypassOnLocal: false, BypassList: [@"example\.com"]);

        Assert.Null(WebChecks.ProxyFor("example.com", proxy));
        Assert.Equal("proxy.lan:8080", WebChecks.ProxyFor("example.org", proxy));
    }

    [Fact]
    public void ProxyFor_WhenTheConfigurationGivesNoProxy_ShouldReturnNull()
    {
        Assert.Null(WebChecks.ProxyFor("example.com", new FakeProxy(_ => null)));
        Assert.Null(WebChecks.ProxyFor("example.com", new FakeProxy(site => site)));
        Assert.Null(WebChecks.ProxyFor("example.com", new FakeProxy(_ => throw new InvalidOperationException("no PAC"))));
    }

    [Theory]
    [InlineData("https", "proxy.lan:8080")]
    [InlineData("http", "proxy.lan:8080")]
    [InlineData("ftp", null)]
    public void ProxyFor_WhenOnlyOneSchemeGoesThroughAProxy_ShouldStillReportIt(string proxied, string? expected)
    {
        var proxy = new FakeProxy(site => site.Scheme == proxied ? new Uri("http://proxy.lan:8080") : null);

        Assert.Equal(expected, WebChecks.ProxyFor("example.com", proxy));
        Assert.Equal(proxied == "http" ? "proxy.lan:8080" : null, WebChecks.ProxyFor("http", "example.com", proxy));
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(30_000, true)]
    [InlineData(0, false)]
    [InlineData(-1, false)]
    [InlineData(30_001, false)]
    public void RequestTimeout_WhenSet_ShouldAcceptOnlyPositiveValuesUpToThirtySeconds(int milliseconds, bool valid)
    {
        var value = TimeSpan.FromMilliseconds(milliseconds);
        if (valid)
        {
            Assert.Equal(value, new WebCheckOptions { RequestTimeout = value }.RequestTimeout);
        }
        else
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new WebCheckOptions { RequestTimeout = value });
        }
    }

    [Fact]
    public async Task Engine_WhenSiteIsWellConfigured_ShouldRunEveryCheckOnlyOnWebsiteTargets()
    {
        var fetcher = new FakeSiteFetcher();
        var scope = new ScopeDeclaration(
            "Mario Rossi",
            OperatorRole.Owner,
            [new Target(TargetKind.Website, "example.com"), new Target(TargetKind.Domain, "example.com")],
            Site.Now);

        var runs = await new CheckEngine(new DenyAll()).RunAsync(
            WebChecks.Create(fetcher, new WebCheckOptions()),
            Profile.Individual(),
            scope,
            TestContext.Current.CancellationToken);

        Assert.Equal(ExpectedIds, runs.Select(r => r.CheckId));
        Assert.All(runs, r => Assert.Empty(Assert.IsType<CheckResult.Executed>(r.Result).Findings));
        Assert.Equal(1, fetcher.Visits);
    }

    [Fact]
    public async Task Engine_WhenSiteHasNoProtectionAtAll_ShouldReportEveryGapMostUrgentFirst()
    {
        var bare = Site.Good() with
        {
            Http = Site.Response(Site.Hop("http://example.com/")),
            Https = Site.Response(Site.Hop("https://example.com/", 200, null, ("Set-Cookie", "PHPSESSID=abc"))),
            Certificates = [Site.Certificate(daysLeft: -3, nameMatches: false, chain: ChainState.Untrusted)],
            SecurityTxt = Site.Response(Site.Hop("https://example.com/.well-known/security.txt", 404)),
        };

        var runs = await new CheckEngine(new DenyAll()).RunAsync(
            WebChecks.Create(new FakeSiteFetcher(bare), new WebCheckOptions()),
            Profile.Individual(),
            Make.Context().Scope,
            TestContext.Current.CancellationToken);

        var findings = FindingPrioritizer.Prioritize(runs.Select(r => r.Result).OfType<CheckResult.Executed>().SelectMany(r => r.Findings));
        Assert.Equal(ExpectedIds.Except(["WEB-HTTPS-001"]).Order(), findings.Select(f => f.Finding.Id).Order());
        Assert.Equal(Severity.High, findings[0].EffectiveSeverity);
        Assert.Equal(Severity.Info, findings[^1].EffectiveSeverity);
    }

    private static Dictionary<string, string> Read(CultureInfo culture)
    {
        var manager = new ResourceManager(typeof(Strings));
        using var set = manager.GetResourceSet(culture, createIfNotExists: true, tryParents: false)!;
        return set.Cast<DictionaryEntry>().ToDictionary(e => (string)e.Key, e => (string)e.Value!);
    }

    private static string[] Placeholders(string text) =>
        [.. System.Text.RegularExpressions.Regex.Matches(text, @"\{\d+\}").Select(m => m.Value).Order()];

    private sealed class DenyAll : IScopeGuard
    {
        public Task<bool> IsAuthorizedAsync(Target target, CancellationToken cancellationToken) => Task.FromResult(false);
    }

}

/// <summary>Everything that changes a setting of the whole process: never run beside other tests.</summary>
[CollectionDefinition(nameof(ProcessWideSettings), DisableParallelization = true)]
public sealed class ProcessWideSettings;

[Collection(nameof(ProcessWideSettings))]
public sealed class SystemProxyTests
{
    [Fact]
    public void SystemProxyFor_WhenCalled_ShouldReadTheProxyOfTheProcess()
    {
        // A known configuration instead of that of the computer running the tests, whose automatic
        // proxy discovery would be real network traffic.
        var real = HttpClient.DefaultProxy;
        try
        {
            HttpClient.DefaultProxy = new FakeProxy(_ => new Uri("http://proxy.lan:3128/"));

            Assert.Equal("proxy.lan:3128", WebChecks.SystemProxyFor("example.com"));
        }
        finally
        {
            HttpClient.DefaultProxy = real;
        }
    }
}
