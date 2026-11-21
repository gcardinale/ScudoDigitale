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
using System.Net.Sockets;
using ScudoDigitale.Core.Dns;

namespace ScudoDigitale.Checks.Web.Tests;

/// <summary>Where the address of a site comes from: the resolver of the checks, not the DNS of the computer.</summary>
public sealed class HttpSiteFetcherDnsTests(TestPki pki) : IClassFixture<TestPki>
{
    private const string Host = TestSite.Host;

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenSiteIsReachedDirectly_ShouldAskTheResolverForItsAddress()
    {
        await using var site = new TestSite(pki);
        var dns = new FakeAddresses(_ => Found("127.0.0.1"));

        var visit = await new HttpSiteFetcher(Named(site, dns)).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Response, visit.Https.End);
        Assert.Equal(200, visit.Https.Hops[^1].Status);
        Assert.Equal([Host], dns.Names);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenAQuestionWasInterrupted_ShouldAskAgainAtTheNextVisit()
    {
        await using var site = new TestSite(pki);
        var first = true;
        var dns = new FakeAddresses(_ =>
        {
            if (first)
            {
                first = false;
                throw new OperationCanceledException();
            }

            return Found("127.0.0.1");
        });
        var fetcher = new HttpSiteFetcher(Named(site, dns));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fetcher.VisitAsync(Host, TestContext.Current.CancellationToken));
        var visit = await fetcher.VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Response, visit.Https.End);
        Assert.Equal([Host, Host], dns.Names);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenRedirectedToAnotherNameOfTheSite_ShouldAskThatNameToo()
    {
        await using var site = new TestSite(pki)
        {
            Override = r => r.Secure && r.Host == Host && r.Path == "/" ? FakeResponse.Redirect("https://www.site.test/", 302) : null,
        };
        var dns = new FakeAddresses(_ => Found("127.0.0.1"));

        var visit = await new HttpSiteFetcher(Named(site, dns)).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Response, visit.Https.End);
        Assert.Equal([Host, "www.site.test"], dns.Names);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenTheFirstAddressDoesNotAnswer_ShouldTryTheNext()
    {
        // Nothing listens on the IPv6 loopback (or the computer has no IPv6 at all): both are skipped.
        await using var site = new TestSite(pki);
        var dns = new FakeAddresses(_ => Found("::1", "127.0.0.1"));

        var visit = await new HttpSiteFetcher(Named(site, dns)).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Response, visit.Https.End);
        Assert.Equal(TrailEnd.ChangedScheme, visit.Http.End);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenEveryAddressRefuses_ShouldReportTheConnectionAsRefused()
    {
        await using var site = new TestSite(pki) { HttpsListens = false };
        var dns = new FakeAddresses(_ => Found("127.0.0.1"));

        var visit = await new HttpSiteFetcher(Named(site, dns)).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Error, visit.Https.End);
        Assert.True(visit.Https.Refused);
    }

    [Theory(Timeout = 30_000)]
    [InlineData(DnsStatus.NonExistentDomain, "https://site.test/: the name site.test does not exist in the DNS")]
    [InlineData(DnsStatus.NoRecords, "https://site.test/: the name site.test has no address in the DNS")]
    [InlineData(DnsStatus.Error, "https://site.test/: the DNS gave no address for site.test: cloudflare-dns.com: HTTP 503")]
    public async Task VisitAsync_WhenTheNameHasNoAddress_ShouldSayWhyAndConnectNowhere(DnsStatus status, string expected)
    {
        await using var site = new TestSite(pki);
        var dns = new FakeAddresses(_ => status switch
        {
            DnsStatus.NonExistentDomain => DnsAnswer<IPAddress>.NonExistentDomain(),
            DnsStatus.NoRecords => DnsAnswer<IPAddress>.NoRecords(),
            _ => DnsAnswer<IPAddress>.Failed("cloudflare-dns.com: HTTP 503"),
        });

        using var culture = new UiCulture("en-US");
        var visit = await new HttpSiteFetcher(Named(site, dns)).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Error, visit.Https.End);
        Assert.Equal(expected, visit.Https.Error);
        Assert.False(visit.Https.Refused);
        Assert.Equal(TrailEnd.Error, visit.Http.End);
        Assert.Empty(site.Requests);
    }

    [Fact(Timeout = 30_000)]
    public async Task OpenAsync_WhenTheConnectionGoesToAProxy_ShouldLeaveItsNameToTheSystem()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var dns = new FakeAddresses(_ => throw new InvalidOperationException("the resolver must not be asked about a proxy"));
            var fetcher = new HttpSiteFetcher(new WebCheckOptions { Resolver = dns });
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;

            await using var stream = await fetcher.OpenAsync(new DnsEndPoint("localhost", port), direct: false, TestContext.Current.CancellationToken);

            Assert.True(stream.CanWrite);
            Assert.Empty(dns.Names);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact(Timeout = 30_000)]
    public async Task OpenAsync_WhenOnlyTheDnsOfTheComputerIsAsked_ShouldLeaveTheNameToTheSystem()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var fetcher = new HttpSiteFetcher(new WebCheckOptions { DnsSource = DnsSource.System });
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;

            await using var stream = await fetcher.OpenAsync(new DnsEndPoint("localhost", port), direct: true, TestContext.Current.CancellationToken);

            Assert.True(stream.CanWrite);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenOnlyTheDnsOfTheComputerIsAsked_ShouldNotAskAnyResolver()
    {
        // Routed to the local server by address: no name is looked up, by anyone.
        await using var site = new TestSite(pki);

        var visit = await new HttpSiteFetcher(site.Options() with { DnsSource = DnsSource.System }).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Response, visit.Https.End);
    }

    [Fact(Timeout = 30_000)]
    public async Task OpenAsync_WhenCancelled_ShouldStopInsteadOfTryingTheNextAddress()
    {
        var dns = new FakeAddresses(_ => Found("127.0.0.1", "127.0.0.2"));
        var fetcher = new HttpSiteFetcher(new WebCheckOptions { Resolver = dns });
        using var cancelled = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await fetcher.OpenAsync(new DnsEndPoint(Host, FakeWebServer.ClosedPort()), direct: true, cancelled.Token));
    }

    [Theory]
    [InlineData("https://site.test/", "site.test", 443, true)]
    [InlineData("https://SITE.test/page", "site.test", 443, true)]
    [InlineData("http://site.test/", "site.test", 80, true)]
    [InlineData("https://site.test/", "proxy.lan", 8080, false)]
    [InlineData("https://site.test/", "site.test", 3128, false)]
    [InlineData("https://xn--caff-8oa.test/", "xn--caff-8oa.test", 443, true)]
    public void IsDirect_WhenComparingTheRequestWithTheEndpoint_ShouldTellASiteFromAProxy(string url, string host, int port, bool expected)
    {
        Assert.Equal(expected, HttpSiteFetcher.IsDirect(new Uri(url), new DnsEndPoint(host, port)));
    }

    [Fact]
    public void IsDirect_WhenTheRequestHasNoAddress_ShouldBeFalse()
    {
        Assert.False(HttpSiteFetcher.IsDirect(null, new DnsEndPoint(Host, 443)));
    }

    private static DnsAnswer<IPAddress> Found(params string[] addresses) => DnsAnswer<IPAddress>.Found(addresses.Select(IPAddress.Parse));

    /// <summary>The options of a test site that keep the name of the host, so the resolver decides the address.</summary>
    private static WebCheckOptions Named(TestSite site, IDnsResolver resolver)
    {
        var routed = site.Options();
        return routed with
        {
            Resolver = resolver,
            Route = endpoint => new DnsEndPoint(endpoint.Host, ((IPEndPoint)routed.Route(endpoint)).Port),
        };
    }

    /// <summary>A resolver that knows only addresses and records the names it was asked.</summary>
    private sealed class FakeAddresses(Func<string, DnsAnswer<IPAddress>> answer) : IDnsResolver
    {
        public ConcurrentQueue<string> Names { get; } = new();

        public Task<DnsAnswer<string>> QueryTxtAsync(string name, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DnsAnswer<MailExchange>> QueryMxAsync(string name, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DnsAnswer<IPAddress>> QueryAddressesAsync(string name, CancellationToken cancellationToken)
        {
            Names.Enqueue(name);
            return Task.FromResult(answer(name));
        }
    }
}
