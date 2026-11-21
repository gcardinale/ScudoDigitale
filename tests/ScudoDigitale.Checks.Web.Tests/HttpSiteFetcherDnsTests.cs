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
    public async Task VisitAsync_WhenAQuestionBroke_ShouldAskAgainInsteadOfRememberingTheFailure()
    {
        await using var site = new TestSite(pki);
        var broken = true;
        var dns = new FakeAddresses(_ => broken ? throw new InvalidOperationException("the resolver broke") : Found("127.0.0.1"));
        var fetcher = new HttpSiteFetcher(Named(site, dns));

        var failed = await fetcher.VisitAsync(Host, TestContext.Current.CancellationToken);
        broken = false;
        var visit = await fetcher.VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Error, failed.Https.End);
        Assert.Contains("the resolver broke", failed.Https.Error, StringComparison.Ordinal);
        Assert.Equal(TrailEnd.Response, visit.Https.End);

        // Once for each of the two starting addresses of the failed visit, once for the good one.
        Assert.Equal([Host, Host, Host], dns.Names);
    }

    [Fact(Timeout = 30_000)]
    public async Task LookupAsync_WhenWhoAskedFirstStopsWaiting_ShouldStillAnswerTheOthers()
    {
        var pending = new TaskCompletionSource<DnsAnswer<IPAddress>>();
        var dns = new FakeAddresses(_ => Found("192.0.2.9")) { Later = _ => pending.Task };
        var fetcher = new HttpSiteFetcher(new WebCheckOptions { Resolver = dns });
        using var impatient = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);

        var first = fetcher.LookupAsync(Host, impatient.Token);
        var second = fetcher.LookupAsync(Host, TestContext.Current.CancellationToken);
        await impatient.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        pending.SetResult(Found("127.0.0.1"));

        Assert.Equal([IPAddress.Loopback], (await second).Records);
        Assert.Equal([IPAddress.Loopback], (await fetcher.LookupAsync(Host, TestContext.Current.CancellationToken)).Records);
        Assert.Equal([Host], dns.Names);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenTheResolverIsSlowerThanARequestMayLast_ShouldStillVisitTheSite()
    {
        // The address of a redirect target is asked before its request, not inside its deadline:
        // otherwise a slow resolver would make a site that works look unusable over HTTPS.
        await using var site = new TestSite(pki)
        {
            Override = r => r.Secure && r.Host == Host && r.Path == "/" ? FakeResponse.Redirect("https://www.site.test/", 302) : null,
        };
        var dns = new FakeAddresses(_ => Found("127.0.0.1"))
        {
            Later = async name =>
            {
                await Task.Delay(name == Host ? 0 : 1500);
                return Found("127.0.0.1");
            },
        };
        var options = Named(site, dns) with { RequestTimeout = TimeSpan.FromMilliseconds(500) };

        var visit = await new HttpSiteFetcher(options).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Response, visit.Https.End);
        Assert.Equal("www.site.test", visit.Https.Hops[^1].Url.Host);
    }

    [Theory(Timeout = 30_000)]
    [InlineData(DnsStatus.NonExistentDomain)]
    [InlineData(DnsStatus.NoRecords)]
    [InlineData(DnsStatus.Error)]
    public async Task VisitAsync_WhenOnlyTheComputerKnowsTheName_ShouldVisitTheSiteAllTheSame(DnsStatus status)
    {
        // A site of the local network, or a name written in the hosts file.
        await using var site = new TestSite(pki);
        var dns = new FakeAddresses(_ => Answer(status));
        var asked = new ConcurrentQueue<string>();
        var options = Named(site, dns) with
        {
            SystemAddresses = (name, _) =>
            {
                asked.Enqueue(name);
                return Task.FromResult<IPAddress[]>([IPAddress.Loopback]);
            },
        };

        var visit = await new HttpSiteFetcher(options).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Response, visit.Https.End);
        Assert.Equal([Host], asked);
    }

    [Fact(Timeout = 30_000)]
    public async Task LookupAsync_WhenTheComputerAnswers_ShouldPutIPv4First()
    {
        var options = new WebCheckOptions
        {
            Resolver = new FakeAddresses(_ => DnsAnswer<IPAddress>.NonExistentDomain()),
            SystemAddresses = (_, _) => Task.FromResult<IPAddress[]>([IPAddress.IPv6Loopback, IPAddress.Loopback]),
        };

        var answer = await new HttpSiteFetcher(options).LookupAsync("intranet.test", TestContext.Current.CancellationToken);

        Assert.Equal([IPAddress.Loopback, IPAddress.IPv6Loopback], answer.Records);
    }

    [Fact(Timeout = 30_000)]
    public async Task LookupAsync_WhenTheComputerHasNoAddressEither_ShouldKeepTheAnswerOfTheResolver()
    {
        var options = new WebCheckOptions
        {
            Resolver = new FakeAddresses(_ => DnsAnswer<IPAddress>.NonExistentDomain()),
            SystemAddresses = (_, _) => Task.FromResult<IPAddress[]>([]),
        };

        var answer = await new HttpSiteFetcher(options).LookupAsync("nowhere.test", TestContext.Current.CancellationToken);

        Assert.Equal(DnsStatus.NonExistentDomain, answer.Status);
    }

    [Fact(Timeout = 30_000)]
    public async Task LookupAsync_WhenTheResolverAnswers_ShouldNotAskTheComputer()
    {
        var options = new WebCheckOptions
        {
            Resolver = new FakeAddresses(_ => Found("192.0.2.9")),
            SystemAddresses = (_, _) => throw new InvalidOperationException("the computer must not be asked"),
        };

        var answer = await new HttpSiteFetcher(options).LookupAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal([IPAddress.Parse("192.0.2.9")], answer.Records);
    }

    [Fact(Timeout = 30_000)]
    public async Task SystemAddresses_WhenNotReplaced_ShouldAskTheOperatingSystem()
    {
        // "localhost" is answered by the system itself: nothing leaves the computer.
        var addresses = await new WebCheckOptions().SystemAddresses("localhost", TestContext.Current.CancellationToken);

        Assert.Contains(addresses, IPAddress.IsLoopback);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenAProxyReachesTheSite_ShouldNotAskTheResolver()
    {
        // The proxy here is the test site itself: it receives the request for the whole address.
        await using var site = new TestSite(pki);
        var dns = new FakeAddresses(_ => throw new InvalidOperationException("through a proxy, the proxy resolves the name"));
        var port = ((IPEndPoint)site.Options().Route(new DnsEndPoint(Host, 80))).Port;
        var options = Named(site, dns) with
        {
            Proxy = new WebProxy($"http://127.0.0.1:{port}"),
            Route = endpoint => endpoint,
        };

        var visit = await new HttpSiteFetcher(options).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Empty(dns.Names);
        Assert.NotEqual(TrailEnd.Error, visit.Http.End);
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
        var dns = new FakeAddresses(_ => Answer(status));

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
    public async Task OpenAsync_WhenCancelled_ShouldEndAsCancelled()
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
        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        Assert.Equal(expected, HttpSiteFetcher.IsDirect(request, new DnsEndPoint(host, port)));
    }

    [Fact]
    public void IsDirect_WhenTheRequestHasNoAddress_ShouldBeFalse()
    {
        using var request = new HttpRequestMessage();

        Assert.False(HttpSiteFetcher.IsDirect(request, new DnsEndPoint(Host, 443)));
    }

    [Fact]
    public void IsDirect_WhenTheRequestOpensATunnelThroughAProxy_ShouldBeFalse()
    {
        // What the handler sends to reach an HTTPS site through a proxy: addressed to the proxy.
        using var request = new HttpRequestMessage(HttpMethod.Connect, "http://proxy.lan:8080/");

        Assert.False(HttpSiteFetcher.IsDirect(request, new DnsEndPoint("proxy.lan", 8080)));
    }

    private static DnsAnswer<IPAddress> Found(params string[] addresses) => DnsAnswer<IPAddress>.Found(addresses.Select(IPAddress.Parse));

    private static DnsAnswer<IPAddress> Answer(DnsStatus status) => status switch
    {
        DnsStatus.NonExistentDomain => DnsAnswer<IPAddress>.NonExistentDomain(),
        DnsStatus.NoRecords => DnsAnswer<IPAddress>.NoRecords(),
        _ => DnsAnswer<IPAddress>.Failed("cloudflare-dns.com: HTTP 503"),
    };

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

        /// <summary>An answer that takes its time, instead of the immediate one.</summary>
        public Func<string, Task<DnsAnswer<IPAddress>>>? Later { get; init; }

        public Task<DnsAnswer<string>> QueryTxtAsync(string name, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DnsAnswer<MailExchange>> QueryMxAsync(string name, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DnsAnswer<IPAddress>> QueryAddressesAsync(string name, CancellationToken cancellationToken)
        {
            Names.Enqueue(name);
            return Later is null ? Task.FromResult(answer(name)) : Later(name);
        }
    }
}
