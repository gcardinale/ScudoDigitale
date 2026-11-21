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
        // The resolver obeys the token it is given, as the real ones do: had it been given the
        // token of who asked first, the question would end with that caller.
        var dns = new FakeAddresses(_ => Found("192.0.2.9")) { Later = (_, token) => pending.Task.WaitAsync(token) };
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
            Later = async (name, _) =>
            {
                await Task.Delay(name == Host ? 0 : 3000);
                return Found("127.0.0.1");
            },
        };
        var options = Named(site, dns) with { RequestTimeout = TimeSpan.FromSeconds(1.5) };

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
    public async Task VisitAsync_WhenOnlyHttpsGoesThroughAProxy_ShouldStillResolveThePlainAddressBeforeItsRequest()
    {
        // HTTPS_PROXY without HTTP_PROXY: the plain address is reached directly, so its name must be
        // resolved in advance like any other, or a slow resolver makes it look as if nothing answered.
        await using var site = new TestSite(pki);
        var dns = new FakeAddresses(_ => Found("127.0.0.1"))
        {
            Later = async (_, _) =>
            {
                await Task.Delay(3000);
                return Found("127.0.0.1");
            },
        };
        var options = Named(site, dns) with
        {
            RequestTimeout = TimeSpan.FromSeconds(1.5),
            Proxy = new FakeProxy(address => address.Scheme == "https" ? new Uri($"http://127.0.0.1:{FakeWebServer.ClosedPort()}") : null),
        };

        var visit = await new HttpSiteFetcher(options).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.ChangedScheme, visit.Http.End);
        Assert.Equal([Host], dns.Names);
    }

    [Theory(Timeout = 30_000)]
    [InlineData(DnsStatus.NonExistentDomain)]
    [InlineData(DnsStatus.NoRecords)]
    public async Task LookupAsync_WhenTheComputerGivesAPublicAddressForANameThatDoesNotExist_ShouldNotBelieveIt(DnsStatus status)
    {
        // What some providers and routers answer in place of "does not exist": their search page.
        var options = new WebCheckOptions
        {
            Resolver = new FakeAddresses(_ => Answer(status)),
            SystemAddresses = (_, _) => Task.FromResult<IPAddress[]>([IPAddress.Parse("203.0.113.7")]),
        };

        var answer = await new HttpSiteFetcher(options).LookupAsync("mistyped.test", TestContext.Current.CancellationToken);

        Assert.Equal(status, answer.Status);
    }

    [Fact(Timeout = 30_000)]
    public async Task LookupAsync_WhenNoResolverAnsweredAndTheComputerKnowsTheName_ShouldBelieveTheComputer()
    {
        var options = new WebCheckOptions
        {
            Resolver = new FakeAddresses(_ => Answer(DnsStatus.Error)),
            SystemAddresses = (_, _) => Task.FromResult<IPAddress[]>([IPAddress.Parse("203.0.113.7")]),
        };

        var answer = await new HttpSiteFetcher(options).LookupAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal([IPAddress.Parse("203.0.113.7")], answer.Records);
    }

    [Fact(Timeout = 30_000)]
    public async Task LookupAsync_WhenNobodyAnswered_ShouldAskAgainTheNextTime()
    {
        var answers = new Queue<DnsAnswer<IPAddress>>([Answer(DnsStatus.Error), Found("127.0.0.1")]);
        var dns = new FakeAddresses(_ => answers.Dequeue());
        var options = new WebCheckOptions
        {
            Resolver = dns,
            SystemAddresses = (_, _) => Task.FromResult<IPAddress[]>([]),
        };
        var fetcher = new HttpSiteFetcher(options);

        var first = await fetcher.LookupAsync(Host, TestContext.Current.CancellationToken);
        var second = await fetcher.LookupAsync(Host, TestContext.Current.CancellationToken);
        var third = await fetcher.LookupAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(DnsStatus.Error, first.Status);
        Assert.Equal(DnsStatus.Ok, second.Status);
        Assert.Equal(DnsStatus.Ok, third.Status);
        Assert.Equal([Host, Host], dns.Names);
    }

    [Fact(Timeout = 30_000)]
    public async Task VisitAsync_WhenNoDnsAnswersForTheNameOfARedirect_ShouldMarkTheTrailAsUnanswered()
    {
        await using var site = new TestSite(pki)
        {
            Override = r => r.Secure && r.Host == Host && r.Path == "/" ? FakeResponse.Redirect("https://www.site.test/", 302) : null,
        };
        var dns = new FakeAddresses(name => name == Host ? Found("127.0.0.1") : Answer(DnsStatus.Error));

        var visit = await new HttpSiteFetcher(Named(site, dns)).VisitAsync(Host, TestContext.Current.CancellationToken);

        Assert.Equal(TrailEnd.Error, visit.Https.End);
        Assert.True(visit.Https.Unanswered);
        Assert.False(visit.Http.Unanswered);
        Assert.Single(visit.Https.Hops);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task RunAsync_WhenNoDnsAnsweredForANameAlongTheWay_ShouldSayItCouldNotRunInsteadOfReportingAProblem(bool https, bool http)
    {
        var unanswered = new Trail([], TrailEnd.Error, null, "https://www.example.com/: the DNS gave no address for www.example.com: timeout", Unanswered: true);
        var visit = Site.Good() with
        {
            Https = https ? unanswered : Site.Good().Https,
            Http = http ? unanswered with { Error = "http side" } : Site.Good().Http,
        };

        var failed = Assert.IsType<ScudoDigitale.Core.CheckResult.Failed>(await Make.RunAsync(visit, "WEB-HTTPS-001"));

        Assert.Contains(https ? "www.example.com" : "http side", failed.Error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.254", true)]
    [InlineData("172.15.0.1", false)]
    [InlineData("172.32.0.1", false)]
    [InlineData("192.168.1.10", true)]
    [InlineData("192.169.1.10", false)]
    [InlineData("169.254.10.10", true)]
    [InlineData("169.253.10.10", false)]
    [InlineData("203.0.113.7", false)]
    [InlineData("::1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("fd12:3456::1", true)]
    [InlineData("2001:db8::1", false)]
    [InlineData("::ffff:192.168.1.10", true)]
    [InlineData("::ffff:203.0.113.7", false)]
    public void IsLocal_WhenGivenAnAddress_ShouldTellThisComputerAndPrivateNetworksFromTheInternet(string address, bool expected)
    {
        Assert.Equal(expected, HttpSiteFetcher.IsLocal(IPAddress.Parse(address)));
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
        public Func<string, CancellationToken, Task<DnsAnswer<IPAddress>>>? Later { get; init; }

        public Task<DnsAnswer<string>> QueryTxtAsync(string name, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DnsAnswer<MailExchange>> QueryMxAsync(string name, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DnsAnswer<IPAddress>> QueryAddressesAsync(string name, CancellationToken cancellationToken)
        {
            Names.Enqueue(name);
            return Later is null ? Task.FromResult(answer(name)) : Later(name, cancellationToken);
        }
    }
}
