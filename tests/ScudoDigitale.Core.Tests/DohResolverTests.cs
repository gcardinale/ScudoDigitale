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

using System.Net;
using System.Text;

using ScudoDigitale.Core.Dns;

namespace ScudoDigitale.Core.Tests;

public sealed class DohResolverTests
{
    private static readonly DnsOptions Fast = new() { Timeout = TimeSpan.FromMilliseconds(100) };

    [Fact]
    public async Task QueryTxtAsync_WhenAnswered_ShouldSendTheNameAndTypeAsJsonRequest()
    {
        var handler = new FakeHandler(_ => Json("""{"Status":0,"Answer":[{"name":"example.com","type":16,"data":"\"v=spf1 -all\""}]}"""));
        var resolver = new DohResolver(Client(handler), DohResolver.Cloudflare, Fast);

        var answer = await resolver.QueryTxtAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal("v=spf1 -all", Assert.Single(answer.Records));
        var request = Assert.Single(handler.Requests);
        Assert.Equal("https://cloudflare-dns.com/dns-query?name=example.com&type=16", request.RequestUri!.ToString());
        Assert.Equal("application/dns-json", Assert.Single(request.Headers.Accept).MediaType);
        Assert.False(request.Headers.Contains("Cookie"));
    }

    [Fact]
    public async Task QueryTxtAsync_WhenNameNeedsEscaping_ShouldEscapeIt()
    {
        var handler = new FakeHandler(_ => Json("""{"Status":0}"""));
        var resolver = new DohResolver(Client(handler), DohResolver.Google, Fast);

        await resolver.QueryTxtAsync("a&b=c.example", TestContext.Current.CancellationToken);

        Assert.Equal("https://dns.google/resolve?name=a%26b%3Dc.example&type=16", handler.Requests[0].RequestUri!.AbsoluteUri);
    }

    [Fact]
    public async Task QueryTxtAsync_WhenAnswerContainsACnameChain_ShouldKeepOnlyTxtRecords()
    {
        var handler = new FakeHandler(_ => Json("""
            {"Status":0,"Answer":[
              {"name":"s1._domainkey.example.com","type":5,"data":"s1.tenant.example.net."},
              {"name":"s1.tenant.example.net","type":16,"data":"\"v=DKIM1; p=AAAA\""},
              {"name":"s1.tenant.example.net","type":16,"data":"plain text"}]}
            """));

        var answer = await new DohResolver(Client(handler), DohResolver.Cloudflare, Fast).QueryTxtAsync("s1._domainkey.example.com", TestContext.Current.CancellationToken);

        Assert.Equal(["v=DKIM1; p=AAAA", "plain text"], answer.Records);
    }

    [Theory]
    [InlineData("\"v=spf1 \" \"-all\"", "v=spf1 -all")]
    [InlineData("\"say \\\"hi\\\" \\\\ ok\"", "say \"hi\" \\ ok")]
    [InlineData("\"semi\\059colon\"", "semi;colon")]
    [InlineData("\"short\\05\"", "short05")]
    [InlineData("\"trailing\\\"", "trailing\"")]
    [InlineData("no quotes at all", "no quotes at all")]
    [InlineData("\"\"", "")]
    public void ParseTxt_WhenDataIsQuoted_ShouldUnescapeAndJoinTheStrings(string data, string expected)
    {
        Assert.Equal(expected, DohResolver.ParseTxt(data));
    }

    [Theory]
    [InlineData("10 mx.example.com.", 10, "mx.example.com")]
    [InlineData("0 .", 0, "")]
    public void ParseMx_WhenDataIsValid_ShouldReadPreferenceAndHost(string data, int preference, string host)
    {
        Assert.Equal(new MailExchange(preference, host), DohResolver.ParseMx(data));
    }

    [Theory]
    [InlineData("mx.example.com.")]
    [InlineData("x mx.example.com.")]
    [InlineData("-1 mx.example.com.")]
    public void ParseMx_WhenDataIsNotAnMxRecord_ShouldReturnNull(string data)
    {
        Assert.Null(DohResolver.ParseMx(data));
    }

    [Fact]
    public async Task QueryMxAsync_WhenAnswered_ShouldReturnTheRecordsAndSkipUnreadableOnes()
    {
        var handler = new FakeHandler(_ => Json("""{"Status":0,"Answer":[{"type":15,"data":"10 mx1.example.com."},{"type":15,"data":"bad"}]}"""));

        var answer = await new DohResolver(Client(handler), DohResolver.Cloudflare, Fast).QueryMxAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal(new MailExchange(10, "mx1.example.com"), Assert.Single(answer.Records));
        Assert.EndsWith("type=15", handler.Requests[0].RequestUri!.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task QueryAddressesAsync_WhenBothFamiliesAnswer_ShouldAskAAndAaaaAndMergeThem()
    {
        var handler = new FakeHandler(r => r.RequestUri!.Query.EndsWith("type=1", StringComparison.Ordinal)
            ? Json("""{"Status":0,"Answer":[{"type":1,"data":"192.0.2.1"},{"type":1,"data":"not-an-ip"}]}""")
            : Json("""{"Status":0,"Answer":[{"type":28,"data":"2001:db8::1"}]}"""));

        var answer = await new DohResolver(Client(handler), DohResolver.Cloudflare, Fast).QueryAddressesAsync("mx.example.com", TestContext.Current.CancellationToken);

        Assert.Equal([IPAddress.Parse("192.0.2.1"), IPAddress.Parse("2001:db8::1")], answer.Records);
        Assert.Equal(2, handler.Requests.Count);
    }

    [Theory]
    [InlineData("""{"Status":3}""", DnsStatus.NonExistentDomain)]
    [InlineData("""{"Status":0}""", DnsStatus.NoRecords)]
    [InlineData("""{"Status":0,"Answer":[{"type":5,"data":"alias.example."}]}""", DnsStatus.NoRecords)]
    [InlineData("""{"Status":2}""", DnsStatus.Error)]
    [InlineData("""{"Status":5}""", DnsStatus.Error)]
    [InlineData("""not json""", DnsStatus.Error)]
    [InlineData("""{"Answer":[]}""", DnsStatus.Error)]
    internal async Task QueryTxtAsync_WhenStatusIsNotAnAnswer_ShouldMapIt(string body, DnsStatus expected)
    {
        var handler = new FakeHandler(_ => Json(body));

        var answer = await new DohResolver(Client(handler), DohResolver.Cloudflare, Fast).QueryTxtAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal(expected, answer.Status);
        if (expected == DnsStatus.Error)
        {
            Assert.StartsWith("cloudflare-dns.com: ", answer.Error, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task QueryTxtAsync_WhenHttpFails_ShouldReturnErrorWithTheStatusCode()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.BadGateway));

        var answer = await new DohResolver(Client(handler), DohResolver.Google, Fast).QueryTxtAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal("dns.google: HTTP 502", answer.Error);
    }

    [Fact]
    public async Task QueryTxtAsync_WhenConnectionFails_ShouldReturnErrorInsteadOfThrowing()
    {
        var handler = new FakeHandler(_ => throw new HttpRequestException("connection refused"));

        var answer = await new DohResolver(Client(handler), DohResolver.Google, Fast).QueryTxtAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal("dns.google: connection refused", answer.Error);
    }

    [Fact(Timeout = 10_000)]
    public async Task QueryTxtAsync_WhenServiceHangs_ShouldGiveUpAfterThreeTimesTheDnsTimeout()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK), hang: true);

        using var culture = new UiCulture("en-US");
        var answer = await new DohResolver(Client(handler), DohResolver.Cloudflare, Fast).QueryTxtAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal("cloudflare-dns.com: no answer within 0.3 seconds", answer.Error);
    }

    [Fact(Timeout = 10_000)]
    public async Task QueryTxtAsync_WhenCallerCancels_ShouldThrow()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK), hang: true);
        var slow = new DnsOptions { Timeout = TimeSpan.FromSeconds(10) };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new DohResolver(Client(handler), DohResolver.Cloudflare, slow).QueryTxtAsync("example.com", cts.Token));
    }

    [Fact]
    public async Task QueryTxtAsync_WhenAlreadyCancelled_ShouldThrowWithoutARequest()
    {
        var handler = new FakeHandler(_ => Json("""{"Status":0}"""));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => new DohResolver(Client(handler), DohResolver.Cloudflare, Fast).QueryTxtAsync("example.com", new CancellationToken(true)));
        Assert.Empty(handler.Requests);
    }

    private static HttpClient Client(HttpMessageHandler handler) => new(handler) { Timeout = Timeout.InfiniteTimeSpan };

    private static HttpResponseMessage Json(string body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/dns-json") };

    /// <summary>Answers with a function, or hangs ignoring the token (as a dead service would).</summary>
    private sealed class FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond, bool hang = false) : HttpMessageHandler
    {
        public List<HttpRequestMessage> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (hang)
            {
                await new TaskCompletionSource().Task;
            }

            return respond(request);
        }
    }
}

public sealed class FallbackResolverTests
{
    [Fact]
    public async Task Query_WhenFirstResolverFails_ShouldAskTheNext()
    {
        var first = new FakeDnsResolver();
        first.Txt["example.com"] = DnsAnswer<string>.Failed("cloudflare: timeout");
        var second = new FakeDnsResolver().WithTxt("example.com", "v=spf1 -all");

        var answer = await new FallbackResolver([first, second]).QueryTxtAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal("v=spf1 -all", Assert.Single(answer.Records));
    }

    [Fact]
    public async Task Query_WhenFirstResolverAnswersNoRecordsOrNxdomain_ShouldNotAskTheNext()
    {
        var first = new FakeDnsResolver();
        first.Mx["gone.example"] = DnsAnswer<MailExchange>.NonExistentDomain();
        var second = new FakeDnsResolver().WithMx("gone.example", (10, "mx.example"));
        var fallback = new FallbackResolver([first, second]);

        Assert.Equal(DnsStatus.NoRecords, (await fallback.QueryTxtAsync("example.com", TestContext.Current.CancellationToken)).Status);
        Assert.Equal(DnsStatus.NonExistentDomain, (await fallback.QueryMxAsync("gone.example", TestContext.Current.CancellationToken)).Status);
        Assert.Empty(second.Queries);
    }

    [Fact]
    public async Task Query_WhenEveryResolverFails_ShouldReportEveryError()
    {
        var first = new FakeDnsResolver();
        first.Addresses["mx.example"] = DnsAnswer<IPAddress>.Failed("cloudflare: timeout");
        var second = new FakeDnsResolver();
        second.Addresses["mx.example"] = DnsAnswer<IPAddress>.Failed("router: refused");

        var answer = await new FallbackResolver([first, second]).QueryAddressesAsync("mx.example", TestContext.Current.CancellationToken);

        Assert.Equal("cloudflare: timeout; router: refused", answer.Error);
    }
}

public sealed class ResolverChoiceTests
{
    [Fact]
    public void CreateResolver_WhenPublic_ShouldAskCloudflareThenGoogleOverHttpsThenTheSystem()
    {
        using var http = new HttpClient();

        var resolver = Assert.IsType<FallbackResolver>(DnsResolvers.Create(new DnsOptions(), http));

        Assert.Collection(
            resolver.Resolvers,
            r => Assert.IsType<DohResolver>(r),
            r => Assert.IsType<DohResolver>(r),
            r => Assert.IsType<DnsClientResolver>(r));
    }

    [Fact]
    public void CreateResolver_WhenSystem_ShouldUseOnlyTheDnsOfTheComputer()
    {
        using var http = new HttpClient();

        Assert.IsType<DnsClientResolver>(DnsResolvers.Create(new DnsOptions { Source = DnsSource.System }, http));
    }

    [Fact]
    public void CreateHttpClient_WhenCalled_ShouldSendNoCookiesAndAGenericUserAgent()
    {
        using var http = DnsResolvers.CreateHttpClient();

        Assert.Equal("ScudoDigitale", http.DefaultRequestHeaders.UserAgent.ToString());
        Assert.Equal(Timeout.InfiniteTimeSpan, http.Timeout);
    }

    [Fact]
    public void CreateHandler_WhenCalled_ShouldNotKeepCookies()
    {
        using var handler = DnsResolvers.CreateHandler();

        Assert.False(handler.UseCookies);
        Assert.Equal(TimeSpan.FromMinutes(2), handler.PooledConnectionLifetime);
    }
}
