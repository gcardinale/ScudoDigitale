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
using DnsClient;

using ScudoDigitale.Core.Dns;

namespace ScudoDigitale.Core.Tests;

public sealed class DnsClientResolverTests
{
    private static readonly DnsOptions Fast = new() { Timeout = TimeSpan.FromMilliseconds(300), Retries = 0 };

    private static DnsClientResolver On(FakeDnsServer server) =>
        new([new NameServer(IPAddress.Loopback, server.Port)], Fast);

    [Fact]
    public async Task QueryTxtAsync_WhenRecordHasSeveralStrings_ShouldJoinThemIntoOneRecord()
    {
        await using var server = new FakeDnsServer()
            .AddTxt("example.com", "v=spf1 include:_spf.example.net ", "-all")
            .AddTxt("example.com", "google-site-verification=abc");

        var answer = await On(server).QueryTxtAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal(DnsStatus.Ok, answer.Status);
        Assert.Equal(2, answer.Records.Count);
        Assert.Contains("v=spf1 include:_spf.example.net -all", answer.Records);
        Assert.Contains("google-site-verification=abc", answer.Records);
    }

    [Fact]
    public async Task QueryTxtAsync_WhenNameIsAlias_ShouldReturnRecordsOfTheTarget()
    {
        await using var server = new FakeDnsServer()
            .AddCname("selector1._domainkey.example.com", "selector1-example-com._domainkey.tenant.example.net")
            .AddTxt("selector1-example-com._domainkey.tenant.example.net", "v=DKIM1; k=rsa; p=AAAA");

        var answer = await On(server).QueryTxtAsync("selector1._domainkey.example.com", TestContext.Current.CancellationToken);

        Assert.Equal("v=DKIM1; k=rsa; p=AAAA", Assert.Single(answer.Records));
    }

    [Fact]
    public async Task QueryTxtAsync_WhenNameHasNoTxt_ShouldReturnNoRecords()
    {
        await using var server = new FakeDnsServer().AddAddress("example.com", "192.0.2.1");

        var answer = await On(server).QueryTxtAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal(DnsStatus.NoRecords, answer.Status);
        Assert.Empty(answer.Records);
    }

    [Fact]
    public async Task QueryTxtAsync_WhenNameDoesNotExist_ShouldReturnNonExistentDomain()
    {
        await using var server = new FakeDnsServer();
        server.NonExistent.Add("missing.example");

        var answer = await On(server).QueryTxtAsync("missing.example", TestContext.Current.CancellationToken);

        Assert.Equal(DnsStatus.NonExistentDomain, answer.Status);
    }

    [Fact]
    public async Task QueryTxtAsync_WhenServerFails_ShouldReturnErrorWithMessage()
    {
        await using var server = new FakeDnsServer();
        server.ServerFailure.Add("example.com");

        var answer = await On(server).QueryTxtAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal(DnsStatus.Error, answer.Status);
        Assert.False(string.IsNullOrWhiteSpace(answer.Error));
    }

    [Fact]
    public async Task QueryTxtAsync_WhenServerDoesNotAnswer_ShouldReturnErrorAfterTimeout()
    {
        await using var server = new FakeDnsServer();
        server.Silent.Add("example.com");

        var answer = await On(server).QueryTxtAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal(DnsStatus.Error, answer.Status);
        Assert.False(string.IsNullOrWhiteSpace(answer.Error));
    }

    [Fact(Timeout = 10_000)]
    public async Task QueryTxtAsync_WhenCancelledWhileWaiting_ShouldThrowOperationCanceled()
    {
        await using var server = new FakeDnsServer();
        server.Silent.Add("example.com");
        var slow = new DnsClientResolver([new NameServer(IPAddress.Loopback, server.Port)], new DnsOptions { Timeout = TimeSpan.FromSeconds(30), Retries = 0 });
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(200));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => slow.QueryTxtAsync("example.com", cts.Token));
    }

    [Fact]
    public async Task QueryTxtAsync_WhenAlreadyCancelled_ShouldThrowWithoutQuerying()
    {
        await using var server = new FakeDnsServer().AddTxt("example.com", "x");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => On(server).QueryTxtAsync("example.com", new CancellationToken(true)));
        Assert.Equal(0, server.Received);
    }

    [Fact]
    public async Task QueryTxtAsync_WhenNoNameServerIsConfigured_ShouldFailWithoutThrowing()
    {
        var resolver = new DnsClientResolver([], Fast);

        using var culture = new UiCulture("en-US");
        var answer = await resolver.QueryTxtAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal(DnsStatus.Error, answer.Status);
        Assert.Contains("no DNS server", answer.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task QueryMxAsync_WhenRecordsExist_ShouldReturnPreferenceAndHostWithoutTrailingDot()
    {
        await using var server = new FakeDnsServer()
            .AddMx("example.com", 10, "mx1.example.com")
            .AddMx("example.com", 20, "mx2.example.com");

        var answer = await On(server).QueryMxAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal(
            [new MailExchange(10, "mx1.example.com"), new MailExchange(20, "mx2.example.com")],
            answer.Records.OrderBy(m => m.Preference));
    }

    [Fact]
    public async Task QueryMxAsync_WhenNullMx_ShouldReturnEmptyHost()
    {
        await using var server = new FakeDnsServer().AddMx("example.com", 0, ".");

        var answer = await On(server).QueryMxAsync("example.com", TestContext.Current.CancellationToken);

        Assert.Equal(new MailExchange(0, string.Empty), Assert.Single(answer.Records));
    }

    [Fact]
    public async Task QueryAddressesAsync_WhenBothFamiliesExist_ShouldReturnIpv4AndIpv6()
    {
        await using var server = new FakeDnsServer()
            .AddAddress("mx.example.com", "192.0.2.25")
            .AddAddress("mx.example.com", "2001:db8::25");

        var answer = await On(server).QueryAddressesAsync("mx.example.com", TestContext.Current.CancellationToken);

        Assert.Equal(DnsStatus.Ok, answer.Status);
        Assert.Equal([IPAddress.Parse("192.0.2.25"), IPAddress.Parse("2001:db8::25")], answer.Records);
    }

    [Fact]
    public void Combine_WhenOnlyOneFamilyHasAddresses_ShouldReturnThem()
    {
        var answer = DnsClientResolver.Combine(DnsAnswer<IPAddress>.Failed("timeout"), DnsAnswer<IPAddress>.Found([IPAddress.IPv6Loopback]));

        Assert.Equal(DnsStatus.Ok, answer.Status);
        Assert.Equal(IPAddress.IPv6Loopback, Assert.Single(answer.Records));
    }

    [Theory]
    [InlineData(DnsStatus.Error, DnsStatus.NoRecords, DnsStatus.Error)]
    [InlineData(DnsStatus.NoRecords, DnsStatus.Error, DnsStatus.Error)]
    [InlineData(DnsStatus.NonExistentDomain, DnsStatus.Error, DnsStatus.Error)]
    [InlineData(DnsStatus.NonExistentDomain, DnsStatus.NoRecords, DnsStatus.NonExistentDomain)]
    [InlineData(DnsStatus.NoRecords, DnsStatus.NonExistentDomain, DnsStatus.NonExistentDomain)]
    [InlineData(DnsStatus.NoRecords, DnsStatus.NoRecords, DnsStatus.NoRecords)]
    internal void Combine_WhenNoAddress_ShouldPreferErrorThenNonExistentThenNoRecords(DnsStatus v4, DnsStatus v6, DnsStatus expected)
    {
        Assert.Equal(expected, DnsClientResolver.Combine(Answer(v4), Answer(v6)).Status);
    }

    [Fact]
    public void Failed_WhenErrorIsBlank_ShouldUseGenericText()
    {
        Assert.Equal("unknown DNS error", DnsAnswer<string>.Failed(" ").Error);
        Assert.Equal("refused", DnsAnswer<string>.Failed("refused").Error);
    }

    private static DnsAnswer<IPAddress> Answer(DnsStatus status) => status switch
    {
        DnsStatus.Error => DnsAnswer<IPAddress>.Failed("timeout"),
        DnsStatus.NonExistentDomain => DnsAnswer<IPAddress>.NonExistentDomain(),
        _ => DnsAnswer<IPAddress>.NoRecords(),
    };
}
