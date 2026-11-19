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

namespace ScudoDigitale.Checks.Email.Tests;

/// <summary>Behaviour shared by every email check: target validation, missing domains, errors, cancellation.</summary>
public sealed class EmailCheckTests
{
    public static TheoryData<string> AllIds => [.. EmailChecks.Create().Select(c => c.Id)];

    [Theory]
    [MemberData(nameof(AllIds))]
    public async Task RunAsync_WhenTargetIsNotADomainName_ShouldFailWithoutQuerying(string id)
    {
        var dns = new FakeDnsResolver();

        using var culture = new UiCulture("en-US");
        var result = await Make.Check(dns, id).RunAsync(Make.Context("https://example.com/"), TestContext.Current.CancellationToken);

        Assert.Equal("'https://example.com/' is not a valid domain name.", Assert.IsType<CheckResult.Failed>(result).Error);
        Assert.Empty(dns.Queries);
    }

    [Fact]
    public async Task RunAsync_WhenTargetIsNotOfKindDomain_ShouldFail()
    {
        var dns = new FakeDnsResolver();

        var result = await Make.Check(dns, SpfChecks.RecordId).RunAsync(Make.Context("example.com", TargetKind.Website), TestContext.Current.CancellationToken);

        Assert.IsType<CheckResult.Failed>(result);
        Assert.Empty(dns.Queries);
    }

    [Theory]
    [MemberData(nameof(AllIds))]
    public async Task RunAsync_WhenDomainDoesNotExist_ShouldFailSayingSo(string id)
    {
        var dns = new FakeDnsResolver();
        dns.Txt["no-such-domain.example"] = DnsAnswer<string>.NonExistentDomain();

        using var culture = new UiCulture("it-IT");
        var result = await Make.RunAsync(dns, id, "no-such-domain.example");

        Assert.Equal("Il dominio no-such-domain.example non esiste nel DNS pubblico.", Assert.IsType<CheckResult.Failed>(result).Error);
    }

    [Fact]
    public async Task RunAsync_WhenDomainIsInternational_ShouldQueryItsPunycode()
    {
        var dns = new FakeDnsResolver().WithTxt("xn--caff-8oa.it", "v=spf1 -all");

        Assert.Empty(await Make.FindingsAsync(dns, SpfChecks.RecordId, "xn--caff-8oa.it"));
        var result = await Make.Check(dns, SpfChecks.RecordId).RunAsync(Make.Context("caffè.it"), TestContext.Current.CancellationToken);
        Assert.IsType<CheckResult.Executed>(result);
        Assert.Contains("TXT xn--caff-8oa.it", dns.Queries);
    }

    [Theory]
    [MemberData(nameof(AllIds))]
    public async Task RunAsync_WhenResolverThrows_ShouldFailInsteadOfThrowing(string id)
    {
        var dns = new FakeDnsResolver();
        dns.Throwing.Add("example.com");

        var result = await Make.RunAsync(dns, id);

        Assert.Contains("resolver exploded", Assert.IsType<CheckResult.Failed>(result).Error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("_dmarc.example.com", DmarcChecks.PolicyId)]
    [InlineData("selector1._domainkey.example.com", DkimChecks.SelectorsId)]
    [InlineData("mx.example.com", MxChecks.HostsId)]
    public async Task RunAsync_WhenResolverThrowsOnALaterQuery_ShouldFailInsteadOfThrowing(string name, string id)
    {
        var dns = new FakeDnsResolver().WithMx("example.com", (10, "mx.example.com"));
        dns.Throwing.Add(name);

        Assert.IsType<CheckResult.Failed>(await Make.RunAsync(dns, id));
    }

    [Theory(Timeout = 10_000)]
    [MemberData(nameof(AllIds))]
    public async Task RunAsync_WhenResolverHangsAndTokenIsCancelled_ShouldThrowOperationCanceled(string id)
    {
        var dns = new FakeDnsResolver();
        dns.Hanging.Add("example.com");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Make.Check(dns, id).RunAsync(Make.Context(), cts.Token));
    }

    [Fact]
    public async Task RunAsync_WhenAlreadyCancelled_ShouldThrowWithoutQuerying()
    {
        var dns = new FakeDnsResolver();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Make.Check(dns, SpfChecks.RecordId).RunAsync(Make.Context(), new CancellationToken(true)));
        Assert.Empty(dns.Queries);
    }

    [Fact(Timeout = 10_000)]
    public async Task RunAsync_WhenOneCheckIsCancelled_ShouldNotCancelTheSharedAnalysisForTheOthers()
    {
        var gate = new TaskCompletionSource();
        var dns = new SlowResolver(gate.Task);
        var checks = EmailChecks.Create(dns, new EmailCheckOptions());
        var record = checks.Single(c => c.Id == SpfChecks.RecordId);
        var all = checks.Single(c => c.Id == SpfChecks.AllId);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);

        var cancelled = record.RunAsync(Make.Context(), cts.Token);
        var waiting = all.RunAsync(Make.Context(), TestContext.Current.CancellationToken);
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled);
        gate.SetResult();

        Assert.Empty(Assert.IsType<CheckResult.Executed>(await waiting).Findings);
        Assert.Equal(1, dns.TxtQueries);
    }

    [Fact(Timeout = 10_000)]
    public async Task EngineTimeout_WhenResolverHangs_ShouldReportFailedAndReturn()
    {
        var dns = new FakeDnsResolver();
        dns.Hanging.Add("example.com");
        var engine = new CheckEngine(new DenyAll(), new CheckEngineOptions { CheckTimeout = TimeSpan.FromMilliseconds(200) });

        var runs = await engine.RunAsync(
            [Make.Check(dns, SpfChecks.RecordId)],
            Profile.Individual(),
            Make.Context().Scope,
            TestContext.Current.CancellationToken);

        Assert.IsType<CheckResult.Failed>(Assert.Single(runs).Result);
    }

    /// <summary>Holds every TXT answer until released, ignoring the token, and counts the TXT queries.</summary>
    private sealed class SlowResolver(Task release) : IDnsResolver
    {
        private int txtQueries;

        public int TxtQueries => txtQueries;

        public async Task<DnsAnswer<string>> QueryTxtAsync(string name, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref txtQueries);
            await release;
            return DnsAnswer<string>.Found(["v=spf1 -all"]);
        }

        public Task<DnsAnswer<MailExchange>> QueryMxAsync(string name, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DnsAnswer<System.Net.IPAddress>> QueryAddressesAsync(string name, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class DenyAll : IScopeGuard
    {
        public Task<bool> IsAuthorizedAsync(Target target, CancellationToken cancellationToken) => Task.FromResult(false);
    }
}
