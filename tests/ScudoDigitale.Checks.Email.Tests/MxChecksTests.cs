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

public sealed class MxChecksTests
{
    [Fact]
    public async Task Records_WhenMxExists_ShouldFindNothing()
    {
        var dns = new FakeDnsResolver().WithMx("example.com", (10, "mx.example.com"));

        Assert.Empty(await Make.FindingsAsync(dns, MxChecks.RecordsId));
    }

    [Fact]
    public async Task Records_WhenNullMx_ShouldFindNothing()
    {
        var dns = new FakeDnsResolver().WithMx("example.com", (0, ""));

        Assert.Empty(await Make.FindingsAsync(dns, MxChecks.RecordsId));
    }

    [Fact]
    public async Task Records_WhenNoMx_ShouldReportLowCertain()
    {
        var finding = await Make.SingleFindingAsync(new FakeDnsResolver(), MxChecks.RecordsId);

        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal(Confidence.Certain, finding.Confidence);
        Assert.Equal(["RFC 5321 §5.1", "RFC 7505"], finding.References);
    }

    [Theory]
    [InlineData(MxChecks.RecordsId)]
    [InlineData(MxChecks.HostsId)]
    public async Task Checks_WhenMxQueryFails_ShouldFail(string id)
    {
        var dns = new FakeDnsResolver();
        dns.Mx["example.com"] = DnsAnswer<MailExchange>.Failed("timeout");

        Assert.Contains("timeout", Assert.IsType<CheckResult.Failed>(await Make.RunAsync(dns, id)).Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Hosts_WhenNoMx_ShouldBeSkipped()
    {
        using var culture = new UiCulture("en-US");
        var skipped = Assert.IsType<CheckResult.Skipped>(await Make.RunAsync(new FakeDnsResolver(), MxChecks.HostsId));

        Assert.Contains("MAIL-MX-001", skipped.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Hosts_WhenNullMx_ShouldBeSkippedSayingSo()
    {
        var dns = new FakeDnsResolver().WithMx("example.com", (0, ""));

        using var culture = new UiCulture("en-US");
        var skipped = Assert.IsType<CheckResult.Skipped>(await Make.RunAsync(dns, MxChecks.HostsId));

        Assert.Contains("null MX", skipped.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Hosts_WhenEveryHostResolves_ShouldFindNothing()
    {
        var dns = new FakeDnsResolver()
            .WithMx("example.com", (10, "mx1.example.com"), (20, "mx2.example.com"))
            .WithAddress("mx1.example.com", "192.0.2.1")
            .WithAddress("mx2.example.com", "2001:db8::2");

        Assert.Empty(await Make.FindingsAsync(dns, MxChecks.HostsId));
    }

    [Fact]
    public async Task Hosts_WhenNoHostResolves_ShouldReportHighForEach()
    {
        var dns = new FakeDnsResolver().WithMx("example.com", (20, "mx2.example.com"), (10, "mx1.example.com"));
        dns.Addresses["mx2.example.com"] = DnsAnswer<System.Net.IPAddress>.NonExistentDomain();

        var findings = await Make.FindingsAsync(dns, MxChecks.HostsId);

        Assert.Equal(["10 mx1.example.com", "20 mx2.example.com"], findings.Select(f => f.Evidence));
        Assert.All(findings, f => Assert.Equal(Severity.High, f.Severity));
    }

    [Fact]
    public async Task Hosts_WhenOnlySomeHostsResolve_ShouldReportMedium()
    {
        var dns = new FakeDnsResolver()
            .WithMx("example.com", (10, "mx1.example.com"), (20, "gone.example.com"))
            .WithAddress("mx1.example.com", "192.0.2.1");

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(dns, MxChecks.HostsId);

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("Mail server without an address (gone.example.com)", finding.Title);
    }

    [Fact]
    public async Task Hosts_WhenMxIsAnIpAddress_ShouldReportMediumWithoutQueryingIt()
    {
        var dns = new FakeDnsResolver()
            .WithMx("example.com", (10, "192.0.2.25"), (20, "mx.example.com"))
            .WithAddress("mx.example.com", "192.0.2.26");

        var finding = await Make.SingleFindingAsync(dns, MxChecks.HostsId);

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("10 192.0.2.25", finding.Evidence);
        Assert.Equal(0, dns.Count("ADDR 192.0.2.25"));
    }

    [Fact]
    public async Task Hosts_WhenNullMxIsMixedWithRealServers_ShouldReportTheRootAsUnresolvable()
    {
        var dns = new FakeDnsResolver()
            .WithMx("example.com", (0, ""), (10, "mx.example.com"))
            .WithAddress("mx.example.com", "192.0.2.1");

        var finding = await Make.SingleFindingAsync(dns, MxChecks.HostsId);

        Assert.Equal("0 .", finding.Evidence);
        Assert.Equal(Severity.Medium, finding.Severity);
    }

    [Fact]
    public async Task Hosts_WhenHostLookupFails_ShouldReportLowToBeVerifiedWithTheError()
    {
        var dns = new FakeDnsResolver().WithMx("example.com", (10, "mx.example.com"));
        dns.Addresses["mx.example.com"] = DnsAnswer<System.Net.IPAddress>.Failed("SERVFAIL");

        var finding = await Make.SingleFindingAsync(dns, MxChecks.HostsId);

        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal(Confidence.ToBeVerified, finding.Confidence);
        Assert.Equal("10 mx.example.com — SERVFAIL", finding.Evidence);
    }

    [Fact]
    public async Task Hosts_WhenSameHostIsListedTwice_ShouldReportItOnce()
    {
        var dns = new FakeDnsResolver().WithMx("example.com", (10, "mx.example.com"), (20, "MX.example.com"));

        Assert.Single(await Make.FindingsAsync(dns, MxChecks.HostsId));
        Assert.Equal(1, dns.Count("ADDR mx.example.com"));
    }

    [Fact]
    public async Task Hosts_WhenMoreThanTheLimit_ShouldResolveOnlyTheMostPreferred()
    {
        var hosts = Enumerable.Range(1, MxChecks.MaxHosts + 5).Select(i => (i, $"mx{i}.example.com")).ToArray();
        var dns = new FakeDnsResolver().WithMx("example.com", hosts);

        var findings = await Make.FindingsAsync(dns, MxChecks.HostsId);

        Assert.Equal(MxChecks.MaxHosts, findings.Count);
        Assert.Equal(MxChecks.MaxHosts, dns.Queries.Count(q => q.StartsWith("ADDR ", StringComparison.Ordinal)));
        Assert.Equal(0, dns.Count($"ADDR mx{MxChecks.MaxHosts + 1}.example.com"));
    }

    [Fact(Timeout = 10_000)]
    public async Task Hosts_WhenCancelledWhileResolving_ShouldThrow()
    {
        var dns = new FakeDnsResolver().WithMx("example.com", (10, "mx.example.com"));
        dns.Hanging.Add("mx.example.com");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Make.Check(dns, MxChecks.HostsId).RunAsync(Make.Context(), cts.Token));
    }

    [Fact]
    public void IsNullMx_WhenCalled_ShouldRequireASingleRootRecord()
    {
        Assert.True(MxChecks.IsNullMx([new MailExchange(0, "")]));
        Assert.False(MxChecks.IsNullMx([new MailExchange(0, ""), new MailExchange(10, "mx.example.com")]));
        Assert.False(MxChecks.IsNullMx([new MailExchange(10, "mx.example.com")]));
        Assert.False(MxChecks.IsNullMx([]));
    }
}
