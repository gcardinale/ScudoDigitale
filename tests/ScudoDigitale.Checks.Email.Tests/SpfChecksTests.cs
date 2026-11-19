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

public sealed class SpfChecksTests
{
    [Fact]
    public async Task Record_WhenNoSpf_ShouldReportHighCertain()
    {
        var dns = new FakeDnsResolver().WithTxt("example.com", "google-site-verification=abc");

        var finding = await Make.SingleFindingAsync(dns, SpfChecks.RecordId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(Confidence.Certain, finding.Confidence);
        Assert.Contains("example.com", finding.Evidence, StringComparison.Ordinal);
        Assert.Equal(["RFC 7208"], finding.References);
    }

    [Fact]
    public async Task Record_WhenTwoSpfRecords_ShouldReportHighWithBothRecords()
    {
        var dns = new FakeDnsResolver().WithTxt("example.com", "v=spf1 -all", "v=spf1 include:x.example ~all");

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(dns, SpfChecks.RecordId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("More than one SPF record", finding.Title);
        Assert.Equal("v=spf1 -all | v=spf1 include:x.example ~all", finding.Evidence);
    }

    [Fact]
    public async Task Record_WhenOneSpfRecord_ShouldFindNothing()
    {
        var dns = new FakeDnsResolver().WithTxt("example.com", "v=spf1 -all", "other=1");

        Assert.Empty(await Make.FindingsAsync(dns, SpfChecks.RecordId));
    }

    [Fact]
    public async Task Record_WhenTxtQueryFails_ShouldFailWithTheError()
    {
        var dns = new FakeDnsResolver();
        dns.Txt["example.com"] = DnsAnswer<string>.Failed("SERVFAIL");

        var result = await Make.RunAsync(dns, SpfChecks.RecordId);

        Assert.Contains("SERVFAIL", Assert.IsType<CheckResult.Failed>(result).Error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("v=spf1 -all")]
    [InlineData("v=spf1 mx ~all")]
    public async Task All_WhenRecordEndsWithFailOrSoftFail_ShouldFindNothing(string record)
    {
        var dns = new FakeDnsResolver().WithTxt("example.com", record);

        Assert.Empty(await Make.FindingsAsync(dns, SpfChecks.AllId));
    }

    [Theory]
    [InlineData("v=spf1 +all")]
    [InlineData("v=spf1 a all")]
    public async Task All_WhenRecordAuthorizesEverybody_ShouldReportHigh(string record)
    {
        var dns = new FakeDnsResolver().WithTxt("example.com", record);

        var finding = await Make.SingleFindingAsync(dns, SpfChecks.AllId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(record, finding.Evidence);
    }

    [Theory]
    [InlineData("v=spf1 ?all")]
    [InlineData("v=spf1 mx")]
    public async Task All_WhenRecordIsNeutralOrHasNoAll_ShouldReportMedium(string record)
    {
        var dns = new FakeDnsResolver().WithTxt("example.com", record);

        var finding = await Make.SingleFindingAsync(dns, SpfChecks.AllId);

        Assert.Equal(Severity.Medium, finding.Severity);
    }

    [Fact]
    public async Task All_WhenRedirectEndsWithFail_ShouldUseTheAllOfTheTarget()
    {
        var dns = new FakeDnsResolver()
            .WithTxt("example.com", "v=spf1 redirect=_spf.example.com")
            .WithTxt("_spf.example.com", "v=spf1 ip4:192.0.2.1 -all");

        Assert.Empty(await Make.FindingsAsync(dns, SpfChecks.AllId));
    }

    [Fact]
    public async Task All_WhenRedirectTargetIsNeutral_ShouldReportMedium()
    {
        var dns = new FakeDnsResolver()
            .WithTxt("example.com", "v=spf1 redirect=_spf.example.com")
            .WithTxt("_spf.example.com", "v=spf1 ip4:192.0.2.1 ?all");

        Assert.Equal(Severity.Medium, (await Make.SingleFindingAsync(dns, SpfChecks.AllId)).Severity);
    }

    [Fact]
    public async Task All_WhenRecordHasAllAndRedirect_ShouldIgnoreTheRedirect()
    {
        var dns = new FakeDnsResolver()
            .WithTxt("example.com", "v=spf1 -all redirect=_spf.example.com")
            .WithTxt("_spf.example.com", "v=spf1 +all");

        Assert.Empty(await Make.FindingsAsync(dns, SpfChecks.AllId));
        Assert.Equal(0, dns.Count("TXT _spf.example.com"));
    }

    [Fact]
    public async Task All_WhenIncludedRecordAuthorizesEverybody_ShouldNotChangeTheAllOfTheDomain()
    {
        var dns = new FakeDnsResolver()
            .WithTxt("example.com", "v=spf1 include:lax.example -all")
            .WithTxt("lax.example", "v=spf1 +all");

        Assert.Empty(await Make.FindingsAsync(dns, SpfChecks.AllId));
    }

    [Theory]
    [InlineData(SpfChecks.AllId)]
    [InlineData(SpfChecks.LookupsId)]
    [InlineData(SpfChecks.SyntaxId)]
    public async Task DependentChecks_WhenThereIsNoSingleSpfRecord_ShouldBeSkipped(string id)
    {
        var none = new FakeDnsResolver().WithTxt("example.com", "other=1");
        var two = new FakeDnsResolver().WithTxt("example.com", "v=spf1 -all", "v=spf1 ~all");

        using var culture = new UiCulture("en-US");
        Assert.Contains("MAIL-SPF-001", Assert.IsType<CheckResult.Skipped>(await Make.RunAsync(none, id)).Reason, StringComparison.Ordinal);
        Assert.IsType<CheckResult.Skipped>(await Make.RunAsync(two, id));
    }

    [Theory]
    [InlineData(SpfChecks.AllId)]
    [InlineData(SpfChecks.LookupsId)]
    [InlineData(SpfChecks.SyntaxId)]
    public async Task DependentChecks_WhenTxtQueryFails_ShouldFail(string id)
    {
        var dns = new FakeDnsResolver();
        dns.Txt["example.com"] = DnsAnswer<string>.Failed("timeout");

        Assert.IsType<CheckResult.Failed>(await Make.RunAsync(dns, id));
    }

    [Fact]
    public async Task Lookups_WhenExactlyTen_ShouldFindNothing()
    {
        var dns = Chain(includes: 10);

        Assert.Empty(await Make.FindingsAsync(dns, SpfChecks.LookupsId));
    }

    [Fact]
    public async Task Lookups_WhenEleven_ShouldReportHighWithTheCount()
    {
        var dns = Chain(includes: 11);

        var finding = await Make.SingleFindingAsync(dns, SpfChecks.LookupsId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Contains("11", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Lookups_WhenNestedIncludesAddUp_ShouldCountEveryLevel()
    {
        // 1 include + (a + mx + include) + (4 x a) + redirect + (exists + ptr) = 11.
        var dns = new FakeDnsResolver()
            .WithTxt("example.com", "v=spf1 include:one.example redirect=two.example")
            .WithTxt("one.example", "v=spf1 a mx include:three.example -all")
            .WithTxt("three.example", "v=spf1 a a a a -all")
            .WithTxt("two.example", "v=spf1 exists:x.example ptr -all");

        var finding = await Make.SingleFindingAsync(dns, SpfChecks.LookupsId);

        Assert.Contains("11", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Lookups_WhenIpAndAllOnly_ShouldNotCountThem()
    {
        var dns = new FakeDnsResolver().WithTxt("example.com", "v=spf1 " + string.Join(' ', Enumerable.Range(1, 20).Select(i => $"ip4:192.0.2.{i}")) + " -all");

        Assert.Empty(await Make.FindingsAsync(dns, SpfChecks.LookupsId));
    }

    [Fact]
    public async Task Lookups_WhenLimitIsExceeded_ShouldStopQueryingFurtherIncludes()
    {
        var dns = Chain(includes: 30);

        await Make.FindingsAsync(dns, SpfChecks.LookupsId);

        Assert.Equal(0, dns.Count("TXT i20.example"));
    }

    [Fact]
    public async Task Syntax_WhenRecordIsClean_ShouldFindNothing()
    {
        var dns = new FakeDnsResolver()
            .WithTxt("example.com", "v=spf1 include:_spf.example.net -all")
            .WithTxt("_spf.example.net", "v=spf1 ip4:192.0.2.0/24 -all");

        Assert.Empty(await Make.FindingsAsync(dns, SpfChecks.SyntaxId));
    }

    [Fact]
    public async Task Syntax_WhenTermIsInvalid_ShouldReportHighWithTheTerm()
    {
        var dns = new FakeDnsResolver().WithTxt("example.com", "v=spf1 ip4:10.1 -all");

        var finding = await Make.SingleFindingAsync(dns, SpfChecks.SyntaxId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("ip4:10.1", finding.Evidence);
    }

    [Fact]
    public async Task Syntax_WhenIncludedRecordHasInvalidTerm_ShouldNameTheIncludedDomain()
    {
        var dns = new FakeDnsResolver()
            .WithTxt("example.com", "v=spf1 include:bad.example -all")
            .WithTxt("bad.example", "v=spf1 ipv4:192.0.2.1 -all");

        var finding = await Make.SingleFindingAsync(dns, SpfChecks.SyntaxId);

        Assert.Equal("bad.example: ipv4:192.0.2.1", finding.Evidence);
    }

    [Theory]
    [InlineData("v=spf1 include:nospf.example -all")]
    [InlineData("v=spf1 redirect=nospf.example")]
    [InlineData("v=spf1 include:two.example -all")]
    [InlineData("v=spf1 include:not_a..domain -all")]
    public async Task Syntax_WhenReferenceHasNoSingleSpf_ShouldReportBrokenReferenceHigh(string record)
    {
        var dns = new FakeDnsResolver()
            .WithTxt("example.com", record)
            .WithTxt("nospf.example", "hello")
            .WithTxt("two.example", "v=spf1 -all", "v=spf1 ~all");

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(dns, SpfChecks.SyntaxId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.StartsWith("SPF include or redirect", finding.Title, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Syntax_WhenIncludesLoop_ShouldReportBrokenReferenceAndStop()
    {
        var dns = new FakeDnsResolver()
            .WithTxt("example.com", "v=spf1 include:a.example -all")
            .WithTxt("a.example", "v=spf1 include:example.com -all");

        var finding = await Make.SingleFindingAsync(dns, SpfChecks.SyntaxId);

        Assert.Equal("a.example: include:example.com", finding.Evidence);
        Assert.Equal(1, dns.Count("TXT a.example"));
    }

    [Fact]
    public async Task Syntax_WhenSameIncludeAppearsTwice_ShouldNotCallItALoop()
    {
        var dns = new FakeDnsResolver()
            .WithTxt("example.com", "v=spf1 include:a.example include:a.example -all")
            .WithTxt("a.example", "v=spf1 -all");

        Assert.Empty(await Make.FindingsAsync(dns, SpfChecks.SyntaxId));
    }

    [Fact]
    public async Task Syntax_WhenIncludeCannotBeResolved_ShouldReportLowToBeVerified()
    {
        var dns = new FakeDnsResolver().WithTxt("example.com", "v=spf1 include:flaky.example -all");
        dns.Txt["flaky.example"] = DnsAnswer<string>.Failed("timeout");

        var finding = await Make.SingleFindingAsync(dns, SpfChecks.SyntaxId);

        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal(Confidence.ToBeVerified, finding.Confidence);
        Assert.Equal("include:flaky.example", finding.Evidence);
    }

    [Fact]
    public async Task Syntax_WhenPtrIsUsed_ShouldReportLow()
    {
        var dns = new FakeDnsResolver().WithTxt("example.com", "v=spf1 ptr -all");

        var finding = await Make.SingleFindingAsync(dns, SpfChecks.SyntaxId);

        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal("ptr", finding.Evidence);
    }

    [Fact]
    public async Task Syntax_WhenIncludeUsesAMacro_ShouldNotQueryIt()
    {
        var dns = new FakeDnsResolver().WithTxt("example.com", "v=spf1 include:%{d}.spf.example -all");

        Assert.Empty(await Make.FindingsAsync(dns, SpfChecks.SyntaxId));
        Assert.DoesNotContain(dns.Queries, q => q.Contains('%', StringComparison.Ordinal));
    }

    [Fact]
    public async Task Syntax_WhenSeveralProblems_ShouldReportEachOne()
    {
        var dns = new FakeDnsResolver().WithTxt("example.com", "v=spf1 ptr foo include:nospf.example -all");

        var findings = await Make.FindingsAsync(dns, SpfChecks.SyntaxId);

        Assert.Equal(3, findings.Count);
        Assert.Equal([Severity.High, Severity.Low, Severity.High], findings.Select(f => f.Severity));
    }

    [Fact]
    public async Task Checks_WhenRunTogether_ShouldQueryTheDomainOnlyOnce()
    {
        var dns = new FakeDnsResolver()
            .WithTxt("example.com", "v=spf1 include:a.example -all")
            .WithTxt("a.example", "v=spf1 -all");
        var checks = EmailChecks.Create(dns, new EmailCheckOptions());

        foreach (var check in checks)
        {
            await check.RunAsync(Make.Context(), TestContext.Current.CancellationToken);
        }

        Assert.Equal(1, dns.Count("TXT example.com"));
        Assert.Equal(1, dns.Count("TXT a.example"));
    }

    /// <summary>A domain whose SPF has <paramref name="includes"/> includes, each with no further lookups.</summary>
    private static FakeDnsResolver Chain(int includes)
    {
        var dns = new FakeDnsResolver().WithTxt(
            "example.com",
            "v=spf1 " + string.Join(' ', Enumerable.Range(1, includes).Select(i => $"include:i{i}.example")) + " -all");
        for (var i = 1; i <= includes; i++)
        {
            dns.WithTxt($"i{i}.example", "v=spf1 ip4:192.0.2.1 -all");
        }

        return dns;
    }
}
