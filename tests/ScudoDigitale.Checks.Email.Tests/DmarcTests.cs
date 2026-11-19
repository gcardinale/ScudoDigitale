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

public sealed class DmarcRecordTests
{
    [Theory]
    [InlineData("v=DMARC1; p=none", true)]
    [InlineData("v=dmarc1;p=reject", true)]
    [InlineData("  v=DMARC1 ; p=reject", true)]
    [InlineData("v=DMARC1", true)]
    [InlineData("v=DMARC10; p=none", false)]
    [InlineData("p=none; v=DMARC1", false)]
    [InlineData("v=spf1 -all", false)]
    public void IsDmarc_WhenCalled_ShouldRecogniseTheVersionTagFirst(string txt, bool expected)
    {
        Assert.Equal(expected, DmarcRecord.IsDmarc(txt));
    }

    [Fact]
    public void TryParse_WhenRecordIsComplete_ShouldReadEveryTag()
    {
        var record = DmarcRecord.TryParse("v=DMARC1; p=Quarantine; sp=reject; pct=50; rua=mailto:a@example.com, mailto:b@example.net; ruf=mailto:x@example.com;");

        Assert.NotNull(record);
        Assert.Equal(DmarcPolicy.Quarantine, record.Policy);
        Assert.Equal(DmarcPolicy.Reject, record.SubdomainPolicy);
        Assert.Equal(50, record.Percent);
        Assert.Equal(["mailto:a@example.com", "mailto:b@example.net"], record.AggregateReports);
    }

    [Fact]
    public void TryParse_WhenOptionalTagsAreMissing_ShouldUseTheDefaults()
    {
        var record = DmarcRecord.TryParse("v=DMARC1; p=reject");

        Assert.NotNull(record);
        Assert.Null(record.SubdomainPolicy);
        Assert.Equal(100, record.Percent);
        Assert.Empty(record.AggregateReports);
    }

    [Theory]
    [InlineData("v=DMARC1")]
    [InlineData("v=DMARC1; rua=mailto:a@example.com")]
    [InlineData("v=DMARC1; p=block")]
    [InlineData("v=DMARC1; p=none; sp=maybe")]
    [InlineData("v=DMARC1; p=none; pct=101")]
    [InlineData("v=DMARC1; p=none; pct=-1")]
    [InlineData("v=DMARC1; p=none; pct=abc")]
    [InlineData("v=DMARC1; p=none; garbage")]
    [InlineData("v=DMARC1; =none")]
    public void TryParse_WhenRecordIsNotValid_ShouldReturnNull(string text)
    {
        Assert.Null(DmarcRecord.TryParse(text));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("100")]
    public void TryParse_WhenPercentIsAtTheBounds_ShouldAcceptIt(string pct)
    {
        Assert.NotNull(DmarcRecord.TryParse("v=DMARC1; p=reject; pct=" + pct));
    }
}

public sealed class DmarcChecksTests
{
    [Fact]
    public async Task Policy_WhenNoRecord_ShouldReportHighCertain()
    {
        var dns = new FakeDnsResolver().WithTxt("_dmarc.example.com", "something-else=1");

        var finding = await Make.SingleFindingAsync(dns, DmarcChecks.PolicyId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(Confidence.Certain, finding.Confidence);
        Assert.Contains("_dmarc.example.com", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Policy_WhenPolicyIsNone_ShouldReportMediumAsInTheSpecification()
    {
        var dns = new FakeDnsResolver().WithTxt("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:d@example.com");

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(dns, DmarcChecks.PolicyId);

        Assert.Equal("MAIL-DMARC-001", finding.Id);
        Assert.Equal("DMARC in monitoring mode (p=none)", finding.Title);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(Confidence.Certain, finding.Confidence);
        Assert.Equal("v=DMARC1; p=none; rua=mailto:d@example.com", finding.Evidence);
        Assert.Equal("Anyone can send email on behalf of the domain without it being blocked.", finding.Risk);
    }

    [Theory]
    [InlineData("v=DMARC1; p=reject")]
    [InlineData("v=DMARC1; p=quarantine; pct=100")]
    public async Task Policy_WhenEnforcedOnEveryMessage_ShouldFindNothing(string record)
    {
        var dns = new FakeDnsResolver().WithTxt("_dmarc.example.com", record);

        Assert.Empty(await Make.FindingsAsync(dns, DmarcChecks.PolicyId));
    }

    [Fact]
    public async Task Policy_WhenPercentIsBelow100_ShouldReportLowWithThePercent()
    {
        var dns = new FakeDnsResolver().WithTxt("_dmarc.example.com", "v=DMARC1; p=reject; pct=99");

        using var culture = new UiCulture("it-IT");
        var finding = await Make.SingleFindingAsync(dns, DmarcChecks.PolicyId);

        Assert.Equal(Severity.Low, finding.Severity);
        Assert.Equal("Criterio DMARC applicato solo al 99% dei messaggi (pct)", finding.Title);
    }

    [Theory]
    [InlineData("v=DMARC1; p=bogus")]
    [InlineData("v=DMARC1; p=reject|v=DMARC1; p=none")]
    public async Task Policy_WhenRecordIsInvalidOrDuplicated_ShouldReportHigh(string records)
    {
        var dns = new FakeDnsResolver().WithTxt("_dmarc.example.com", records.Split('|'));

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(dns, DmarcChecks.PolicyId);

        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal("DMARC record not valid", finding.Title);
        Assert.Equal(records.Replace("|", " | ", StringComparison.Ordinal), finding.Evidence);
    }

    [Fact]
    public async Task Policy_WhenSubdomainInheritsReject_ShouldFindNothing()
    {
        var dns = new FakeDnsResolver().WithTxt("_dmarc.example.com", "v=DMARC1; p=reject");

        Assert.Empty(await Make.FindingsAsync(dns, DmarcChecks.PolicyId, "mail.example.com"));
        Assert.Equal(1, dns.Count("TXT _dmarc.mail.example.com"));
    }

    [Fact]
    public async Task Policy_WhenSubdomainInheritsSpNone_ShouldReportMediumProbableAndNameTheSource()
    {
        var dns = new FakeDnsResolver().WithTxt("_dmarc.example.com", "v=DMARC1; p=reject; sp=none");

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(dns, DmarcChecks.PolicyId, "a.b.example.com");

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(Confidence.Probable, finding.Confidence);
        Assert.Equal("Inherited from _dmarc.example.com: v=DMARC1; p=reject; sp=none", finding.Evidence);
        Assert.Equal(1, dns.Count("TXT _dmarc.b.example.com"));
    }

    [Fact]
    public async Task Policy_WhenSubdomainHasItsOwnRecord_ShouldNotLookAtTheParent()
    {
        var dns = new FakeDnsResolver()
            .WithTxt("_dmarc.mail.example.com", "v=DMARC1; p=none")
            .WithTxt("_dmarc.example.com", "v=DMARC1; p=reject");

        var finding = await Make.SingleFindingAsync(dns, DmarcChecks.PolicyId, "mail.example.com");

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(Confidence.Certain, finding.Confidence);
        Assert.Equal(0, dns.Count("TXT _dmarc.example.com"));
    }

    [Fact]
    public async Task Policy_WhenNoRecordAnywhere_ShouldReportTheNameOfTheDomainItself()
    {
        var dns = new FakeDnsResolver();

        var finding = await Make.SingleFindingAsync(dns, DmarcChecks.PolicyId, "mail.example.com");

        Assert.Contains("_dmarc.mail.example.com", finding.Evidence, StringComparison.Ordinal);
        Assert.Equal(1, dns.Count("TXT _dmarc.example.com"));
    }

    [Theory]
    [InlineData(DmarcChecks.PolicyId)]
    [InlineData(DmarcChecks.ReportsId)]
    [InlineData(DmarcChecks.SubdomainId)]
    public async Task Checks_WhenLookupFails_ShouldFailNamingTheQuery(string id)
    {
        var dns = new FakeDnsResolver();
        dns.Txt["_dmarc.example.com"] = DnsAnswer<string>.Failed("REFUSED");

        var failed = Assert.IsType<CheckResult.Failed>(await Make.RunAsync(dns, id));

        Assert.Contains("_dmarc.example.com", failed.Error, StringComparison.Ordinal);
        Assert.Contains("REFUSED", failed.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reports_WhenRuaIsMissing_ShouldReportLow()
    {
        var dns = new FakeDnsResolver().WithTxt("_dmarc.example.com", "v=DMARC1; p=reject; ruf=mailto:f@example.com");

        var finding = await Make.SingleFindingAsync(dns, DmarcChecks.ReportsId);

        Assert.Equal(Severity.Low, finding.Severity);
    }

    [Fact]
    public async Task Reports_WhenRuaIsPresent_ShouldFindNothing()
    {
        var dns = new FakeDnsResolver().WithTxt("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:d@example.com");

        Assert.Empty(await Make.FindingsAsync(dns, DmarcChecks.ReportsId));
    }

    [Theory]
    [InlineData(DmarcChecks.ReportsId, "")]
    [InlineData(DmarcChecks.ReportsId, "v=DMARC1; p=wrong")]
    [InlineData(DmarcChecks.SubdomainId, "")]
    [InlineData(DmarcChecks.SubdomainId, "v=DMARC1; p=wrong")]
    public async Task DependentChecks_WhenNoValidRecord_ShouldBeSkipped(string id, string record)
    {
        var dns = new FakeDnsResolver();
        if (record.Length > 0)
        {
            dns.WithTxt("_dmarc.example.com", record);
        }

        using var culture = new UiCulture("en-US");
        var skipped = Assert.IsType<CheckResult.Skipped>(await Make.RunAsync(dns, id));

        Assert.Contains("MAIL-DMARC-001", skipped.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Subdomain_WhenPolicyIsEnforcedButSpIsNone_ShouldReportLow()
    {
        var dns = new FakeDnsResolver().WithTxt("_dmarc.example.com", "v=DMARC1; p=reject; sp=none");

        var finding = await Make.SingleFindingAsync(dns, DmarcChecks.SubdomainId);

        Assert.Equal(Severity.Low, finding.Severity);
    }

    [Theory]
    [InlineData("v=DMARC1; p=none; sp=none")]
    [InlineData("v=DMARC1; p=reject")]
    [InlineData("v=DMARC1; p=reject; sp=quarantine")]
    public async Task Subdomain_WhenSpDoesNotWeakenThePolicy_ShouldFindNothing(string record)
    {
        var dns = new FakeDnsResolver().WithTxt("_dmarc.example.com", record);

        Assert.Empty(await Make.FindingsAsync(dns, DmarcChecks.SubdomainId));
    }

    [Fact]
    public async Task Subdomain_WhenRecordIsInherited_ShouldLeaveTheVerdictToThePolicyCheck()
    {
        var dns = new FakeDnsResolver().WithTxt("_dmarc.example.com", "v=DMARC1; p=reject; sp=none");

        Assert.Empty(await Make.FindingsAsync(dns, DmarcChecks.SubdomainId, "mail.example.com"));
    }
}
