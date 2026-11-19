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

namespace ScudoDigitale.Checks.Email.Tests;

public sealed class SpfRecordTests
{
    [Theory]
    [InlineData("v=spf1 -all", true)]
    [InlineData("v=spf1", true)]
    [InlineData("V=SPF1 include:x.example ~all", true)]
    [InlineData("v=spf10 -all", false)]
    [InlineData("v=spf1-all", false)]
    [InlineData(" v=spf1 -all", false)]
    [InlineData("google-site-verification=abc", false)]
    public void IsSpf_WhenCalled_ShouldRecogniseOnlyTheVersionTag(string txt, bool expected)
    {
        Assert.Equal(expected, SpfRecord.IsSpf(txt));
    }

    [Fact]
    public void Parse_WhenRecordIsTypical_ShouldReadMechanismsQualifiersAndDomains()
    {
        var record = SpfRecord.Parse("v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx:Mail.Example.com/24 include:_spf.example.net. ~all");

        Assert.Empty(record.InvalidTerms);
        Assert.Equal(["ip4", "ip6", "a", "mx", "include", "all"], record.Mechanisms.Select(m => m.Name));
        Assert.Equal("mail.example.com", record.Mechanisms[3].Domain);
        Assert.Equal("_spf.example.net", record.Mechanisms[4].Domain);
        Assert.Null(record.Mechanisms[2].Domain);
        Assert.Equal(SpfQualifier.SoftFail, record.All);
        Assert.Null(record.Redirect);
    }

    [Theory]
    [InlineData("v=spf1 +all", SpfQualifier.Pass)]
    [InlineData("v=spf1 all", SpfQualifier.Pass)]
    [InlineData("v=spf1 -all", SpfQualifier.Fail)]
    [InlineData("v=spf1 ~all", SpfQualifier.SoftFail)]
    [InlineData("v=spf1 ?all", SpfQualifier.Neutral)]
    [InlineData("v=spf1 -all +all", SpfQualifier.Fail)]
    internal void All_WhenRecordHasAll_ShouldReturnTheQualifierOfTheFirstOne(string text, SpfQualifier expected)
    {
        Assert.Equal(expected, SpfRecord.Parse(text).All);
    }

    [Fact]
    public void Parse_WhenRecordHasModifiers_ShouldKeepRedirectAndIgnoreTheOthers()
    {
        var record = SpfRecord.Parse("v=spf1 exp=explain.example.com redirect=_SPF.Example.com. unknown-mod=x");

        Assert.Equal("_spf.example.com", record.Redirect);
        Assert.Empty(record.InvalidTerms);
        Assert.Empty(record.Mechanisms);
        Assert.Null(record.All);
    }

    [Theory]
    [InlineData("redirect=")]
    [InlineData("include")]
    [InlineData("include:")]
    [InlineData("include:x.example/24")]
    [InlineData("exists")]
    [InlineData("all:x")]
    [InlineData("ip4:10.1")]
    [InlineData("ip4:300.1.1.1")]
    [InlineData("ip4:192.0.2.0/33")]
    [InlineData("ip4:2001:db8::1")]
    [InlineData("ip4")]
    [InlineData("ip6:192.0.2.1")]
    [InlineData("ip6:2001:db8::/129")]
    [InlineData("ip6:2001:db8::/")]
    [InlineData("a:")]
    [InlineData("a/")]
    [InlineData("a/33")]
    [InlineData("mx//129")]
    [InlineData("mx/24//64//1")]
    [InlineData("mx///64")]
    [InlineData("ptr:")]
    [InlineData("+")]
    [InlineData("spf2.0/pra")]
    [InlineData("includes:x.example")]
    public void Parse_WhenTermIsNotValid_ShouldCollectIt(string term)
    {
        var record = SpfRecord.Parse("v=spf1 " + term + " -all");

        Assert.Equal(term, Assert.Single(record.InvalidTerms));
        Assert.Equal(SpfQualifier.Fail, record.All);
    }

    [Theory]
    [InlineData("a/24")]
    [InlineData("a//64")]
    [InlineData("mx/24//64")]
    [InlineData("a:example.com/24//64")]
    [InlineData("ptr")]
    [InlineData("ptr:example.com")]
    [InlineData("exists:%{i}.bl.example.com")]
    [InlineData("ip4:192.0.2.1")]
    [InlineData("ip6:::1/128")]
    [InlineData("?include:example.net")]
    public void Parse_WhenTermIsValid_ShouldAcceptIt(string term)
    {
        var record = SpfRecord.Parse("v=spf1 " + term);

        Assert.Empty(record.InvalidTerms);
        Assert.Single(record.Mechanisms);
    }

    [Fact]
    public void Parse_WhenRedirectAppearsTwice_ShouldReportTheSecond()
    {
        var record = SpfRecord.Parse("v=spf1 redirect=a.example redirect=b.example");

        Assert.Equal("a.example", record.Redirect);
        Assert.Equal("redirect=b.example", Assert.Single(record.InvalidTerms));
    }
}
