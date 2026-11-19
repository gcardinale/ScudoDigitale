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

using System.Formats.Asn1;
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Email.Tests;

/// <summary>Builds RSA public keys of any size without generating them, so short keys work on every OS.</summary>
internal static class RsaKeys
{
    public static byte[] Pkcs1(int bits)
    {
        var modulus = new byte[(bits + 7) / 8];
        modulus.AsSpan().Fill(0x5A);
        modulus[0] = (byte)(0xFF >> ((8 - (bits % 8)) % 8));
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            writer.WriteIntegerUnsigned(modulus);
            writer.WriteInteger(65537);
        }

        return writer.Encode();
    }

    public static byte[] Spki(int bits, string oid = "1.2.840.113549.1.1.1")
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using (writer.PushSequence())
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(oid);
                writer.WriteNull();
            }

            writer.WriteBitString(Pkcs1(bits));
        }

        return writer.Encode();
    }

    public static string Record(int bits, string extra = "") => $"v=DKIM1; k=rsa;{extra} p={Convert.ToBase64String(Spki(bits))}";
}

public sealed class DkimKeyTests
{
    [Theory]
    [InlineData(512)]
    [InlineData(1023)]
    [InlineData(1024)]
    [InlineData(2048)]
    [InlineData(4096)]
    public void RsaModulusBits_WhenKeyIsSubjectPublicKeyInfo_ShouldReturnItsSize(int bits)
    {
        Assert.Equal(bits, DkimKey.RsaModulusBits(RsaKeys.Spki(bits)));
    }

    [Fact]
    public void RsaModulusBits_WhenKeyIsBarePkcs1_ShouldReturnItsSize()
    {
        Assert.Equal(1024, DkimKey.RsaModulusBits(RsaKeys.Pkcs1(1024)));
    }

    [Fact]
    public void RsaModulusBits_WhenKeyIsGeneratedByThePlatform_ShouldAgreeWithIt()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);

        Assert.Equal(2048, DkimKey.RsaModulusBits(rsa.ExportSubjectPublicKeyInfo()));
    }

    [Fact]
    public void RsaModulusBits_WhenAlgorithmIsNotRsa_ShouldReturnNull()
    {
        Assert.Null(DkimKey.RsaModulusBits(RsaKeys.Spki(2048, oid: "1.2.840.10045.2.1")));
    }

    [Theory]
    [InlineData(new byte[] { 1, 2, 3 })]
    [InlineData(new byte[] { 0x30, 0x03, 0x02, 0x01, 0x00 })]
    public void RsaModulusBits_WhenBytesAreNotAKey_ShouldReturnNull(byte[] der)
    {
        Assert.Null(DkimKey.RsaModulusBits(der));
    }

    [Fact]
    public void TryParse_WhenRecordIsRsa_ShouldReadTypeAndSize()
    {
        var key = DkimKey.TryParse("s1", RsaKeys.Record(2048));

        Assert.Equal(new DkimKey("s1", "rsa", 2048, Revoked: false, Readable: true, Testing: false), key);
    }

    [Fact]
    public void TryParse_WhenKeyTypeIsOmitted_ShouldAssumeRsa()
    {
        var key = DkimKey.TryParse("s1", "p=" + Convert.ToBase64String(RsaKeys.Spki(1024)));

        Assert.Equal("rsa", key?.KeyType);
        Assert.Equal(1024, key?.Bits);
    }

    [Fact]
    public void TryParse_WhenKeyIsSplitByWhitespace_ShouldStillReadIt()
    {
        var base64 = Convert.ToBase64String(RsaKeys.Spki(2048));
        var key = DkimKey.TryParse("s1", "v=DKIM1; p=" + base64[..100] + " \t" + base64[100..]);

        Assert.Equal(2048, key?.Bits);
    }

    [Fact]
    public void TryParse_WhenKeyIsEd25519_ShouldBeReadableWithoutBits()
    {
        var key = DkimKey.TryParse("ed", "v=DKIM1; k=ed25519; p=" + Convert.ToBase64String(new byte[32]));

        Assert.Equal(new DkimKey("ed", "ed25519", null, false, true, false), key);
    }

    [Theory]
    [InlineData("v=DKIM1; k=ed25519; p=AAAA")]
    [InlineData("v=DKIM1; k=rsa; p=not*base64")]
    [InlineData("v=DKIM1; k=rsa; p=AQID")]
    [InlineData("v=DKIM1; k=dsa; p=AQID")]
    public void TryParse_WhenKeyCannotBeDecoded_ShouldBeUnreadable(string text)
    {
        var key = DkimKey.TryParse("s1", text);

        Assert.NotNull(key);
        Assert.False(key.Readable);
        Assert.False(key.Revoked);
    }

    [Fact]
    public void TryParse_WhenPIsEmpty_ShouldBeRevoked()
    {
        var key = DkimKey.TryParse("old", "v=DKIM1; k=rsa; p=");

        Assert.True(key?.Revoked);
    }

    [Theory]
    [InlineData("v=DKIM1; t=y; p=X", true)]
    [InlineData("v=DKIM1; t=s:Y; p=X", true)]
    [InlineData("v=DKIM1; t=s; p=X", false)]
    public void TryParse_WhenTagTHasFlags_ShouldDetectTestMode(string text, bool testing)
    {
        Assert.Equal(testing, DkimKey.TryParse("s1", text)?.Testing);
    }

    [Theory]
    [InlineData("v=spf1 -all")]
    [InlineData("v=DKIM2; p=AQID")]
    [InlineData("k=rsa")]
    public void TryParse_WhenRecordIsNotADkimKey_ShouldReturnNull(string text)
    {
        Assert.Null(DkimKey.TryParse("s1", text));
    }
}

public sealed class DkimChecksTests
{
    [Fact]
    public async Task Selectors_WhenNoKeyIsFound_ShouldReportMediumToBeVerifiedListingTheSelectors()
    {
        var dns = new FakeDnsResolver();

        var finding = await Make.SingleFindingAsync(dns, DkimChecks.SelectorsId);

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(Confidence.ToBeVerified, finding.Confidence);
        Assert.Contains("selector1, selector2, google", finding.Evidence, StringComparison.Ordinal);
        Assert.Equal(EmailCheckOptions.CommonDkimSelectors.Count, dns.Queries.Count(q => q.EndsWith("._domainkey.example.com", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Selectors_WhenACommonSelectorHasAKey_ShouldFindNothing()
    {
        var dns = new FakeDnsResolver().WithTxt("google._domainkey.example.com", RsaKeys.Record(2048));

        Assert.Empty(await Make.FindingsAsync(dns, DkimChecks.SelectorsId));
    }

    [Theory]
    [InlineData("ovhmo-selector-1")]
    [InlineData("ovhmo-selector-2")]
    public async Task Selectors_WhenDomainUsesOvhMxPlan_ShouldFindTheKeyWithoutExtraSelectors(string selector)
    {
        // OVHcloud MX Plan signs with its own selectors (found on gcardinale.it on 19/11/2026).
        var dns = new FakeDnsResolver().WithTxt(selector + "._domainkey.example.com", RsaKeys.Record(2048));

        Assert.Empty(await Make.FindingsAsync(dns, DkimChecks.SelectorsId));
    }

    [Fact]
    public async Task Selectors_WhenUserSuppliesASelector_ShouldTryItToo()
    {
        var dns = new FakeDnsResolver().WithTxt("custom2026._domainkey.example.com", RsaKeys.Record(2048));
        var options = new EmailCheckOptions { DkimSelectors = [" Custom2026 ", "google"] };

        Assert.Empty(await Make.FindingsAsync(dns, DkimChecks.SelectorsId, options: options));
        Assert.Equal(1, dns.Count("TXT google._domainkey.example.com"));
    }

    [Fact]
    public async Task Selectors_WhenOnlyRevokedKeysExist_ShouldReportNotFound()
    {
        var dns = new FakeDnsResolver().WithTxt("default._domainkey.example.com", "v=DKIM1; p=");

        Assert.Equal(DkimChecks.SelectorsId, (await Make.SingleFindingAsync(dns, DkimChecks.SelectorsId)).Id);
        Assert.IsType<CheckResult.Skipped>(await Make.RunAsync(dns, DkimChecks.KeysId));
    }

    [Fact]
    public async Task Selectors_WhenTxtIsNotADkimKey_ShouldIgnoreIt()
    {
        var dns = new FakeDnsResolver().WithTxt("default._domainkey.example.com", "v=spf1 -all");

        Assert.Single(await Make.FindingsAsync(dns, DkimChecks.SelectorsId));
    }

    [Theory]
    [InlineData(DkimChecks.SelectorsId)]
    [InlineData(DkimChecks.KeysId)]
    public async Task Checks_WhenEverySelectorQueryFails_ShouldFail(string id)
    {
        var dns = new FakeDnsResolver();
        foreach (var selector in EmailCheckOptions.CommonDkimSelectors)
        {
            dns.Txt[$"{selector}._domainkey.example.com"] = DnsAnswer<string>.Failed("timeout");
        }

        var failed = Assert.IsType<CheckResult.Failed>(await Make.RunAsync(dns, id));

        Assert.Contains("_domainkey.example.com", failed.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Selectors_WhenSomeQueriesFailAndNoKeyIsFound_ShouldSayWhichSelectorsWereNotAnswered()
    {
        var dns = new FakeDnsResolver();
        dns.Txt["selector1._domainkey.example.com"] = DnsAnswer<string>.Failed("timeout");
        dns.Txt["google._domainkey.example.com"] = DnsAnswer<string>.Failed("timeout");

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(dns, DkimChecks.SelectorsId);

        Assert.Equal(Confidence.ToBeVerified, finding.Confidence);
        Assert.EndsWith("The DNS did not answer for: selector1, google.", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact(Timeout = 10_000)]
    public async Task Selectors_WhenSomeSelectorsHangBeyondTheBudget_ShouldReportThemAsUnansweredInTime()
    {
        var dns = new FakeDnsResolver();
        dns.Hanging.Add("selector1._domainkey.example.com");
        dns.Hanging.Add("google._domainkey.example.com");
        var options = new EmailCheckOptions { DkimTimeBudget = TimeSpan.FromMilliseconds(300) };

        using var culture = new UiCulture("en-US");
        var result = await Make.Check(dns, DkimChecks.SelectorsId, options).RunAsync(Make.Context(), TestContext.Current.CancellationToken);

        var finding = Assert.Single(Assert.IsType<CheckResult.Executed>(result).Findings);
        Assert.EndsWith("The DNS did not answer for: selector1, google.", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact(Timeout = 10_000)]
    public async Task Selectors_WhenEverySelectorHangs_ShouldFailSayingNoAnswerInTime()
    {
        var dns = new FakeDnsResolver();
        foreach (var selector in EmailCheckOptions.CommonDkimSelectors)
        {
            dns.Hanging.Add($"{selector}._domainkey.example.com");
        }

        var options = new EmailCheckOptions { DkimTimeBudget = TimeSpan.FromMilliseconds(300), MaxConcurrentDnsQueries = 2 };

        using var culture = new UiCulture("en-US");
        var result = await Make.Check(dns, DkimChecks.SelectorsId, options).RunAsync(Make.Context(), TestContext.Current.CancellationToken);

        Assert.Contains("no answer within 0.3 seconds", Assert.IsType<CheckResult.Failed>(result).Error, StringComparison.Ordinal);
    }

    [Fact]
    public void DkimTimeBudget_WhenNotSet_ShouldStayWellBelowTheCheckTimeout()
    {
        Assert.Equal(TimeSpan.FromSeconds(25), new EmailCheckOptions().DkimTimeBudget);
        Assert.True(new EmailCheckOptions().DkimTimeBudget < new ScudoDigitale.Core.CheckEngineOptions().CheckTimeout / 2);
    }

    [Fact]
    public async Task Selectors_WhenEveryQueryIsAnswered_ShouldNotMentionUnansweredSelectors()
    {
        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(new FakeDnsResolver(), DkimChecks.SelectorsId);

        Assert.DoesNotContain("did not answer", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Selectors_WhenSomeQueriesFailButAKeyIsFound_ShouldFindNothing()
    {
        var dns = new FakeDnsResolver().WithTxt("s1._domainkey.example.com", RsaKeys.Record(2048));
        dns.Txt["default._domainkey.example.com"] = DnsAnswer<string>.Failed("timeout");

        Assert.Empty(await Make.FindingsAsync(dns, DkimChecks.SelectorsId));
    }

    [Fact]
    public async Task Keys_WhenNoKey_ShouldBeSkipped()
    {
        using var culture = new UiCulture("en-US");
        var skipped = Assert.IsType<CheckResult.Skipped>(await Make.RunAsync(new FakeDnsResolver(), DkimChecks.KeysId));

        Assert.Contains("MAIL-DKIM-001", skipped.Reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(2048)]
    [InlineData(4096)]
    public async Task Keys_WhenRsaKeyIsAtLeast2048_ShouldFindNothing(int bits)
    {
        var dns = new FakeDnsResolver().WithTxt("s1._domainkey.example.com", RsaKeys.Record(bits));

        Assert.Empty(await Make.FindingsAsync(dns, DkimChecks.KeysId));
    }

    [Theory]
    [InlineData(1024, Severity.Medium)]
    [InlineData(2047, Severity.Medium)]
    [InlineData(1023, Severity.High)]
    [InlineData(512, Severity.High)]
    public async Task Keys_WhenRsaKeyIsShort_ShouldReportBySize(int bits, Severity expected)
    {
        var dns = new FakeDnsResolver().WithTxt("s1._domainkey.example.com", RsaKeys.Record(bits));

        using var culture = new UiCulture("en-US");
        var finding = await Make.SingleFindingAsync(dns, DkimChecks.KeysId);

        Assert.Equal(expected, finding.Severity);
        Assert.Contains($"{bits} bit", finding.Title, StringComparison.Ordinal);
        Assert.Equal($"s1._domainkey.example.com: k=rsa, {bits} bit", finding.Evidence);
    }

    [Fact]
    public async Task Keys_WhenKeyIsUnreadable_ShouldReportMedium()
    {
        var dns = new FakeDnsResolver().WithTxt("s1._domainkey.example.com", "v=DKIM1; k=rsa; p=AQID");

        var finding = await Make.SingleFindingAsync(dns, DkimChecks.KeysId);

        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal("s1._domainkey.example.com: k=rsa", finding.Evidence);
    }

    [Fact]
    public async Task Keys_WhenKeyIsInTestMode_ShouldReportLowEvenIfStrong()
    {
        var dns = new FakeDnsResolver().WithTxt("s1._domainkey.example.com", RsaKeys.Record(2048, " t=y;"));

        Assert.Equal(Severity.Low, (await Make.SingleFindingAsync(dns, DkimChecks.KeysId)).Severity);
    }

    [Fact]
    public async Task Keys_WhenShortKeyIsAlsoInTestMode_ShouldReportBoth()
    {
        var dns = new FakeDnsResolver().WithTxt("s1._domainkey.example.com", RsaKeys.Record(1024, " t=y;"));

        var findings = await Make.FindingsAsync(dns, DkimChecks.KeysId);

        Assert.Equal([Severity.Medium, Severity.Low], findings.Select(f => f.Severity));
    }

    [Fact]
    public async Task Keys_WhenSeveralSelectorsHaveKeys_ShouldReportEachWeakOneInSelectorOrder()
    {
        var dns = new FakeDnsResolver()
            .WithTxt("selector2._domainkey.example.com", RsaKeys.Record(1024))
            .WithTxt("selector1._domainkey.example.com", RsaKeys.Record(512))
            .WithTxt("google._domainkey.example.com", RsaKeys.Record(2048))
            .WithTxt("ed._domainkey.example.com", "v=DKIM1; k=ed25519; p=" + Convert.ToBase64String(new byte[32]));

        var findings = await Make.FindingsAsync(dns, DkimChecks.KeysId, options: new EmailCheckOptions { DkimSelectors = ["ed"] });

        Assert.Equal(
            ["selector1._domainkey.example.com: k=rsa, 512 bit", "selector2._domainkey.example.com: k=rsa, 1024 bit"],
            findings.Select(f => f.Evidence));
    }

    [Fact]
    public async Task Selectors_WhenManySelectors_ShouldNeverExceedTheConcurrencyLimit()
    {
        var dns = new CountingResolver();
        var check = EmailChecks.Create(dns, new EmailCheckOptions { MaxConcurrentDnsQueries = 2 }).Single(c => c.Id == DkimChecks.SelectorsId);

        await check.RunAsync(Make.Context(), TestContext.Current.CancellationToken);

        Assert.Equal(2, dns.MaxInFlight);
    }

    /// <summary>Answers after a short delay and records how many queries were in flight at once.</summary>
    private sealed class CountingResolver : IDnsResolver
    {
        private int inFlight;

        public int MaxInFlight { get; private set; }

        public async Task<DnsAnswer<string>> QueryTxtAsync(string name, CancellationToken cancellationToken)
        {
            var now = Interlocked.Increment(ref inFlight);
            lock (this)
            {
                MaxInFlight = Math.Max(MaxInFlight, now);
            }

            await Task.Delay(20, CancellationToken.None);
            Interlocked.Decrement(ref inFlight);
            return DnsAnswer<string>.NoRecords();
        }

        public Task<DnsAnswer<MailExchange>> QueryMxAsync(string name, CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task<DnsAnswer<System.Net.IPAddress>> QueryAddressesAsync(string name, CancellationToken cancellationToken) => throw new NotSupportedException();
    }
}
