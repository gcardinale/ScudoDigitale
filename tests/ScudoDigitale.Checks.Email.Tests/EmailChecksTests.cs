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

using System.Collections;
using System.Globalization;
using System.Resources;
using ScudoDigitale.Checks.Email.Resources;
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Email.Tests;

public sealed class EmailChecksTests
{
    private static readonly string[] ExpectedIds =
    [
        "MAIL-SPF-001", "MAIL-SPF-002", "MAIL-SPF-003", "MAIL-SPF-004",
        "MAIL-DMARC-001", "MAIL-DMARC-002", "MAIL-DMARC-003",
        "MAIL-DKIM-001", "MAIL-DKIM-002",
        "MAIL-MX-001", "MAIL-MX-002",
    ];

    [Fact]
    public void Create_WhenCalled_ShouldReturnThePassiveDomainChecksInReportOrder()
    {
        var checks = EmailChecks.Create();

        Assert.Equal(ExpectedIds, checks.Select(c => c.Id));
        Assert.All(checks, c =>
        {
            Assert.True(Finding.IsCheckId(c.Id));
            Assert.Equal(CheckArea.Email, c.Area);
            Assert.Equal(TargetKind.Domain, c.AppliesTo);
            Assert.Equal(ScopeRequirement.Passive, c.Scope);
        });
    }

    [Fact]
    public void Create_WhenOptionsAreGiven_ShouldBuildTheSameChecks()
    {
        var checks = EmailChecks.Create(new EmailCheckOptions { DkimSelectors = ["custom"], DnsRetries = 0 });

        Assert.Equal(ExpectedIds, checks.Select(c => c.Id));
    }

    [Theory]
    [InlineData("en-US", "SPF record", "Mail servers (MX)")]
    [InlineData("it-IT", "Record SPF", "Server di posta (MX)")]
    public void Title_WhenUiLanguageChanges_ShouldFollowIt(string culture, string first, string last)
    {
        var checks = EmailChecks.Create();

        using var ui = new UiCulture(culture);
        Assert.Equal(first, checks[0].Title);
        Assert.Equal(last, checks[^2].Title);
        Assert.All(checks, c => Assert.False(string.IsNullOrWhiteSpace(c.Title)));
        Assert.Equal(checks.Count, checks.Select(c => c.Title).Distinct().Count());
    }

    [Fact]
    public void Resources_WhenComparingLanguages_ShouldHaveTheSameKeysAndPlaceholders()
    {
        var english = Read(CultureInfo.InvariantCulture);
        var italian = Read(CultureInfo.GetCultureInfo("it"));

        Assert.Equal(english.Keys.Order(), italian.Keys.Order());
        foreach (var (key, text) in english)
        {
            Assert.False(string.IsNullOrWhiteSpace(text), key);
            Assert.NotEqual(text, italian[key]);
            Assert.Equal(Placeholders(text), Placeholders(italian[key]));
        }
    }

    [Fact]
    public async Task Engine_WhenDomainIsWellConfigured_ShouldRunEveryCheckWithoutProblems()
    {
        var dns = new FakeDnsResolver()
            .WithTxt("example.com", "v=spf1 include:_spf.example.net -all")
            .WithTxt("_spf.example.net", "v=spf1 ip4:192.0.2.0/24 -all")
            .WithTxt("_dmarc.example.com", "v=DMARC1; p=reject; rua=mailto:dmarc@example.com")
            .WithTxt("selector1._domainkey.example.com", RsaKeys.Record(2048))
            .WithMx("example.com", (10, "mx.example.com"))
            .WithAddress("mx.example.com", "192.0.2.25");
        var target = new Target(TargetKind.Domain, "Example.COM.");
        var engine = new CheckEngine(new DenyAll());

        var runs = await engine.RunAsync(
            EmailChecks.Create(dns, new EmailCheckOptions()),
            Profile.Individual(),
            new ScopeDeclaration("Mario Rossi", OperatorRole.Owner, [target, new Target(TargetKind.Website, "https://example.com")], Make.DeclaredAt),
            TestContext.Current.CancellationToken);

        Assert.Equal(ExpectedIds, runs.Select(r => r.CheckId));
        Assert.All(runs, r => Assert.Empty(Assert.IsType<CheckResult.Executed>(r.Result).Findings));
    }

    [Fact]
    public async Task Engine_WhenDomainHasNothing_ShouldReportTheMainGapsAndSkipTheRest()
    {
        var dns = new FakeDnsResolver().WithTxt("example.com", "hello");

        var runs = await new CheckEngine(new DenyAll()).RunAsync(
            EmailChecks.Create(dns, new EmailCheckOptions()),
            Profile.Individual(),
            new ScopeDeclaration("Mario Rossi", OperatorRole.Owner, [new Target(TargetKind.Domain, "example.com")], Make.DeclaredAt),
            TestContext.Current.CancellationToken);

        var findings = runs.Select(r => r.Result).OfType<CheckResult.Executed>().SelectMany(r => r.Findings).ToArray();
        Assert.Equal(["MAIL-SPF-001", "MAIL-DMARC-001", "MAIL-DKIM-001", "MAIL-MX-001"], findings.Select(f => f.Id));
        Assert.Equal(7, runs.Count(r => r.Result is CheckResult.Skipped));
        var prioritized = FindingPrioritizer.Prioritize(findings);
        Assert.Equal(Severity.High, prioritized[0].EffectiveSeverity);
    }

    private static Dictionary<string, string> Read(CultureInfo culture)
    {
        var manager = new ResourceManager(typeof(Strings));
        using var set = manager.GetResourceSet(culture, createIfNotExists: true, tryParents: false)!;
        return set.Cast<DictionaryEntry>().ToDictionary(e => (string)e.Key, e => (string)e.Value!);
    }

    private static string[] Placeholders(string text) =>
        [.. System.Text.RegularExpressions.Regex.Matches(text, @"\{\d+\}").Select(m => m.Value).Order()];

    private sealed class DenyAll : IScopeGuard
    {
        public Task<bool> IsAuthorizedAsync(Target target, CancellationToken cancellationToken) => Task.FromResult(false);
    }
}
