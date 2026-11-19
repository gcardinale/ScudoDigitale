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

using System.Globalization;
using ScudoDigitale.Checks.Email;
using ScudoDigitale.Core;

namespace ScudoDigitale.Cli.Tests;

public sealed class ScanCommandTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 19, 10, 30, 0, TimeSpan.FromHours(1));

    [Fact]
    public async Task Scan_WhenDomainHasProblems_ShouldPrintThemMostUrgentFirstWithEvidenceRiskAndFix()
    {
        var fake = new FakeChecks(Medium("MAIL-DMARC-001"), Passed("MAIL-SPF-001"), High("MAIL-SPF-002"), Skipped("MAIL-DKIM-002"), Failed("MAIL-MX-001"));

        using var culture = new UiCulture("en-US");
        var (exitCode, output, error) = await RunAsync(fake, "scan", "--mail", "Example.COM", "--operator", "Mario Rossi", "--role", "SecurityOfficer");

        Assert.Equal(0, exitCode);
        Assert.Empty(error);
        Assert.StartsWith(Attribution.Banner, output, StringComparison.Ordinal);
        Assert.Contains("does not replace a penetration test", output, StringComparison.Ordinal);
        // The date format belongs to the platform: ICU (Linux, macOS) puts a narrow no-break space before "AM".
        Assert.Contains($"Declared by Mario Rossi (security officer) on {Now.ToString("g", CultureInfo.CurrentCulture)}.", output, StringComparison.Ordinal);
        Assert.Contains("Checking example.com: 5 checks per target", output, StringComparison.Ordinal);
        Assert.Contains("== Email — example.com ==", output, StringComparison.Ordinal);

        var high = output.IndexOf("[HIGH] MAIL-SPF-002  Title of MAIL-SPF-002", StringComparison.Ordinal);
        var medium = output.IndexOf("[MEDIUM] MAIL-DMARC-001  Title of MAIL-DMARC-001", StringComparison.Ordinal);
        Assert.True(high > 0 && medium > high, output);
        Assert.Contains("      Evidence: evidence of MAIL-DMARC-001", output, StringComparison.Ordinal);
        Assert.Contains("      Risk: risk of MAIL-DMARC-001", output, StringComparison.Ordinal);
        Assert.Contains("      Fix: fix of MAIL-DMARC-001", output, StringComparison.Ordinal);
        Assert.Contains("      Confidence: probable", output, StringComparison.Ordinal);
        Assert.Contains("      References: RFC 7489", output, StringComparison.Ordinal);

        Assert.Contains("Checks passed\n  OK MAIL-SPF-001  Check MAIL-SPF-001", Normalize(output), StringComparison.Ordinal);
        Assert.Contains("Checks skipped\n  -- MAIL-DKIM-002  Check MAIL-DKIM-002: no key to look at", Normalize(output), StringComparison.Ordinal);
        Assert.Contains("Checks that could not run\n  !! MAIL-MX-001  Check MAIL-MX-001: DNS timeout", Normalize(output), StringComparison.Ordinal);
        Assert.Contains("Summary: 0 critical, 1 high, 1 medium, 0 low, 0 info · 1 checks passed, 1 skipped, 1 could not run.", output, StringComparison.Ordinal);
        Assert.EndsWith(Attribution.Notice + Environment.NewLine, output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WhenUiIsItalian_ShouldPrintItalianLabels()
    {
        var fake = new FakeChecks(High("MAIL-SPF-001"));

        using var culture = new UiCulture("it-IT");
        var (_, output, _) = await RunAsync(fake, "scan", "--mail", "example.com");

        Assert.Contains("== Posta — example.com ==", output, StringComparison.Ordinal);
        Assert.Contains("[ALTO] MAIL-SPF-001", output, StringComparison.Ordinal);
        Assert.Contains("      Correzione: fix of MAIL-SPF-001", output, StringComparison.Ordinal);
        Assert.Contains($"Dichiarato da tester (titolare) il {Now.ToString("g", CultureInfo.CurrentCulture)}.", output, StringComparison.Ordinal);
        Assert.Contains("19/11/2026", output, StringComparison.Ordinal);
        Assert.Contains("Riepilogo: 0 critici, 1 alti", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WhenNothingIsFound_ShouldSaySoForEachTarget()
    {
        var fake = new FakeChecks(Passed("MAIL-SPF-001"));

        using var culture = new UiCulture("en-US");
        var (exitCode, output, _) = await RunAsync(fake, "scan", "--mail", "a.example", "--mail", "b.example");

        Assert.Equal(0, exitCode);
        Assert.Equal(2, CountOf(output, "No problems found."));
        Assert.True(output.IndexOf("== Email — a.example ==", StringComparison.Ordinal) < output.IndexOf("== Email — b.example ==", StringComparison.Ordinal));
        Assert.Contains("Summary: 0 critical, 0 high, 0 medium, 0 low, 0 info · 2 checks passed, 0 skipped, 0 could not run.", output, StringComparison.Ordinal);
        Assert.DoesNotContain("Checks skipped", output, StringComparison.Ordinal);
        Assert.DoesNotContain("Checks that could not run", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WhenTwoDomainsDiffer_ShouldPrintEachProblemUnderItsOwnDomain()
    {
        var byTarget = new TargetAwareCheck("MAIL-DMARC-001", target => target == "bad.example"
            ? new CheckResult.Executed([new Finding("MAIL-DMARC-001", CheckArea.Email, "Only bad", Severity.High, Confidence.Certain, target)])
            : new CheckResult.Executed([]));
        var fake = new FakeChecks(byTarget);

        using var culture = new UiCulture("en-US");
        var (_, output, _) = await RunAsync(fake, "scan", "--mail", "good.example", "--mail", "bad.example");

        var text = Normalize(output);
        var good = text[text.IndexOf("== Email — good.example ==", StringComparison.Ordinal)..text.IndexOf("== Email — bad.example ==", StringComparison.Ordinal)];
        Assert.Contains("No problems found.", good, StringComparison.Ordinal);
        Assert.DoesNotContain("Only bad", good, StringComparison.Ordinal);
        Assert.Equal(1, CountOf(output, "Only bad"));
        Assert.Equal(1, CountOf(output, "OK MAIL-DMARC-001"));
    }

    [Fact]
    public async Task Scan_WhenFindingHasNoOptionalText_ShouldPrintOnlyWhatIsThere()
    {
        var bare = new Finding("MAIL-MX-001", CheckArea.Email, "Bare", Severity.Info, Confidence.ToBeVerified, "example.com");
        var fake = new FakeChecks(new FakeCheck("MAIL-MX-001", new CheckResult.Executed([bare])));

        using var culture = new UiCulture("en-US");
        var (_, output, _) = await RunAsync(fake, "scan", "--mail", "example.com");

        Assert.Contains("[INFO] MAIL-MX-001  Bare", output, StringComparison.Ordinal);
        Assert.Contains("      Confidence: to be verified", output, StringComparison.Ordinal);
        Assert.DoesNotContain("Evidence:", output, StringComparison.Ordinal);
        Assert.DoesNotContain("References:", output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("scan")]
    [InlineData("scan", "--mail", " ")]
    public async Task Scan_WhenNoDomainIsGiven_ShouldExitWithTwoAndRunNothing(params string[] args)
    {
        var fake = new FakeChecks(Passed("MAIL-SPF-001"));

        using var culture = new UiCulture("en-US");
        var (exitCode, output, error) = await RunAsync(fake, args);

        Assert.Equal(ScanCommand.InvalidInput, exitCode);
        Assert.Contains("--mail <domain>", error, StringComparison.Ordinal);
        Assert.Empty(output);
        Assert.Null(fake.Options);
    }

    [Fact]
    public async Task Scan_WhenSelectorIsInvalid_ShouldExitWithTwoNamingIt()
    {
        var fake = new FakeChecks(Passed("MAIL-SPF-001"));

        using var culture = new UiCulture("en-US");
        var (exitCode, _, error) = await RunAsync(fake, "scan", "--mail", "example.com", "--dkim-selector", "ok1", "--dkim-selector", "bad selector");

        Assert.Equal(ScanCommand.InvalidInput, exitCode);
        Assert.Contains("'bad selector' is not a valid DKIM selector.", error, StringComparison.Ordinal);
        Assert.Null(fake.Options);
    }

    [Fact]
    public async Task Scan_WhenOptionsAreGiven_ShouldPassThemToTheChecks()
    {
        var fake = new FakeChecks(Passed("MAIL-SPF-001"));

        await RunAsync(fake, "scan", "--mail", "example.com", "--dkim-selector", "OVH1", "--system-dns");

        Assert.Equal(["ovh1"], fake.Options!.DkimSelectors);
        Assert.Equal(DnsSource.System, fake.Options.DnsSource);
    }

    [Fact]
    public async Task Scan_WhenDefaultsAreUsed_ShouldAskPublicDnsAndDeclareTheUserAsOwner()
    {
        var fake = new FakeChecks(Passed("MAIL-SPF-001"));

        using var culture = new UiCulture("en-US");
        var (_, output, _) = await RunAsync(fake, "scan", "--mail", "example.com", "--operator", "  ");

        Assert.Equal(DnsSource.Public, fake.Options!.DnsSource);
        Assert.Empty(fake.Options.DkimSelectors);
        Assert.Contains("Declared by tester (owner)", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WhenNoUserNameIsAvailable_ShouldDeclareTheOperatorAsNotDeclared()
    {
        var fake = new FakeChecks(Passed("MAIL-SPF-001"));
        var services = new CliServices(fake.Create, () => Now, () => " ");

        using var culture = new UiCulture("en-US");
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        await CliApp.RunAsync(["scan", "--mail", "example.com", "--role", "AppointedPerson"], output, TextWriter.Null, services, TestContext.Current.CancellationToken);

        Assert.Contains("Declared by not declared (appointed person)", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WhenRoleIsUnknown_ShouldFailTheCommandLine()
    {
        var (exitCode, _, error) = await RunAsync(new FakeChecks(), "scan", "--mail", "example.com", "--role", "Boss");

        Assert.Equal(1, exitCode);
        Assert.Contains("Boss", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WhenCheckIsActive_ShouldNeverRunItBecauseOwnershipCannotBeProvenYet()
    {
        var active = new FakeCheck("WEB-FILES-001", new CheckResult.Executed([]), ScopeRequirement.ActiveOwnedOnly);
        var fake = new FakeChecks(active);

        using var culture = new UiCulture("en-US");
        var (_, output, _) = await RunAsync(fake, "scan", "--mail", "example.com");

        Assert.False(active.Ran);
        Assert.Contains("-- WEB-FILES-001", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PassiveOnlyScopeGuard_WhenAsked_ShouldAlwaysRefuse()
    {
        var guard = new PassiveOnlyScopeGuard();

        Assert.False(await guard.IsAuthorizedAsync(new Target(TargetKind.Domain, "example.com"), TestContext.Current.CancellationToken));
        Assert.False(await guard.IsAuthorizedAsync(new Target(TargetKind.Network, "192.168.1.0/24"), TestContext.Current.CancellationToken));
    }

    [Fact]
    public void Default_WhenUsed_ShouldBuildTheRealEmailChecksAndReadClockAndUser()
    {
        var services = CliServices.Default;

        Assert.Equal(11, services.CreateEmailChecks(new EmailCheckOptions()).Count);
        Assert.InRange(services.Now(), DateTimeOffset.Now.AddMinutes(-1), DateTimeOffset.Now.AddMinutes(1));
        Assert.Equal(Environment.UserName, services.DefaultOperator());
    }

    [Theory]
    [InlineData(Severity.Critical, "CRITICAL")]
    [InlineData(Severity.Low, "LOW")]
    [InlineData(Severity.Info, "INFO")]
    public void SeverityLabel_WhenCalled_ShouldBeUpperCaseAndLocalized(Severity severity, string expected)
    {
        using var culture = new UiCulture("en-US");

        Assert.Equal(expected, ScanReport.SeverityLabel(severity));
    }

    private static async Task<(int ExitCode, string Output, string Error)> RunAsync(FakeChecks fake, params string[] args)
    {
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        using var error = new StringWriter(CultureInfo.InvariantCulture);
        var services = new CliServices(fake.Create, () => Now, () => "tester");
        var exitCode = await CliApp.RunAsync(args, output, error, services, TestContext.Current.CancellationToken);
        return (exitCode, output.ToString(), error.ToString());
    }

    private static string Normalize(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal);

    private static int CountOf(string text, string value) => (text.Length - text.Replace(value, string.Empty, StringComparison.Ordinal).Length) / value.Length;

    private static FakeCheck High(string id) => WithFinding(id, Severity.High, Confidence.Certain);

    private static FakeCheck Medium(string id) => WithFinding(id, Severity.Medium, Confidence.Probable);

    private static FakeCheck WithFinding(string id, Severity severity, Confidence confidence) =>
        new(id, new CheckResult.Executed(
        [
            new Finding(id, CheckArea.Email, "Title of " + id, severity, confidence, "example.com")
            {
                Evidence = "evidence of " + id,
                Risk = "risk of " + id,
                Fix = "fix of " + id,
                References = ["RFC 7489"],
            },
        ]));

    private static FakeCheck Passed(string id) => new(id, new CheckResult.Executed([]));

    private static FakeCheck Skipped(string id) => new(id, new CheckResult.Skipped("no key to look at"));

    private static FakeCheck Failed(string id) => new(id, new CheckResult.Failed("DNS timeout"));

    /// <summary>Hands out the given checks and records the options they were built with.</summary>
    private sealed class FakeChecks(params ICheck[] checks)
    {
        public EmailCheckOptions? Options { get; private set; }

        public IReadOnlyList<ICheck> Create(EmailCheckOptions options)
        {
            Options = options;
            return checks;
        }
    }

    private sealed class FakeCheck(string id, CheckResult result, ScopeRequirement scope = ScopeRequirement.Passive) : ICheck
    {
        public bool Ran { get; private set; }

        public string Id => id;

        public string Title => "Check " + id;

        public CheckArea Area => CheckArea.Email;

        public TargetKind AppliesTo => TargetKind.Domain;

        public ScopeRequirement Scope => scope;

        public Task<CheckResult> RunAsync(CheckContext context, CancellationToken cancellationToken)
        {
            Ran = true;
            return Task.FromResult(result);
        }
    }

    /// <summary>A check whose result depends on the target.</summary>
    private sealed class TargetAwareCheck(string id, Func<string, CheckResult> result) : ICheck
    {
        public string Id => id;

        public string Title => "Check " + id;

        public CheckArea Area => CheckArea.Email;

        public TargetKind AppliesTo => TargetKind.Domain;

        public ScopeRequirement Scope => ScopeRequirement.Passive;

        public Task<CheckResult> RunAsync(CheckContext context, CancellationToken cancellationToken) => Task.FromResult(result(context.Target.Value));
    }

    private sealed class UiCulture : IDisposable
    {
        private readonly CultureInfo previous = CultureInfo.CurrentCulture;
        private readonly CultureInfo previousUi = CultureInfo.CurrentUICulture;

        public UiCulture(string name)
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name);
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name);
        }

        public void Dispose()
        {
            CultureInfo.CurrentCulture = previous;
            CultureInfo.CurrentUICulture = previousUi;
        }
    }
}
