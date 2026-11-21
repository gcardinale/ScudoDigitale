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

namespace ScudoDigitale.Checks.Web.Tests;

/// <summary>
/// Counterproofs: for every check, a site where the problem is there and one where it is not, seen
/// through the real checks, the real engine and real connections to a local server. The site without
/// the problem is the same well-configured site for all of them, so each problem is proven to be
/// reported by its own check and by that check only when it is really there.
/// </summary>
public sealed class CounterproofTests(TestPki pki) : IClassFixture<TestPki>
{
    public static TheoryData<string> CheckIds =>
    [
        "WEB-HTTPS-001", "WEB-HTTPS-002", "WEB-CERT-001", "WEB-CERT-002", "WEB-CERT-003", "WEB-HSTS-001",
        "WEB-HDR-001", "WEB-HDR-002", "WEB-HDR-003", "WEB-HDR-004", "WEB-HDR-005",
        "WEB-COOKIE-001", "WEB-COOKIE-002", "WEB-COOKIE-003", "WEB-SECTXT-001",
    ];

    [Fact]
    public void CheckIds_WhenCompared_ShouldCoverEveryCheckOfTheModule()
    {
        Assert.Equal(WebChecks.Create().Select(c => c.Id), CheckIds.Select(row => row.Data));
    }

    [Theory(Timeout = 30_000)]
    [MemberData(nameof(CheckIds))]
    public async Task Check_WhenTheProblemIsThere_ShouldReportItUnderItsOwnId(string id)
    {
        await using var site = WithProblem(id, out var options);

        var runs = await RunAsync(options, TestContext.Current.CancellationToken);

        var result = Assert.IsType<CheckResult.Executed>(runs.Single(r => r.CheckId == id).Result);
        Assert.NotEmpty(result.Findings);
        Assert.All(result.Findings, f =>
        {
            Assert.Equal(id, f.Id);
            Assert.Equal(TestSite.Host, f.Target);
        });
    }

    [Theory(Timeout = 30_000)]
    [MemberData(nameof(CheckIds))]
    public async Task Check_WhenTheProblemIsNotThere_ShouldReportNothing(string id)
    {
        await using var site = new TestSite(pki);

        var runs = await RunAsync(site.Options(), TestContext.Current.CancellationToken);

        Assert.Empty(Assert.IsType<CheckResult.Executed>(runs.Single(r => r.CheckId == id).Result).Findings);
    }

    /// <summary>The well-configured site with exactly one thing wrong: the subject of the given check.</summary>
    private TestSite WithProblem(string id, out WebCheckOptions options)
    {
        TestSite site;
        switch (id)
        {
            case "WEB-HTTPS-001":
                site = new TestSite(pki) { HttpsListens = false, HttpRedirects = false };
                options = site.Options();
                break;
            case "WEB-HTTPS-002":
                site = new TestSite(pki) { HttpRedirects = false };
                options = site.Options();
                break;
            case "WEB-CERT-001":
                site = new TestSite(pki, pki.Expired);
                options = site.Options();
                break;
            case "WEB-CERT-002":
                site = new TestSite(pki, pki.SelfSigned);
                options = site.Options();
                break;
            case "WEB-CERT-003":
                site = new TestSite(pki, pki.WrongName);
                options = site.Options();
                break;
            case "WEB-HSTS-001":
                site = new TestSite(pki);
                options = site.Remove("Strict-Transport-Security");
                break;
            case "WEB-HDR-001":
                site = new TestSite(pki);
                options = site.Set("Content-Security-Policy", "frame-ancestors 'none'; script-src * 'unsafe-inline'");
                break;
            case "WEB-HDR-002":
                site = new TestSite(pki);
                site.Remove("X-Frame-Options");
                options = site.Set("Content-Security-Policy", "default-src 'self'");
                break;
            case "WEB-HDR-003":
                site = new TestSite(pki);
                options = site.Remove("X-Content-Type-Options");
                break;
            case "WEB-HDR-004":
                site = new TestSite(pki);
                options = site.Set("Referrer-Policy", "unsafe-url");
                break;
            case "WEB-HDR-005":
                site = new TestSite(pki);
                options = site.Remove("Permissions-Policy");
                break;
            case "WEB-COOKIE-001":
                site = new TestSite(pki);
                options = site.Set("Set-Cookie", "session=abc123; Path=/; HttpOnly; SameSite=Lax");
                break;
            case "WEB-COOKIE-002":
                site = new TestSite(pki);
                options = site.Set("Set-Cookie", "session=abc123; Path=/; Secure; SameSite=Lax");
                break;
            case "WEB-COOKIE-003":
                site = new TestSite(pki);
                options = site.Set("Set-Cookie", "session=abc123; Path=/; Secure; HttpOnly");
                break;
            default:
                site = new TestSite(pki) { SecurityTxt = null };
                options = site.Options();
                break;
        }

        return site;
    }

    private static Task<IReadOnlyList<CheckRun>> RunAsync(WebCheckOptions options, CancellationToken cancellationToken) =>
        new CheckEngine(new DenyAll()).RunAsync(
            WebChecks.Create(new HttpSiteFetcher(options), options),
            Profile.Individual(),
            new ScopeDeclaration("Mario Rossi", OperatorRole.Owner, [new Target(TargetKind.Website, TestSite.Host)], DateTimeOffset.UtcNow),
            cancellationToken);

    private sealed class DenyAll : IScopeGuard
    {
        public Task<bool> IsAuthorizedAsync(Target target, CancellationToken cancellationToken) => Task.FromResult(false);
    }
}
