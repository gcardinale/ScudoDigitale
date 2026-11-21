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
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Web.Tests;

/// <summary>Sets the culture and UI culture for the current async flow and restores it on dispose.</summary>
internal sealed class UiCulture : IDisposable
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

/// <summary>
/// Hands out a prepared visit instead of touching the network. It can throw, or hang forever while
/// ignoring the cancellation token (as a rude real server would).
/// </summary>
internal sealed class FakeSiteFetcher(SiteVisit? visit = null) : ISiteFetcher
{
    private int visits;

    public Exception? Throws { get; set; }

    public bool Hangs { get; set; }

    public Task? Release { get; set; }

    /// <summary>Time spent before the first await, on the thread of the caller.</summary>
    public TimeSpan Blocks { get; set; }

    public int Visits => visits;

    public async Task<SiteVisit> VisitAsync(string host, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref visits);
        Thread.Sleep(Blocks);
        if (Throws is not null)
        {
            throw Throws;
        }

        if (Hangs)
        {
            await new TaskCompletionSource().Task;
        }

        if (Release is not null)
        {
            await Release;
        }

        return visit ?? Site.Good(host);
    }
}

/// <summary>Builds visits: a well-configured site, and variations of it.</summary>
internal static class Site
{
    public const string Host = "example.com";

    public static readonly DateTimeOffset Now = new(2026, 11, 21, 10, 0, 0, TimeSpan.Zero);

    public static readonly (string Name, string Value)[] GoodHeaders =
    [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "geolocation=()"),
        ("Set-Cookie", "session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"),
    ];

    public const string GoodSecurityTxt = "# Our security contact\nContact: mailto:security@example.com\nExpires: 2027-06-30T23:59:59Z\n";

    public static Hop Hop(string url, int status = 200, string? body = null, params (string Name, string Value)[] headers) =>
        new(new Uri(url), status, [.. headers.Select(h => KeyValuePair.Create(h.Name, h.Value))], body);

    public static Hop RedirectHop(string url, string location, int status = 301) => Hop(url, status, null, ("Location", location));

    public static Trail Response(params Hop[] hops) => new(hops, TrailEnd.Response);

    public static Trail Stopped(TrailEnd end, string next, params Hop[] hops) => new(hops, end, new Uri(next));

    public static CertificateInfo Certificate(
        string host = Host,
        int daysLeft = 60,
        bool nameMatches = true,
        ChainState chain = ChainState.Trusted,
        string detail = "NoError") =>
        new(host, [host, "www." + host], Now.AddDays(-30), Now.AddDays(daysLeft), nameMatches, chain, detail);

    /// <summary>A site with nothing to report.</summary>
    public static SiteVisit Good(string host = Host) => new(
        host,
        Now,
        Stopped(TrailEnd.ChangedScheme, $"https://{host}/", RedirectHop($"http://{host}/", $"https://{host}/")),
        Response(Hop($"https://{host}/", 200, "<html><head><title>Home</title></head></html>", GoodHeaders)),
        [Certificate(host)],
        Response(Hop($"https://{host}/.well-known/security.txt", 200, GoodSecurityTxt, ("Content-Type", "text/plain"))));

    /// <summary>The same visit with the headers of the home page replaced.</summary>
    public static SiteVisit WithPageHeaders(this SiteVisit visit, params (string Name, string Value)[] headers) =>
        visit with { Https = Response(Hop(visit.Https.Hops[^1].Url.AbsoluteUri, 200, visit.Https.Hops[^1].Body, headers)) };

    /// <summary>The same visit with one header of the home page set to the given values, or removed when there are none.</summary>
    public static SiteVisit WithHeader(this SiteVisit visit, string name, params string[] values) =>
        visit.WithPageHeaders(
        [
            .. GoodHeaders.Where(h => !h.Name.Equals(name, StringComparison.OrdinalIgnoreCase)),
            .. values.Select(v => (name, v)),
        ]);

    /// <summary>The same visit with another HTML body for the home page.</summary>
    public static SiteVisit WithBody(this SiteVisit visit, string? html)
    {
        var page = visit.Https.Hops[^1];
        return visit with { Https = Response(page with { Body = html }) };
    }

    /// <summary>The same visit with another text for security.txt.</summary>
    public static SiteVisit WithSecurityTxt(this SiteVisit visit, string text) => visit with
    {
        SecurityTxt = Response(Hop($"https://{visit.Host}/.well-known/security.txt", 200, text, ("Content-Type", "text/plain"))),
    };
}

/// <summary>Builders and runners shared by the tests.</summary>
internal static class Make
{
    public static CheckContext Context(string site = Site.Host, TargetKind kind = TargetKind.Website)
    {
        var target = new Target(kind, site);
        return new CheckContext(target, Profile.Individual(), new ScopeDeclaration("Mario Rossi", OperatorRole.Owner, [target], Site.Now));
    }

    public static ICheck Check(ISiteFetcher fetcher, string id, WebCheckOptions? options = null) =>
        WebChecks.Create(fetcher, options ?? new WebCheckOptions()).Single(c => c.Id == id);

    public static Task<CheckResult> RunAsync(SiteVisit visit, string id) =>
        Check(new FakeSiteFetcher(visit), id).RunAsync(Context(visit.Host), CancellationToken.None);

    public static async Task<IReadOnlyList<Finding>> FindingsAsync(SiteVisit visit, string id) =>
        Assert.IsType<CheckResult.Executed>(await RunAsync(visit, id)).Findings;

    public static async Task<Finding> SingleFindingAsync(SiteVisit visit, string id)
    {
        var finding = Assert.Single(await FindingsAsync(visit, id));
        Assert.Equal(id, finding.Id);
        Assert.Equal(CheckArea.Web, finding.Area);
        Assert.Equal(visit.Host, finding.Target);
        Assert.False(string.IsNullOrWhiteSpace(finding.Title));
        Assert.False(string.IsNullOrWhiteSpace(finding.Evidence));
        Assert.False(string.IsNullOrWhiteSpace(finding.Risk));
        Assert.False(string.IsNullOrWhiteSpace(finding.Fix));
        Assert.NotEmpty(finding.References);
        return finding;
    }
}
