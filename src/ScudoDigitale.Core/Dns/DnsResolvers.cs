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

namespace ScudoDigitale.Core.Dns;

/// <summary>
/// Creates the DNS resolver shared by the check modules, so every area asks the same servers in the
/// same way (ADR-006).
/// </summary>
public static class DnsResolvers
{
    /// <summary>
    /// One client for every run, so connections to the DNS over HTTPS services are reused. No cookies,
    /// a generic user agent, and the proxy of the system (which companies often require).
    /// </summary>
    private static readonly HttpClient Http = CreateHttpClient();

    /// <summary>
    /// The resolver chosen by <see cref="DnsOptions.Source"/>: with <see cref="DnsSource.Public"/>
    /// Cloudflare and then Google over DNS over HTTPS, then the DNS of this computer; with
    /// <see cref="DnsSource.System"/> the DNS of this computer only.
    /// </summary>
    /// <param name="options">The DNS source and timeouts; defaults when <see langword="null"/>.</param>
    /// <returns>The resolver.</returns>
    public static IDnsResolver Create(DnsOptions? options = null) => Create(options ?? new DnsOptions(), Http);

    /// <summary>The resolver chosen by <see cref="DnsOptions.Source"/>, on a given HTTP client.</summary>
    /// <param name="options">The DNS source and timeouts.</param>
    /// <param name="http">Client for DNS over HTTPS.</param>
    /// <returns>The resolver.</returns>
    internal static IDnsResolver Create(DnsOptions options, HttpClient http) =>
        options.Source == DnsSource.System
            ? new DnsClientResolver(options)
            : new FallbackResolver(
            [
                new DohResolver(http, DohResolver.Cloudflare, options),
                new DohResolver(http, DohResolver.Google, options),
                new DnsClientResolver(options),
            ]);

    /// <summary>The client used for DNS over HTTPS.</summary>
    /// <returns>The client.</returns>
    internal static HttpClient CreateHttpClient()
    {
        var client = new HttpClient(CreateHandler())
        {
            // Each request has its own deadline (DohResolver).
            Timeout = Timeout.InfiniteTimeSpan,
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("ScudoDigitale");
        return client;
    }

    /// <summary>The handler of <see cref="CreateHttpClient"/>: no cookies, connections renewed every 2 minutes.</summary>
    /// <returns>The handler.</returns>
    internal static SocketsHttpHandler CreateHandler() => new()
    {
        UseCookies = false,
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
    };
}
