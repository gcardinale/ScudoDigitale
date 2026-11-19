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

namespace ScudoDigitale.Checks.Email;

/// <summary>
/// Entry point of the email area: the passive checks on a domain (SPF, DMARC, DKIM, MX). They read
/// only the public DNS and never send or receive mail.
/// </summary>
public static class EmailChecks
{
    /// <summary>
    /// One client for every run, so connections to the DNS over HTTPS services are reused. No cookies,
    /// a generic user agent, and the proxy of the system (which companies often require).
    /// </summary>
    private static readonly HttpClient Http = CreateHttpClient();

    /// <summary>
    /// Creates the email checks. The checks of one call share their DNS answers, so create a new
    /// set for every run: a set reused later would repeat the answers of the first run.
    /// </summary>
    /// <param name="options">DNS timeouts, concurrency and extra DKIM selectors; defaults when <see langword="null"/>.</param>
    /// <returns>The checks, in report order.</returns>
    public static IReadOnlyList<ICheck> Create(EmailCheckOptions? options = null)
    {
        options ??= new EmailCheckOptions();
        return Create(CreateResolver(options, Http), options);
    }

    /// <summary>
    /// The resolver chosen by <see cref="EmailCheckOptions.DnsSource"/>: with
    /// <see cref="DnsSource.Public"/> Cloudflare and then Google over DNS over HTTPS, then the DNS of
    /// this computer; with <see cref="DnsSource.System"/> the DNS of this computer only (ADR-006).
    /// </summary>
    /// <param name="options">The DNS source and timeouts.</param>
    /// <param name="http">Client for DNS over HTTPS.</param>
    /// <returns>The resolver.</returns>
    internal static IDnsResolver CreateResolver(EmailCheckOptions options, HttpClient http) =>
        options.DnsSource == DnsSource.System
            ? new DnsClientResolver(options)
            : new FallbackResolver(
            [
                new DohResolver(http, DohResolver.Cloudflare, options),
                new DohResolver(http, DohResolver.Google, options),
                new DnsClientResolver(options),
            ]);

    /// <summary>Creates the email checks on a given resolver.</summary>
    /// <param name="resolver">Where the DNS answers come from.</param>
    /// <param name="options">DNS concurrency and extra DKIM selectors.</param>
    /// <returns>The checks, in report order.</returns>
    internal static IReadOnlyList<ICheck> Create(IDnsResolver resolver, EmailCheckOptions options)
    {
        var inspector = new EmailDomainInspector(resolver, options);
        return
        [
            .. SpfChecks.Create(inspector),
            .. DmarcChecks.Create(inspector),
            .. DkimChecks.Create(inspector),
            .. MxChecks.Create(inspector),
        ];
    }

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
