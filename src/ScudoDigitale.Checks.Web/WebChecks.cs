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

using System.Diagnostics.CodeAnalysis;
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Web;

/// <summary>
/// Entry point of the website area: the passive checks on a site (HTTPS, certificate, security
/// headers, cookies, security.txt). They make only the requests of a normal first visit: no login,
/// no form, no path other than the home page and the standard security.txt addresses.
/// </summary>
public static class WebChecks
{
    /// <summary>
    /// Creates the website checks. The checks of one call share their visit to each site, so create a
    /// new set for every run: a set reused later would repeat what the first run saw.
    /// </summary>
    /// <param name="options">Request timeout; defaults when <see langword="null"/>.</param>
    /// <returns>The checks, in report order.</returns>
    public static IReadOnlyList<ICheck> Create(WebCheckOptions? options = null)
    {
        options ??= new WebCheckOptions();
        return Create(new HttpSiteFetcher(options), options);
    }

    /// <summary>
    /// Turns what the user typed into the name of the site to check: a domain name such as
    /// <c>example.com</c>, or an <c>http</c>/<c>https</c> URL of which only the host is used.
    /// </summary>
    /// <param name="value">A domain name or a URL.</param>
    /// <param name="host">The lower-case host name (punycode for internationalized names), when valid.</param>
    /// <returns><see langword="true"/> if the value names a website.</returns>
    public static bool TryNormalizeTarget(string? value, [NotNullWhen(true)] out string? host) =>
        HostName.TryNormalize(value, out host);

    /// <summary>Creates the website checks on a given fetcher.</summary>
    /// <param name="fetcher">Visits the sites.</param>
    /// <param name="options">The time budget of a visit.</param>
    /// <returns>The checks, in report order.</returns>
    internal static IReadOnlyList<ICheck> Create(ISiteFetcher fetcher, WebCheckOptions options)
    {
        var inspector = new WebSiteInspector(fetcher, options);
        return
        [
            .. HttpsChecks.Create(inspector),
            .. CertificateChecks.Create(inspector),
            .. HeaderChecks.Create(inspector),
            .. CookieChecks.Create(inspector),
            .. SecurityTxtChecks.Create(inspector),
        ];
    }
}
