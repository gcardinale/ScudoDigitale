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
    /// Creates the email checks. The checks of one call share their DNS answers, so create a new
    /// set for every run: a set reused later would repeat the answers of the first run.
    /// </summary>
    /// <param name="options">DNS timeouts, concurrency and extra DKIM selectors; defaults when <see langword="null"/>.</param>
    /// <returns>The checks, in report order.</returns>
    public static IReadOnlyList<ICheck> Create(EmailCheckOptions? options = null)
    {
        options ??= new EmailCheckOptions();
        return Create(new DnsClientResolver(options), options);
    }

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
}
