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

using System.Net;

namespace ScudoDigitale.Core.Dns;

/// <summary>
/// The DNS queries the checks need. Implementations report every DNS problem through
/// <see cref="DnsAnswer{T}"/> and throw only <see cref="OperationCanceledException"/> when cancelled.
/// </summary>
public interface IDnsResolver
{
    /// <summary>TXT records of <paramref name="name"/>; the strings of each record are joined.</summary>
    /// <param name="name">Name to query.</param>
    /// <param name="cancellationToken">Cancels the query.</param>
    /// <returns>The answer.</returns>
    Task<DnsAnswer<string>> QueryTxtAsync(string name, CancellationToken cancellationToken);

    /// <summary>MX records of <paramref name="name"/>.</summary>
    /// <param name="name">Name to query.</param>
    /// <param name="cancellationToken">Cancels the query.</param>
    /// <returns>The answer.</returns>
    Task<DnsAnswer<MailExchange>> QueryMxAsync(string name, CancellationToken cancellationToken);

    /// <summary>IPv4 and IPv6 addresses (A and AAAA records) of <paramref name="name"/>.</summary>
    /// <param name="name">Name to query.</param>
    /// <param name="cancellationToken">Cancels the query.</param>
    /// <returns>The answer.</returns>
    Task<DnsAnswer<IPAddress>> QueryAddressesAsync(string name, CancellationToken cancellationToken);
}
