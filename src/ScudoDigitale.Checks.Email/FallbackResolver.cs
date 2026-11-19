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

namespace ScudoDigitale.Checks.Email;

/// <summary>
/// Asks a list of resolvers in order and moves to the next one only when a query fails. An answer
/// such as "no records" or "does not exist" is final: asking elsewhere would not change it.
/// </summary>
internal sealed class FallbackResolver : IDnsResolver
{
    /// <summary>Creates the resolver.</summary>
    /// <param name="resolvers">The resolvers, in the order they are asked; at least one.</param>
    public FallbackResolver(IReadOnlyList<IDnsResolver> resolvers)
    {
        Resolvers = resolvers;
    }

    /// <summary>The resolvers, in the order they are asked.</summary>
    public IReadOnlyList<IDnsResolver> Resolvers { get; }

    /// <inheritdoc />
    public Task<DnsAnswer<string>> QueryTxtAsync(string name, CancellationToken cancellationToken) =>
        AskAsync((r, ct) => r.QueryTxtAsync(name, ct), cancellationToken);

    /// <inheritdoc />
    public Task<DnsAnswer<MailExchange>> QueryMxAsync(string name, CancellationToken cancellationToken) =>
        AskAsync((r, ct) => r.QueryMxAsync(name, ct), cancellationToken);

    /// <inheritdoc />
    public Task<DnsAnswer<IPAddress>> QueryAddressesAsync(string name, CancellationToken cancellationToken) =>
        AskAsync((r, ct) => r.QueryAddressesAsync(name, ct), cancellationToken);

    private async Task<DnsAnswer<T>> AskAsync<T>(Func<IDnsResolver, CancellationToken, Task<DnsAnswer<T>>> query, CancellationToken cancellationToken)
    {
        var errors = new List<string>();
        foreach (var resolver in Resolvers)
        {
            var answer = await query(resolver, cancellationToken).ConfigureAwait(false);
            if (answer.Status != DnsStatus.Error)
            {
                return answer;
            }

            errors.Add(answer.Error!);
        }

        return DnsAnswer<T>.Failed(string.Join("; ", errors));
    }
}
