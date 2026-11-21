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
using System.Net;
using DnsClient;
using DnsClient.Protocol;
using ScudoDigitale.Core.Resources;

namespace ScudoDigitale.Core.Dns;

/// <summary>
/// <see cref="IDnsResolver"/> on DnsClient.NET, using the DNS servers configured on this computer.
/// It never falls back to a public resolver: with no configured server every query fails and says
/// why, so no connection is made that the user did not configure (zero telemetry).
/// </summary>
internal sealed class DnsClientResolver : IDnsResolver
{
    private readonly LookupClient? client;

    /// <summary>Creates a resolver on the DNS servers configured on this computer.</summary>
    /// <param name="options">Timeout and retries.</param>
    public DnsClientResolver(DnsOptions options)
        : this(SystemNameServers(), options)
    {
    }

    /// <summary>Creates a resolver on the given DNS servers.</summary>
    /// <param name="nameServers">DNS servers to ask; with none, every query fails.</param>
    /// <param name="options">Timeout and retries.</param>
    internal DnsClientResolver(IReadOnlyCollection<NameServer> nameServers, DnsOptions options)
    {
        if (nameServers.Count == 0)
        {
            return;
        }

        client = new LookupClient(new LookupClientOptions(nameServers.ToArray())
        {
            AutoResolveNameServers = false,
            Timeout = options.Timeout,
            Retries = options.Retries,
            UseCache = true,
            CacheFailedResults = false,
            ThrowDnsErrors = false,
            UseTcpFallback = true,
            EnableAuditTrail = false,
        });
    }

    /// <inheritdoc />
    public Task<DnsAnswer<string>> QueryTxtAsync(string name, CancellationToken cancellationToken) =>
        QueryAsync(name, QueryType.TXT, r => r.Answers.TxtRecords().Select(t => string.Concat(t.Text)), cancellationToken);

    /// <inheritdoc />
    public Task<DnsAnswer<MailExchange>> QueryMxAsync(string name, CancellationToken cancellationToken) =>
        QueryAsync(
            name,
            QueryType.MX,
            r => r.Answers.MxRecords().Select(m => new MailExchange(m.Preference, m.Exchange.Value.TrimEnd('.'))),
            cancellationToken);

    /// <inheritdoc />
    public async Task<DnsAnswer<IPAddress>> QueryAddressesAsync(string name, CancellationToken cancellationToken)
    {
        // Both questions at once: a server that does not answer costs one timeout, not two.
        var v4 = QueryAsync(name, QueryType.A, r => r.Answers.ARecords().Select(a => a.Address), cancellationToken);
        var v6 = QueryAsync(name, QueryType.AAAA, r => r.Answers.AaaaRecords().Select(a => a.Address), cancellationToken);
        return Combine(await v4.ConfigureAwait(false), await v6.ConfigureAwait(false));
    }

    /// <summary>
    /// Merges the A and AAAA answers: any address wins; otherwise an error wins over "does not
    /// exist", which wins over "no records".
    /// </summary>
    /// <param name="v4">Answer to the A query.</param>
    /// <param name="v6">Answer to the AAAA query.</param>
    /// <returns>The merged answer.</returns>
    internal static DnsAnswer<IPAddress> Combine(DnsAnswer<IPAddress> v4, DnsAnswer<IPAddress> v6)
    {
        if (v4.Records.Count + v6.Records.Count > 0)
        {
            return DnsAnswer<IPAddress>.Found(v4.Records.Concat(v6.Records));
        }

        if (v4.Status == DnsStatus.Error)
        {
            return v4;
        }

        if (v6.Status == DnsStatus.Error)
        {
            return v6;
        }

        return v4.Status == DnsStatus.NonExistentDomain || v6.Status == DnsStatus.NonExistentDomain
            ? DnsAnswer<IPAddress>.NonExistentDomain()
            : DnsAnswer<IPAddress>.NoRecords();
    }

    /// <summary>The DNS servers of this computer, without the public fallback of DnsClient.</summary>
    [ExcludeFromCodeCoverage(Justification = "Reads the network configuration of the machine; the empty case is tested through the internal constructor.")]
    private static NameServer[] SystemNameServers()
    {
        try
        {
            return NameServer.ResolveNameServers(skipIPv6SiteLocal: true, fallbackToGooglePublicDns: false).ToArray();
        }
        catch (Exception)
        {
            return [];
        }
    }

    private async Task<DnsAnswer<T>> QueryAsync<T>(
        string name,
        QueryType type,
        Func<IDnsQueryResponse, IEnumerable<T>> select,
        CancellationToken cancellationToken)
    {
        if (client is null)
        {
            return DnsAnswer<T>.Failed(Strings.NoDnsServer);
        }

        cancellationToken.ThrowIfCancellationRequested();
        IDnsQueryResponse response;
        try
        {
            // WaitAsync enforces the cancellation even if the library does not observe the token.
            response = await client.QueryAsync(name, type, QueryClass.IN, cancellationToken)
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Timeouts and network errors are thrown by DnsClient even with ThrowDnsErrors = false.
            return DnsAnswer<T>.Failed(ex.Message);
        }

        if (response.HasError)
        {
            return response.Header.ResponseCode == DnsHeaderResponseCode.NotExistentDomain
                ? DnsAnswer<T>.NonExistentDomain()
                : DnsAnswer<T>.Failed(response.ErrorMessage);
        }

        return DnsAnswer<T>.Found(select(response));
    }
}
