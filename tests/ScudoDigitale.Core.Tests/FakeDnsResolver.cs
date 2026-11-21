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

using System.Collections.Concurrent;
using System.Net;
using ScudoDigitale.Core.Dns;

namespace ScudoDigitale.Core.Tests;

/// <summary>
/// In-memory DNS. Unknown names have no records. A name can be made to throw, or to hang forever
/// while ignoring the cancellation token (as a rude real resolver would).
/// </summary>
internal sealed class FakeDnsResolver : IDnsResolver
{
    public Dictionary<string, DnsAnswer<string>> Txt { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, DnsAnswer<MailExchange>> Mx { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, DnsAnswer<IPAddress>> Addresses { get; } = new(StringComparer.Ordinal);

    public HashSet<string> Throwing { get; } = new(StringComparer.Ordinal);

    public HashSet<string> Hanging { get; } = new(StringComparer.Ordinal);

    public ConcurrentQueue<string> Queries { get; } = new();

    public FakeDnsResolver WithTxt(string name, params string[] records)
    {
        Txt[name] = DnsAnswer<string>.Found(records);
        return this;
    }

    public FakeDnsResolver WithMx(string name, params (int Preference, string Host)[] records)
    {
        Mx[name] = DnsAnswer<MailExchange>.Found(records.Select(r => new MailExchange(r.Preference, r.Host)));
        return this;
    }

    public FakeDnsResolver WithAddress(string name, string address)
    {
        Addresses[name] = DnsAnswer<IPAddress>.Found([IPAddress.Parse(address)]);
        return this;
    }

    public Task<DnsAnswer<string>> QueryTxtAsync(string name, CancellationToken cancellationToken) => Answer("TXT", name, Txt);

    public Task<DnsAnswer<MailExchange>> QueryMxAsync(string name, CancellationToken cancellationToken) => Answer("MX", name, Mx);

    public Task<DnsAnswer<IPAddress>> QueryAddressesAsync(string name, CancellationToken cancellationToken) => Answer("ADDR", name, Addresses);

    public int Count(string query) => Queries.Count(q => q == query);

    private Task<DnsAnswer<T>> Answer<T>(string type, string name, Dictionary<string, DnsAnswer<T>> map)
    {
        Queries.Enqueue($"{type} {name}");
        if (Throwing.Contains(name))
        {
            throw new InvalidOperationException("resolver exploded on " + name);
        }

        if (Hanging.Contains(name))
        {
            return new TaskCompletionSource<DnsAnswer<T>>().Task;
        }

        return Task.FromResult(map.TryGetValue(name, out var answer) ? answer : DnsAnswer<T>.NoRecords());
    }
}
