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

/// <summary>How a DNS query ended.</summary>
public enum DnsStatus
{
    /// <summary>The name exists and has records of the requested type.</summary>
    Ok,

    /// <summary>The name exists but has no records of the requested type.</summary>
    NoRecords,

    /// <summary>The name does not exist (NXDOMAIN).</summary>
    NonExistentDomain,

    /// <summary>The query failed (timeout, server failure, refused, no DNS server).</summary>
    Error,
}

/// <summary>
/// Answer to a DNS query: the records found, or why there are none. Create instances with the
/// static methods, so the status and the records always agree.
/// </summary>
/// <typeparam name="T">Type of the records.</typeparam>
public sealed record DnsAnswer<T>
{
    private DnsAnswer(DnsStatus status, IReadOnlyList<T> records, string? error)
    {
        Status = status;
        Records = records;
        Error = error;
    }

    /// <summary>How the query ended.</summary>
    public DnsStatus Status { get; }

    /// <summary>The records found; empty unless <see cref="Status"/> is <see cref="DnsStatus.Ok"/>.</summary>
    public IReadOnlyList<T> Records { get; }

    /// <summary>Description of the error when <see cref="Status"/> is <see cref="DnsStatus.Error"/>.</summary>
    public string? Error { get; }

    /// <summary>Records found; an empty sequence gives <see cref="DnsStatus.NoRecords"/>.</summary>
    /// <param name="records">The records.</param>
    /// <returns>The answer.</returns>
    public static DnsAnswer<T> Found(IEnumerable<T> records)
    {
        var list = records.ToArray();
        return list.Length == 0 ? NoRecords() : new DnsAnswer<T>(DnsStatus.Ok, list, null);
    }

    /// <summary>The name exists but has no records of the requested type.</summary>
    /// <returns>The answer.</returns>
    public static DnsAnswer<T> NoRecords() => new(DnsStatus.NoRecords, [], null);

    /// <summary>The name does not exist.</summary>
    /// <returns>The answer.</returns>
    public static DnsAnswer<T> NonExistentDomain() => new(DnsStatus.NonExistentDomain, [], null);

    /// <summary>The query failed.</summary>
    /// <param name="error">What went wrong; a blank text is replaced by a generic one.</param>
    /// <returns>The answer.</returns>
    public static DnsAnswer<T> Failed(string? error) =>
        new(DnsStatus.Error, [], string.IsNullOrWhiteSpace(error) ? "unknown DNS error" : error);
}
