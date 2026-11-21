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

/// <summary>Which DNS servers answer the queries of the checks, and how long they are waited for.</summary>
public sealed record DnsOptions
{
    /// <summary>Upper limit of <see cref="Timeout"/>: 30 seconds.</summary>
    public static readonly TimeSpan MaxTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Upper limit of <see cref="Retries"/>.</summary>
    public const int MaxRetries = 5;

    private readonly DnsSource source = DnsSource.Public;
    private readonly TimeSpan timeout = TimeSpan.FromSeconds(2);
    private readonly int retries = 1;

    /// <summary>
    /// Which DNS servers answer. Default <see cref="DnsSource.Public"/>: Cloudflare and then Google
    /// over DNS over HTTPS, then the DNS of this computer (ADR-006).
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not defined.</exception>
    public DnsSource Source
    {
        get => source;
        init => source = Enum.IsDefined(value)
            ? value
            : throw new ArgumentOutOfRangeException(nameof(Source), value, "Unknown DNS source.");
    }

    /// <summary>
    /// Timeout of a single query on the DNS of this computer; tripled for DNS over HTTPS, to leave
    /// room for the TLS handshake. Default 2 seconds, at most <see cref="MaxTimeout"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is zero, negative or above <see cref="MaxTimeout"/>.</exception>
    public TimeSpan Timeout
    {
        get => timeout;
        init => timeout = value > TimeSpan.Zero && value <= MaxTimeout
            ? value
            : throw new ArgumentOutOfRangeException(nameof(Timeout), value, "Must be positive and at most 30 seconds.");
    }

    /// <summary>
    /// How many times a query is repeated on each DNS server of this computer after a timeout.
    /// Default 1, at most <see cref="MaxRetries"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative or above <see cref="MaxRetries"/>.</exception>
    public int Retries
    {
        get => retries;
        init => retries = value is >= 0 and <= MaxRetries
            ? value
            : throw new ArgumentOutOfRangeException(nameof(Retries), value, "Must be between 0 and 5.");
    }
}
