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
using System.Security.Cryptography.X509Certificates;
using ScudoDigitale.Core.Dns;

namespace ScudoDigitale.Checks.Web;

/// <summary>
/// Settings of the website checks. The defaults are cautious: a handful of requests per site, each
/// with a short timeout.
/// </summary>
public sealed record WebCheckOptions
{
    /// <summary>Upper limit of <see cref="RequestTimeout"/>: 30 seconds.</summary>
    public static readonly TimeSpan MaxRequestTimeout = TimeSpan.FromSeconds(30);

    private readonly TimeSpan requestTimeout = TimeSpan.FromSeconds(10);
    private readonly DnsSource dnsSource = DnsSource.Public;

    /// <summary>
    /// Which DNS servers give the address of a site. Default <see cref="Core.Dns.DnsSource.Public"/>:
    /// Cloudflare and then Google over DNS over HTTPS, then the DNS of this computer (ADR-006).
    /// With <see cref="Core.Dns.DnsSource.System"/> the name is left to the operating system, as for
    /// any connection. Through a proxy, the proxy resolves the name.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not defined.</exception>
    public DnsSource DnsSource
    {
        get => dnsSource;
        init => dnsSource = Enum.IsDefined(value)
            ? value
            : throw new ArgumentOutOfRangeException(nameof(DnsSource), value, "Unknown DNS source.");
    }

    /// <summary>Timeout of a single request, connection included. Default 10 seconds, at most <see cref="MaxRequestTimeout"/>.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is zero, negative or above <see cref="MaxRequestTimeout"/>.</exception>
    public TimeSpan RequestTimeout
    {
        get => requestTimeout;
        init => requestTimeout = value > TimeSpan.Zero && value <= MaxRequestTimeout
            ? value
            : throw new ArgumentOutOfRangeException(nameof(RequestTimeout), value, "Must be positive and at most 30 seconds.");
    }

    /// <summary>
    /// Time allowed to the whole visit of a site (40 seconds), below the 60-second default timeout of
    /// a check. Internal: only tests change it.
    /// </summary>
    internal TimeSpan VisitBudget { get; init; } = TimeSpan.FromSeconds(40);

    /// <summary>
    /// Where a connection really goes. Internal: tests send it to a local server, or keep the name
    /// and change only the port to exercise the resolver.
    /// </summary>
    internal Func<DnsEndPoint, EndPoint> Route { get; init; } = static endpoint => endpoint;

    /// <summary>The resolver used instead of the one chosen by <see cref="DnsSource"/>. Internal: tests use an in-memory one.</summary>
    internal IDnsResolver? Resolver { get; init; }

    /// <summary>
    /// Authorities trusted instead of those of the operating system. Internal: tests use their own
    /// authority, so no certificate is ever installed on the computer.
    /// </summary>
    internal X509Certificate2Collection? TrustedRoots { get; init; }

    /// <summary>The current time. Internal: tests fix it to judge expiry dates.</summary>
    internal Func<DateTimeOffset> Clock { get; init; } = static () => DateTimeOffset.UtcNow;
}
