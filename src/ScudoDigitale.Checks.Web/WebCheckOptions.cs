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

    /// <summary>Where a connection really goes. Internal: tests send it to a local server.</summary>
    internal Func<DnsEndPoint, EndPoint> Route { get; init; } = static endpoint => endpoint;

    /// <summary>
    /// Authorities trusted instead of those of the operating system. Internal: tests use their own
    /// authority, so no certificate is ever installed on the computer.
    /// </summary>
    internal X509Certificate2Collection? TrustedRoots { get; init; }

    /// <summary>The current time. Internal: tests fix it to judge expiry dates.</summary>
    internal Func<DateTimeOffset> Clock { get; init; } = static () => DateTimeOffset.UtcNow;
}
