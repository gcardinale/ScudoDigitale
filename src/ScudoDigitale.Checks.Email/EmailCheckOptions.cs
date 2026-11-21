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

namespace ScudoDigitale.Checks.Email;

/// <summary>
/// Settings of the email checks. The defaults are cautious: short DNS timeouts and few queries at
/// the same time.
/// </summary>
public sealed record EmailCheckOptions
{
    /// <summary>Upper limit of <see cref="DnsTimeout"/>: 30 seconds.</summary>
    public static readonly TimeSpan MaxDnsTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Upper limit of <see cref="DnsRetries"/>.</summary>
    public const int MaxDnsRetries = 5;

    /// <summary>Upper limit of <see cref="MaxConcurrentDnsQueries"/>.</summary>
    public const int MaxConcurrentDnsQueriesLimit = 32;

    private readonly TimeSpan dnsTimeout = TimeSpan.FromSeconds(2);
    private readonly int dnsRetries = 1;
    private readonly DnsSource dnsSource = DnsSource.Public;
    private readonly int maxConcurrentDnsQueries = 4;
    private readonly IReadOnlyList<string> dkimSelectors = [];

    /// <summary>
    /// DKIM selectors tried on every domain. Selectors cannot be listed from the DNS, so a missing
    /// DKIM key is always reported as "to be verified" and the user can add their own selectors
    /// with <see cref="DkimSelectors"/>.
    /// </summary>
    public static IReadOnlyList<string> CommonDkimSelectors { get; } =
    [
        "default", "dkim", "mail", "email", "smtp", "selector1", "selector2", "google",
        "k1", "k2", "k3", "s1", "s2", "sig1", "key1", "key2", "mx", "dk",
        "fm1", "fm2", "fm3", "protonmail", "protonmail2", "protonmail3", "zoho", "mandrill", "everlytickey1",
        "ovhmo-selector-1", "ovhmo-selector-2",
    ];

    /// <summary>
    /// Extra DKIM selectors supplied by the user, tried together with <see cref="CommonDkimSelectors"/>.
    /// Surrounding spaces are removed and names are lower-cased; default empty.
    /// </summary>
    /// <exception cref="ArgumentNullException">The list is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">An item is not a valid selector (one or more DNS labels).</exception>
    public IReadOnlyList<string> DkimSelectors
    {
        get => dkimSelectors;
        init
        {
            ArgumentNullException.ThrowIfNull(value, nameof(DkimSelectors));
            dkimSelectors = value.Select(NormalizeSelector).Distinct(StringComparer.Ordinal).ToArray();
        }
    }

    /// <summary>
    /// Which DNS servers answer the queries. Default <see cref="Core.Dns.DnsSource.Public"/>: Cloudflare
    /// and then Google over DNS over HTTPS, then the DNS of this computer.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not defined.</exception>
    public DnsSource DnsSource
    {
        get => dnsSource;
        init => dnsSource = Enum.IsDefined(value)
            ? value
            : throw new ArgumentOutOfRangeException(nameof(DnsSource), value, "Unknown DNS source.");
    }

    /// <summary>Timeout of a single DNS query. Default 2 seconds, at most <see cref="MaxDnsTimeout"/>.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is zero, negative or above <see cref="MaxDnsTimeout"/>.</exception>
    public TimeSpan DnsTimeout
    {
        get => dnsTimeout;
        init => dnsTimeout = value > TimeSpan.Zero && value <= MaxDnsTimeout
            ? value
            : throw new ArgumentOutOfRangeException(nameof(DnsTimeout), value, "Must be positive and at most 30 seconds.");
    }

    /// <summary>
    /// How many times a DNS query is repeated on each server after a timeout. Default 1: home routers
    /// often drop DNS packets, and a short timeout with one retry is faster and more reliable than a
    /// long timeout. At most <see cref="MaxDnsRetries"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is negative or above <see cref="MaxDnsRetries"/>.</exception>
    public int DnsRetries
    {
        get => dnsRetries;
        init => dnsRetries = value is >= 0 and <= MaxDnsRetries
            ? value
            : throw new ArgumentOutOfRangeException(nameof(DnsRetries), value, "Must be between 0 and 5.");
    }

    /// <summary>
    /// How many DNS queries a single check may have in flight at the same time (DKIM selectors, MX
    /// hosts). Default 4, because the DNS forwarders of home routers drop queries that arrive in
    /// bursts. At most <see cref="MaxConcurrentDnsQueriesLimit"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is less than 1 or above <see cref="MaxConcurrentDnsQueriesLimit"/>.</exception>
    public int MaxConcurrentDnsQueries
    {
        get => maxConcurrentDnsQueries;
        init => maxConcurrentDnsQueries = value is >= 1 and <= MaxConcurrentDnsQueriesLimit
            ? value
            : throw new ArgumentOutOfRangeException(nameof(MaxConcurrentDnsQueries), value, "Must be between 1 and 32.");
    }

    /// <summary>The DNS settings, in the form the shared resolver takes.</summary>
    internal DnsOptions Dns => new() { Source = DnsSource, Timeout = DnsTimeout, Retries = DnsRetries };

    /// <summary>
    /// Time allowed to the whole DKIM analysis of a domain (25 seconds), well below the 60-second
    /// default timeout of a check. Internal: only tests change it.
    /// </summary>
    internal TimeSpan DkimTimeBudget { get; init; } = TimeSpan.FromSeconds(25);

    private static string NormalizeSelector(string? selector)
    {
        var normalized = selector?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(normalized) || !normalized.Split('.').All(DomainName.IsLabel))
        {
            throw new ArgumentException($"'{selector}' is not a valid DKIM selector.", nameof(DkimSelectors));
        }

        return normalized;
    }
}
