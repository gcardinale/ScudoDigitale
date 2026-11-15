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

namespace ScudoDigitale.Core;

/// <summary>
/// Something being checked: a domain, an email address, a website, a network or the local machine.
/// </summary>
public sealed record Target
{
    /// <summary>
    /// Creates a target.
    /// </summary>
    /// <param name="kind">Kind of target.</param>
    /// <param name="value">
    /// Identifier of the target (domain, address, URL, range). Surrounding spaces are removed; a domain
    /// is lower-cased and loses its trailing dot, and so does the domain part of an email address, so
    /// <c>Example.COM.</c> and <c>example.com</c> are the same target.
    /// </param>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="kind"/> is not a defined value.</exception>
    /// <exception cref="ArgumentException"><paramref name="value"/> is empty or blank.</exception>
    public Target(TargetKind kind, string value)
    {
        if (!Enum.IsDefined(kind))
        {
            throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown target kind.");
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        Kind = kind;
        Value = Normalize(kind, value.Trim());
    }

    /// <summary>Kind of target.</summary>
    public TargetKind Kind { get; }

    /// <summary>Identifier of the target, without surrounding spaces.</summary>
    public string Value { get; }

    /// <inheritdoc />
    public override string ToString() => $"{Kind}:{Value}";

    private static string Normalize(TargetKind kind, string value)
    {
        switch (kind)
        {
            case TargetKind.Domain:
                return NormalizeDomain(value);
            case TargetKind.EmailAddress:
                var at = value.LastIndexOf('@');
                return at < 0 ? value : value[..(at + 1)] + NormalizeDomain(value[(at + 1)..]);
            default:
                return value;
        }
    }

    private static string NormalizeDomain(string domain)
    {
        var trimmed = domain.TrimEnd('.');
        return (trimmed.Length == 0 ? domain : trimmed).ToLowerInvariant();
    }
}
