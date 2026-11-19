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
using System.Globalization;
using System.Net;

namespace ScudoDigitale.Checks.Email;

/// <summary>Validation and normalization of DNS names.</summary>
internal static class DomainName
{
    /// <summary>Maximum length of a domain name in text form, without the trailing dot.</summary>
    public const int MaxLength = 253;

    private const int MaxLabelLength = 63;

    private static readonly IdnMapping Idn = new();

    /// <summary>
    /// Turns <paramref name="value"/> into a lower-case ASCII domain name (internationalized names
    /// become punycode), if it is a valid domain with at least two labels. URLs, email addresses,
    /// IP addresses and names with spaces are rejected.
    /// </summary>
    /// <param name="value">The candidate name.</param>
    /// <param name="domain">The normalized name, when valid.</param>
    /// <returns><see langword="true"/> if the name is valid.</returns>
    public static bool TryNormalize(string? value, [NotNullWhen(true)] out string? domain)
    {
        domain = null;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var text = value.Trim();
        if (text.EndsWith('.'))
        {
            text = text[..^1];
        }

        if (IPAddress.TryParse(text, out _))
        {
            return false;
        }

        string ascii;
        try
        {
            ascii = Idn.GetAscii(text).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return false;
        }

        // IdnMapping already rejects most over-long names, but it is NLS on Windows and ICU elsewhere:
        // the limits are enforced here too, so they do not depend on the platform.
        var labels = ascii.Split('.');
        if (ascii.Length > MaxLength || labels.Length < 2 || !labels.All(IsLabel))
        {
            return false;
        }

        domain = ascii;
        return true;
    }

    /// <summary>
    /// Whether <paramref name="label"/> is a valid lower-case DNS label: 1-63 letters, digits,
    /// hyphens or underscores, not starting or ending with a hyphen.
    /// </summary>
    /// <param name="label">The candidate label.</param>
    /// <returns><see langword="true"/> if the label is valid.</returns>
    public static bool IsLabel(string label) =>
        label.Length is >= 1 and <= MaxLabelLength
        && label[0] != '-'
        && label[^1] != '-'
        && label.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_');

    /// <summary>
    /// The parent of <paramref name="domain"/>, or <see langword="null"/> when the parent would have
    /// fewer than two labels (so <c>example.com</c> has no parent here).
    /// </summary>
    /// <param name="domain">A normalized domain name.</param>
    /// <returns>The parent domain, or <see langword="null"/>.</returns>
    public static string? Parent(string domain)
    {
        var dot = domain.IndexOf('.', StringComparison.Ordinal);
        var parent = domain[(dot + 1)..];
        return parent.Contains('.', StringComparison.Ordinal) ? parent : null;
    }
}
