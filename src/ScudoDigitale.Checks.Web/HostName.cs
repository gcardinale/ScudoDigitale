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

namespace ScudoDigitale.Checks.Web;

/// <summary>Validation and normalization of the name of a website, and the boundary of a site.</summary>
internal static class HostName
{
    /// <summary>Maximum length of a host name in text form, without the trailing dot.</summary>
    public const int MaxLength = 253;

    private const int MaxLabelLength = 63;

    private static readonly IdnMapping Idn = new();

    /// <summary>
    /// Turns <paramref name="value"/> into a lower-case ASCII host name (internationalized names
    /// become punycode). A domain name with at least two labels is accepted, and so is an
    /// <c>http</c> or <c>https</c> URL on the standard port: only its host is used, the path is never
    /// visited. IP addresses, other ports and names with spaces are rejected.
    /// </summary>
    /// <param name="value">The candidate name or URL.</param>
    /// <param name="host">The normalized host name, when valid.</param>
    /// <returns><see langword="true"/> if the value names a website.</returns>
    public static bool TryNormalize(string? value, [NotNullWhen(true)] out string? host)
    {
        host = null;
        var text = (value ?? string.Empty).Trim();
        if (text.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(text, UriKind.Absolute, out var uri)
                || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps)
                || !uri.IsDefaultPort)
            {
                return false;
            }

            text = uri.Host;
        }

        if (text.EndsWith('.'))
        {
            text = text[..^1];
        }

        if (text.Length == 0 || IPAddress.TryParse(text, out _))
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

        // IdnMapping is NLS on Windows and ICU elsewhere: the limits are enforced here too, so they
        // do not depend on the platform.
        var labels = ascii.Split('.');
        if (ascii.Length > MaxLength || labels.Length < 2 || !labels.All(IsLabel))
        {
            return false;
        }

        host = ascii;
        return true;
    }

    /// <summary>
    /// Whether <paramref name="host"/> belongs to the declared site: the same name, the same name
    /// with or without <c>www.</c>, or a subdomain of it. Redirects are followed only inside this
    /// boundary, so no connection goes to a domain that was not declared.
    /// </summary>
    /// <param name="site">The declared host name, normalized.</param>
    /// <param name="host">The host a redirect points to.</param>
    /// <returns><see langword="true"/> if the host is part of the site.</returns>
    public static bool IsInSite(string site, string host)
    {
        var other = host.TrimEnd('.').ToLowerInvariant();
        return other == site
            || other.EndsWith("." + site, StringComparison.Ordinal)
            || site == "www." + other;
    }

    private static bool IsLabel(string label) =>
        label.Length is >= 1 and <= MaxLabelLength
        && label[0] != '-'
        && label[^1] != '-'
        && label.All(c => c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-');
}
