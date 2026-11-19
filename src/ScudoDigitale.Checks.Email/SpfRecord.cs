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
using System.Net.Sockets;

namespace ScudoDigitale.Checks.Email;

/// <summary>Qualifier of an SPF mechanism (RFC 7208 §4.6.2).</summary>
internal enum SpfQualifier
{
    /// <summary><c>+</c>, the default: the sender is authorized.</summary>
    Pass,

    /// <summary><c>-</c>: the sender is not authorized.</summary>
    Fail,

    /// <summary><c>~</c>: probably not authorized.</summary>
    SoftFail,

    /// <summary><c>?</c>: no statement.</summary>
    Neutral,
}

/// <summary>A mechanism of an SPF record, for example <c>include:_spf.example.com</c>.</summary>
/// <param name="Qualifier">The qualifier.</param>
/// <param name="Name">Lower-case name: all, include, a, mx, ptr, ip4, ip6 or exists.</param>
/// <param name="Domain">Domain specification, when the mechanism has one.</param>
/// <param name="Text">The term as written in the record.</param>
internal sealed record SpfMechanism(SpfQualifier Qualifier, string Name, string? Domain, string Text);

/// <summary>
/// A parsed SPF record (RFC 7208). Parsing never fails: invalid terms are collected in
/// <see cref="InvalidTerms"/>, because each of them is a finding.
/// </summary>
internal sealed class SpfRecord
{
    private SpfRecord(string text, IReadOnlyList<SpfMechanism> mechanisms, string? redirect, IReadOnlyList<string> invalidTerms)
    {
        Text = text;
        Mechanisms = mechanisms;
        Redirect = redirect;
        InvalidTerms = invalidTerms;
    }

    /// <summary>The record as published.</summary>
    public string Text { get; }

    /// <summary>The valid mechanisms, in order.</summary>
    public IReadOnlyList<SpfMechanism> Mechanisms { get; }

    /// <summary>Target of the <c>redirect=</c> modifier, if any.</summary>
    public string? Redirect { get; }

    /// <summary>Terms that are not valid SPF (unknown mechanisms, missing or wrong arguments).</summary>
    public IReadOnlyList<string> InvalidTerms { get; }

    /// <summary>
    /// Qualifier of the first <c>all</c> mechanism, or <see langword="null"/> when there is none.
    /// Evaluation stops at <c>all</c>, so later terms never apply.
    /// </summary>
    public SpfQualifier? All => Mechanisms.FirstOrDefault(m => m.Name == "all")?.Qualifier;

    /// <summary>
    /// Whether a TXT record is an SPF record: it starts with <c>v=spf1</c> followed by a space or by
    /// nothing (RFC 7208 §4.5), in any letter case.
    /// </summary>
    /// <param name="txt">The TXT record.</param>
    /// <returns><see langword="true"/> for an SPF record.</returns>
    public static bool IsSpf(string txt) =>
        txt.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase) && (txt.Length == 6 || txt[6] == ' ');

    /// <summary>Parses an SPF record.</summary>
    /// <param name="text">A record for which <see cref="IsSpf"/> is <see langword="true"/>.</param>
    /// <returns>The parsed record.</returns>
    public static SpfRecord Parse(string text)
    {
        var mechanisms = new List<SpfMechanism>();
        var invalid = new List<string>();
        string? redirect = null;

        foreach (var term in text.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1))
        {
            if (IsModifier(term, out var name, out var value))
            {
                if (name != "redirect")
                {
                    continue;
                }

                if (redirect is not null || value.Length == 0)
                {
                    invalid.Add(term);
                }
                else
                {
                    redirect = NormalizeDomain(value);
                }

                continue;
            }

            var mechanism = ParseMechanism(term);
            if (mechanism is null)
            {
                invalid.Add(term);
            }
            else
            {
                mechanisms.Add(mechanism);
            }
        }

        return new SpfRecord(text, mechanisms, redirect, invalid);
    }

    private static bool IsModifier(string term, out string name, out string value)
    {
        var equals = term.IndexOf('=', StringComparison.Ordinal);
        var colon = term.IndexOf(':', StringComparison.Ordinal);
        var isModifier = equals > 0
            && (colon < 0 || equals < colon)
            && char.IsAsciiLetter(term[0])
            && term[..equals].All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
        name = isModifier ? term[..equals].ToLowerInvariant() : string.Empty;
        value = isModifier ? term[(equals + 1)..] : string.Empty;
        return isModifier;
    }

    private static SpfMechanism? ParseMechanism(string term)
    {
        var qualifier = term[0] switch
        {
            '+' => SpfQualifier.Pass,
            '-' => SpfQualifier.Fail,
            '~' => SpfQualifier.SoftFail,
            '?' => SpfQualifier.Neutral,
            _ => (SpfQualifier?)null,
        };
        var body = qualifier is null ? term : term[1..];
        var end = body.IndexOfAny([':', '/']);
        var name = (end < 0 ? body : body[..end]).ToLowerInvariant();
        var rest = end < 0 ? string.Empty : body[end..];
        var valid = name switch
        {
            "all" => rest.Length == 0,
            "include" or "exists" => rest.Length > 1 && rest[0] == ':' && !rest.Contains('/', StringComparison.Ordinal),
            "a" or "mx" => IsOptionalDomainWithCidr(rest),
            "ptr" => rest.Length == 0 || (rest.Length > 1 && rest[0] == ':'),
            "ip4" => IsAddress(rest, AddressFamily.InterNetwork, 32),
            "ip6" => IsAddress(rest, AddressFamily.InterNetworkV6, 128),
            _ => false,
        };
        if (!valid)
        {
            return null;
        }

        string? domain = null;
        if (name is "include" or "exists" or "a" or "mx" or "ptr" && rest.StartsWith(':'))
        {
            var spec = rest[1..];
            var slash = spec.IndexOf('/', StringComparison.Ordinal);
            domain = NormalizeDomain(slash < 0 ? spec : spec[..slash]);
        }

        return new SpfMechanism(qualifier ?? SpfQualifier.Pass, name, domain, term);
    }

    private static bool IsOptionalDomainWithCidr(string rest)
    {
        if (rest.StartsWith(':'))
        {
            var slash = rest.IndexOf('/', StringComparison.Ordinal);
            var domain = slash < 0 ? rest[1..] : rest[1..slash];
            if (domain.Length == 0)
            {
                return false;
            }

            rest = slash < 0 ? string.Empty : rest[slash..];
        }

        // Dual CIDR: "/24", "//64" or "/24//64".
        if (rest.Length == 0)
        {
            return true;
        }

        var parts = rest.Split("//");
        var v4 = parts[0];
        var v6 = parts.Length > 1 ? parts[1] : null;
        return parts.Length <= 2
            && (v4.Length == 0 ? parts.Length == 2 : v4[0] == '/' && IsPrefix(v4[1..], 32))
            && (v6 is null || IsPrefix(v6, 128));
    }

    private static bool IsAddress(string rest, AddressFamily family, int maxPrefix)
    {
        if (rest.Length < 2 || rest[0] != ':')
        {
            return false;
        }

        var value = rest[1..];
        var slash = value.IndexOf('/', StringComparison.Ordinal);
        var address = slash < 0 ? value : value[..slash];
        var parsed = IPAddress.TryParse(address, out var ip) && ip.AddressFamily == family;
        if (family == AddressFamily.InterNetwork)
        {
            // IPAddress.TryParse accepts shortened IPv4 forms such as "10.1"; SPF does not.
            parsed &= address.Split('.').Length == 4;
        }

        return parsed && (slash < 0 || IsPrefix(value[(slash + 1)..], maxPrefix));
    }

    private static bool IsPrefix(string text, int max) =>
        text.Length is >= 1 and <= 3 && text.All(char.IsAsciiDigit) && int.Parse(text, System.Globalization.CultureInfo.InvariantCulture) <= max;

    private static string NormalizeDomain(string value) => value.TrimEnd('.').ToLowerInvariant();
}
