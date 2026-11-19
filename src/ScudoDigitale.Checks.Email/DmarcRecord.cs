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

using System.Globalization;

namespace ScudoDigitale.Checks.Email;

/// <summary>DMARC policy (RFC 7489 §6.3, tags <c>p</c> and <c>sp</c>).</summary>
internal enum DmarcPolicy
{
    /// <summary>Monitoring only: nothing is blocked.</summary>
    None,

    /// <summary>Failing messages go to spam.</summary>
    Quarantine,

    /// <summary>Failing messages are rejected.</summary>
    Reject,
}

/// <summary>A valid DMARC record.</summary>
/// <param name="Text">The record as published.</param>
/// <param name="Policy">The <c>p</c> tag.</param>
/// <param name="SubdomainPolicy">The <c>sp</c> tag, if present.</param>
/// <param name="Percent">The <c>pct</c> tag, 100 when absent.</param>
/// <param name="AggregateReports">The addresses of the <c>rua</c> tag.</param>
internal sealed record DmarcRecord(
    string Text,
    DmarcPolicy Policy,
    DmarcPolicy? SubdomainPolicy,
    int Percent,
    IReadOnlyList<string> AggregateReports)
{
    /// <summary>
    /// Whether a TXT record is meant as DMARC: it starts with <c>v=DMARC1</c>, in any letter case,
    /// followed by <c>;</c>, a space or nothing. Other TXT records at <c>_dmarc</c> are ignored.
    /// </summary>
    /// <param name="txt">The TXT record.</param>
    /// <returns><see langword="true"/> for a DMARC record.</returns>
    public static bool IsDmarc(string txt)
    {
        var text = txt.TrimStart();
        return text.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase)
            && (text.Length == 8 || text[8] is ';' or ' ' or '\t');
    }

    /// <summary>
    /// Parses a DMARC record. It is valid when the first tag is <c>v=DMARC1</c>, <c>p</c> is present
    /// and every known tag has a valid value; unknown tags are ignored (RFC 7489 §6.3).
    /// </summary>
    /// <param name="text">A record for which <see cref="IsDmarc"/> is <see langword="true"/>.</param>
    /// <returns>The record, or <see langword="null"/> when it is not valid.</returns>
    public static DmarcRecord? TryParse(string text)
    {
        var tags = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var part in text.Split(';'))
        {
            var tag = part.Trim();
            if (tag.Length == 0)
            {
                continue;
            }

            var equals = tag.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0)
            {
                return null;
            }

            tags.TryAdd(tag[..equals].Trim().ToLowerInvariant(), tag[(equals + 1)..].Trim());
        }

        if (!tags.TryGetValue("p", out var p) || ParsePolicy(p) is not { } policy)
        {
            return null;
        }

        DmarcPolicy? subdomainPolicy = null;
        if (tags.TryGetValue("sp", out var sp))
        {
            subdomainPolicy = ParsePolicy(sp);
            if (subdomainPolicy is null)
            {
                return null;
            }
        }

        var percent = 100;
        if (tags.TryGetValue("pct", out var pct)
            && !(int.TryParse(pct, NumberStyles.None, CultureInfo.InvariantCulture, out percent) && percent <= 100))
        {
            return null;
        }

        var reports = tags.TryGetValue("rua", out var rua)
            ? rua.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [];
        return new DmarcRecord(text, policy, subdomainPolicy, percent, reports);
    }

    private static DmarcPolicy? ParsePolicy(string value) => value.ToLowerInvariant() switch
    {
        "none" => DmarcPolicy.None,
        "quarantine" => DmarcPolicy.Quarantine,
        "reject" => DmarcPolicy.Reject,
        _ => null,
    };
}
