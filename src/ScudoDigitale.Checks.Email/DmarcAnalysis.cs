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

/// <summary>Result of looking up the DMARC record of a domain.</summary>
/// <param name="DnsError">Set when a lookup failed.</param>
/// <param name="Source">The name queried last: where the record was found, or <c>_dmarc.&lt;domain&gt;</c>.</param>
/// <param name="Inherited">Whether the record belongs to a parent domain.</param>
/// <param name="Records">The DMARC records published at <paramref name="Source"/>.</param>
/// <param name="Record">The parsed record, when there is exactly one and it is valid.</param>
internal sealed record DmarcAnalysis(
    string? DnsError,
    string Source,
    bool Inherited,
    IReadOnlyList<string> Records,
    DmarcRecord? Record);

/// <summary>Looks up the DMARC record of a domain.</summary>
internal static class DmarcAnalyzer
{
    /// <summary>
    /// Looks for <c>_dmarc.&lt;domain&gt;</c>; when there is none, walks up the parent domains (as
    /// the DMARC tree walk does) down to two labels. Without the public suffix list the domain that
    /// owns the policy is a guess, so an inherited record is reported as "probable".
    /// </summary>
    /// <param name="inspector">Shared DNS answers.</param>
    /// <param name="domain">Normalized domain.</param>
    /// <returns>The analysis.</returns>
    public static async Task<DmarcAnalysis> AnalyzeAsync(EmailDomainInspector inspector, string domain)
    {
        for (var name = domain; name is not null; name = DomainName.Parent(name))
        {
            var source = "_dmarc." + name;
            var answer = await inspector.GetTxtAsync(source, CancellationToken.None).ConfigureAwait(false);
            if (answer.Status == DnsStatus.Error)
            {
                return new DmarcAnalysis(answer.Error, source, false, [], null);
            }

            var records = answer.Records.Where(DmarcRecord.IsDmarc).ToArray();
            if (records.Length > 0)
            {
                var record = records.Length == 1 ? DmarcRecord.TryParse(records[0]) : null;
                return new DmarcAnalysis(null, source, name != domain, records, record);
            }
        }

        return new DmarcAnalysis(null, "_dmarc." + domain, false, [], null);
    }
}
