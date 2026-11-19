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

using System.Collections.Immutable;

namespace ScudoDigitale.Checks.Email;

/// <summary>Kind of problem found while following an SPF record and its includes.</summary>
internal enum SpfProblemKind
{
    /// <summary>A term is not valid SPF.</summary>
    SyntaxError,

    /// <summary>An include or redirect points to a domain without a single SPF record, or loops.</summary>
    BrokenReference,

    /// <summary>An include or redirect could not be checked because of a DNS error.</summary>
    Unverified,

    /// <summary>The deprecated <c>ptr</c> mechanism is used.</summary>
    Ptr,
}

/// <summary>A problem found in an SPF record or in one of the records it includes.</summary>
/// <param name="Kind">Kind of problem.</param>
/// <param name="Evidence">The term involved, prefixed by its domain when it is not the checked one.</param>
internal sealed record SpfProblem(SpfProblemKind Kind, string Evidence);

/// <summary>Result of following the SPF record of a domain.</summary>
/// <param name="DnsError">Set when the TXT records of the domain could not be read.</param>
/// <param name="Records">The SPF records published at the domain.</param>
/// <param name="Record">The parsed record, when there is exactly one.</param>
/// <param name="Lookups">DNS lookups counted (RFC 7208 §4.6.4); counting stops once the limit is exceeded.</param>
/// <param name="EffectiveAll">The <c>all</c> that ends evaluation, after following <c>redirect=</c>.</param>
/// <param name="Problems">Problems found in the record and in the records it includes.</param>
internal sealed record SpfAnalysis(
    string? DnsError,
    IReadOnlyList<string> Records,
    SpfRecord? Record,
    int Lookups,
    SpfQualifier? EffectiveAll,
    IReadOnlyList<SpfProblem> Problems);

/// <summary>Reads the SPF record of a domain and follows its includes and redirects.</summary>
internal static class SpfAnalyzer
{
    /// <summary>Maximum number of DNS lookups allowed by RFC 7208 §4.6.4.</summary>
    public const int LookupLimit = 10;

    /// <summary>Analyzes the SPF record of <paramref name="domain"/>.</summary>
    /// <param name="inspector">Shared DNS answers.</param>
    /// <param name="domain">Normalized domain.</param>
    /// <returns>The analysis.</returns>
    public static async Task<SpfAnalysis> AnalyzeAsync(EmailDomainInspector inspector, string domain)
    {
        var answer = await inspector.GetTxtAsync(domain, CancellationToken.None).ConfigureAwait(false);
        if (answer.Status == DnsStatus.Error)
        {
            return new SpfAnalysis(answer.Error, [], null, 0, null, []);
        }

        var records = answer.Records.Where(SpfRecord.IsSpf).ToArray();
        if (records.Length != 1)
        {
            return new SpfAnalysis(null, records, null, 0, null, []);
        }

        var record = SpfRecord.Parse(records[0]);
        var walker = new Walker(inspector, domain);
        var all = await walker.WalkAsync(domain, record, [domain]).ConfigureAwait(false);
        return new SpfAnalysis(null, records, record, walker.Lookups, all, walker.Problems);
    }

    /// <summary>Follows includes and redirects, counting lookups and collecting problems.</summary>
    private sealed class Walker(EmailDomainInspector inspector, string checkedDomain)
    {
        public int Lookups { get; private set; }

        public List<SpfProblem> Problems { get; } = [];

        /// <summary>Walks a record; returns the qualifier of the <c>all</c> that ends its evaluation.</summary>
        public async Task<SpfQualifier?> WalkAsync(string domain, SpfRecord record, ImmutableHashSet<string> path)
        {
            foreach (var term in record.InvalidTerms)
            {
                Problems.Add(new SpfProblem(SpfProblemKind.SyntaxError, Evidence(domain, term)));
            }

            foreach (var mechanism in record.Mechanisms)
            {
                if (mechanism.Name == "ptr")
                {
                    Problems.Add(new SpfProblem(SpfProblemKind.Ptr, Evidence(domain, mechanism.Text)));
                }

                if (mechanism.Name is not ("include" or "a" or "mx" or "ptr" or "exists"))
                {
                    continue;
                }

                Lookups++;
                if (mechanism.Name == "include")
                {
                    var included = await ResolveAsync(domain, mechanism.Text, mechanism.Domain!, path).ConfigureAwait(false);
                    if (included is not null)
                    {
                        // The all of an included record never ends the evaluation of the includer.
                        await WalkAsync(mechanism.Domain!, included, path.Add(mechanism.Domain!)).ConfigureAwait(false);
                    }
                }
            }

            if (record.All is { } all)
            {
                return all;
            }

            if (record.Redirect is not { } redirect)
            {
                return null;
            }

            Lookups++;
            var target = await ResolveAsync(domain, "redirect=" + redirect, redirect, path).ConfigureAwait(false);
            return target is null ? null : await WalkAsync(redirect, target, path.Add(redirect)).ConfigureAwait(false);
        }

        private async Task<SpfRecord?> ResolveAsync(string domain, string term, string target, ImmutableHashSet<string> path)
        {
            // A macro (%{d}, %{i}...) can only be expanded for a real message; beyond the limit the
            // count is already enough for the finding, so nothing more is queried.
            if (target.Contains('%', StringComparison.Ordinal) || Lookups > LookupLimit)
            {
                return null;
            }

            if (path.Contains(target) || !DomainName.TryNormalize(target, out var name))
            {
                Problems.Add(new SpfProblem(SpfProblemKind.BrokenReference, Evidence(domain, term)));
                return null;
            }

            var answer = await inspector.GetTxtAsync(name, CancellationToken.None).ConfigureAwait(false);
            if (answer.Status == DnsStatus.Error)
            {
                Problems.Add(new SpfProblem(SpfProblemKind.Unverified, Evidence(domain, term)));
                return null;
            }

            var records = answer.Records.Where(SpfRecord.IsSpf).ToArray();
            if (records.Length != 1)
            {
                Problems.Add(new SpfProblem(SpfProblemKind.BrokenReference, Evidence(domain, term)));
                return null;
            }

            return SpfRecord.Parse(records[0]);
        }

        private string Evidence(string domain, string term) => domain == checkedDomain ? term : $"{domain}: {term}";
    }
}
