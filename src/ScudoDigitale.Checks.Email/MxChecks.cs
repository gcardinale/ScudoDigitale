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
using ScudoDigitale.Checks.Email.Resources;
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Email;

/// <summary>MX checks (RFC 5321, RFC 7505): mail servers published, and their names resolve.</summary>
internal static class MxChecks
{
    /// <summary>Id of the check on the presence of MX records.</summary>
    public const string RecordsId = "MAIL-MX-001";

    /// <summary>Id of the check on the names of the MX servers.</summary>
    public const string HostsId = "MAIL-MX-002";

    /// <summary>At most this many MX hosts are resolved, so a huge MX set cannot flood the resolver.</summary>
    public const int MaxHosts = 10;

    /// <summary>Creates the MX checks.</summary>
    /// <param name="inspector">Shared DNS analyses of the run.</param>
    /// <returns>The checks.</returns>
    public static IEnumerable<ICheck> Create(EmailDomainInspector inspector)
    {
        yield return new EmailCheck(RecordsId, () => Strings.MxRecordsCheck, inspector, RecordsAsync);
        yield return new EmailCheck(HostsId, () => Strings.MxHostsCheck, inspector, HostsAsync);
    }

    /// <summary>Whether the MX set is the null MX of RFC 7505: a single record pointing to the root.</summary>
    /// <param name="exchanges">The MX records.</param>
    /// <returns><see langword="true"/> for a null MX.</returns>
    internal static bool IsNullMx(IReadOnlyList<MailExchange> exchanges) => exchanges is [{ Host: "" }];

    private static async Task<CheckResult> RecordsAsync(EmailDomainInspector inspector, string domain, CancellationToken cancellationToken)
    {
        var mx = await inspector.GetMxAsync(domain, cancellationToken).ConfigureAwait(false);
        return mx.Status switch
        {
            DnsStatus.Error => EmailFinding.DnsFailed(domain, mx.Error),
            DnsStatus.Ok => EmailFinding.Executed(),
            _ => EmailFinding.Executed(EmailFinding.Create(
                RecordsId, Strings.MxMissingTitle, Severity.Low, Confidence.Certain, domain,
                EmailFinding.Format(Strings.EvidenceNoMx, domain),
                Strings.MxMissingRisk, Strings.MxMissingFix, "RFC 5321 §5.1", "RFC 7505")),
        };
    }

    private static async Task<CheckResult> HostsAsync(EmailDomainInspector inspector, string domain, CancellationToken cancellationToken)
    {
        var mx = await inspector.GetMxAsync(domain, cancellationToken).ConfigureAwait(false);
        if (mx.Status == DnsStatus.Error)
        {
            return EmailFinding.DnsFailed(domain, mx.Error);
        }

        if (mx.Records.Count == 0)
        {
            return new CheckResult.Skipped(Strings.SkippedNoMx);
        }

        if (IsNullMx(mx.Records))
        {
            return new CheckResult.Skipped(Strings.SkippedNullMx);
        }

        var exchanges = mx.Records
            .OrderBy(e => e.Preference)
            .DistinctBy(e => e.Host, StringComparer.OrdinalIgnoreCase)
            .Take(MaxHosts)
            .ToArray();
        using var gate = new SemaphoreSlim(inspector.Options.MaxConcurrentDnsQueries);
        var outcomes = await Task.WhenAll(exchanges.Select(e => ResolveAsync(inspector, e, gate, cancellationToken))).ConfigureAwait(false);

        // When no server has an address, mail to the domain cannot be delivered at all.
        var anyResolved = outcomes.Any(o => o.Status == DnsStatus.Ok);
        var findings = new List<Finding>();
        foreach (var (exchange, outcome) in exchanges.Zip(outcomes))
        {
            var host = exchange.Host.Length == 0 ? "." : exchange.Host;
            var evidence = $"{exchange.Preference} {host}";
            if (outcome.IsAddressLiteral)
            {
                findings.Add(EmailFinding.Create(
                    HostsId, EmailFinding.Format(Strings.MxAddressLiteralTitle, host), Severity.Medium, Confidence.Certain, domain,
                    evidence, Strings.MxAddressLiteralRisk, Strings.MxAddressLiteralFix, "RFC 5321 §5.1"));
            }
            else if (outcome.Status == DnsStatus.Error)
            {
                findings.Add(EmailFinding.Create(
                    HostsId, EmailFinding.Format(Strings.MxUnverifiedTitle, host), Severity.Low, Confidence.ToBeVerified, domain,
                    evidence + " — " + outcome.Error, Strings.MxUnresolvableRisk, Strings.MxUnverifiedFix, "RFC 5321 §5.1"));
            }
            else if (outcome.Status != DnsStatus.Ok)
            {
                findings.Add(EmailFinding.Create(
                    HostsId, EmailFinding.Format(Strings.MxUnresolvableTitle, host), anyResolved ? Severity.Medium : Severity.High,
                    Confidence.Certain, domain, evidence, Strings.MxUnresolvableRisk, Strings.MxUnresolvableFix, "RFC 5321 §5.1"));
            }
        }

        return EmailFinding.Executed(findings);
    }

    private static async Task<HostOutcome> ResolveAsync(
        EmailDomainInspector inspector,
        MailExchange exchange,
        SemaphoreSlim gate,
        CancellationToken cancellationToken)
    {
        if (IPAddress.TryParse(exchange.Host, out _))
        {
            return new HostOutcome(DnsStatus.NoRecords, null, IsAddressLiteral: true);
        }

        if (exchange.Host.Length == 0)
        {
            // A "0 ." mixed with real servers: the root has no address.
            return new HostOutcome(DnsStatus.NoRecords, null, IsAddressLiteral: false);
        }

        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // WaitAsync: the deadline holds even if the resolver ignores the token.
            var answer = await inspector.Resolver.QueryAddressesAsync(exchange.Host, cancellationToken)
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);
            return new HostOutcome(answer.Status, answer.Error, IsAddressLiteral: false);
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>What resolving one MX host gave.</summary>
    private sealed record HostOutcome(DnsStatus Status, string? Error, bool IsAddressLiteral);
}
