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

using ScudoDigitale.Checks.Email.Resources;
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Email;

/// <summary>DMARC checks (RFC 7489): policy, aggregate reports, subdomain policy.</summary>
internal static class DmarcChecks
{
    /// <summary>Id of the check on the DMARC policy.</summary>
    public const string PolicyId = "MAIL-DMARC-001";

    /// <summary>Id of the check on the aggregate reports (<c>rua</c>).</summary>
    public const string ReportsId = "MAIL-DMARC-002";

    /// <summary>Id of the check on the subdomain policy (<c>sp</c>).</summary>
    public const string SubdomainId = "MAIL-DMARC-003";

    private const string Rfc = "RFC 7489";

    /// <summary>Creates the DMARC checks.</summary>
    /// <param name="inspector">Shared DNS analyses of the run.</param>
    /// <returns>The checks.</returns>
    public static IEnumerable<ICheck> Create(EmailDomainInspector inspector)
    {
        yield return new EmailCheck(PolicyId, () => Strings.DmarcPolicyCheck, inspector, PolicyAsync);
        yield return new EmailCheck(ReportsId, () => Strings.DmarcReportsCheck, inspector, ReportsAsync);
        yield return new EmailCheck(SubdomainId, () => Strings.DmarcSubdomainCheck, inspector, SubdomainAsync);
    }

    private static async Task<CheckResult> PolicyAsync(EmailDomainInspector inspector, string domain, CancellationToken cancellationToken)
    {
        var dmarc = await inspector.GetDmarcAsync(domain, cancellationToken).ConfigureAwait(false);
        if (dmarc.DnsError is not null)
        {
            return EmailFinding.DnsFailed(dmarc.Source, dmarc.DnsError);
        }

        if (dmarc.Records.Count == 0)
        {
            return EmailFinding.Executed(EmailFinding.Create(
                PolicyId, Strings.DmarcMissingTitle, Severity.High, Confidence.Certain, domain,
                EmailFinding.Format(Strings.EvidenceNoRecord, dmarc.Source),
                Strings.DmarcMissingRisk, Strings.DmarcMissingFix, Rfc + " §6.1"));
        }

        if (dmarc.Record is not { } record)
        {
            return EmailFinding.Executed(EmailFinding.Create(
                PolicyId, Strings.DmarcInvalidTitle, Severity.High, Confidence.Certain, domain,
                Evidence(dmarc, string.Join(" | ", dmarc.Records)),
                Strings.DmarcInvalidRisk, Strings.DmarcInvalidFix, Rfc + " §6.3", Rfc + " §6.6.3"));
        }

        // A subdomain without its own record follows the sp of the parent, or its p.
        var policy = dmarc.Inherited ? record.SubdomainPolicy ?? record.Policy : record.Policy;
        var confidence = dmarc.Inherited ? Confidence.Probable : Confidence.Certain;
        if (policy == DmarcPolicy.None)
        {
            return EmailFinding.Executed(EmailFinding.Create(
                PolicyId, Strings.DmarcNoneTitle, Severity.Medium, confidence, domain, Evidence(dmarc, record.Text),
                Strings.DmarcNoneRisk, Strings.DmarcNoneFix, Rfc + " §6.3"));
        }

        if (record.Percent < 100)
        {
            return EmailFinding.Executed(EmailFinding.Create(
                PolicyId, EmailFinding.Format(Strings.DmarcPartialTitle, record.Percent), Severity.Low, confidence, domain,
                Evidence(dmarc, record.Text), Strings.DmarcPartialRisk, Strings.DmarcPartialFix, Rfc + " §6.3"));
        }

        return EmailFinding.Executed();
    }

    private static async Task<CheckResult> ReportsAsync(EmailDomainInspector inspector, string domain, CancellationToken cancellationToken)
    {
        var dmarc = await inspector.GetDmarcAsync(domain, cancellationToken).ConfigureAwait(false);
        if (NotEvaluable(dmarc) is { } early)
        {
            return early;
        }

        return dmarc.Record!.AggregateReports.Count > 0
            ? EmailFinding.Executed()
            : EmailFinding.Executed(EmailFinding.Create(
                ReportsId, Strings.DmarcNoReportsTitle, Severity.Low, Confidence.Certain, domain, Evidence(dmarc, dmarc.Record.Text),
                Strings.DmarcNoReportsRisk, Strings.DmarcNoReportsFix, Rfc + " §7.2"));
    }

    private static async Task<CheckResult> SubdomainAsync(EmailDomainInspector inspector, string domain, CancellationToken cancellationToken)
    {
        var dmarc = await inspector.GetDmarcAsync(domain, cancellationToken).ConfigureAwait(false);
        if (NotEvaluable(dmarc) is { } early)
        {
            return early;
        }

        // An inherited sp is already the policy of this domain, evaluated by MAIL-DMARC-001.
        var record = dmarc.Record!;
        return !dmarc.Inherited && record.Policy != DmarcPolicy.None && record.SubdomainPolicy == DmarcPolicy.None
            ? EmailFinding.Executed(EmailFinding.Create(
                SubdomainId, Strings.DmarcSubdomainNoneTitle, Severity.Low, Confidence.Certain, domain, record.Text,
                Strings.DmarcSubdomainNoneRisk, Strings.DmarcSubdomainNoneFix, Rfc + " §6.3"))
            : EmailFinding.Executed();
    }

    /// <summary>The early result when there is no valid DMARC record, otherwise <see langword="null"/>.</summary>
    private static CheckResult? NotEvaluable(DmarcAnalysis dmarc)
    {
        if (dmarc.DnsError is not null)
        {
            return EmailFinding.DnsFailed(dmarc.Source, dmarc.DnsError);
        }

        return dmarc.Record is null ? new CheckResult.Skipped(Strings.SkippedNoDmarc) : null;
    }

    private static string Evidence(DmarcAnalysis dmarc, string text) =>
        dmarc.Inherited ? EmailFinding.Format(Strings.EvidenceInheritedFrom, dmarc.Source) + " " + text : text;
}
