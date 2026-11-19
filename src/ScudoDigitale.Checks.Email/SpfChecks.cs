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

/// <summary>SPF checks (RFC 7208): record present and unique, final <c>all</c>, lookup limit, syntax.</summary>
internal static class SpfChecks
{
    /// <summary>Id of the check on the presence and uniqueness of the SPF record.</summary>
    public const string RecordId = "MAIL-SPF-001";

    /// <summary>Id of the check on the final <c>all</c> mechanism.</summary>
    public const string AllId = "MAIL-SPF-002";

    /// <summary>Id of the check on the limit of 10 DNS lookups.</summary>
    public const string LookupsId = "MAIL-SPF-003";

    /// <summary>Id of the check on syntax, includes and deprecated mechanisms.</summary>
    public const string SyntaxId = "MAIL-SPF-004";

    private const string Rfc = "RFC 7208";

    /// <summary>Creates the SPF checks.</summary>
    /// <param name="inspector">Shared DNS analyses of the run.</param>
    /// <returns>The checks.</returns>
    public static IEnumerable<ICheck> Create(EmailDomainInspector inspector)
    {
        yield return new EmailCheck(RecordId, () => Strings.SpfRecordCheck, inspector, RecordAsync);
        yield return new EmailCheck(AllId, () => Strings.SpfAllCheck, inspector, AllAsync);
        yield return new EmailCheck(LookupsId, () => Strings.SpfLookupsCheck, inspector, LookupsAsync);
        yield return new EmailCheck(SyntaxId, () => Strings.SpfSyntaxCheck, inspector, SyntaxAsync);
    }

    private static async Task<CheckResult> RecordAsync(EmailDomainInspector inspector, string domain, CancellationToken cancellationToken)
    {
        var spf = await inspector.GetSpfAsync(domain, cancellationToken).ConfigureAwait(false);
        if (spf.DnsError is not null)
        {
            return EmailFinding.DnsFailed(domain, spf.DnsError);
        }

        return spf.Records.Count switch
        {
            0 => EmailFinding.Executed(EmailFinding.Create(
                RecordId,
                Strings.SpfMissingTitle,
                Severity.High,
                Confidence.Certain,
                domain,
                EmailFinding.Format(Strings.EvidenceNoRecord, domain),
                Strings.SpfMissingRisk,
                Strings.SpfMissingFix,
                Rfc)),
            1 => EmailFinding.Executed(),
            _ => EmailFinding.Executed(EmailFinding.Create(
                RecordId,
                Strings.SpfMultipleTitle,
                Severity.High,
                Confidence.Certain,
                domain,
                string.Join(" | ", spf.Records),
                Strings.SpfMultipleRisk,
                Strings.SpfMultipleFix,
                Rfc + " §4.5")),
        };
    }

    private static async Task<CheckResult> AllAsync(EmailDomainInspector inspector, string domain, CancellationToken cancellationToken)
    {
        var spf = await inspector.GetSpfAsync(domain, cancellationToken).ConfigureAwait(false);
        if (NotEvaluable(spf, domain) is { } early)
        {
            return early;
        }

        return spf.EffectiveAll switch
        {
            SpfQualifier.Fail or SpfQualifier.SoftFail => EmailFinding.Executed(),
            SpfQualifier.Pass => EmailFinding.Executed(EmailFinding.Create(
                AllId,
                Strings.SpfAllPassTitle,
                Severity.High,
                Confidence.Certain,
                domain,
                spf.Record!.Text,
                Strings.SpfAllPassRisk,
                Strings.SpfAllFix,
                Rfc + " §5.1")),
            _ => EmailFinding.Executed(EmailFinding.Create(
                AllId,
                Strings.SpfAllNeutralTitle,
                Severity.Medium,
                Confidence.Certain,
                domain,
                spf.Record!.Text,
                Strings.SpfAllNeutralRisk,
                Strings.SpfAllFix,
                Rfc + " §4.7")),
        };
    }

    private static async Task<CheckResult> LookupsAsync(EmailDomainInspector inspector, string domain, CancellationToken cancellationToken)
    {
        var spf = await inspector.GetSpfAsync(domain, cancellationToken).ConfigureAwait(false);
        if (NotEvaluable(spf, domain) is { } early)
        {
            return early;
        }

        if (spf.Lookups <= SpfAnalyzer.LookupLimit)
        {
            return EmailFinding.Executed();
        }

        return EmailFinding.Executed(EmailFinding.Create(
            LookupsId,
            Strings.SpfTooManyLookupsTitle,
            Severity.High,
            Confidence.Certain,
            domain,
            EmailFinding.Format(Strings.EvidenceSpfLookups, spf.Lookups),
            Strings.SpfTooManyLookupsRisk,
            Strings.SpfTooManyLookupsFix,
            Rfc + " §4.6.4"));
    }

    private static async Task<CheckResult> SyntaxAsync(EmailDomainInspector inspector, string domain, CancellationToken cancellationToken)
    {
        var spf = await inspector.GetSpfAsync(domain, cancellationToken).ConfigureAwait(false);
        if (NotEvaluable(spf, domain) is { } early)
        {
            return early;
        }

        return EmailFinding.Executed(spf.Problems.Select(problem => problem.Kind switch
        {
            SpfProblemKind.SyntaxError => EmailFinding.Create(
                SyntaxId, Strings.SpfSyntaxErrorTitle, Severity.High, Confidence.Certain, domain, problem.Evidence,
                Strings.SpfSyntaxErrorRisk, Strings.SpfSyntaxErrorFix, Rfc + " §4.6"),
            SpfProblemKind.BrokenReference => EmailFinding.Create(
                SyntaxId, Strings.SpfBrokenReferenceTitle, Severity.High, Confidence.Certain, domain, problem.Evidence,
                Strings.SpfBrokenReferenceRisk, Strings.SpfBrokenReferenceFix, Rfc + " §5.2"),
            SpfProblemKind.Unverified => EmailFinding.Create(
                SyntaxId, Strings.SpfUnverifiedTitle, Severity.Low, Confidence.ToBeVerified, domain, problem.Evidence,
                Strings.SpfUnverifiedRisk, Strings.SpfUnverifiedFix, Rfc + " §5.2"),
            _ => EmailFinding.Create(
                SyntaxId, Strings.SpfPtrTitle, Severity.Low, Confidence.Certain, domain, problem.Evidence,
                Strings.SpfPtrRisk, Strings.SpfPtrFix, Rfc + " §5.5"),
        }));
    }

    /// <summary>The early result when there is no single SPF record to evaluate, otherwise <see langword="null"/>.</summary>
    private static CheckResult? NotEvaluable(SpfAnalysis spf, string domain)
    {
        if (spf.DnsError is not null)
        {
            return EmailFinding.DnsFailed(domain, spf.DnsError);
        }

        return spf.Record is null ? new CheckResult.Skipped(Strings.SkippedNoSpf) : null;
    }
}
