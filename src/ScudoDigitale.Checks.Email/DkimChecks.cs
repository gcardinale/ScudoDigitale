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

/// <summary>DKIM checks (RFC 6376): a key on the common selectors, and the quality of the keys found.</summary>
internal static class DkimChecks
{
    /// <summary>Id of the check on the presence of a DKIM key.</summary>
    public const string SelectorsId = "MAIL-DKIM-001";

    /// <summary>Id of the check on the DKIM keys found.</summary>
    public const string KeysId = "MAIL-DKIM-002";

    /// <summary>Minimum RSA key length accepted by verifiers (RFC 8301 §3.2).</summary>
    public const int MinimumRsaBits = 1024;

    /// <summary>Recommended RSA key length (RFC 8301 §3.2).</summary>
    public const int RecommendedRsaBits = 2048;

    private const string Rfc = "RFC 6376";

    /// <summary>Creates the DKIM checks.</summary>
    /// <param name="inspector">Shared DNS analyses of the run.</param>
    /// <returns>The checks.</returns>
    public static IEnumerable<ICheck> Create(EmailDomainInspector inspector)
    {
        yield return new EmailCheck(SelectorsId, () => Strings.DkimSelectorsCheck, inspector, SelectorsAsync);
        yield return new EmailCheck(KeysId, () => Strings.DkimKeysCheck, inspector, KeysAsync);
    }

    private static async Task<CheckResult> SelectorsAsync(EmailDomainInspector inspector, string domain, CancellationToken cancellationToken)
    {
        var dkim = await inspector.GetDkimAsync(domain, cancellationToken).ConfigureAwait(false);
        if (dkim.DnsError is not null)
        {
            return EmailFinding.DnsFailed("_domainkey." + domain, dkim.DnsError);
        }

        return dkim.ActiveKeys.Any()
            ? EmailFinding.Executed()
            : EmailFinding.Executed(EmailFinding.Create(
                SelectorsId, Strings.DkimNotFoundTitle, Severity.Medium, Confidence.ToBeVerified, domain,
                Evidence(dkim),
                Strings.DkimNotFoundRisk, Strings.DkimNotFoundFix, Rfc));
    }

    /// <summary>The selectors tried and, if any, those the DNS did not answer for.</summary>
    private static string Evidence(DkimAnalysis dkim)
    {
        var tried = EmailFinding.Format(Strings.EvidenceDkimSelectorsTried, string.Join(", ", dkim.SelectorsTried));
        return dkim.Unanswered.Count == 0
            ? tried
            : tried + " " + EmailFinding.Format(Strings.EvidenceDkimSelectorsUnanswered, string.Join(", ", dkim.Unanswered));
    }

    private static async Task<CheckResult> KeysAsync(EmailDomainInspector inspector, string domain, CancellationToken cancellationToken)
    {
        var dkim = await inspector.GetDkimAsync(domain, cancellationToken).ConfigureAwait(false);
        if (dkim.DnsError is not null)
        {
            return EmailFinding.DnsFailed("_domainkey." + domain, dkim.DnsError);
        }

        var keys = dkim.ActiveKeys.ToArray();
        if (keys.Length == 0)
        {
            return new CheckResult.Skipped(Strings.SkippedNoDkim);
        }

        var findings = new List<Finding>();
        foreach (var key in keys)
        {
            var name = $"{key.Selector}._domainkey.{domain}";
            var evidence = key.Bits is { } size ? $"{name}: k={key.KeyType}, {size} bit" : $"{name}: k={key.KeyType}";
            if (!key.Readable)
            {
                findings.Add(EmailFinding.Create(
                    KeysId, EmailFinding.Format(Strings.DkimUnreadableTitle, key.Selector), Severity.Medium, Confidence.Certain, domain,
                    evidence, Strings.DkimUnreadableRisk, Strings.DkimUnreadableFix, Rfc + " §3.6.1"));
            }
            else if (key.Bits < MinimumRsaBits)
            {
                findings.Add(EmailFinding.Create(
                    KeysId, EmailFinding.Format(Strings.DkimWeakKeyTitle, key.Selector, key.Bits), Severity.High, Confidence.Certain, domain,
                    evidence, Strings.DkimWeakKeyRisk, Strings.DkimNewKeyFix, "RFC 8301 §3.2"));
            }
            else if (key.Bits < RecommendedRsaBits)
            {
                findings.Add(EmailFinding.Create(
                    KeysId, EmailFinding.Format(Strings.DkimShortKeyTitle, key.Selector, key.Bits), Severity.Medium, Confidence.Certain, domain,
                    evidence, Strings.DkimShortKeyRisk, Strings.DkimNewKeyFix, "RFC 8301 §3.2"));
            }

            if (key.Testing)
            {
                findings.Add(EmailFinding.Create(
                    KeysId, EmailFinding.Format(Strings.DkimTestingTitle, key.Selector), Severity.Low, Confidence.Certain, domain,
                    evidence, Strings.DkimTestingRisk, Strings.DkimTestingFix, Rfc + " §3.6.1"));
            }
        }

        return EmailFinding.Executed(findings);
    }
}
