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
using ScudoDigitale.Checks.Web.Resources;
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Web;

/// <summary>Certificate checks: validity dates, chain of authorities, name.</summary>
internal static class CertificateChecks
{
    /// <summary>Id of the check on the validity dates.</summary>
    public const string ExpiryId = "WEB-CERT-001";

    /// <summary>Id of the check on the chain of authorities.</summary>
    public const string ChainId = "WEB-CERT-002";

    /// <summary>Id of the check on the name of the certificate.</summary>
    public const string NameId = "WEB-CERT-003";

    /// <summary>A certificate with fewer days left than this is urgent.</summary>
    public const int UrgentDays = 14;

    /// <summary>A certificate with at most this many days left is worth a reminder.</summary>
    public const int ReminderDays = 30;

    /// <summary>Creates the certificate checks.</summary>
    /// <param name="inspector">Shared visits of the run.</param>
    /// <returns>The checks.</returns>
    public static IEnumerable<ICheck> Create(WebSiteInspector inspector)
    {
        yield return new WebCheck(ExpiryId, () => Strings.CertExpiryCheck, inspector, visit => ForEach(visit, Expiry));
        yield return new WebCheck(ChainId, () => Strings.CertChainCheck, inspector, visit => ForEach(visit, Chain));
        yield return new WebCheck(NameId, () => Strings.CertNameCheck, inspector, visit => ForEach(visit, Name));
    }

    private static CheckResult ForEach(SiteVisit visit, Func<SiteVisit, CertificateInfo, Finding?> rule)
    {
        if (visit.Certificates.Count > 0)
        {
            return WebFinding.Executed(visit.Certificates.Select(certificate => rule(visit, certificate)).OfType<Finding>());
        }

        return visit.Https.End == TrailEnd.Error
            ? new CheckResult.Skipped(Strings.SkippedNoHttps)
            : new CheckResult.Failed(Strings.CertificateNotRead);
    }

    private static Finding? Expiry(SiteVisit visit, CertificateInfo certificate)
    {
        var evidence = WebFinding.Format(
            Strings.EvidenceCertValidity,
            certificate.Host,
            certificate.NotBefore.ToString("d", CultureInfo.CurrentCulture),
            certificate.NotAfter.ToString("d", CultureInfo.CurrentCulture));
        Finding Create(string title, Severity severity, string risk) => WebFinding.Create(
            ExpiryId, title, severity, Confidence.Certain, visit.Host, evidence, risk, Strings.CertRenewFix, "RFC 5280 §4.1.2.5");

        if (visit.VisitedAt < certificate.NotBefore)
        {
            return Create(WebFinding.Format(Strings.CertNotYetValidTitle, certificate.Host), Severity.High, Strings.CertExpiredRisk);
        }

        if (visit.VisitedAt > certificate.NotAfter)
        {
            return Create(WebFinding.Format(Strings.CertExpiredTitle, certificate.Host), Severity.High, Strings.CertExpiredRisk);
        }

        var days = (int)(certificate.NotAfter - visit.VisitedAt).TotalDays;
        return days > ReminderDays
            ? null
            : Create(
                WebFinding.Format(Strings.CertExpiringTitle, certificate.Host, days),
                days < UrgentDays ? Severity.Medium : Severity.Low,
                Strings.CertExpiringRisk);
    }

    private static Finding? Chain(SiteVisit visit, CertificateInfo certificate) => certificate.Chain switch
    {
        ChainState.Trusted => null,
        ChainState.Incomplete => WebFinding.Create(
            ChainId, WebFinding.Format(Strings.CertIncompleteTitle, certificate.Host), Severity.Medium, Confidence.Probable, visit.Host,
            $"{certificate.Host}: {certificate.ChainDetail}", Strings.CertIncompleteRisk, Strings.CertIncompleteFix, "RFC 5246 §7.4.2"),
        _ => WebFinding.Create(
            ChainId, WebFinding.Format(Strings.CertUntrustedTitle, certificate.Host), Severity.High, Confidence.Certain, visit.Host,
            $"{certificate.Host}: {certificate.ChainDetail}", Strings.CertUntrustedRisk, Strings.CertUntrustedFix, "RFC 5280 §6"),
    };

    private static Finding? Name(SiteVisit visit, CertificateInfo certificate) => certificate.NameMatches
        ? null
        : WebFinding.Create(
            NameId, WebFinding.Format(Strings.CertNameTitle, certificate.Host), Severity.High, Confidence.Certain, visit.Host,
            WebFinding.Format(Strings.EvidenceCertNames, certificate.Host, string.Join(", ", certificate.Names.Take(5))),
            Strings.CertNameRisk, Strings.CertNameFix, "RFC 9110 §4.3.4");
}
