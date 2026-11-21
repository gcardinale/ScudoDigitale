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

/// <summary>Check on the security.txt file (RFC 9116): where to report a vulnerability of the site.</summary>
internal static class SecurityTxtChecks
{
    /// <summary>Id of the check.</summary>
    public const string FileId = "WEB-SECTXT-001";

    private const string Rfc = "RFC 9116";

    /// <summary>Creates the check.</summary>
    /// <param name="inspector">Shared visits of the run.</param>
    /// <returns>The check.</returns>
    public static IEnumerable<ICheck> Create(WebSiteInspector inspector)
    {
        yield return new WebCheck(FileId, () => Strings.SecurityTxtCheck, inspector, File);
    }

    private static CheckResult File(SiteVisit visit)
    {
        if (visit.SecurityTxt is not { } trail)
        {
            return new CheckResult.Skipped(Strings.SkippedNoHttps);
        }

        switch (trail.End)
        {
            case TrailEnd.Error:
                return new CheckResult.Failed(WebFinding.Format(Strings.FetchFailed, "security.txt", trail.Error));
            case TrailEnd.TooManyRedirects:
                return WebFinding.TooManyRedirects(trail);
            case TrailEnd.ChangedScheme or TrailEnd.LeftSite:
                // The file may well be there, but following the redirect would contact an address
                // that was not declared.
                return WebFinding.Executed(WebFinding.Create(
                    FileId, Strings.SecurityTxtElsewhereTitle, Severity.Info, Confidence.ToBeVerified, visit.Host,
                    trail.Path, Strings.SecurityTxtMissingRisk, Strings.SecurityTxtElsewhereFix, Rfc + " §3"));
        }

        var file = trail.Hops[^1];
        if (file.Body is not { } text)
        {
            return WebFinding.Executed(WebFinding.Create(
                FileId, Strings.SecurityTxtMissingTitle, Severity.Info, Confidence.Certain, visit.Host,
                WebFinding.Format(Strings.EvidenceNoSecurityTxt, SafeUrl.Show(file.Url), file.Status),
                Strings.SecurityTxtMissingRisk, Strings.SecurityTxtMissingFix, Rfc + " §3"));
        }

        var fields = Fields(text);
        var findings = new List<Finding>();
        if (!fields.Any(f => f.Name == "contact"))
        {
            findings.Add(WebFinding.Create(
                FileId, Strings.SecurityTxtNoContactTitle, Severity.Low, Confidence.Certain, visit.Host,
                SafeUrl.Show(file.Url), Strings.SecurityTxtNoContactRisk, Strings.SecurityTxtNoContactFix, Rfc + " §2.5.3"));
        }

        var expires = fields.FirstOrDefault(f => f.Name == "expires").Value;
        if (!DateTimeOffset.TryParse(expires, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var until))
        {
            findings.Add(WebFinding.Create(
                FileId, Strings.SecurityTxtNoExpiresTitle, Severity.Low, Confidence.Certain, visit.Host,
                SafeUrl.Show(file.Url), Strings.SecurityTxtExpiresRisk, Strings.SecurityTxtExpiresFix, Rfc + " §2.5.5"));
        }
        else if (until < visit.VisitedAt)
        {
            findings.Add(WebFinding.Create(
                FileId, Strings.SecurityTxtExpiredTitle, Severity.Low, Confidence.Certain, visit.Host,
                $"{SafeUrl.Show(file.Url)} — Expires: {expires}", Strings.SecurityTxtExpiresRisk, Strings.SecurityTxtExpiresFix, Rfc + " §2.5.5"));
        }

        return WebFinding.Executed(findings);
    }

    /// <summary>The fields of a security.txt file: names in lower case, comments and blank lines left out.</summary>
    /// <param name="text">The file.</param>
    /// <returns>The fields with a value, in file order.</returns>
    internal static IReadOnlyList<(string Name, string Value)> Fields(string text) =>
    [
        .. text.Split('\n')
            .Select(line => line.Trim())
            .Where(line => !line.StartsWith('#'))
            .Select(line => line.Split(':', 2, StringSplitOptions.TrimEntries))
            .Where(parts => parts.Length == 2 && parts[1].Length > 0)
            .Select(parts => (parts[0].ToLowerInvariant(), parts[1])),
    ];
}
