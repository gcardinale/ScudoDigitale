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

using ScudoDigitale.Checks.Web.Resources;
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Web;

/// <summary>HTTPS checks: the site answers over HTTPS, and plain HTTP sends visitors there.</summary>
internal static class HttpsChecks
{
    /// <summary>Id of the check on the site answering over HTTPS.</summary>
    public const string AvailableId = "WEB-HTTPS-001";

    /// <summary>Id of the check on the redirect from HTTP to HTTPS.</summary>
    public const string RedirectId = "WEB-HTTPS-002";

    private const string Reference = "RFC 9110 §4.2.2";

    /// <summary>Creates the HTTPS checks.</summary>
    /// <param name="inspector">Shared visits of the run.</param>
    /// <returns>The checks.</returns>
    public static IEnumerable<ICheck> Create(WebSiteInspector inspector)
    {
        yield return new WebCheck(AvailableId, () => Strings.HttpsAvailableCheck, inspector, Available);
        yield return new WebCheck(RedirectId, () => Strings.HttpRedirectCheck, inspector, Redirect);
    }

    private static CheckResult Available(SiteVisit visit) => visit.Https switch
    {
        { End: TrailEnd.Error, Refused: true } => WebFinding.Executed(WebFinding.Create(
            AvailableId, Strings.HttpsMissingTitle, Severity.High, Confidence.Certain, visit.Host,
            visit.Https.Error, Strings.HttpsMissingRisk, Strings.HttpsMissingFix, Reference)),

        // No answer in time, a broken handshake, a protocol this computer does not accept: HTTPS may
        // be there and simply not usable from here, so the finding does not claim more than that.
        { End: TrailEnd.Error } => WebFinding.Executed(WebFinding.Create(
            AvailableId, Strings.HttpsUnusableTitle, Severity.High, Confidence.ToBeVerified, visit.Host,
            visit.Https.Error, Strings.HttpsUnusableRisk, Strings.HttpsUnusableFix, Reference)),
        { End: TrailEnd.ChangedScheme } => WebFinding.Executed(WebFinding.Create(
            AvailableId, Strings.HttpsBackToHttpTitle, Severity.High, Confidence.Certain, visit.Host,
            visit.Https.Path, Strings.HttpsBackToHttpRisk, Strings.HttpsBackToHttpFix, Reference)),
        _ => WebFinding.Executed(),
    };

    private static CheckResult Redirect(SiteVisit visit) => visit.Http switch
    {
        // Nothing answers on port 80: nothing is served in clear.
        { End: TrailEnd.Error } => WebFinding.Executed(),
        { End: TrailEnd.TooManyRedirects } trail => WebFinding.TooManyRedirects(trail),
        { End: TrailEnd.ChangedScheme, Hops.Count: 1 } => WebFinding.Executed(),
        { End: TrailEnd.Response } trail when trail.Hops[^1].Status >= 400 => WebFinding.Executed(),
        { End: TrailEnd.Response } trail => WebFinding.Executed(WebFinding.Create(
            RedirectId, Strings.HttpNoRedirectTitle, Severity.Medium, Confidence.Certain, visit.Host,
            WebFinding.Format(Strings.EvidenceHttpStatus, trail.Path, trail.Hops[^1].Status),
            Strings.HttpNoRedirectRisk, Strings.HttpRedirectFix, Reference)),

        // HTTPS is reached only after another address in clear, or the visitor is sent elsewhere in clear.
        var trail => WebFinding.Executed(WebFinding.Create(
            RedirectId, Strings.HttpClearHopTitle, Severity.Low, Confidence.Certain, visit.Host,
            trail.Path, Strings.HttpClearHopRisk, Strings.HttpRedirectFix, Reference)),
    };
}
