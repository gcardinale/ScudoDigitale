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

/// <summary>
/// Checks on the cookies the site sets on a first visit, before any login or consent: the only ones
/// a passive visit can see.
/// </summary>
internal static class CookieChecks
{
    /// <summary>Id of the check on <c>Secure</c>.</summary>
    public const string SecureId = "WEB-COOKIE-001";

    /// <summary>Id of the check on <c>HttpOnly</c>.</summary>
    public const string HttpOnlyId = "WEB-COOKIE-002";

    /// <summary>Id of the check on <c>SameSite</c>.</summary>
    public const string SameSiteId = "WEB-COOKIE-003";

    /// <summary>Creates the cookie checks.</summary>
    /// <param name="inspector">Shared visits of the run.</param>
    /// <returns>The checks.</returns>
    public static IEnumerable<ICheck> Create(WebSiteInspector inspector)
    {
        yield return new WebCheck(SecureId, () => Strings.CookieSecureCheck, inspector, visit => ForEach(visit, Secure));
        yield return new WebCheck(HttpOnlyId, () => Strings.CookieHttpOnlyCheck, inspector, visit => ForEach(visit, HttpOnly));
        yield return new WebCheck(SameSiteId, () => Strings.CookieSameSiteCheck, inspector, visit => ForEach(visit, SameSite));
    }

    private static CheckResult ForEach(SiteVisit visit, Func<string, SetCookie, Finding?> rule)
    {
        if (WebFinding.NoPage(visit) is { } early)
        {
            return early;
        }

        // Redirects set cookies too; of two cookies with the same name the browser keeps the last.
        var cookies = visit.Https.Hops
            .SelectMany(hop => hop.Values("Set-Cookie"))
            .SelectMany(SetCookie.ParseAll)
            .GroupBy(cookie => cookie.Name, StringComparer.Ordinal)
            .Select(group => group.Last())
            .ToArray();
        return cookies.Length == 0
            ? new CheckResult.Skipped(Strings.SkippedNoCookies)
            : WebFinding.Executed(cookies.Select(cookie => rule(visit.Host, cookie)).OfType<Finding>());
    }

    private static Finding? Secure(string host, SetCookie cookie) => cookie.Secure
        ? null
        : WebFinding.Create(
            SecureId, WebFinding.Format(Strings.CookieNoSecureTitle, cookie.Name), Severity.Medium, Confidence.Certain, host,
            cookie.Display, Strings.CookieNoSecureRisk, Strings.CookieNoSecureFix, "RFC 6265 §4.1.2.5");

    private static Finding? HttpOnly(string host, SetCookie cookie) => cookie.HttpOnly
        ? null
        : WebFinding.Create(
            HttpOnlyId, WebFinding.Format(Strings.CookieNoHttpOnlyTitle, cookie.Name),
            cookie.LooksLikeSession ? Severity.Medium : Severity.Low,

            // Some cookies are read by the scripts of the page on purpose: only the owner knows.
            Confidence.Probable, host,
            cookie.Display, Strings.CookieNoHttpOnlyRisk, Strings.CookieNoHttpOnlyFix, "RFC 6265 §4.1.2.6");

    private static Finding? SameSite(string host, SetCookie cookie) => cookie switch
    {
        { SameSite: "none", Secure: false } => WebFinding.Create(
            SameSiteId, WebFinding.Format(Strings.CookieSameSiteNoneTitle, cookie.Name), Severity.Medium, Confidence.Certain, host,
            cookie.Display, Strings.CookieSameSiteNoneRisk, Strings.CookieSameSiteNoneFix, "RFC 6265bis §4.1.2.7"),
        { SameSite: "strict" or "lax" or "none" } => null,
        _ => WebFinding.Create(
            SameSiteId, WebFinding.Format(Strings.CookieNoSameSiteTitle, cookie.Name), Severity.Low, Confidence.Certain, host,
            cookie.Display, Strings.CookieNoSameSiteRisk, Strings.CookieNoSameSiteFix, "RFC 6265bis §4.1.2.7"),
    };
}
