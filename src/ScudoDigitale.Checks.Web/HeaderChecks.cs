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

/// <summary>Checks on the security headers of the home page served over HTTPS.</summary>
internal static class HeaderChecks
{
    /// <summary>Id of the check on <c>Strict-Transport-Security</c>.</summary>
    public const string HstsId = "WEB-HSTS-001";

    /// <summary>Id of the check on <c>Content-Security-Policy</c>.</summary>
    public const string CspId = "WEB-HDR-001";

    /// <summary>Id of the check on the protection from clickjacking.</summary>
    public const string FrameId = "WEB-HDR-002";

    /// <summary>Id of the check on <c>X-Content-Type-Options</c>.</summary>
    public const string NosniffId = "WEB-HDR-003";

    /// <summary>Id of the check on <c>Referrer-Policy</c>.</summary>
    public const string ReferrerId = "WEB-HDR-004";

    /// <summary>Id of the check on <c>Permissions-Policy</c>.</summary>
    public const string PermissionsId = "WEB-HDR-005";

    /// <summary>Shortest <c>max-age</c> of HSTS that is not reported: six months, in seconds.</summary>
    public const long MinimumHstsMaxAge = 15_552_000;

    private const string HstsHeader = "Strict-Transport-Security";
    private const string CspHeader = "Content-Security-Policy";
    private const string FrameHeader = "X-Frame-Options";
    private const string NosniffHeader = "X-Content-Type-Options";
    private const string ReferrerHeader = "Referrer-Policy";
    private const string PermissionsHeader = "Permissions-Policy";

    /// <summary>Old values of <c>meta name="referrer"</c> that browsers still map to a policy.</summary>
    private static readonly Dictionary<string, string> LegacyReferrerValues = new(StringComparer.Ordinal)
    {
        ["never"] = "no-referrer",
        ["default"] = "no-referrer-when-downgrade",
        ["always"] = "unsafe-url",
        ["origin-when-crossorigin"] = "origin-when-cross-origin",
    };

    private static readonly string[] ReferrerPolicies =
    [
        "no-referrer", "no-referrer-when-downgrade", "same-origin", "origin", "strict-origin",
        "origin-when-cross-origin", "strict-origin-when-cross-origin", "unsafe-url",
    ];

    /// <summary>Creates the header checks.</summary>
    /// <param name="inspector">Shared visits of the run.</param>
    /// <returns>The checks.</returns>
    public static IEnumerable<ICheck> Create(WebSiteInspector inspector)
    {
        yield return new WebCheck(HstsId, () => Strings.HstsCheck, inspector, visit => OnPage(visit, HstsRule));
        yield return new WebCheck(CspId, () => Strings.CspCheck, inspector, visit => OnPage(visit, Csp));
        yield return new WebCheck(FrameId, () => Strings.FrameCheck, inspector, visit => OnPage(visit, Frame));
        yield return new WebCheck(NosniffId, () => Strings.NosniffCheck, inspector, visit => OnPage(visit, Nosniff));
        yield return new WebCheck(ReferrerId, () => Strings.ReferrerCheck, inspector, visit => OnPage(visit, Referrer));
        yield return new WebCheck(PermissionsId, () => Strings.PermissionsCheck, inspector, visit => OnPage(visit, Permissions));
    }

    private static CheckResult OnPage(SiteVisit visit, Func<string, Hop, Finding?> rule) =>
        WebFinding.NoPage(visit) ?? WebFinding.Executed(new[] { rule(visit.Host, WebFinding.Page(visit)) }.OfType<Finding>());

    private static Finding? HstsRule(string host, Hop page)
    {
        Finding Medium(string title, string evidence) => WebFinding.Create(
            HstsId, title, Severity.Medium, Confidence.Certain, host, evidence, Strings.HstsMissingRisk, Strings.HstsFix, "RFC 6797");

        // RFC 6797 §8.1: only the first header counts.
        if (page.Values(HstsHeader).FirstOrDefault() is not { } value)
        {
            return Medium(Strings.HstsMissingTitle, WebFinding.NoHeader(page, HstsHeader));
        }

        var evidence = WebFinding.Header(HstsHeader, value);
        return Hsts.MaxAge(value) switch
        {
            null => Medium(Strings.HstsInvalidTitle, evidence),
            0 => Medium(Strings.HstsDisabledTitle, evidence),
            < MinimumHstsMaxAge => WebFinding.Create(
                HstsId, Strings.HstsShortTitle, Severity.Low, Confidence.Certain, host, evidence,
                Strings.HstsShortRisk, Strings.HstsFix, "RFC 6797 §11.2"),
            _ => null,
        };
    }

    private static Finding? Csp(string host, Hop page)
    {
        const string Reference = "W3C Content Security Policy Level 3";
        var texts = page.Values(CspHeader).Concat(HtmlMeta.Contents(page.Body, "http-equiv", CspHeader)).ToArray();
        var policies = ContentSecurityPolicy.Parse(texts);
        if (policies.Count == 0)
        {
            return page.Values(CspHeader + "-Report-Only").FirstOrDefault() is { } reportOnly
                ? WebFinding.Create(
                    CspId, Strings.CspReportOnlyTitle, Severity.Low, Confidence.Certain, host,
                    WebFinding.Header(CspHeader + "-Report-Only", reportOnly), Strings.CspReportOnlyRisk, Strings.CspReportOnlyFix, Reference)
                : WebFinding.Create(
                    CspId, Strings.CspMissingTitle, Severity.Medium, Confidence.Certain, host,
                    WebFinding.NoHeader(page, CspHeader), Strings.CspMissingRisk, Strings.CspMissingFix, Reference);
        }

        // Browsers apply every policy: one that limits scripts is enough.
        return policies.Any(policy => policy.RestrictsScripts())
            ? null
            : WebFinding.Create(
                CspId, Strings.CspWeakTitle, Severity.Low, Confidence.Certain, host,
                WebFinding.Header(CspHeader, string.Join(", ", texts)), Strings.CspWeakRisk, Strings.CspWeakFix, Reference);
    }

    private static Finding? Frame(string host, Hop page)
    {
        // frame-ancestors is ignored in a meta element: only the header counts. A list that allows
        // any site protects nothing.
        if (ContentSecurityPolicy.Parse(page.Values(CspHeader))
            .Any(policy => policy.Sources("frame-ancestors") is { } ancestors && !ancestors.Any(a => a is "*" or "http:" or "https:")))
        {
            return null;
        }

        var values = page.Values(FrameHeader).SelectMany(v => v.Split(',')).Select(v => v.Trim().ToUpperInvariant()).ToArray();
        if (values.Length == 0)
        {
            return WebFinding.Create(
                FrameId, Strings.FrameMissingTitle, Severity.Medium, Confidence.Certain, host,
                WebFinding.NoHeader(page, FrameHeader), Strings.FrameMissingRisk, Strings.FrameFix, "RFC 7034", "W3C Content Security Policy Level 3");
        }

        return values.All(v => v is "DENY" or "SAMEORIGIN")
            ? null
            : WebFinding.Create(
                FrameId, Strings.FrameInvalidTitle, Severity.Medium, Confidence.Certain, host,
                WebFinding.Header(FrameHeader, string.Join(", ", page.Values(FrameHeader))), Strings.FrameInvalidRisk, Strings.FrameFix, "RFC 7034 §2.1");
    }

    private static Finding? Nosniff(string host, Hop page)
    {
        var values = page.Values(NosniffHeader).ToArray();

        // As browsers do (Fetch): of several values, joined by commas or sent twice, the first counts.
        var first = values.SelectMany(v => v.Split(',')).Select(v => v.Trim()).FirstOrDefault();
        if (string.Equals(first, "nosniff", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return WebFinding.Create(
            NosniffId,
            values.Length == 0 ? Strings.NosniffMissingTitle : Strings.NosniffInvalidTitle,
            Severity.Low,
            Confidence.Certain,
            host,
            values.Length == 0 ? WebFinding.NoHeader(page, NosniffHeader) : WebFinding.Header(NosniffHeader, string.Join(", ", values)),
            Strings.NosniffRisk,
            Strings.NosniffFix,
            "WHATWG Fetch §3.6");
    }

    private static Finding? Referrer(string host, Hop page)
    {
        const string Reference = "W3C Referrer Policy";
        var meta = HtmlMeta.Contents(page.Body, "name", "referrer")
            .Select(content => LegacyReferrerValues.GetValueOrDefault(content.Trim().ToLowerInvariant(), content));
        var values = page.Values(ReferrerHeader).Concat(meta).ToArray();

        // Of a list, browsers use the last policy they know.
        var policy = values.SelectMany(v => v.Split(',')).Select(v => v.Trim().ToLowerInvariant()).LastOrDefault(v => ReferrerPolicies.Contains(v));
        return policy switch
        {
            null => WebFinding.Create(
                ReferrerId, Strings.ReferrerMissingTitle, Severity.Low, Confidence.Certain, host,
                values.Length == 0 ? WebFinding.NoHeader(page, ReferrerHeader) : WebFinding.Header(ReferrerHeader, string.Join(", ", values)),
                Strings.ReferrerMissingRisk, Strings.ReferrerFix, Reference),
            "unsafe-url" or "no-referrer-when-downgrade" => WebFinding.Create(
                ReferrerId, Strings.ReferrerWeakTitle, Severity.Low, Confidence.Certain, host,
                WebFinding.Header(ReferrerHeader, string.Join(", ", values)), Strings.ReferrerWeakRisk, Strings.ReferrerFix, Reference),
            _ => null,
        };
    }

    private static Finding? Permissions(string host, Hop page) => page.Values(PermissionsHeader).Any()
        ? null
        : WebFinding.Create(
            PermissionsId, Strings.PermissionsMissingTitle, Severity.Info, Confidence.Certain, host,
            WebFinding.NoHeader(page, PermissionsHeader), Strings.PermissionsMissingRisk, Strings.PermissionsFix, "W3C Permissions Policy");
}
