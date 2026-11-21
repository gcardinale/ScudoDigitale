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

/// <summary>Helpers shared by the website rules to build findings and results.</summary>
internal static class WebFinding
{
    /// <summary>Longest header value quoted in the evidence of a finding.</summary>
    public const int MaxEvidenceLength = 300;

    /// <summary>Creates a website finding.</summary>
    /// <param name="id">Id of the check.</param>
    /// <param name="title">Localized title.</param>
    /// <param name="severity">Severity.</param>
    /// <param name="confidence">Confidence.</param>
    /// <param name="target">The site.</param>
    /// <param name="evidence">What was observed.</param>
    /// <param name="risk">Localized risk.</param>
    /// <param name="fix">Localized fix.</param>
    /// <param name="references">Standards the finding refers to.</param>
    /// <returns>The finding.</returns>
    public static Finding Create(
        string id,
        string title,
        Severity severity,
        Confidence confidence,
        string target,
        string? evidence,
        string risk,
        string fix,
        params string[] references) =>
        new(id, CheckArea.Web, title, severity, confidence, target)
        {
            Evidence = evidence,
            Risk = risk,
            Fix = fix,
            References = references,
        };

    /// <summary>Result with the given findings (possibly none).</summary>
    /// <param name="findings">The findings.</param>
    /// <returns>The result.</returns>
    public static CheckResult Executed(params IEnumerable<Finding> findings) => new CheckResult.Executed(findings);

    /// <summary>
    /// The early result when there is no home page over HTTPS to evaluate, otherwise
    /// <see langword="null"/>: then <see cref="Page"/> is the page.
    /// </summary>
    /// <param name="visit">The visit.</param>
    /// <returns>Skipped or failed, with the reason; <see langword="null"/> when the page is there.</returns>
    public static CheckResult? NoPage(SiteVisit visit) => visit.Https switch
    {
        { End: TrailEnd.Error } => new CheckResult.Skipped(Strings.SkippedNoHttps),
        { End: TrailEnd.ChangedScheme } => new CheckResult.Skipped(Strings.SkippedBackToHttp),
        { End: TrailEnd.LeftSite } trail => new CheckResult.Skipped(Format(Strings.SkippedLeftSite, trail.Next!.Host)),
        { End: TrailEnd.TooManyRedirects } trail => TooManyRedirects(trail),
        var trail when trail.Hops[^1].Status >= 400 =>
            new CheckResult.Failed(Format(Strings.PageStatus, SafeUrl.Show(trail.Hops[^1].Url), trail.Hops[^1].Status)),
        _ => null,
    };

    /// <summary>The home page over HTTPS; valid only when <see cref="NoPage"/> returned <see langword="null"/>.</summary>
    /// <param name="visit">The visit.</param>
    /// <returns>The last response of the HTTPS chain.</returns>
    public static Hop Page(SiteVisit visit) => visit.Https.Hops[^1];

    /// <summary>Result of a chain with more redirects than a visit follows.</summary>
    /// <param name="trail">The chain.</param>
    /// <returns>The result.</returns>
    public static CheckResult TooManyRedirects(Trail trail) =>
        new CheckResult.Failed(Format(Strings.TooManyRedirects, HttpSiteFetcher.MaxRedirects, trail.Path));

    /// <summary>Evidence for a header that is not there.</summary>
    /// <param name="page">The response.</param>
    /// <param name="header">The header name.</param>
    /// <returns>The text.</returns>
    public static string NoHeader(Hop page, string header) => Format(Strings.EvidenceNoHeader, SafeUrl.Show(page.Url), header);

    /// <summary>Evidence for a header value, shortened when very long.</summary>
    /// <param name="header">The header name.</param>
    /// <param name="value">Its value.</param>
    /// <returns>The text.</returns>
    public static string Header(string header, string value) =>
        $"{header}: {(value.Length > MaxEvidenceLength ? value[..MaxEvidenceLength] + "…" : value)}";

    /// <summary>Formats a localized text with the current culture.</summary>
    /// <param name="format">The localized format.</param>
    /// <param name="arguments">Its arguments.</param>
    /// <returns>The text.</returns>
    public static string Format(string format, params object?[] arguments) =>
        string.Format(CultureInfo.CurrentCulture, format, arguments);
}
