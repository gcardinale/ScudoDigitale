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

namespace ScudoDigitale.Core;

/// <summary>
/// Computes the effective severity of findings and sorts them by urgency
/// (docs/development/patterns.md, "Prioritization").
/// </summary>
public static class FindingPrioritizer
{
    /// <summary>EPSS probability from which the severity is raised by one level.</summary>
    public const double EpssRaiseThreshold = 0.1;

    /// <summary>
    /// Effective severity of a finding: KEV is always <see cref="Severity.Critical"/>; otherwise the
    /// CVSS score, when present, replaces the severity assigned by the check; then an EPSS of at least
    /// <see cref="EpssRaiseThreshold"/> raises it by one level.
    /// </summary>
    /// <param name="finding">The finding.</param>
    /// <returns>The effective severity.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="finding"/> is <see langword="null"/>.</exception>
    public static Severity EffectiveSeverity(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        if (finding.Kev)
        {
            return Severity.Critical;
        }

        var severity = finding.Cvss is { } score ? FromCvss(score) : finding.Severity;
        return finding.Epss >= EpssRaiseThreshold && severity < Severity.Critical ? severity + 1 : severity;
    }

    /// <summary>
    /// Qualitative CVSS v3/v4 rating: 0 None (here <see cref="Severity.Info"/>), 0.1-3.9 Low,
    /// 4.0-6.9 Medium, 7.0-8.9 High, 9.0-10.0 Critical.
    /// </summary>
    /// <param name="score">CVSS base score, from 0 to 10.</param>
    /// <returns>The matching severity.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="score"/> is outside 0-10 or not a number.</exception>
    public static Severity FromCvss(double score) => score switch
    {
        0.0 => Severity.Info,
        > 0.0 and < 4.0 => Severity.Low,
        >= 4.0 and < 7.0 => Severity.Medium,
        >= 7.0 and < 9.0 => Severity.High,
        >= 9.0 and <= 10.0 => Severity.Critical,
        _ => throw new ArgumentOutOfRangeException(nameof(score), score, "Must be between 0 and 10."),
    };

    /// <summary>
    /// Returns the findings with their effective severity, most urgent first: KEV, then severity,
    /// then EPSS (missing last), then confidence, then id and target so the order is always the same.
    /// </summary>
    /// <param name="findings">The findings to prioritize.</param>
    /// <returns>A new sorted list; the input is not modified.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="findings"/> or one of its items is <see langword="null"/>.</exception>
    public static IReadOnlyList<Finding> Prioritize(IEnumerable<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        var list = findings.ToArray();
        if (list.Any(f => f is null))
        {
            throw new ArgumentNullException(nameof(findings), "A finding is null.");
        }

        return list
            .Select(f => f with { Severity = EffectiveSeverity(f) })
            .OrderByDescending(f => f.Kev)
            .ThenByDescending(f => f.Severity)
            .ThenByDescending(f => f.Epss ?? -1.0)
            .ThenByDescending(f => f.Confidence)
            .ThenBy(f => f.Id, StringComparer.Ordinal)
            .ThenBy(f => f.Target, StringComparer.Ordinal)
            .ToArray();
    }
}
