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
using ScudoDigitale.Checks.Email.Resources;
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Email;

/// <summary>Helpers shared by the email rules to build findings and results.</summary>
internal static class EmailFinding
{
    /// <summary>Creates an email finding.</summary>
    /// <param name="id">Id of the check.</param>
    /// <param name="title">Localized title.</param>
    /// <param name="severity">Severity.</param>
    /// <param name="confidence">Confidence.</param>
    /// <param name="target">The domain.</param>
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
        new(id, CheckArea.Email, title, severity, confidence, target)
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

    /// <summary>Result of a DNS query that failed.</summary>
    /// <param name="name">The name that was queried.</param>
    /// <param name="error">What went wrong.</param>
    /// <returns>The result.</returns>
    public static CheckResult DnsFailed(string name, string? error) =>
        new CheckResult.Failed(Format(Strings.DnsQueryFailed, name, error ?? string.Empty));

    /// <summary>Formats a localized text with the current culture.</summary>
    /// <param name="format">The localized format.</param>
    /// <param name="arguments">Its arguments.</param>
    /// <returns>The text.</returns>
    public static string Format(string format, params object?[] arguments) =>
        string.Format(CultureInfo.CurrentCulture, format, arguments);
}
