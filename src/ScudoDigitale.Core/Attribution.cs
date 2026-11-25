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
using ScudoDigitale.Core.Resources;

namespace ScudoDigitale.Core;

/// <summary>
/// Mandatory attribution (AGPL-3.0 section 7(b), see NOTICE). It must appear in the command-line
/// banner, in the About screen and in the footer of every report page. This is the only place where
/// the text is defined: do not copy it elsewhere.
/// </summary>
public static class Attribution
{
    /// <summary>Name of the program.</summary>
    public const string ProductName = "Scudo Digitale";

    /// <summary>Author and copyright holder.</summary>
    public const string Author = "Gaetano Cardinale";

    /// <summary>Website of the author.</summary>
    public const string Website = "https://gcardinale.it";

    /// <summary>SPDX identifier of the license.</summary>
    public const string License = "AGPL-3.0-or-later";

    /// <summary>The attribution line: "Scudo Digitale — © Gaetano Cardinale — https://gcardinale.it".</summary>
    public const string Notice = ProductName + " — © " + Author + " — " + Website;

    /// <summary>Startup banner of the command line, ending with <see cref="Notice"/>.</summary>
    public const string Banner =
        """
        ╔═══════════════════════════════════════════════════════════════╗
        ║   ███████╗ ██████╗██╗   ██╗██████╗  ██████╗                   ║
        ║   ██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗                  ║
        ║   ███████╗██║     ██║   ██║██║  ██║██║   ██║                  ║
        ║   ╚════██║██║     ██║   ██║██║  ██║██║   ██║                  ║
        ║   ███████║╚██████╗╚██████╔╝██████╔╝╚██████╔╝  D I G I T A L E ║
        ║   ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝                   ║
        ╚═══════════════════════════════════════════════════════════════╝
        """
        + "\n" + Notice;

    /// <summary>
    /// Footer for every report page, for example
    /// "Report generated with Scudo Digitale v1.0 — © Gaetano Cardinale — https://gcardinale.it — AGPL-3.0-or-later".
    /// Only the leading words are localized; the attribution itself never changes.
    /// </summary>
    /// <param name="version">Program version, for example <c>1.0</c>.</param>
    /// <returns>The footer text in the current UI language.</returns>
    /// <exception cref="ArgumentException"><paramref name="version"/> is empty or blank.</exception>
    public static string ReportFooter(string version) => ReportFooter(version, CultureInfo.CurrentUICulture);

    /// <summary>
    /// Footer for every report page, with the leading words in the language of <paramref name="culture"/>:
    /// a report keeps the language it was written in, whatever the language of the computer that renders it.
    /// </summary>
    /// <param name="version">Program version, for example <c>1.0</c>.</param>
    /// <param name="culture">Language of the report.</param>
    /// <returns>The footer text.</returns>
    /// <exception cref="ArgumentException"><paramref name="version"/> is empty or blank.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="culture"/> is <see langword="null"/>.</exception>
    public static string ReportFooter(string version, CultureInfo culture)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        ArgumentNullException.ThrowIfNull(culture);
        var leading = Strings.ResourceManager.GetString(nameof(Strings.ReportGeneratedWith), culture);
        return $"{leading} {ProductName} v{version.Trim()} — © {Author} — {Website} — {License}";
    }
}
