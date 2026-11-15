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
    public static string ReportFooter(string version)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(version);
        return $"{Strings.ReportGeneratedWith} {ProductName} v{version.Trim()} — © {Author} — {Website} — {License}";
    }
}
