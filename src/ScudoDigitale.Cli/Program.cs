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

using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace ScudoDigitale.Cli;

/// <summary>
/// Entry point of <c>scudo</c>.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Only wires the real console to CliApp, which is fully tested.")]
internal static class Program
{
    /// <summary>
    /// Runs the command line on the real console.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    /// <returns>The process exit code.</returns>
    private static int Main(string[] args)
    {
        // The banner uses box-drawing characters: make sure the Windows console shows them.
        Console.OutputEncoding = Encoding.UTF8;
        return CliApp.Run(args, Console.Out, Console.Error);
    }
}
