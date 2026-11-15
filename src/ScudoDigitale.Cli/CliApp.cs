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

using System.CommandLine;
using ScudoDigitale.Cli.Resources;
using ScudoDigitale.Core;

namespace ScudoDigitale.Cli;

/// <summary>
/// Builds and runs the <c>scudo</c> command line. Kept separate from <see cref="Program"/>
/// so it can be tested with in-memory writers.
/// </summary>
internal static class CliApp
{
    /// <summary>
    /// Parses <paramref name="args"/> and runs the matching command.
    /// </summary>
    /// <param name="args">Command-line arguments.</param>
    /// <param name="output">Where normal output is written.</param>
    /// <param name="error">Where errors are written.</param>
    /// <returns>The process exit code: 0 on success.</returns>
    public static int Run(string[] args, TextWriter output, TextWriter error)
    {
        var root = BuildRootCommand();
        var configuration = new InvocationConfiguration { Output = output, Error = error };
        return root.Parse(args).Invoke(configuration);
    }

    /// <summary>
    /// Builds the root command. Without a subcommand it prints the banner, the attribution and the
    /// self-assessment warning (docs/00-functional-spec.md §1).
    /// </summary>
    /// <returns>The root command.</returns>
    internal static RootCommand BuildRootCommand()
    {
        var root = new RootCommand(Strings.RootDescription);
        root.SetAction(parseResult =>
        {
            var output = parseResult.InvocationConfiguration.Output;
            output.WriteLine(Attribution.Banner);
            output.WriteLine();
            output.WriteLine(Strings.Disclaimer);
            output.WriteLine();
            output.WriteLine(Strings.UsageHint);
            return 0;
        });
        return root;
    }
}
