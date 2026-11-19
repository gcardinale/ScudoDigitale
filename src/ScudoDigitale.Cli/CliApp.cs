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
    /// <param name="services">Checks, clock and user name; the real ones when <see langword="null"/>.</param>
    /// <param name="cancellationToken">Stops a running scan.</param>
    /// <returns>The process exit code: 0 on success, 1 for a wrong command line, 2 for invalid input.</returns>
    public static Task<int> RunAsync(
        string[] args,
        TextWriter output,
        TextWriter error,
        CliServices? services = null,
        CancellationToken cancellationToken = default)
    {
        var root = BuildRootCommand(services ?? CliServices.Default);
        var configuration = new InvocationConfiguration { Output = output, Error = error };
        return root.Parse(args).InvokeAsync(configuration, cancellationToken);
    }

    /// <summary>
    /// Builds the root command. Without a subcommand it prints the banner, the attribution and the
    /// self-assessment warning (docs/00-functional-spec.md §1).
    /// </summary>
    /// <param name="services">Checks, clock and user name for the subcommands.</param>
    /// <returns>The root command.</returns>
    internal static RootCommand BuildRootCommand(CliServices services)
    {
        var root = new RootCommand(Strings.RootDescription) { ScanCommand.Create(services) };
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
