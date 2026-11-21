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
using System.Globalization;
using ScudoDigitale.Checks.Email;
using ScudoDigitale.Checks.Web;
using ScudoDigitale.Cli.Resources;
using ScudoDigitale.Core;

namespace ScudoDigitale.Cli;

/// <summary>
/// <c>scudo scan</c>: runs the checks on the declared targets and prints the results. In v0.1 the
/// targets are domains for the email checks (<c>--mail</c>) and websites for the passive website
/// checks (<c>--web</c>); the two can be given together, also for the same domain.
/// </summary>
internal static class ScanCommand
{
    /// <summary>Exit code when there is nothing to check or an option value is not valid.</summary>
    public const int InvalidInput = 2;

    /// <summary>Builds the command.</summary>
    /// <param name="services">Checks, clock and user name.</param>
    /// <returns>The command.</returns>
    public static Command Create(CliServices services)
    {
        var mail = new Option<string[]>("--mail") { Description = Strings.MailOptionDescription, HelpName = "domain" };
        var web = new Option<string[]>("--web") { Description = Strings.WebOptionDescription, HelpName = "domain" };
        var selectors = new Option<string[]>("--dkim-selector") { Description = Strings.DkimSelectorOptionDescription, HelpName = "selector" };
        var systemDns = new Option<bool>("--system-dns") { Description = Strings.SystemDnsOptionDescription };
        var operatorName = new Option<string>("--operator") { Description = Strings.OperatorOptionDescription, HelpName = "name" };
        var role = new Option<OperatorRole>("--role") { Description = Strings.RoleOptionDescription, DefaultValueFactory = _ => OperatorRole.Owner };

        var command = new Command("scan", Strings.ScanDescription) { mail, web, selectors, systemDns, operatorName, role };
        command.SetAction((parseResult, cancellationToken) => RunAsync(
            new ScanRequest(
                parseResult.GetValue(mail) ?? [],
                parseResult.GetValue(web) ?? [],
                parseResult.GetValue(selectors) ?? [],
                parseResult.GetValue(systemDns),
                parseResult.GetValue(operatorName),
                parseResult.GetValue(role)),
            services,
            parseResult.InvocationConfiguration.Output,
            parseResult.InvocationConfiguration.Error,
            cancellationToken));
        return command;
    }

    /// <summary>Validates the request, runs the checks and prints the results.</summary>
    /// <param name="request">The parsed options.</param>
    /// <param name="services">Checks, clock and user name.</param>
    /// <param name="output">Where the results go.</param>
    /// <param name="error">Where input errors go.</param>
    /// <param name="cancellationToken">Stops the run (Ctrl+C).</param>
    /// <returns>0 when the checks ran, whatever they found; <see cref="InvalidInput"/> otherwise.</returns>
    internal static async Task<int> RunAsync(
        ScanRequest request,
        CliServices services,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        var domains = request.Domains.Where(d => !string.IsNullOrWhiteSpace(d)).ToArray();
        var sites = request.Websites.Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
        if (domains.Length + sites.Length == 0)
        {
            await error.WriteLineAsync(Strings.NoTargets).ConfigureAwait(false);
            return InvalidInput;
        }

        var hosts = new List<string>();
        foreach (var site in sites)
        {
            if (!WebChecks.TryNormalizeTarget(site, out var host))
            {
                await error.WriteLineAsync(Format(Strings.InvalidWebTarget, site)).ConfigureAwait(false);
                return InvalidInput;
            }

            hosts.Add(host);
        }

        if (request.DkimSelectors.FirstOrDefault(s => !IsSelector(s)) is { } invalid)
        {
            await error.WriteLineAsync(Format(Strings.InvalidSelector, invalid)).ConfigureAwait(false);
            return InvalidInput;
        }

        var options = new EmailCheckOptions
        {
            DkimSelectors = request.DkimSelectors,
            DnsSource = request.SystemDns ? DnsSource.System : DnsSource.Public,
        };
        var operatorName = FirstNonBlank(request.Operator, services.DefaultOperator()) ?? Strings.UnknownOperator;
        var scope = new ScopeDeclaration(
            operatorName,
            request.Role,
            domains.Select(d => new Target(TargetKind.Domain, d))
                .Concat(hosts.Select(h => new Target(TargetKind.Website, h))),
            services.Now());

        // Each area is built only when asked for: the engine runs a check on the targets of its kind.
        ICheck[] checks =
        [
            .. domains.Length > 0 ? services.CreateEmailChecks(options) : [],
            .. hosts.Count > 0 ? services.CreateWebChecks(new WebCheckOptions()) : [],
        ];

        var report = new ScanReport(output);
        report.WriteHeader(scope, checks);
        var runs = await new CheckEngine(new PassiveOnlyScopeGuard())
            .RunAsync(checks, Profile.Individual(), scope, cancellationToken)
            .ConfigureAwait(false);
        report.WriteResults(scope, runs);
        return 0;
    }

    private static bool IsSelector(string selector)
    {
        try
        {
            _ = new EmailCheckOptions { DkimSelectors = [selector] };
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static string? FirstNonBlank(params string?[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v))?.Trim();

    private static string Format(string format, params object?[] arguments) => string.Format(CultureInfo.CurrentCulture, format, arguments);
}

/// <summary>The options of <c>scudo scan</c>, after parsing.</summary>
/// <param name="Domains">Values of <c>--mail</c>.</param>
/// <param name="Websites">Values of <c>--web</c>.</param>
/// <param name="DkimSelectors">Values of <c>--dkim-selector</c>.</param>
/// <param name="SystemDns">Whether <c>--system-dns</c> was given.</param>
/// <param name="Operator">Value of <c>--operator</c>, if any.</param>
/// <param name="Role">Value of <c>--role</c>.</param>
internal sealed record ScanRequest(
    IReadOnlyList<string> Domains,
    IReadOnlyList<string> Websites,
    IReadOnlyList<string> DkimSelectors,
    bool SystemDns,
    string? Operator,
    OperatorRole Role);
