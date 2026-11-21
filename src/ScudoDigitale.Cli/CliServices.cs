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

using ScudoDigitale.Checks.Email;
using ScudoDigitale.Checks.Web;
using ScudoDigitale.Core;

namespace ScudoDigitale.Cli;

/// <summary>
/// What the commands need from the outside world, so tests can replace the network, the clock and
/// the user name.
/// </summary>
/// <param name="CreateEmailChecks">Builds the email checks for one run.</param>
/// <param name="CreateWebChecks">Builds the website checks for one run.</param>
/// <param name="Now">The current time, for the scope declaration.</param>
/// <param name="DefaultOperator">Name used when <c>--operator</c> is not given.</param>
internal sealed record CliServices(
    Func<EmailCheckOptions, IReadOnlyList<ICheck>> CreateEmailChecks,
    Func<WebCheckOptions, IReadOnlyList<ICheck>> CreateWebChecks,
    Func<DateTimeOffset> Now,
    Func<string> DefaultOperator)
{
    /// <summary>The real email and website checks, the system clock and the user name of this computer.</summary>
    public static CliServices Default { get; } = new(EmailChecks.Create, WebChecks.Create, () => DateTimeOffset.Now, () => Environment.UserName);
}
