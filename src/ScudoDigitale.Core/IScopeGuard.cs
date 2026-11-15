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
/// Decides whether an active check may touch a target (ADR-004): only the local network of
/// this computer, or a domain whose ownership has been proven with the TXT record
/// <c>scudo-digitale-verify=&lt;token&gt;</c> or the file <c>/.well-known/scudo-digitale.txt</c>.
/// </summary>
public interface IScopeGuard
{
    /// <summary>
    /// Checks whether <paramref name="target"/> is within the verified scope.
    /// </summary>
    /// <param name="target">The target an active check wants to probe.</param>
    /// <param name="cancellationToken">Cancels the verification.</param>
    /// <returns><see langword="true"/> only if the target is verified as the user's own.</returns>
    Task<bool> IsAuthorizedAsync(Target target, CancellationToken cancellationToken);
}
