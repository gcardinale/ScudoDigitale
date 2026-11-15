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
/// A single security check. Implementations must not throw: problems are reported as
/// <see cref="CheckResult.Skipped"/> or <see cref="CheckResult.Failed"/>. If one throws anyway,
/// <see cref="CheckEngine"/> turns the exception into <see cref="CheckResult.Failed"/>.
/// </summary>
public interface ICheck
{
    /// <summary>Stable id in the form <c>AREA-TOPIC-NNN</c>, for example <c>MAIL-DMARC-001</c>.</summary>
    string Id { get; }

    /// <summary>Area the check belongs to.</summary>
    CheckArea Area { get; }

    /// <summary>Kind of target the check applies to.</summary>
    TargetKind AppliesTo { get; }

    /// <summary>
    /// Whether the check is passive or needs the target to be in the verified scope.
    /// </summary>
    ScopeRequirement Scope { get; }

    /// <summary>
    /// Runs the check against <see cref="CheckContext.Target"/>.
    /// </summary>
    /// <param name="context">Target, profile and scope declaration.</param>
    /// <param name="cancellationToken">Cancelled when the user stops the run or the check times out.</param>
    /// <returns>The outcome of the check.</returns>
    Task<CheckResult> RunAsync(CheckContext context, CancellationToken cancellationToken);
}
