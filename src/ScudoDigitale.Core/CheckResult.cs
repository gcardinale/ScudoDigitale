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
/// Outcome of running a check: <see cref="Executed"/>, <see cref="Skipped"/> or <see cref="Failed"/>.
/// A check reports problems through this type and never throws towards the engine.
/// </summary>
public abstract record CheckResult
{
    private CheckResult()
    {
    }

    /// <summary>
    /// The check ran. An empty list means nothing was found.
    /// </summary>
    public sealed record Executed : CheckResult
    {
        /// <summary>
        /// Creates an executed result.
        /// </summary>
        /// <param name="findings">What the check found; may be empty.</param>
        /// <exception cref="ArgumentNullException"><paramref name="findings"/> or one of its items is <see langword="null"/>.</exception>
        public Executed(IEnumerable<Finding> findings)
        {
            ArgumentNullException.ThrowIfNull(findings);
            var list = findings.ToArray();
            if (list.Any(f => f is null))
            {
                throw new ArgumentNullException(nameof(findings), "A finding is null.");
            }

            Findings = list;
        }

        /// <summary>What the check found; may be empty.</summary>
        public IReadOnlyList<Finding> Findings { get; }
    }

    /// <summary>
    /// The check could not run here (platform, privileges, scope) and says why. Shown in the report.
    /// </summary>
    public sealed record Skipped : CheckResult
    {
        /// <summary>
        /// Creates a skipped result.
        /// </summary>
        /// <param name="reason">User-facing, localized reason.</param>
        /// <exception cref="ArgumentException"><paramref name="reason"/> is empty or blank.</exception>
        public Skipped(string reason)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(reason);
            Reason = reason;
        }

        /// <summary>User-facing, localized reason.</summary>
        public string Reason { get; }
    }

    /// <summary>
    /// The check tried to run and failed. Shown in the report; the other checks continue.
    /// </summary>
    public sealed record Failed : CheckResult
    {
        /// <summary>
        /// Creates a failed result.
        /// </summary>
        /// <param name="error">User-facing, localized description of the error.</param>
        /// <exception cref="ArgumentException"><paramref name="error"/> is empty or blank.</exception>
        public Failed(string error)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(error);
            Error = error;
        }

        /// <summary>User-facing, localized description of the error.</summary>
        public string Error { get; }
    }
}
