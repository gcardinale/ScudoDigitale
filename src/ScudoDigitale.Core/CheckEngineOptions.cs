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
/// Limits applied by <see cref="CheckEngine"/>. The defaults are cautious, so as not to
/// disturb fragile home devices.
/// </summary>
public sealed record CheckEngineOptions
{
    private readonly int maxConcurrentChecks = 4;
    private readonly TimeSpan checkTimeout = TimeSpan.FromSeconds(60);

    /// <summary>Upper limit of <see cref="CheckTimeout"/>: one hour.</summary>
    public static readonly TimeSpan MaxCheckTimeout = TimeSpan.FromHours(1);

    /// <summary>How many checks may run at the same time. Default 4.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is less than 1.</exception>
    public int MaxConcurrentChecks
    {
        get => maxConcurrentChecks;
        init => maxConcurrentChecks = value >= 1
            ? value
            : throw new ArgumentOutOfRangeException(nameof(MaxConcurrentChecks), value, "Must be at least 1.");
    }

    /// <summary>
    /// Maximum duration of a single check, scope verification included. Default 60 seconds, at most
    /// <see cref="MaxCheckTimeout"/>. A check that ignores the timeout keeps its concurrency slot for at
    /// most another <see cref="CheckTimeout"/> before the slot is given to the next check.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is zero, negative or above <see cref="MaxCheckTimeout"/>.</exception>
    public TimeSpan CheckTimeout
    {
        get => checkTimeout;
        init => checkTimeout = value > TimeSpan.Zero && value <= MaxCheckTimeout
            ? value
            : throw new ArgumentOutOfRangeException(nameof(CheckTimeout), value, "Must be positive and at most one hour.");
    }
}
