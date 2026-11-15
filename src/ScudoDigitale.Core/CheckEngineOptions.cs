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

    /// <summary>How many checks may run at the same time. Default 4.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is less than 1.</exception>
    public int MaxConcurrentChecks
    {
        get => maxConcurrentChecks;
        init => maxConcurrentChecks = value >= 1
            ? value
            : throw new ArgumentOutOfRangeException(nameof(MaxConcurrentChecks), value, "Must be at least 1.");
    }

    /// <summary>Maximum duration of a single check, scope verification included. Default 60 seconds.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is zero or negative.</exception>
    public TimeSpan CheckTimeout
    {
        get => checkTimeout;
        init => checkTimeout = value > TimeSpan.Zero
            ? value
            : throw new ArgumentOutOfRangeException(nameof(CheckTimeout), value, "Must be positive.");
    }
}
