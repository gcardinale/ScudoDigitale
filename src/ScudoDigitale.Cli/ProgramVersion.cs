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

using System.Reflection;

namespace ScudoDigitale.Cli;

/// <summary>The version of the program, as written in the reports.</summary>
internal static class ProgramVersion
{
    /// <summary>The version of this build, for example <c>0.1.0</c>.</summary>
    public static string Current { get; } = Of(typeof(ProgramVersion).Assembly);

    /// <summary>
    /// The informational version of an assembly without the build metadata that the SDK appends
    /// after <c>+</c> (the commit id): the report shows the version people download.
    /// </summary>
    /// <param name="assembly">The assembly.</param>
    /// <returns>The version, or <c>0.0.0</c> when the assembly declares none.</returns>
    internal static string Of(Assembly assembly)
    {
        var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        return string.IsNullOrWhiteSpace(version) ? "0.0.0" : version.Split('+')[0];
    }
}
