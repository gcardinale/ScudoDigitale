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
using System.Reflection.Emit;

namespace ScudoDigitale.Cli.Tests;

public sealed class ProgramVersionTests
{
    [Fact]
    public void Of_WhenVersionHasBuildMetadata_ShouldDropIt()
    {
        Assert.Equal("1.2.3", ProgramVersion.Of(Dynamic("1.2.3+5c66f18")));
        Assert.Equal("0.1.0-beta", ProgramVersion.Of(Dynamic("0.1.0-beta")));
    }

    [Fact]
    public void Of_WhenAssemblyDeclaresNoVersion_ShouldBeZero()
    {
        Assert.Equal("0.0.0", ProgramVersion.Of(Dynamic(null)));
        Assert.Equal("0.0.0", ProgramVersion.Of(Dynamic(" ")));
    }

    [Fact]
    public void Current_WhenRead_ShouldBeTheVersionOfTheBuildWithoutMetadata()
    {
        Assert.Equal(ProgramVersion.Of(typeof(ProgramVersion).Assembly), ProgramVersion.Current);
        Assert.DoesNotContain('+', ProgramVersion.Current);
    }

    private static AssemblyBuilder Dynamic(string? informationalVersion)
    {
        var attributes = informationalVersion is null
            ? []
            : new[] { new CustomAttributeBuilder(typeof(AssemblyInformationalVersionAttribute).GetConstructor([typeof(string)])!, [informationalVersion]) };
        return AssemblyBuilder.DefineDynamicAssembly(new AssemblyName("VersionProbe" + Guid.NewGuid().ToString("N")), AssemblyBuilderAccess.Run, attributes);
    }
}
