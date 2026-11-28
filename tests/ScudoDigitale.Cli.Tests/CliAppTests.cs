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

using System.Globalization;
using ScudoDigitale.Cli;
using ScudoDigitale.Core;

namespace ScudoDigitale.Cli.Tests;

public class CliAppTests
{
    [Fact]
    public void Run_WhenNoArguments_ShouldPrintBannerAttributionAndDisclaimer()
    {
        using var _ = new UiCulture("en-US");

        var (exitCode, output, error) = Run();

        Assert.Equal(0, exitCode);
        Assert.StartsWith(Attribution.Banner, output, StringComparison.Ordinal);
        Assert.Contains(Attribution.Notice, output, StringComparison.Ordinal);
        Assert.Contains("does not replace a penetration test or legal advice", output, StringComparison.Ordinal);
        Assert.Contains("scudo scan --mail", output, StringComparison.Ordinal);
        Assert.Empty(error);
    }

    [Fact]
    public void Run_WhenUiCultureIsItalian_ShouldPrintTheDisclaimerInItalian()
    {
        using var _ = new UiCulture("it-IT");

        var (_, output, _) = Run();

        Assert.Contains(Attribution.Notice, output, StringComparison.Ordinal);
        Assert.Contains("non sostituisce un penetration test né una consulenza legale", output, StringComparison.Ordinal);
    }

    [Fact]
    public void Run_WhenHelpRequested_ShouldShowTheDescription()
    {
        using var _ = new UiCulture("en-US");

        var (exitCode, output, _) = Run("--help");

        Assert.Equal(0, exitCode);
        Assert.Contains("free, open-source security self-assessment", output, StringComparison.Ordinal);
        Assert.DoesNotContain(Attribution.Banner, output, StringComparison.Ordinal);
    }

    [Fact]
    public void Run_WhenVersionRequested_ShouldPrintTheVersion()
    {
        var (exitCode, output, _) = Run("--version");

        Assert.Equal(0, exitCode);
        Assert.StartsWith(ProgramVersion.Current, output, StringComparison.Ordinal);
        // The version in Directory.Build.props reaches the program: 0.0.0 means it was lost.
        Assert.NotEqual("0.0.0", ProgramVersion.Current);
    }

    [Fact]
    public void Run_WhenArgumentIsUnknown_ShouldFailAndWriteAnError()
    {
        var (exitCode, output, error) = Run("--no-such-option");

        Assert.NotEqual(0, exitCode);
        Assert.Contains("--no-such-option", error + output, StringComparison.Ordinal);
        Assert.DoesNotContain(Attribution.Banner, output, StringComparison.Ordinal);
    }

    private static (int ExitCode, string Output, string Error) Run(params string[] args)
    {
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        using var error = new StringWriter(CultureInfo.InvariantCulture);
        var exitCode = CliApp.RunAsync(args, output, error).GetAwaiter().GetResult();
        return (exitCode, output.ToString(), error.ToString());
    }

    private sealed class UiCulture : IDisposable
    {
        private readonly CultureInfo previous = CultureInfo.CurrentCulture;
        private readonly CultureInfo previousUi = CultureInfo.CurrentUICulture;

        public UiCulture(string name)
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name);
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name);
        }

        public void Dispose()
        {
            CultureInfo.CurrentCulture = previous;
            CultureInfo.CurrentUICulture = previousUi;
        }
    }
}
