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

using System.Xml.Linq;

namespace ScudoDigitale.Cli.Tests;

/// <summary>
/// The executables ship THIRD-PARTY-NOTICES.txt with the licenses of the libraries inside them: when a
/// library is added or moved to another version, the file has to follow, or the notices lie.
/// </summary>
public class ThirdPartyNoticesTests
{
    // Used only by the tests, never shipped in the executables.
    private static readonly string[] TestOnly = ["xunit.v3", "coverlet.MTP"];

    [Fact]
    public void Notices_WhenComparedWithCentralPackages_ShouldListEveryShippedPackageWithItsVersion()
    {
        var root = RepositoryRoot();
        var notices = File.ReadAllLines(Path.Combine(root, "THIRD-PARTY-NOTICES.txt"));
        var packages = XDocument.Load(Path.Combine(root, "Directory.Packages.props"))
            .Descendants("PackageVersion")
            .Select(p => (Name: (string)p.Attribute("Include")!, Version: (string)p.Attribute("Version")!))
            .Where(p => !TestOnly.Contains(p.Name))
            .ToList();

        Assert.NotEmpty(packages);
        Assert.All(packages, p => Assert.Contains(
            notices,
            line => line.StartsWith(p.Name + " ", StringComparison.Ordinal) && line.Contains($" {p.Version} ", StringComparison.Ordinal)));
    }

    [Fact]
    public void Notices_WhenRead_ShouldStateTheAgplVersionOfTheExecutableAndWhereThePdfSharpSourceIs()
    {
        var notices = File.ReadAllText(Path.Combine(RepositoryRoot(), "THIRD-PARTY-NOTICES.txt"));

        Assert.Contains("conveyed under the GNU AGPL version 3", notices, StringComparison.Ordinal);
        Assert.Contains("https://github.com/empira/PDFsharp", notices, StringComparison.Ordinal);
        Assert.Contains("DOTNET-THIRD-PARTY-NOTICES.txt", notices, StringComparison.Ordinal);
    }

    private static string RepositoryRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "ScudoDigitale.sln")))
            {
                return dir.FullName;
            }
        }

        throw new InvalidOperationException("ScudoDigitale.sln not found above " + AppContext.BaseDirectory);
    }
}
