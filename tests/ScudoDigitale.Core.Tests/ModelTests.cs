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

using ScudoDigitale.Core;

namespace ScudoDigitale.Core.Tests;

public class TargetTests
{
    [Fact]
    public void Constructor_WhenValueHasSpaces_ShouldTrimIt()
    {
        var target = new Target(TargetKind.Domain, "  example.com ");

        Assert.Equal(TargetKind.Domain, target.Kind);
        Assert.Equal("example.com", target.Value);
        Assert.Equal("Domain:example.com", target.ToString());
    }

    [Fact]
    public void Equality_WhenKindAndValueMatch_ShouldBeEqual()
    {
        Assert.Equal(new Target(TargetKind.Domain, "example.com"), new Target(TargetKind.Domain, " example.com"));
        Assert.NotEqual(new Target(TargetKind.Domain, "example.com"), new Target(TargetKind.Website, "example.com"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void Constructor_WhenValueIsBlank_ShouldThrow(string value)
    {
        Assert.Throws<ArgumentException>(() => new Target(TargetKind.Domain, value));
    }

    [Fact]
    public void Constructor_WhenValueIsNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => new Target(TargetKind.Domain, null!));
    }

    [Fact]
    public void Constructor_WhenKindIsUndefined_ShouldThrow()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new Target((TargetKind)999, "example.com"));
    }
}

public class ProfileTests
{
    [Fact]
    public void Individual_WhenCreated_ShouldHaveNoCompanyData()
    {
        var profile = Profile.Individual();

        Assert.Equal(ProfileKind.Individual, profile.Kind);
        Assert.Null(profile.CompanyName);
        Assert.Null(profile.VatNumber);
        Assert.Null(profile.AtecoCode);
        Assert.Null(profile.Employees);
        Assert.Null(profile.AnnualTurnoverEur);
    }

    [Fact]
    public void Company_WhenAllDataGiven_ShouldKeepTrimmedValues()
    {
        var profile = Profile.Company(" Casa SRL ", 12, 1_500_000m, " IT01234567890 ", " 62.01 ");

        Assert.Equal(ProfileKind.Company, profile.Kind);
        Assert.Equal("Casa SRL", profile.CompanyName);
        Assert.Equal(12, profile.Employees);
        Assert.Equal(1_500_000m, profile.AnnualTurnoverEur);
        Assert.Equal("IT01234567890", profile.VatNumber);
        Assert.Equal("62.01", profile.AtecoCode);
    }

    [Fact]
    public void Company_WhenOptionalTextsAreBlank_ShouldStoreNull()
    {
        var profile = Profile.Company("Casa SRL", vatNumber: "  ", atecoCode: "");

        Assert.Null(profile.VatNumber);
        Assert.Null(profile.AtecoCode);
    }

    [Fact]
    public void Company_WhenNumbersAreZero_ShouldAcceptThem()
    {
        var profile = Profile.Company("Casa SRL", 0, 0m);

        Assert.Equal(0, profile.Employees);
        Assert.Equal(0m, profile.AnnualTurnoverEur);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Company_WhenNameIsBlank_ShouldThrow(string name)
    {
        Assert.Throws<ArgumentException>(() => Profile.Company(name));
    }

    [Fact]
    public void Company_WhenEmployeesAreNegative_ShouldThrow()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Profile.Company("Casa SRL", employees: -1));
    }

    [Fact]
    public void Company_WhenTurnoverIsNegative_ShouldThrow()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Profile.Company("Casa SRL", annualTurnoverEur: -0.01m));
    }
}

public class ScopeDeclarationTests
{
    private static readonly Target Domain = new(TargetKind.Domain, "example.com");
    private static readonly Target Network = new(TargetKind.Network, "192.168.1.0/24");

    [Fact]
    public void Constructor_WhenValid_ShouldKeepValuesAndRemoveDuplicatesInOrder()
    {
        var scope = new ScopeDeclaration(
            " Mario Rossi ",
            OperatorRole.SecurityOfficer,
            [Network, Domain, new Target(TargetKind.Network, "192.168.1.0/24")],
            Make.DeclaredAt);

        Assert.Equal("Mario Rossi", scope.OperatorName);
        Assert.Equal(OperatorRole.SecurityOfficer, scope.OperatorRole);
        Assert.Equal([Network, Domain], scope.Targets);
        Assert.Equal(Make.DeclaredAt, scope.DeclaredAt);
    }

    [Fact]
    public void Constructor_WhenSourceListChangesLater_ShouldNotBeAffected()
    {
        var source = new List<Target> { Domain };
        var scope = new ScopeDeclaration("Mario Rossi", OperatorRole.Owner, source, Make.DeclaredAt);

        source.Add(Network);

        Assert.Single(scope.Targets);
    }

    [Fact]
    public void Constructor_WhenNameIsBlank_ShouldThrow()
    {
        Assert.Throws<ArgumentException>(() => new ScopeDeclaration(" ", OperatorRole.Owner, [Domain], Make.DeclaredAt));
    }

    [Fact]
    public void Constructor_WhenTargetsAreEmpty_ShouldThrow()
    {
        Assert.Throws<ArgumentException>(() => new ScopeDeclaration("Mario Rossi", OperatorRole.Owner, [], Make.DeclaredAt));
    }

    [Fact]
    public void Constructor_WhenTargetsAreNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => new ScopeDeclaration("Mario Rossi", OperatorRole.Owner, null!, Make.DeclaredAt));
    }

    [Fact]
    public void Constructor_WhenATargetIsNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => new ScopeDeclaration("Mario Rossi", OperatorRole.Owner, [Domain, null!], Make.DeclaredAt));
    }

    [Fact]
    public void Constructor_WhenRoleIsUndefined_ShouldThrow()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ScopeDeclaration("Mario Rossi", (OperatorRole)42, [Domain], Make.DeclaredAt));
    }
}

public class CheckResultTests
{
    [Fact]
    public void Executed_WhenSourceListChangesLater_ShouldNotBeAffected()
    {
        var source = new List<Finding> { Make.Finding() };
        var result = new CheckResult.Executed(source);

        source.Clear();

        Assert.Single(result.Findings);
    }

    [Fact]
    public void Executed_WhenEmpty_ShouldBeAllowed()
    {
        Assert.Empty(new CheckResult.Executed([]).Findings);
    }

    [Fact]
    public void Executed_WhenFindingsAreNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => new CheckResult.Executed(null!));
    }

    [Fact]
    public void Executed_WhenAFindingIsNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => new CheckResult.Executed([Make.Finding(), null!]));
    }

    [Fact]
    public void Skipped_WhenReasonGiven_ShouldKeepIt()
    {
        Assert.Equal("requires Linux with BlueZ", new CheckResult.Skipped("requires Linux with BlueZ").Reason);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void Skipped_WhenReasonIsBlank_ShouldThrow(string reason)
    {
        Assert.Throws<ArgumentException>(() => new CheckResult.Skipped(reason));
    }

    [Fact]
    public void Failed_WhenErrorGiven_ShouldKeepIt()
    {
        Assert.Equal("DNS timeout", new CheckResult.Failed("DNS timeout").Error);
    }

    [Theory]
    [InlineData("")]
    [InlineData("  ")]
    public void Failed_WhenErrorIsBlank_ShouldThrow(string error)
    {
        Assert.Throws<ArgumentException>(() => new CheckResult.Failed(error));
    }
}

public class CheckEngineOptionsTests
{
    [Fact]
    public void Defaults_WhenCreated_ShouldBeCautious()
    {
        var options = new CheckEngineOptions();

        Assert.Equal(4, options.MaxConcurrentChecks);
        Assert.Equal(TimeSpan.FromSeconds(60), options.CheckTimeout);
    }

    [Fact]
    public void Init_WhenValuesAreAtTheLowerBound_ShouldAcceptThem()
    {
        var options = new CheckEngineOptions { MaxConcurrentChecks = 1, CheckTimeout = TimeSpan.FromTicks(1) };

        Assert.Equal(1, options.MaxConcurrentChecks);
        Assert.Equal(TimeSpan.FromTicks(1), options.CheckTimeout);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void MaxConcurrentChecks_WhenLessThanOne_ShouldThrow(int value)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CheckEngineOptions { MaxConcurrentChecks = value });
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void CheckTimeout_WhenNotPositive_ShouldThrow(long ticks)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new CheckEngineOptions { CheckTimeout = TimeSpan.FromTicks(ticks) });
    }
}
