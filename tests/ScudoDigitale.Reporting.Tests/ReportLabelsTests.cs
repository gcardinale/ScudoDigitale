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

namespace ScudoDigitale.Reporting.Tests;

public sealed class ReportLabelsTests
{
    [Fact]
    public void For_WhenLanguageIsUnknownToThePlatform_ShouldFallBackToEnglish()
    {
        var labels = ReportLabels.For(Make.Document() with { Language = "not a culture name!" });

        Assert.Equal("en", labels.Culture.Name);
        Assert.Equal("Risk", labels.Get("RiskLabel"));
    }

    [Fact]
    public void For_WhenThreadIsEnglish_ShouldUseTheLanguageOfTheDocument()
    {
        using var _ = new UiCulture("en-US");

        var labels = ReportLabels.For(Make.Document() with { Language = "it-IT" });

        Assert.Equal("Rischio", labels.Get("RiskLabel"));
        Assert.Equal("Alto", labels.Severity(Severity.High));
        Assert.Equal("da verificare", labels.Confidence(Confidence.ToBeVerified));
        Assert.Equal("incaricato", labels.Role(OperatorRole.AppointedPerson));
        Assert.Equal("Rete locale", labels.Area(CheckArea.Network));
        Assert.Equal("questo computer", labels.TargetKind(TargetKind.LocalMachine));
        Assert.Equal(Make.DeclaredAt.ToString("g", System.Globalization.CultureInfo.GetCultureInfo("it-IT")), labels.Date(Make.DeclaredAt));
        Assert.StartsWith("25/11/2026", labels.Date(Make.DeclaredAt), StringComparison.Ordinal);
    }

    [Fact]
    public void Get_WhenNameIsUnknown_ShouldReturnTheName()
    {
        Assert.Equal("NoSuchLabel", ReportLabels.For(Make.Document()).Get("NoSuchLabel"));
    }

    [Fact]
    public void Profile_WhenCompanyHasMissingValues_ShouldSayNotGiven()
    {
        var labels = ReportLabels.For(Make.Document() with { Language = "en-US" });

        var text = labels.Profile(new ReportProfile { Kind = ProfileKind.Company });

        Assert.Equal("not given (employees: not given · annual turnover: not given · VAT number: not given · ATECO: not given)", text);
    }

    [Fact]
    public void Profile_WhenCompanyIsComplete_ShouldFormatNumbersInTheLanguageOfTheReport()
    {
        var labels = ReportLabels.For(Make.Document() with { Language = "it-IT" });
        var profile = new ReportProfile { Kind = ProfileKind.Company, CompanyName = "Rossi SRL", Employees = 1200, AnnualTurnoverEur = 10_000_000m, VatNumber = "IT01234567890", AtecoCode = "62.01" };

        Assert.Equal("Rossi SRL (dipendenti: 1.200 · fatturato annuo: 10.000.000 € · partita IVA: IT01234567890 · ATECO: 62.01)", labels.Profile(profile));
        Assert.Equal("una persona", labels.Profile(new ReportProfile { Kind = ProfileKind.Individual }));
    }

    [Fact]
    public void Targets_WhenThereAreNone_ShouldSayQuestionnairesOnly()
    {
        var labels = ReportLabels.For(Make.Document() with { Language = "en-US" });

        Assert.Equal("no system: questionnaires only", labels.Targets(new ReportDeclaration { OperatorName = "x", OperatorRole = OperatorRole.Owner, DeclaredAt = Make.DeclaredAt }));
        Assert.Equal("example.com (domain), www.example.com (website)", labels.Targets(Make.Document().Declaration));
    }

    [Fact]
    public void SectionHeading_WhenTargetIsMissing_ShouldShowOnlyTheArea()
    {
        var labels = ReportLabels.For(Make.Document() with { Language = "en-US" });

        Assert.Equal("Email — example.com", labels.SectionHeading(new ReportSection { Area = CheckArea.Email, Target = "example.com" }));
        Assert.Equal("NIS2", labels.SectionHeading(new ReportSection { Area = CheckArea.Nis2 }));
    }

    [Fact]
    public void VulnerabilityDatabase_WhenVersionIsKnown_ShouldShowIt()
    {
        var document = Make.Document() with { Language = "en-US" };
        var labels = ReportLabels.For(document);

        Assert.Equal("CVE database: not used in this version", labels.VulnerabilityDatabase(document));
        Assert.Equal("CVE database: 2026-11-25", labels.VulnerabilityDatabase(document with { VulnerabilityDatabaseVersion = "2026-11-25" }));
    }

    [Fact]
    public void SaysNoProblems_WhenNothingWasChecked_ShouldBeFalse()
    {
        var passed = new[] { new ReportCheck("MAIL-SPF-001", "SPF") };
        var finding = Make.Document().Sections[0].Findings;

        Assert.True(ReportLabels.SaysNoProblems(new ReportSection { Area = CheckArea.Email, Passed = passed }));
        Assert.False(ReportLabels.SaysNoProblems(new ReportSection { Area = CheckArea.Email, Skipped = passed, Failed = passed }));
        Assert.False(ReportLabels.SaysNoProblems(new ReportSection { Area = CheckArea.Email, Passed = passed, Findings = finding }));
    }

    [Theory]
    [InlineData(Severity.Critical, "sev-critical")]
    [InlineData(Severity.Info, "sev-info")]
    public void SeverityClass_WhenCalled_ShouldBeLowerCase(Severity severity, string expected)
    {
        Assert.Equal(expected, ReportLabels.SeverityClass(severity));
    }
}
