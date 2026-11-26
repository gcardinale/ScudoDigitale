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

public sealed class ReportBuilderTests
{
    [Fact]
    public void Build_WhenRunsCoverTwoAreas_ShouldOrderSectionsAsTheSpecThenByDeclarationOrder()
    {
        var second = new Target(TargetKind.Domain, "second.example");
        CheckRun[] runs =
        [
            Make.Executed(second, "MAIL-SPF-001"),
            Make.Executed(Make.Mail, "MAIL-SPF-001"),
            Make.Executed(Make.Site, "WEB-HSTS-001"),
        ];

        var document = ReportBuilder.Build(Make.Scope(Make.Mail, second, Make.Site), Profile.Individual(), runs, "0.1.0", Make.GeneratedAt);

        // Spec §4: websites come before email, whatever the order of the declaration.
        Assert.Equal(
            [(CheckArea.Web, "www.example.com"), (CheckArea.Email, "example.com"), (CheckArea.Email, "second.example")],
            document.Sections.Select(s => (s.Area, s.Target)));
    }

    [Fact]
    public void Build_WhenSectionHasSeveralFindings_ShouldSortThemMostUrgentFirstWithEffectiveSeverity()
    {
        var cve = new Finding("MAIL-TLS-001", CheckArea.Email, "Old server", Severity.Low, Confidence.Certain, "example.com") { Cvss = 9.8 };
        var runs = new[]
        {
            Make.Executed(Make.Mail, "MAIL-DMARC-001", Make.Finding("MAIL-DMARC-001", Severity.Medium)),
            Make.Executed(Make.Mail, "MAIL-TLS-001", cve),
        };

        var findings = ReportBuilder.Build(Make.Scope(Make.Mail), Profile.Individual(), runs, "0.1.0", Make.GeneratedAt).Sections.Single().Findings;

        Assert.Equal(["MAIL-TLS-001", "MAIL-DMARC-001"], findings.Select(f => f.Id));
        Assert.Equal(Severity.Low, findings[0].Severity);
        Assert.Equal(Severity.Critical, findings[0].EffectiveSeverity);
        Assert.Equal(9.8, findings[0].Cvss);
    }

    [Fact]
    public void Build_WhenFindingHasEveryField_ShouldCopyThemAll()
    {
        var web = Make.Document().Sections.Single(s => s.Area == CheckArea.Web);

        var kev = web.Findings[0];
        Assert.Equal("WEB-CMS-001", kev.Id);
        Assert.Equal(CheckArea.Web, kev.Area);
        Assert.Equal("Outdated CMS", kev.Title);
        Assert.Equal(Severity.Low, kev.Severity);
        Assert.Equal(Severity.Critical, kev.EffectiveSeverity);
        Assert.Equal(Confidence.Probable, kev.Confidence);
        Assert.Equal("www.example.com", kev.Target);
        Assert.Equal("generator: WordPress 5.0", kev.Evidence);
        Assert.Equal(["CVE-2019-8942"], kev.Cve);
        Assert.Equal(8.8, kev.Cvss);
        Assert.Equal(0.97, kev.Epss);
        Assert.True(kev.Kev);
        Assert.Null(kev.Risk);
        Assert.Equal("Update WordPress.", kev.Fix);
        Assert.Equal(["CISA KEV"], kev.References);
    }

    [Fact]
    public void Build_WhenChecksPassSkipOrFail_ShouldListEachWithItsDetail()
    {
        var email = Make.Document().Sections.Single(s => s.Area == CheckArea.Email);

        Assert.Equal([new ReportCheck("MAIL-SPF-001", "Check MAIL-SPF-001")], email.Passed);
        Assert.Equal([new ReportCheck("MAIL-DKIM-002", "Check MAIL-DKIM-002", "no key to look at")], email.Skipped);
        Assert.Equal([new ReportCheck("MAIL-MX-001", "Check MAIL-MX-001", "DNS timeout")], email.Failed);
        Assert.Equal(["MAIL-DMARC-001"], email.Findings.Select(f => f.Id));
    }

    [Fact]
    public void Build_WhenCalled_ShouldCopyDeclarationProfileVersionAndNotes()
    {
        var document = ReportBuilder.Build(
            Make.Scope(Make.Mail, Make.Site),
            Profile.Company("Rossi SRL", 12, 1_500_000m, "IT01234567890", "62.01"),
            [],
            " 0.1.0 ",
            Make.GeneratedAt,
            [" a note ", "", "   "]);

        Assert.Equal(ReportDocument.CurrentSchemaVersion, document.SchemaVersion);
        Assert.Equal("Scudo Digitale", document.Program);
        Assert.Equal("0.1.0", document.ProgramVersion);
        Assert.Null(document.VulnerabilityDatabaseVersion);
        Assert.Equal(Make.GeneratedAt, document.GeneratedAt);
        Assert.Equal("Mario Rossi", document.Declaration.OperatorName);
        Assert.Equal(OperatorRole.SecurityOfficer, document.Declaration.OperatorRole);
        Assert.Equal(Make.DeclaredAt, document.Declaration.DeclaredAt);
        Assert.Equal([new ReportTarget(TargetKind.Domain, "example.com"), new ReportTarget(TargetKind.Website, "www.example.com")], document.Declaration.Targets);
        Assert.Equal(ProfileKind.Company, document.Profile.Kind);
        Assert.Equal("Rossi SRL", document.Profile.CompanyName);
        Assert.Equal(12, document.Profile.Employees);
        Assert.Equal(1_500_000m, document.Profile.AnnualTurnoverEur);
        Assert.Equal("IT01234567890", document.Profile.VatNumber);
        Assert.Equal("62.01", document.Profile.AtecoCode);
        Assert.Equal(["a note"], document.Notes);
        Assert.Empty(document.Sections);
    }

    [Fact]
    public void Build_WhenQuestionnairesAreGiven_ShouldPlaceThemByAreaAfterTheTechnicalSections()
    {
        var nis2 = ReportBuilder.QuestionnaireSection(CheckArea.Nis2, [], []);
        var gdpr = ReportBuilder.QuestionnaireSection(CheckArea.Gdpr, [], []);
        var email = ReportBuilder.QuestionnaireSection(CheckArea.Email, [], []);

        var document = ReportBuilder.Build(
            Make.Scope(Make.Mail),
            Profile.Individual(),
            [Make.Executed(Make.Mail, "MAIL-SPF-001")],
            "0.1.0",
            Make.GeneratedAt,
            questionnaires: [nis2, email, gdpr]);

        // In the same area the technical section stays first: the sort is stable.
        Assert.Equal(
            [(CheckArea.Email, "example.com"), (CheckArea.Email, null), (CheckArea.Gdpr, null), (CheckArea.Nis2, null)],
            document.Sections.Select(s => (s.Area, s.Target)));
    }

    [Fact]
    public void Build_WhenRunTargetIsNotDeclared_ShouldPutItLastInItsArea()
    {
        var undeclared = new Target(TargetKind.Domain, "aaa.example");

        var document = ReportBuilder.Build(
            Make.Scope(Make.Mail),
            Profile.Individual(),
            [Make.Executed(undeclared, "MAIL-SPF-001"), Make.Executed(Make.Mail, "MAIL-SPF-001")],
            "0.1.0",
            Make.GeneratedAt);

        Assert.Equal(["example.com", "aaa.example"], document.Sections.Select(s => s.Target));
    }

    [Theory]
    [InlineData("it-IT", "it-IT")]
    [InlineData("en-US", "en-US")]
    [InlineData("", "en")]
    public void Build_WhenUiCultureIsSet_ShouldRecordItAsTheLanguage(string culture, string expected)
    {
        using var _ = new UiCulture(culture);

        var document = ReportBuilder.Build(Make.Scope(), Profile.Individual(), [], "0.1.0", Make.GeneratedAt);

        Assert.Equal(expected, document.Language);
    }

    [Fact]
    public void Build_WhenAnArgumentIsMissing_ShouldThrow()
    {
        var scope = Make.Scope();
        var profile = Profile.Individual();

        Assert.Throws<ArgumentNullException>(() => ReportBuilder.Build(null!, profile, [], "0.1.0", Make.GeneratedAt));
        Assert.Throws<ArgumentNullException>(() => ReportBuilder.Build(scope, null!, [], "0.1.0", Make.GeneratedAt));
        Assert.Throws<ArgumentNullException>(() => ReportBuilder.Build(scope, profile, null!, "0.1.0", Make.GeneratedAt));
        Assert.Throws<ArgumentNullException>(() => ReportBuilder.Build(scope, profile, [null!], "0.1.0", Make.GeneratedAt));
        Assert.Throws<ArgumentNullException>(() => ReportBuilder.Build(scope, profile, [], "0.1.0", Make.GeneratedAt, questionnaires: [null!]));
        Assert.Throws<ArgumentException>(() => ReportBuilder.Build(scope, profile, [], "  ", Make.GeneratedAt));
    }

    [Fact]
    public void QuestionnaireSection_WhenCalled_ShouldPrioritizeFindingsAndHaveNoTarget()
    {
        var section = ReportBuilder.QuestionnaireSection(
            CheckArea.Gdpr,
            [Make.Finding("GDPR-ART30-001", Severity.Medium, CheckArea.Gdpr), Make.Finding("GDPR-ART33-001", Severity.High, CheckArea.Gdpr)],
            [new ReportCheck("GDPR-ART32-001", "Security measures")]);

        Assert.Equal(CheckArea.Gdpr, section.Area);
        Assert.Null(section.Target);
        Assert.Equal(["GDPR-ART33-001", "GDPR-ART30-001"], section.Findings.Select(f => f.Id));
        Assert.Equal([new ReportCheck("GDPR-ART32-001", "Security measures")], section.Passed);
        Assert.Empty(section.Skipped);
        Assert.Empty(section.Failed);
    }

    [Fact]
    public void QuestionnaireSection_WhenAListIsMissing_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => ReportBuilder.QuestionnaireSection(CheckArea.Gdpr, null!, []));
        Assert.Throws<ArgumentNullException>(() => ReportBuilder.QuestionnaireSection(CheckArea.Gdpr, [], null!));
        Assert.Throws<ArgumentNullException>(() => ReportBuilder.QuestionnaireSection(CheckArea.Gdpr, [], [null!]));
    }
}
