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

namespace ScudoDigitale.Compliance.Tests;

public sealed class QuestionnaireEvaluatorTests
{
    private static readonly Questionnaire Company = QuestionnaireCatalog.Get(QuestionnaireCatalog.GdprCompany);
    private static readonly Questionnaire Individual = QuestionnaireCatalog.Get(QuestionnaireCatalog.GdprIndividual);
    private static readonly Questionnaire Nis2 = QuestionnaireCatalog.Get(QuestionnaireCatalog.Nis2);

    [Fact]
    public void Evaluate_WhenEveryAnswerIsYes_ShouldGiveNoFindingAndListEveryQuestion()
    {
        var outcome = QuestionnaireEvaluator.Evaluate(Individual, Make.AllYesNo(Individual, Answers.Yes), "Mario Rossi", null, Make.English);

        Assert.Empty(outcome.Findings);
        Assert.Equal(["GDPR-BACKUP-001", "GDPR-PASSWORD-001", "GDPR-MFA-001", "GDPR-UPDATE-001", "GDPR-DEVICE-001"], outcome.Passed.Select(p => p.Id));
        Assert.Equal("Backup of personal files", outcome.Passed[0].Label);
        Assert.Null(outcome.Passed[0].Detail);
        Assert.Same(Individual, outcome.Questionnaire);
        Assert.Null(outcome.Nis2Scope);
    }

    [Fact]
    public void Evaluate_WhenAnswerIsNo_ShouldGiveACertainFindingWithTheTextsOfTheQuestion()
    {
        var answers = Make.AllYesNo(Company, Answers.Yes);
        answers["GDPR-ART33-001"] = Answers.No;

        var finding = Assert.Single(QuestionnaireEvaluator.Evaluate(Company, answers, "Rossi SRL", null, Make.Italian).Findings);

        Assert.Equal("GDPR-ART33-001", finding.Id);
        Assert.Equal(CheckArea.Gdpr, finding.Area);
        Assert.Equal("Manca la procedura per le violazioni dei dati", finding.Title);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(Confidence.Certain, finding.Confidence);
        Assert.Equal("Rossi SRL", finding.Target);
        Assert.Equal("Risposta: no.", finding.Evidence);
        Assert.StartsWith("In un incidente le 72 ore", finding.Risk, StringComparison.Ordinal);
        Assert.StartsWith("Scrivere una procedura di una pagina", finding.Fix, StringComparison.Ordinal);
        Assert.Equal(["GDPR art. 33", "GDPR art. 34"], finding.References);
    }

    [Fact]
    public void Evaluate_WhenAnswerIsUnknownOrMissing_ShouldGiveTheSameFindingToBeVerified()
    {
        var answers = Make.AllYesNo(Individual, Answers.Yes);
        answers["GDPR-MFA-001"] = Answers.Unknown;
        answers.Remove("GDPR-UPDATE-001");

        var findings = QuestionnaireEvaluator.Evaluate(Individual, answers, "Mario Rossi", null, Make.English).Findings;

        Assert.Equal(["GDPR-MFA-001", "GDPR-UPDATE-001"], findings.Select(f => f.Id));
        Assert.All(findings, f => Assert.Equal(Confidence.ToBeVerified, f.Confidence));
        Assert.Equal("Answer: don't know.", findings[0].Evidence);
        Assert.Equal("No answer given.", findings[1].Evidence);
    }

    [Fact]
    public void Evaluate_WhenNotApplicable_ShouldPassOnlyWhereTheQuestionAllowsIt()
    {
        var answers = Make.AllYesNo(Company, Answers.NotApplicable);

        var outcome = QuestionnaireEvaluator.Evaluate(Company, answers, "Rossi SRL", null, Make.Italian);

        // Allowed for processors, DPIA and DPO; elsewhere "not applicable" is an answer that settles nothing.
        Assert.Equal(["GDPR-ART28-001", "GDPR-ART35-001", "GDPR-ART37-001"], outcome.Passed.Select(p => p.Id));
        Assert.All(outcome.Passed, p => Assert.Equal("non applicabile", p.Detail));
        Assert.Equal(["GDPR-ART30-001", "GDPR-ART13-001", "GDPR-ART32-001", "GDPR-ART33-001"], outcome.Findings.Select(f => f.Id));
        Assert.All(outcome.Findings, f => Assert.Equal(Confidence.ToBeVerified, f.Confidence));
    }

    [Fact]
    public void Evaluate_WhenNoTechnicalCheckRan_ShouldLeaveTheTechnicalQuestionOut()
    {
        var outcome = QuestionnaireEvaluator.Evaluate(Company, Make.AllYesNo(Company, Answers.Yes), "Rossi SRL", null, Make.English);

        Assert.DoesNotContain("GDPR-ART32-002", outcome.Passed.Select(p => p.Id).Concat(outcome.Findings.Select(f => f.Id)));
    }

    [Fact]
    public void Evaluate_WhenTechnicalFindingsAreBelowMedium_ShouldPassTheTechnicalQuestion()
    {
        PrioritizedFinding[] technical = [Make.Technical("MAIL-DMARC-002", Severity.Low), Make.Technical("WEB-HDR-005", Severity.Info, CheckArea.Web), Make.Technical("GDPR-ART30-001", Severity.High, CheckArea.Gdpr)];

        var outcome = QuestionnaireEvaluator.Evaluate(Company, Make.AllYesNo(Company, Answers.Yes), "Rossi SRL", new TechnicalEvidence(technical, [CheckArea.Web, CheckArea.Email, CheckArea.Email]), Make.English);

        Assert.Empty(outcome.Findings);
        // What was looked at is said, once per area, in the order of the report.
        Assert.Contains(new AnsweredQuestion("GDPR-ART32-002", "Technical evidence for art. 32", "areas checked: websites, email"), outcome.Passed);
    }

    [Fact]
    public void Evaluate_WhenTechnicalFindingsAreMediumOrAbove_ShouldListThemInOneArt32Finding()
    {
        PrioritizedFinding[] technical =
        [
            Make.Technical("MAIL-DMARC-001", Severity.Medium),
            Make.Technical("WEB-CERT-001", Severity.Critical, CheckArea.Web, "www.example.com"),
            Make.Technical("MAIL-SPF-004", Severity.Low),
        ];

        var finding = Assert.Single(QuestionnaireEvaluator.Evaluate(Company, Make.AllYesNo(Company, Answers.Yes), "Rossi SRL", new TechnicalEvidence(technical, [CheckArea.Email, CheckArea.Web]), Make.Italian).Findings);

        Assert.Equal("GDPR-ART32-002", finding.Id);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(Confidence.Probable, finding.Confidence);
        Assert.Equal("2 risultati tecnici di gravità media o superiore: MAIL-DMARC-001 (example.com), WEB-CERT-001 (www.example.com) (aree controllate: siti web, posta)", finding.Evidence);
        Assert.Equal(["GDPR art. 32"], finding.References);
    }

    [Fact]
    public void Evaluate_WhenThereAreManyTechnicalFindings_ShouldListTenAndCountTheRest()
    {
        var technical = Enumerable.Range(100, 13).Select(i => Make.Technical($"MAIL-X-{i}", Severity.High)).ToArray();

        var finding = Assert.Single(QuestionnaireEvaluator.Evaluate(Company, Make.AllYesNo(Company, Answers.Yes), "Rossi SRL", new TechnicalEvidence(technical, [CheckArea.Email]), Make.English).Findings);

        Assert.StartsWith("13 technical findings of Medium severity or above: MAIL-X-100 (example.com), ", finding.Evidence, StringComparison.Ordinal);
        Assert.EndsWith("MAIL-X-109 (example.com) and 3 more (areas checked: email)", finding.Evidence, StringComparison.Ordinal);
        Assert.DoesNotContain("MAIL-X-110", finding.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void Evaluate_WhenNis2CompanyIsInScope_ShouldGiveTheScopeAndAskTheObligations()
    {
        var answers = Make.AllYesNo(Nis2, Answers.Yes);
        answers[Nis2Scope.SectorQuestion] = "annex2-food";
        answers[Nis2Scope.SpecialQuestion] = Answers.No;
        answers[Nis2Scope.EmployeesQuestion] = "from50to249";
        answers[Nis2Scope.TurnoverQuestion] = "upTo50m";
        answers[Nis2Scope.BalanceQuestion] = "upTo43m";
        answers["NIS2-ART25-001"] = Answers.No;

        var outcome = QuestionnaireEvaluator.Evaluate(Nis2, answers, "Rossi SRL", null, Make.Italian);

        Assert.Equal(Nis2Outcome.ProbablyImportant, outcome.Nis2Scope);
        Assert.Equal([QuestionnaireEvaluator.Nis2ScopeFinding, "NIS2-ART25-001"], outcome.Findings.Select(f => f.Id));
        var scope = outcome.Findings[0];
        Assert.Equal("Probabilmente soggetto importante NIS2", scope.Title);
        Assert.Equal(Severity.Info, scope.Severity);
        Assert.Equal(Confidence.Probable, scope.Confidence);
        Assert.Equal(CheckArea.Nis2, scope.Area);
        Assert.Equal(
            "Settore: Alimenti (produzione industriale e trasformazione, distribuzione all'ingrosso); Inclusi a prescindere dalla dimensione: No; Dipendenti: Da 50 a 249; Fatturato annuo: Oltre 10 e fino a 50 milioni di euro; Totale di bilancio: Oltre 10 e fino a 43 milioni di euro",
            scope.Evidence);
        Assert.StartsWith("Registrarsi, o aggiornare la registrazione, sulla piattaforma ACN", scope.Fix, StringComparison.Ordinal);
        Assert.Equal(["D.Lgs. 138/2024 art. 3", "D.Lgs. 138/2024 art. 6", "Raccomandazione 2003/361/CE"], scope.References);
        Assert.Equal(4, outcome.Passed.Count);
    }

    [Fact]
    public void Evaluate_WhenNis2CompanyIsOutOfScope_ShouldNotAskTheObligations()
    {
        var answers = Make.Answers((Nis2Scope.SectorQuestion, Nis2Scope.NoSector), (Nis2Scope.SpecialQuestion, Answers.No));

        var outcome = QuestionnaireEvaluator.Evaluate(Nis2, answers, "Rossi SRL", null, Make.English);

        var scope = Assert.Single(outcome.Findings);
        Assert.Equal("Probably outside NIS2", scope.Title);
        Assert.Contains("Sector: None of these", scope.Evidence, StringComparison.Ordinal);
        Assert.Contains("Employees: no answer", scope.Evidence, StringComparison.Ordinal);
        Assert.Empty(outcome.Passed);
    }

    [Fact]
    public void Evaluate_WhenNis2ScopeIsUnknown_ShouldMarkItToBeVerifiedAndStillAskTheObligations()
    {
        var outcome = QuestionnaireEvaluator.Evaluate(Nis2, Make.Answers(), "Rossi SRL", null, Make.English);

        Assert.Equal(Nis2Outcome.ToBeVerified, outcome.Nis2Scope);
        Assert.Equal(Confidence.ToBeVerified, outcome.Findings[0].Confidence);
        Assert.Equal("NIS2 scope to be verified", outcome.Findings[0].Title);
        Assert.Equal(6, outcome.Findings.Count);
    }

    [Fact]
    public void TechnicalEvidenceOf_WhenNoCheckWasExecuted_ShouldBeNull()
    {
        var target = new Target(TargetKind.Domain, "example.com");
        CheckRun[] runs =
        [
            new("MAIL-SPF-001", "SPF", CheckArea.Email, target, new CheckResult.Skipped("offline")),
            new("MAIL-MX-001", "MX", CheckArea.Email, target, new CheckResult.Failed("DNS timeout")),
        ];

        Assert.Null(TechnicalEvidence.Of(runs));
        Assert.Null(TechnicalEvidence.Of([]));
        Assert.Throws<ArgumentNullException>(() => TechnicalEvidence.Of(null!));
    }

    [Fact]
    public void TechnicalEvidenceOf_WhenSomeChecksWereExecuted_ShouldKeepOnlyTheirFindingsAndAreas()
    {
        var mail = new Target(TargetKind.Domain, "example.com");
        var site = new Target(TargetKind.Website, "www.example.com");
        var low = new Finding("MAIL-SPF-004", CheckArea.Email, "ptr", Severity.Low, Confidence.Certain, "example.com");
        var high = new Finding("MAIL-DMARC-001", CheckArea.Email, "DMARC", Severity.High, Confidence.Certain, "example.com");
        CheckRun[] runs =
        [
            new("MAIL-SPF-004", "SPF", CheckArea.Email, mail, new CheckResult.Executed([low])),
            new("MAIL-DMARC-001", "DMARC", CheckArea.Email, mail, new CheckResult.Executed([high])),
            new("WEB-CERT-001", "Certificate", CheckArea.Web, site, new CheckResult.Failed("unreachable")),
        ];

        var evidence = TechnicalEvidence.Of(runs)!;

        Assert.Equal([CheckArea.Email], evidence.Areas);
        Assert.Equal(["MAIL-DMARC-001", "MAIL-SPF-004"], evidence.Findings.Select(f => f.Finding.Id));
    }

    [Theory]
    [InlineData(Nis2Outcome.ProbablyEssential, "Probably an essential entity under NIS2")]
    [InlineData(Nis2Outcome.ProbablyInScope, "Probably within NIS2, category to be verified")]
    public void ScopeTitle_WhenOutcomeIsGiven_ShouldBeTranslated(Nis2Outcome outcome, string expected)
    {
        Assert.Equal(expected, QuestionnaireEvaluator.ScopeTitle(outcome, Make.English));
    }

    [Fact]
    public void IsAsked_WhenQuestionHasNoCondition_ShouldAlwaysBeTrue()
    {
        var always = Company.Questions[0];
        var obligation = Nis2.Questions.First(q => q.AskIf is not null);

        Assert.True(QuestionnaireEvaluator.IsAsked(always, null));
        Assert.False(QuestionnaireEvaluator.IsAsked(obligation, null));
        Assert.False(QuestionnaireEvaluator.IsAsked(obligation, Nis2Outcome.ProbablyOutOfScope));
        Assert.True(QuestionnaireEvaluator.IsAsked(obligation, Nis2Outcome.ToBeVerified));
        Assert.Throws<ArgumentNullException>(() => QuestionnaireEvaluator.IsAsked(null!, null));
    }

    [Fact]
    public void Evaluate_WhenAnArgumentIsMissing_ShouldThrow()
    {
        var answers = Make.Answers();

        Assert.Throws<ArgumentNullException>(() => QuestionnaireEvaluator.Evaluate(null!, answers, "x", null, Make.English));
        Assert.Throws<ArgumentNullException>(() => QuestionnaireEvaluator.Evaluate(Company, null!, "x", null, Make.English));
        Assert.Throws<ArgumentException>(() => QuestionnaireEvaluator.Evaluate(Company, answers, " ", null, Make.English));
        Assert.Throws<ArgumentNullException>(() => QuestionnaireEvaluator.Evaluate(Company, answers, "x", null, null!));
    }
}
