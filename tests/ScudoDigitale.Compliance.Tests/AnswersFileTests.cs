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

namespace ScudoDigitale.Compliance.Tests;

public sealed class AnswersFileTests
{
    [Fact]
    public void Read_WhenJsonIsAnObjectOfTexts_ShouldReturnTheAnswers()
    {
        var answers = AnswersFile.Read("""{ "GDPR-ART30-001": "yes", "NIS2-SECTOR-001": "annex2-food" }""");

        Assert.Equal("yes", answers["GDPR-ART30-001"]);
        Assert.Equal("annex2-food", answers["NIS2-SECTOR-001"]);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("""["yes"]""")]
    [InlineData("""{ "GDPR-ART30-001": true }""")]
    [InlineData("""{ "GDPR-ART30-001": null }""")]
    [InlineData("null")]
    public void Read_WhenJsonIsNotAnObjectOfTexts_ShouldThrowInvalidData(string json)
    {
        Assert.Throws<InvalidDataException>(() => AnswersFile.Read(json));
    }

    [Fact]
    public void Validate_WhenAnswersHaveTypos_ShouldListEveryOneSorted()
    {
        var questionnaires = new[] { QuestionnaireCatalog.Get(QuestionnaireCatalog.GdprCompany), QuestionnaireCatalog.Get(QuestionnaireCatalog.Nis2) };
        var answers = Make.Answers(
            ("GDPR-ART30-001", "si"),
            ("GDPR-ART13-001", Answers.NotApplicable),
            ("GDPR-ART37-001", Answers.NotApplicable),
            ("GDPR-ART32-002", Answers.Yes),
            ("NIS2-SECTOR-001", "annex9-moon"),
            ("NIS2-ART7-001", Answers.Unknown),
            ("GDPR-BACKUP-001", Answers.Yes));

        var errors = AnswersFile.Validate(answers, questionnaires);

        Assert.Equal(5, errors.Count);
        Assert.StartsWith("GDPR-ART13-001: 'notApplicable' is not an answer to this question; accepted: yes, no, unknown.", errors[0], StringComparison.Ordinal);
        Assert.StartsWith("GDPR-ART30-001: 'si'", errors[1], StringComparison.Ordinal);
        Assert.StartsWith("GDPR-ART32-002: 'yes'", errors[2], StringComparison.Ordinal);
        Assert.Equal("GDPR-BACKUP-001: no such question in the questionnaires of this assessment.", errors[3]);
        Assert.StartsWith("NIS2-SECTOR-001: 'annex9-moon'", errors[4], StringComparison.Ordinal);
    }

    [Fact]
    public void Accepted_WhenQuestionAllowsNotApplicable_ShouldListIt()
    {
        var company = QuestionnaireCatalog.Get(QuestionnaireCatalog.GdprCompany);

        Assert.Equal([Answers.Yes, Answers.No, Answers.Unknown, Answers.NotApplicable], AnswersFile.Accepted(company.Questions.Single(q => q.Id == "GDPR-ART37-001")));
        Assert.Empty(AnswersFile.Accepted(company.Questions.Single(q => q.Kind == QuestionKind.Technical)));
    }

    [Fact]
    public void ReadValidateAccepted_WhenArgumentIsNull_ShouldThrow()
    {
        Assert.Throws<ArgumentNullException>(() => AnswersFile.Read(null!));
        Assert.Throws<ArgumentNullException>(() => AnswersFile.Validate(null!, []));
        Assert.Throws<ArgumentNullException>(() => AnswersFile.Validate(Make.Answers(), null!));
        Assert.Throws<ArgumentNullException>(() => AnswersFile.Accepted(null!));
    }
}
