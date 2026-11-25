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

public sealed class QuestionnaireCatalogTests
{
    [Fact]
    public void All_WhenLoaded_ShouldHaveTheThreeQuestionnairesOfTheBeta()
    {
        Assert.Equal([QuestionnaireCatalog.GdprCompany, QuestionnaireCatalog.GdprIndividual, QuestionnaireCatalog.Nis2], QuestionnaireCatalog.All.Select(q => q.Id));
        Assert.All(QuestionnaireCatalog.All, q => Assert.Empty(QuestionnaireCatalog.Validate(q)));
        int Count(string id, QuestionKind kind) => QuestionnaireCatalog.Get(id).Questions.Count(q => q.Kind == kind);
        Assert.Equal((7, 1), (Count(QuestionnaireCatalog.GdprCompany, QuestionKind.YesNo), Count(QuestionnaireCatalog.GdprCompany, QuestionKind.Technical)));
        Assert.Equal(5, Count(QuestionnaireCatalog.GdprIndividual, QuestionKind.YesNo));
        Assert.Equal((5, 5), (Count(QuestionnaireCatalog.Nis2, QuestionKind.Choice), Count(QuestionnaireCatalog.Nis2, QuestionKind.YesNo)));
    }

    [Fact]
    public void Get_WhenIdIsKnown_ShouldReturnItAndGdprForShouldFollowTheProfile()
    {
        Assert.Equal(CheckArea.Nis2, QuestionnaireCatalog.Get(QuestionnaireCatalog.Nis2).Area);
        Assert.Equal(QuestionnaireCatalog.GdprCompany, QuestionnaireCatalog.GdprFor(ProfileKind.Company).Id);
        Assert.Equal(QuestionnaireCatalog.GdprIndividual, QuestionnaireCatalog.GdprFor(ProfileKind.Individual).Id);
        Assert.Equal(ProfileKind.Individual, QuestionnaireCatalog.GdprFor(ProfileKind.Individual).Profile);
        Assert.Throws<KeyNotFoundException>(() => QuestionnaireCatalog.Get("nope"));
    }

    [Fact]
    public void Nis2_WhenLoaded_ShouldHaveEveryScopeQuestionWithTheOptionsTheAssessmentReads()
    {
        var nis2 = QuestionnaireCatalog.Get(QuestionnaireCatalog.Nis2);
        Question Q(string id) => Assert.Single(nis2.Questions, q => q.Id == id);

        foreach (var id in Nis2Scope.Questions)
        {
            Assert.Equal(QuestionKind.Choice, Q(id).Kind);
            Assert.Contains("unknown", Q(id).Options.Select(o => o.Id));
        }

        var sectors = Q(Nis2Scope.SectorQuestion).Options.Select(o => o.Id).ToArray();
        Assert.Equal(10, sectors.Count(s => s.StartsWith(Nis2Scope.AnnexIPrefix, StringComparison.Ordinal)));
        Assert.Equal(7, sectors.Count(s => s.StartsWith(Nis2Scope.AnnexIIPrefix, StringComparison.Ordinal)));
        Assert.Contains(Nis2Scope.NoSector, sectors);
        Assert.Equal([Answers.Yes, Answers.No, "unknown"], Q(Nis2Scope.SpecialQuestion).Options.Select(o => o.Id));
        Assert.Equal(["under50", "from50to249", "from250", "unknown"], Q(Nis2Scope.EmployeesQuestion).Options.Select(o => o.Id));
        Assert.Equal(["upTo10m", "upTo50m", "over50m", "unknown"], Q(Nis2Scope.TurnoverQuestion).Options.Select(o => o.Id));
        Assert.Equal(["upTo10m", "upTo43m", "over43m", "unknown"], Q(Nis2Scope.BalanceQuestion).Options.Select(o => o.Id));

        // Every obligation waits for the scope; the scope questions do not.
        Assert.All(nis2.Questions.Where(q => q.Kind == QuestionKind.YesNo), q => Assert.Equal(Question.Conditions.Nis2InScope, q.AskIf));
        Assert.All(nis2.Questions.Where(q => q.Kind == QuestionKind.Choice), q => Assert.Null(q.AskIf));
    }

    [Fact]
    public void Parse_WhenQuestionnaireIsValid_ShouldReadEveryField()
    {
        var q = QuestionnaireCatalog.Parse(Make.Json(), "test.json");

        Assert.Equal("test", q.Id);
        Assert.Equal("2026-11-25", q.Version);
        Assert.Equal(CheckArea.Gdpr, q.Area);
        Assert.Equal(ProfileKind.Company, q.Profile);
        Assert.Equal("Titolo", q.Title.In(Make.Italian));
        Assert.Equal("Notice", q.Notice.In(Make.English));
        var question = Assert.Single(q.Questions);
        Assert.Equal(Severity.High, question.Severity);
        Assert.Equal(["GDPR art. 30"], question.References);
        Assert.False(question.AllowNotApplicable);
    }

    [Theory]
    [InlineData("\"severity\": \"High\",", "", "severity is required")]
    [InlineData("\"severity\": \"High\",", "\"severity\": 3,", "could not be converted")]
    [InlineData("\"severity\": \"High\",", "\"severity\": \"High\", \"sevrity\": \"Low\",", "sevrity")]
    [InlineData("\"it\": \"Problema\"", "\"it\": \" \"", "finding needs both English and Italian")]
    [InlineData("\"finding\": { \"en\": \"Problem\", \"it\": \"Problema\" },", "", "finding is required")]
    [InlineData("\"fix\": { \"en\": \"Fix\", \"it\": \"Correzione\" },", "", "fix is required")]
    [InlineData("GDPR-TEST-001", "GDPR-TEST-1", "AREA-TOPIC-NNN")]
    [InlineData("\"it\": \"Etichetta\"", "\"it\": \"\"", "label needs both English and Italian")]
    [InlineData("\"references\": [\"GDPR art. 30\"]", "\"references\": [\" \"]", "a reference is blank")]
    [InlineData("\"kind\": \"YesNo\",", "\"kind\": \"YesNo\", \"askIf\": \"whenever\",", "unknown condition")]
    [InlineData("\"kind\": \"YesNo\",", "\"kind\": \"YesNo\", \"minimumSeverity\": \"Low\",", "minimumSeverity")]
    [InlineData("\"kind\": \"YesNo\",", "\"kind\": \"Technical\",", "minimumSeverity")]
    [InlineData("\"kind\": \"YesNo\",", "\"kind\": \"YesNo\", \"options\": [{ \"id\": \"a\", \"text\": { \"en\": \"A\", \"it\": \"A\" } }],", "only a choice has options")]
    [InlineData("\"kind\": \"YesNo\",", "\"kind\": \"Choice\",", "a choice raises no finding")]
    public void Parse_WhenAQuestionIsBroken_ShouldRefuseItAndSayWhy(string valid, string broken, string expected)
    {
        Assert.Contains(valid, Make.DefaultQuestion, StringComparison.Ordinal);

        var e = Assert.Throws<InvalidDataException>(() => QuestionnaireCatalog.Parse(Make.Json(Make.DefaultQuestion.Replace(valid, broken, StringComparison.Ordinal)), "test.json"));

        Assert.Contains(expected, e.Message, StringComparison.Ordinal);
        Assert.StartsWith("test.json: ", e.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{ "id": "NIS2-A-001", "kind": "Choice", "label": { "en": "L", "it": "L" }, "text": { "en": "T", "it": "T" }, "options": [{ "id": "a", "text": { "en": "A", "it": "A" } }] }""", "at least two options")]
    [InlineData("""{ "id": "NIS2-A-001", "kind": "Choice", "label": { "en": "L", "it": "L" }, "text": { "en": "T", "it": "T" }, "options": [{ "id": "a", "text": { "en": "A", "it": "A" } }, { "id": "a", "text": { "en": "B", "it": "B" } }] }""", "option ids must be unique")]
    [InlineData("""{ "id": "NIS2-A-001", "kind": "Choice", "label": { "en": "L", "it": "L" }, "text": { "en": "T", "it": "T" }, "options": [{ "id": " ", "text": { "en": "A", "it": "A" } }, { "id": "b", "text": { "en": "B", "it": "" } }] }""", "option b needs both")]
    public void Parse_WhenAChoiceIsBroken_ShouldRefuseIt(string question, string expected)
    {
        var e = Assert.Throws<InvalidDataException>(() => QuestionnaireCatalog.Parse(Make.Json(question, area: "Nis2"), "test.json"));

        Assert.Contains(expected, e.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_WhenTheQuestionnaireItselfIsBroken_ShouldRefuseIt()
    {
        Assert.Contains("is repeated", Assert.Throws<InvalidDataException>(() => QuestionnaireCatalog.Parse(Make.Json(Make.DefaultQuestion + ", " + Make.DefaultQuestion), "t")).Message, StringComparison.Ordinal);
        Assert.Contains("not a questionnaire area", Assert.Throws<InvalidDataException>(() => QuestionnaireCatalog.Parse(Make.Json(area: "Email"), "t")).Message, StringComparison.Ordinal);
        Assert.Contains("no questions", Assert.Throws<InvalidDataException>(() => QuestionnaireCatalog.Parse(Make.Json(question: ""), "t")).Message, StringComparison.Ordinal);
        Assert.Contains("id and version are required", Assert.Throws<InvalidDataException>(() => QuestionnaireCatalog.Parse(Make.Json().Replace("\"2026-11-25\"", "\" \"", StringComparison.Ordinal), "t")).Message, StringComparison.Ordinal);
        Assert.Contains("title needs both", Assert.Throws<InvalidDataException>(() => QuestionnaireCatalog.Parse(Make.Json().Replace("\"Titolo\"", "\"\"", StringComparison.Ordinal), "t")).Message, StringComparison.Ordinal);
        Assert.Throws<InvalidDataException>(() => QuestionnaireCatalog.Parse("null", "t"));
        Assert.Throws<InvalidDataException>(() => QuestionnaireCatalog.Parse("not json", "t"));
        Assert.Throws<InvalidDataException>(() => QuestionnaireCatalog.Parse(Make.Json().Replace("\"notice\"", "\"notes\"", StringComparison.Ordinal), "t"));
    }

    [Fact]
    public void In_WhenCultureIsItalianOrAnotherLanguage_ShouldPickItalianOrEnglish()
    {
        var text = new LocalizedText("Hello", "Ciao");

        Assert.Equal("Ciao", text.In(System.Globalization.CultureInfo.GetCultureInfo("it-CH")));
        Assert.Equal("Hello", text.In(System.Globalization.CultureInfo.GetCultureInfo("de-DE")));
        Assert.Equal("Hello", text.In(System.Globalization.CultureInfo.InvariantCulture));
        Assert.Throws<ArgumentNullException>(() => text.In(null!));
    }
}
