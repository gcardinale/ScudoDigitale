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
using ScudoDigitale.Compliance;
using ScudoDigitale.Core;
using ScudoDigitale.Reporting;

namespace ScudoDigitale.Cli.Tests;

public sealed class QuestionnaireCommandTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 25, 11, 0, 0, TimeSpan.FromHours(1));

    [Fact]
    public async Task Scan_WhenOnlyTheGdprQuestionnaireIsAsked_ShouldAskInTheTerminalAndReportTheAnswers()
    {
        using var culture = new Culture("it-IT");

        // Backup sì, password no, 2FA non so, aggiornamenti sì, dispositivi non applicabile.
        var (exitCode, output, error) = await RunAsync("s\nn\n?\ny\nna\n", "scan", "--gdpr");

        Assert.Equal(0, exitCode);
        Assert.Empty(error);
        Assert.DoesNotContain("Controllo", output, StringComparison.Ordinal);
        Assert.Contains("== Proteggere i propri dati personali: buone pratiche ==\nRispondi a ogni domanda e premi Invio.", Normalize(output), StringComparison.Ordinal);
        Assert.Contains("[1] Tieni una copia dei file importanti", output, StringComparison.Ordinal);
        Assert.Contains("  s = sì · n = no · ? = non so · na = non applicabile", output, StringComparison.Ordinal);
        Assert.Contains("[MEDIO] GDPR-PASSWORD-001  Le stesse password su più account", output, StringComparison.Ordinal);
        Assert.Contains("[ALTO] GDPR-MFA-001  Verifica in due passaggi non attiva sugli account principali", output, StringComparison.Ordinal);
        Assert.Contains("      Affidabilità: da verificare", output, StringComparison.Ordinal);
        Assert.Contains("Domande senza problemi\n  OK GDPR-BACKUP-001  Copia dei file personali\n  OK GDPR-UPDATE-001  Aggiornamenti automatici\n  OK GDPR-DEVICE-001  Dispositivi condivisi: non applicabile", Normalize(output), StringComparison.Ordinal);
        Assert.Contains("Riepilogo: 0 critici, 1 alti, 1 medi", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WhenAnAnswerIsNotValid_ShouldAskAgain()
    {
        using var culture = new Culture("en-US");

        var (exitCode, output, _) = await RunAsync("maybe\ny\ny\ny\ny\nna\n", "scan", "--gdpr");

        Assert.Equal(0, exitCode);
        Assert.Equal(1, Count(output, "  Not a valid answer, try again."));
        Assert.Contains("No problems found.", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WhenTheInputEnds_ShouldCountTheRestAsDontKnow()
    {
        using var culture = new Culture("en-US");

        var (exitCode, output, _) = await RunAsync("y\n", "scan", "--gdpr");

        Assert.Equal(0, exitCode);
        Assert.Contains("Input ended: the questions not answered count as \"don't know\".", output, StringComparison.Ordinal);
        Assert.Contains("  OK GDPR-BACKUP-001  Backup of personal files", output, StringComparison.Ordinal);
        Assert.Equal(4, Count(output, "      Evidence: No answer given."));
    }

    [Fact]
    public async Task Scan_WhenNis2CompanyIsOutOfScope_ShouldNotAskTheObligations()
    {
        using var culture = new Culture("en-US");

        // Sector "none of these" (option 18), not in the special categories (2), under 50 people, small turnover and balance.
        var (exitCode, output, _) = await RunAsync("18\n2\n1\n1\n1\n", "scan", "--nis2", "--profile", "Company", "--company", "Rossi SRL");

        Assert.Equal(0, exitCode);
        Assert.Contains("  18) None of these", output, StringComparison.Ordinal);
        Assert.Contains("[5] What is the annual balance sheet total (adding that of linked enterprises and the share of partner enterprises)?", output, StringComparison.Ordinal);
        Assert.DoesNotContain("[6]", output, StringComparison.Ordinal);
        Assert.Contains("[INFO] NIS2-SCOPE-001  Probably outside NIS2", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WhenNis2ScopeIsUnknown_ShouldAskTheObligationsToo()
    {
        using var culture = new Culture("en-US");

        var (_, output, _) = await RunAsync("?\n?\n?\n?\n?\ny\ny\ny\ny\ny\n", "scan", "--nis2", "--profile", "Company", "--company", "Rossi SRL");

        Assert.Contains("[10] Is there a procedure to notify CSIRT Italia", output, StringComparison.Ordinal);
        Assert.Contains("[INFO] NIS2-SCOPE-001  NIS2 scope to be verified", output, StringComparison.Ordinal);
        Assert.Contains("  OK NIS2-ART25-001  Incident notification", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WhenAnswersComeFromAFile_ShouldAskNothingAndPutTheQuestionnairesInTheReport()
    {
        var folder = Path.Combine(Path.GetTempPath(), "scudo-cli-q-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            var answers = Path.Combine(folder, "answers.json");
            await File.WriteAllTextAsync(answers, """
                {
                  "GDPR-ART30-001": "yes", "GDPR-ART13-001": "yes", "GDPR-ART28-001": "notApplicable", "GDPR-ART32-001": "yes",
                  "GDPR-ART33-001": "no", "GDPR-ART35-001": "notApplicable", "GDPR-ART37-001": "notApplicable",
                  "NIS2-SECTOR-001": "annex2-food", "NIS2-SPECIAL-001": "no", "NIS2-EMPLOYEES-001": "from50to249",
                  "NIS2-TURNOVER-001": "upTo50m", "NIS2-BALANCE-001": "upTo43m",
                  "NIS2-ART7-001": "yes", "NIS2-ART23-001": "yes", "NIS2-ART24-001": "yes", "NIS2-ART24-002": "yes", "NIS2-ART25-001": "yes"
                }
                """, TestContext.Current.CancellationToken);

            using var culture = new Culture("en-US");
            var (exitCode, output, error) = await RunAsync(
                string.Empty,
                [new DmarcCheck()],
                "scan", "--mail", "example.com", "--profile", "Company", "--company", "Rossi SRL", "--gdpr", "--nis2", "--answers", answers, "--report", folder);

            Assert.Equal(0, exitCode);
            Assert.Empty(error);
            Assert.DoesNotContain("[1]", output, StringComparison.Ordinal);
            Assert.Contains("== GDPR: main obligations of the controller ==", output, StringComparison.Ordinal);
            Assert.Contains("[INFO] NIS2-SCOPE-001  Probably an important entity under NIS2", output, StringComparison.Ordinal);

            var json = Directory.GetFiles(folder, "scudo-report-*.json").Single();
            var document = ReportJson.Read(await File.ReadAllTextAsync(json, TestContext.Current.CancellationToken));
            Assert.Equal(ProfileKind.Company, document.Profile.Kind);
            Assert.Equal("Rossi SRL", document.Profile.CompanyName);
            Assert.Equal([CheckArea.Email, CheckArea.Gdpr, CheckArea.Nis2], document.Sections.Select(s => s.Area));
            var gdpr = document.Sections[1];
            Assert.Null(gdpr.Target);
            Assert.Equal(["GDPR-ART33-001", "GDPR-ART32-002"], gdpr.Findings.Select(f => f.Id));
            Assert.Equal("1 technical findings of Medium severity or above: MAIL-DMARC-001 (example.com) (areas checked: email)", gdpr.Findings[1].Evidence);
            Assert.Equal("Rossi SRL", gdpr.Findings[0].Target);
            Assert.Contains(new ReportCheck("GDPR-ART28-001", "Processors under contract", "not applicable"), gdpr.Passed);
            Assert.Equal(5, document.Sections[2].Passed.Count);
            Assert.Equal(2, document.Notes.Count);
            Assert.StartsWith("GDPR: main obligations of the controller (questionnaire gdpr-company, version 2026-11-25). Indicative.", document.Notes[0], StringComparison.Ordinal);
            Assert.Contains("(questionnaire nis2, version 2026-11-25)", document.Notes[1], StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(folder, recursive: true);
        }
    }

    [Fact]
    public async Task Scan_WhenEveryTechnicalCheckFailed_ShouldNotCallArticle32Fine()
    {
        var file = await AnswersAsync("{ \"GDPR-ART30-001\": \"yes\" }");
        try
        {
            using var culture = new Culture("en-US");
            var (exitCode, output, _) = await RunAsync(string.Empty, [new FailingCheck()], "scan", "--mail", "example.com", "--profile", "Company", "--company", "Rossi SRL", "--gdpr", "--answers", file);

            Assert.Equal(0, exitCode);
            Assert.Contains("!! MAIL-DMARC-001  DMARC policy: DNS timeout", output, StringComparison.Ordinal);
            // Nothing was checked, so nothing can be said about the technical side of art. 32.
            Assert.DoesNotContain("GDPR-ART32-002", output, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public async Task Scan_WhenSomeTechnicalCheckRanWithoutProblems_ShouldSayWhichAreasArticle32Covers()
    {
        var file = await AnswersAsync("{ \"GDPR-ART30-001\": \"yes\" }");
        try
        {
            using var culture = new Culture("it-IT");
            var (_, output, _) = await RunAsync(string.Empty, [new FailingCheck(), new PassingCheck()], "scan", "--mail", "example.com", "--profile", "Company", "--company", "Rossi SRL", "--gdpr", "--answers", file);

            Assert.Contains("  OK GDPR-ART32-002  Riscontri tecnici per l'art. 32: aree controllate: posta", output, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public async Task Scan_WhenTheInputEndsInTheFirstOfTwoQuestionnaires_ShouldStopAskingAndSayItOnce()
    {
        using var culture = new Culture("en-US");

        var (exitCode, output, _) = await RunAsync("y\n", "scan", "--gdpr", "--nis2", "--profile", "Company", "--company", "Rossi SRL");

        Assert.Equal(0, exitCode);
        Assert.Equal(1, Count(output, "Input ended"));
        Assert.DoesNotContain("In which of these sectors", output, StringComparison.Ordinal);
        Assert.Contains("[INFO] NIS2-SCOPE-001  NIS2 scope to be verified", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WhenTheAnswersFileHasTypos_ShouldListThemAndRunNothing()
    {
        var file = Path.Combine(Path.GetTempPath(), "scudo-answers-" + Guid.NewGuid().ToString("N") + ".json");
        await File.WriteAllTextAsync(file, """{ "GDPR-BACKUP-001": "si", "GDPR-NOPE-001": "yes" }""", TestContext.Current.CancellationToken);
        try
        {
            using var culture = new Culture("en-US");
            var (exitCode, output, error) = await RunAsync(string.Empty, "scan", "--gdpr", "--answers", file);

            Assert.Equal(ScanCommand.InvalidInput, exitCode);
            Assert.Empty(output);
            Assert.StartsWith($"The answers in {file} are not valid:", error, StringComparison.Ordinal);
            Assert.Contains("  GDPR-BACKUP-001: 'si' is not an answer to this question", error, StringComparison.Ordinal);
            Assert.Contains("  GDPR-NOPE-001: no such question", error, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("not json")]
    public async Task Scan_WhenTheAnswersFileCannotBeRead_ShouldSaySo(string content)
    {
        var file = Path.Combine(Path.GetTempPath(), "scudo-answers-" + Guid.NewGuid().ToString("N") + ".json");
        if (content != "missing")
        {
            await File.WriteAllTextAsync(file, content, TestContext.Current.CancellationToken);
        }

        try
        {
            using var culture = new Culture("en-US");
            var (exitCode, _, error) = await RunAsync(string.Empty, "scan", "--gdpr", "--answers", file);

            Assert.Equal(ScanCommand.InvalidInput, exitCode);
            Assert.StartsWith($"The answers could not be read from {file}: ", error, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Theory]
    [InlineData("--profile Company --gdpr", "--profile Company needs the name of the company")]
    [InlineData("--profile Company --company  --gdpr", "--profile Company needs the name of the company")]
    [InlineData("--nis2", "The NIS2 questionnaire is for companies")]
    public async Task Scan_WhenTheProfileDoesNotFit_ShouldRefuse(string arguments, string expected)
    {
        using var culture = new Culture("en-US");

        var (exitCode, output, error) = await RunAsync(string.Empty, ["scan", .. arguments.Split(' ')]);

        Assert.Equal(ScanCommand.InvalidInput, exitCode);
        Assert.Empty(output);
        Assert.Contains(expected, error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Scan_WhenNothingIsAsked_ShouldMentionTheQuestionnaires()
    {
        using var culture = new Culture("en-US");

        var (exitCode, _, error) = await RunAsync(string.Empty, "scan");

        Assert.Equal(ScanCommand.InvalidInput, exitCode);
        Assert.Contains("or a questionnaire with --gdpr or --nis2.", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(" S ", "yes")]
    [InlineData("sì", "yes")]
    [InlineData("yes", "yes")]
    [InlineData("NO", "no")]
    [InlineData("non so", "unknown")]
    [InlineData("unknown", "unknown")]
    [InlineData("n/a", null)]
    [InlineData("", null)]
    public void Parse_WhenYesNoQuestionDoesNotAllowNotApplicable_ShouldReadTheUsualWords(string typed, string? expected)
    {
        var question = QuestionnaireCatalog.Get(QuestionnaireCatalog.GdprCompany).Questions[0];

        Assert.Equal(expected, QuestionnairePrompt.Parse(question, typed));
    }

    [Theory]
    [InlineData("1", "under50")]
    [InlineData("4", "unknown")]
    [InlineData("?", "unknown")]
    [InlineData("0", null)]
    [InlineData("5", null)]
    [InlineData("-1", null)]
    [InlineData("due", null)]
    public void Parse_WhenChoice_ShouldAcceptTheNumberOfAnOptionOrAQuestionMark(string typed, string? expected)
    {
        var question = QuestionnaireCatalog.Get(QuestionnaireCatalog.Nis2).Questions.Single(q => q.Id == Nis2Scope.EmployeesQuestion);

        Assert.Equal(expected, QuestionnairePrompt.Parse(question, typed));
    }

    [Fact]
    public void Parse_WhenChoiceHasNoDontKnowOption_ShouldRefuseAQuestionMark()
    {
        var question = new Question
        {
            Id = "NIS2-TEST-001",
            Kind = QuestionKind.Choice,
            Label = new("L", "L"),
            Text = new("T", "T"),
            Options = [new("a", new("A", "A")), new("b", new("B", "B"))],
        };

        Assert.Null(QuestionnairePrompt.Parse(question, "?"));
        Assert.Equal("b", QuestionnairePrompt.Parse(question, "2"));
    }

    private static Task<(int ExitCode, string Output, string Error)> RunAsync(string input, params string[] args) => RunAsync(input, [], args);

    private static async Task<string> AnswersAsync(string json)
    {
        var file = Path.Combine(Path.GetTempPath(), "scudo-answers-" + Guid.NewGuid().ToString("N") + ".json");
        await File.WriteAllTextAsync(file, json, TestContext.Current.CancellationToken);
        return file;
    }

    private static async Task<(int ExitCode, string Output, string Error)> RunAsync(string input, ICheck[] emailChecks, params string[] args)
    {
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        using var error = new StringWriter(CultureInfo.InvariantCulture);
        using var reader = new StringReader(input);
        var services = new CliServices(_ => emailChecks, _ => [], _ => null, () => Now, () => "tester", reader);
        var exitCode = await CliApp.RunAsync(args, output, error, services, TestContext.Current.CancellationToken);
        return (exitCode, output.ToString(), error.ToString());
    }

    private static string Normalize(string text) => text.Replace("\r\n", "\n", StringComparison.Ordinal);

    private static int Count(string text, string value) => (text.Length - text.Replace(value, string.Empty, StringComparison.Ordinal).Length) / value.Length;

    /// <summary>An email check that always finds DMARC in monitoring mode (Medium).</summary>
    private sealed class DmarcCheck : ICheck
    {
        public string Id => "MAIL-DMARC-001";

        public string Title => "DMARC policy";

        public CheckArea Area => CheckArea.Email;

        public TargetKind AppliesTo => TargetKind.Domain;

        public ScopeRequirement Scope => ScopeRequirement.Passive;

        public Task<CheckResult> RunAsync(CheckContext context, CancellationToken cancellationToken) =>
            Task.FromResult<CheckResult>(new CheckResult.Executed([new Finding(Id, Area, "DMARC in monitoring mode", Severity.Medium, Confidence.Certain, context.Target.Value)]));
    }

    /// <summary>An email check that always fails, as with a DNS that does not answer.</summary>
    private sealed class FailingCheck : ICheck
    {
        public string Id => "MAIL-DMARC-001";

        public string Title => "DMARC policy";

        public CheckArea Area => CheckArea.Email;

        public TargetKind AppliesTo => TargetKind.Domain;

        public ScopeRequirement Scope => ScopeRequirement.Passive;

        public Task<CheckResult> RunAsync(CheckContext context, CancellationToken cancellationToken) =>
            Task.FromResult<CheckResult>(new CheckResult.Failed("DNS timeout"));
    }

    /// <summary>An email check that finds nothing.</summary>
    private sealed class PassingCheck : ICheck
    {
        public string Id => "MAIL-SPF-001";

        public string Title => "SPF record";

        public CheckArea Area => CheckArea.Email;

        public TargetKind AppliesTo => TargetKind.Domain;

        public ScopeRequirement Scope => ScopeRequirement.Passive;

        public Task<CheckResult> RunAsync(CheckContext context, CancellationToken cancellationToken) =>
            Task.FromResult<CheckResult>(new CheckResult.Executed([]));
    }

    private sealed class Culture : IDisposable
    {
        private readonly CultureInfo previous = CultureInfo.CurrentCulture;
        private readonly CultureInfo previousUi = CultureInfo.CurrentUICulture;

        public Culture(string name)
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
