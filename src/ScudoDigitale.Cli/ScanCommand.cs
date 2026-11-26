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

using System.CommandLine;
using System.Globalization;
using ScudoDigitale.Checks.Email;
using ScudoDigitale.Checks.Web;
using ScudoDigitale.Cli.Resources;
using ScudoDigitale.Compliance;
using ScudoDigitale.Core;
using ScudoDigitale.Core.Dns;
using ScudoDigitale.Reporting;

namespace ScudoDigitale.Cli;

/// <summary>
/// <c>scudo scan</c>: runs the checks on the declared targets and prints the results. In v0.1 the
/// targets are domains for the email checks (<c>--mail</c>) and websites for the passive website
/// checks (<c>--web</c>); the two can be given together, also for the same domain. With
/// <c>--report</c> the results are also written as HTML, PDF and JSON. With <c>--gdpr</c> and
/// <c>--nis2</c> the questionnaires are answered too (ADR-008), in the terminal or from <c>--answers</c>.
/// </summary>
internal static class ScanCommand
{
    /// <summary>Exit code when there is nothing to check or an option value is not valid.</summary>
    public const int InvalidInput = 2;

    /// <summary>Exit code when the checks ran but the report files could not be written.</summary>
    public const int ReportNotWritten = 3;

    /// <summary>Builds the command.</summary>
    /// <param name="services">Checks, clock and user name.</param>
    /// <returns>The command.</returns>
    public static Command Create(CliServices services)
    {
        var mail = new Option<string[]>("--mail") { Description = Strings.MailOptionDescription, HelpName = "domain" };
        var web = new Option<string[]>("--web") { Description = Strings.WebOptionDescription, HelpName = "domain" };
        var selectors = new Option<string[]>("--dkim-selector") { Description = Strings.DkimSelectorOptionDescription, HelpName = "selector" };
        var systemDns = new Option<bool>("--system-dns") { Description = Strings.SystemDnsOptionDescription };
        var operatorName = new Option<string>("--operator") { Description = Strings.OperatorOptionDescription, HelpName = "name" };
        var role = new Option<OperatorRole>("--role") { Description = Strings.RoleOptionDescription, DefaultValueFactory = _ => OperatorRole.Owner };
        var report = new Option<string>("--report") { Description = Strings.ReportOptionDescription, HelpName = "folder" };
        var profile = new Option<ProfileKind>("--profile") { Description = Strings.ProfileOptionDescription, DefaultValueFactory = _ => ProfileKind.Individual };
        var company = new Option<string>("--company") { Description = Strings.CompanyOptionDescription, HelpName = "name" };
        var gdpr = new Option<bool>("--gdpr") { Description = Strings.GdprOptionDescription };
        var nis2 = new Option<bool>("--nis2") { Description = Strings.Nis2OptionDescription };
        var answers = new Option<string>("--answers") { Description = Strings.AnswersOptionDescription, HelpName = "file" };

        var command = new Command("scan", Strings.ScanDescription) { mail, web, selectors, systemDns, operatorName, role, report, profile, company, gdpr, nis2, answers };
        command.SetAction((parseResult, cancellationToken) => RunAsync(
            new ScanRequest(
                parseResult.GetValue(mail) ?? [],
                parseResult.GetValue(web) ?? [],
                parseResult.GetValue(selectors) ?? [],
                parseResult.GetValue(systemDns),
                parseResult.GetValue(operatorName),
                parseResult.GetValue(role),
                parseResult.GetValue(report),
                parseResult.GetValue(profile),
                parseResult.GetValue(company),
                parseResult.GetValue(gdpr),
                parseResult.GetValue(nis2),
                parseResult.GetValue(answers)),
            services,
            parseResult.InvocationConfiguration.Output,
            parseResult.InvocationConfiguration.Error,
            cancellationToken));
        return command;
    }

    /// <summary>Validates the request, runs the checks and prints the results.</summary>
    /// <param name="request">The parsed options.</param>
    /// <param name="services">Checks, clock and user name.</param>
    /// <param name="output">Where the results go.</param>
    /// <param name="error">Where input errors go.</param>
    /// <param name="cancellationToken">Stops the run (Ctrl+C).</param>
    /// <returns>
    /// 0 when the checks ran, whatever they found; <see cref="InvalidInput"/> for a wrong option value;
    /// <see cref="ReportNotWritten"/> when the report files could not be written.
    /// </returns>
    internal static async Task<int> RunAsync(
        ScanRequest request,
        CliServices services,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        var domains = request.Domains.Where(d => !string.IsNullOrWhiteSpace(d)).ToArray();
        var sites = request.Websites.Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
        if (domains.Length + sites.Length == 0 && !request.Gdpr && !request.Nis2)
        {
            await error.WriteLineAsync(Strings.NoTargets).ConfigureAwait(false);
            return InvalidInput;
        }

        var hosts = new List<string>();
        foreach (var site in sites)
        {
            if (!WebChecks.TryNormalizeTarget(site, out var host))
            {
                await error.WriteLineAsync(Format(Strings.InvalidWebTarget, site)).ConfigureAwait(false);
                return InvalidInput;
            }

            hosts.Add(host);
        }

        if (request.ReportFolder is { } folder && string.IsNullOrWhiteSpace(folder))
        {
            await error.WriteLineAsync(Strings.InvalidReportFolder).ConfigureAwait(false);
            return InvalidInput;
        }

        if (request.DkimSelectors.FirstOrDefault(s => !IsSelector(s)) is { } invalid)
        {
            await error.WriteLineAsync(Format(Strings.InvalidSelector, invalid)).ConfigureAwait(false);
            return InvalidInput;
        }

        if (request.Profile == ProfileKind.Company && string.IsNullOrWhiteSpace(request.Company))
        {
            await error.WriteLineAsync(Strings.CompanyNameRequired).ConfigureAwait(false);
            return InvalidInput;
        }

        if (request.Nis2 && request.Profile != ProfileKind.Company)
        {
            await error.WriteLineAsync(Strings.Nis2NeedsCompany).ConfigureAwait(false);
            return InvalidInput;
        }

        var profile = request.Profile == ProfileKind.Company ? Profile.Company(request.Company!) : Profile.Individual();
        Questionnaire[] questionnaires =
        [
            .. request.Gdpr ? [QuestionnaireCatalog.GdprFor(profile.Kind)] : Array.Empty<Questionnaire>(),
            .. request.Nis2 ? [QuestionnaireCatalog.Get(QuestionnaireCatalog.Nis2)] : Array.Empty<Questionnaire>(),
        ];

        IReadOnlyDictionary<string, string>? givenAnswers = null;
        if (request.AnswersFile is { } answersFile)
        {
            givenAnswers = await ReadAnswersAsync(answersFile, questionnaires, error, cancellationToken).ConfigureAwait(false);
            if (givenAnswers is null)
            {
                return InvalidInput;
            }
        }

        var dns = request.SystemDns ? DnsSource.System : DnsSource.Public;
        var options = new EmailCheckOptions
        {
            DkimSelectors = request.DkimSelectors,
            DnsSource = dns,
        };
        var operatorName = FirstNonBlank(request.Operator, services.DefaultOperator()) ?? Strings.UnknownOperator;
        var scope = new ScopeDeclaration(
            operatorName,
            request.Role,
            domains.Select(d => new Target(TargetKind.Domain, d))
                .Concat(hosts.Select(h => new Target(TargetKind.Website, h))),
            services.Now());

        // Each area is built only when asked for: the engine runs a check on the targets of its kind.
        ICheck[] checks =
        [
            .. domains.Length > 0 ? services.CreateEmailChecks(options) : [],
            .. hosts.Count > 0 ? services.CreateWebChecks(new WebCheckOptions { DnsSource = dns }) : [],
        ];

        var report = new ScanReport(output);
        report.WriteHeader(scope, checks);

        // A proxy between this computer and the site changes what the certificate checks see: say it,
        // on screen and in the report.
        var notes = new List<string>();
        foreach (var host in hosts)
        {
            if (services.WebProxyFor(host) is { } proxy)
            {
                var note = Format(Strings.WebProxyNote, host, proxy);
                notes.Add(note);
                report.WriteNote(note);
            }
        }

        // The questions come before the checks: the user is at the keyboard now, not after a minute of DNS.
        var culture = CultureInfo.CurrentUICulture;
        var allAnswers = givenAnswers
            ?? (questionnaires.Length > 0 ? QuestionnairePrompt.Ask(questionnaires, services.Input ?? Console.In, output, culture) : new Dictionary<string, string>());

        var runs = await new CheckEngine(new PassiveOnlyScopeGuard())
            .RunAsync(checks, profile, scope, cancellationToken)
            .ConfigureAwait(false);

        // The technical findings feed the art. 32 question only when some check was really executed:
        // checks that were all skipped or failed prove nothing (ADR-008).
        var technical = TechnicalEvidence.Of(runs);
        var subject = profile.CompanyName ?? operatorName;
        var outcomes = questionnaires.Select(q => QuestionnaireEvaluator.Evaluate(q, allAnswers, subject, technical, culture)).ToArray();
        report.WriteResults(scope, runs, outcomes);

        if (request.ReportFolder is null)
        {
            return 0;
        }

        notes.AddRange(outcomes.Select(o => Format(Strings.QuestionnaireNote, o.Questionnaire.Title.In(culture), o.Questionnaire.Id, o.Questionnaire.Version, o.Questionnaire.Notice.In(culture))));
        var sections = outcomes.Select(o => ReportBuilder.QuestionnaireSection(
            o.Questionnaire.Area,
            o.Findings,
            o.Passed.Select(p => new ReportCheck(p.Id, p.Label, p.Detail))));
        var document = ReportBuilder.Build(scope, profile, runs, ProgramVersion.Current, services.Now(), notes, sections);
        try
        {
            var paths = await ReportFiles.WriteAsync(document, request.ReportFolder, cancellationToken).ConfigureAwait(false);
            await output.WriteLineAsync(Format(Strings.ReportWritten, paths.Html, paths.Pdf, paths.Json)).ConfigureAwait(false);
            return 0;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // The checks ran and their results are on screen: only the files are missing. Any error
            // (disk, path, but also the template or the PDF library) ends here, never as a crash.
            await error.WriteLineAsync(Format(Strings.ReportNotWritten, request.ReportFolder, e.Message)).ConfigureAwait(false);
            return ReportNotWritten;
        }
    }

    private static async Task<IReadOnlyDictionary<string, string>?> ReadAnswersAsync(
        string path,
        IReadOnlyList<Questionnaire> questionnaires,
        TextWriter error,
        CancellationToken cancellationToken)
    {
        IReadOnlyDictionary<string, string> answers;
        try
        {
            answers = AnswersFile.Read(await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException or NotSupportedException)
        {
            await error.WriteLineAsync(Format(Strings.AnswersNotRead, path, e.Message)).ConfigureAwait(false);
            return null;
        }

        var problems = AnswersFile.Validate(answers, questionnaires);
        if (problems.Count == 0)
        {
            return answers;
        }

        await error.WriteLineAsync(Format(Strings.AnswersInvalid, path)).ConfigureAwait(false);
        foreach (var problem in problems)
        {
            await error.WriteLineAsync("  " + problem).ConfigureAwait(false);
        }

        return null;
    }

    private static bool IsSelector(string selector)
    {
        try
        {
            _ = new EmailCheckOptions { DkimSelectors = [selector] };
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static string? FirstNonBlank(params string?[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v))?.Trim();

    private static string Format(string format, params object?[] arguments) => string.Format(CultureInfo.CurrentCulture, format, arguments);
}

/// <summary>The options of <c>scudo scan</c>, after parsing.</summary>
/// <param name="Domains">Values of <c>--mail</c>.</param>
/// <param name="Websites">Values of <c>--web</c>.</param>
/// <param name="DkimSelectors">Values of <c>--dkim-selector</c>.</param>
/// <param name="SystemDns">Whether <c>--system-dns</c> was given.</param>
/// <param name="Operator">Value of <c>--operator</c>, if any.</param>
/// <param name="Role">Value of <c>--role</c>.</param>
/// <param name="ReportFolder">Value of <c>--report</c>: where to write the report files; <see langword="null"/> for none.</param>
/// <param name="Profile">Value of <c>--profile</c>.</param>
/// <param name="Company">Value of <c>--company</c>, required for a company.</param>
/// <param name="Gdpr">Whether <c>--gdpr</c> was given.</param>
/// <param name="Nis2">Whether <c>--nis2</c> was given.</param>
/// <param name="AnswersFile">Value of <c>--answers</c>: the file of answers; <see langword="null"/> to ask in the terminal.</param>
internal sealed record ScanRequest(
    IReadOnlyList<string> Domains,
    IReadOnlyList<string> Websites,
    IReadOnlyList<string> DkimSelectors,
    bool SystemDns,
    string? Operator,
    OperatorRole Role,
    string? ReportFolder = null,
    ProfileKind Profile = ProfileKind.Individual,
    string? Company = null,
    bool Gdpr = false,
    bool Nis2 = false,
    string? AnswersFile = null);
