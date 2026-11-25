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

using System.Text.Json;
using System.Text.Json.Serialization;
using ScudoDigitale.Core;

namespace ScudoDigitale.Compliance;

/// <summary>
/// The questionnaires included in the program (<c>Questionnaires/*.json</c>, ADR-008), read and
/// validated once. A questionnaire with a missing language, a bad or repeated id, or a question
/// without its finding texts is refused, so a mistake in a JSON file stops the build's tests instead
/// of reaching a report.
/// </summary>
public static class QuestionnaireCatalog
{
    /// <summary>Id of the GDPR questionnaire for individuals.</summary>
    public const string GdprIndividual = "gdpr-individual";

    /// <summary>Id of the GDPR questionnaire for companies.</summary>
    public const string GdprCompany = "gdpr-company";

    /// <summary>Id of the NIS2 questionnaire (companies only).</summary>
    public const string Nis2 = "nis2";

    private const string ResourcePrefix = "ScudoDigitale.Compliance.Questionnaires.";

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true,
        // A misspelt property would otherwise be ignored in silence.
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        Converters = { new JsonStringEnumConverter(allowIntegerValues: false) },
    };

    private static readonly Lazy<IReadOnlyList<Questionnaire>> Loaded = new(LoadAll);

    /// <summary>Every questionnaire included in the program.</summary>
    public static IReadOnlyList<Questionnaire> All => Loaded.Value;

    /// <summary>A questionnaire by id.</summary>
    /// <param name="id">For example <see cref="GdprCompany"/>.</param>
    /// <returns>The questionnaire.</returns>
    /// <exception cref="KeyNotFoundException">No questionnaire has that id.</exception>
    public static Questionnaire Get(string id) =>
        All.FirstOrDefault(q => q.Id == id) ?? throw new KeyNotFoundException($"No questionnaire with id '{id}'.");

    /// <summary>The GDPR questionnaire for a kind of profile.</summary>
    /// <param name="profile">Individual or company.</param>
    /// <returns>The questionnaire.</returns>
    public static Questionnaire GdprFor(ProfileKind profile) => Get(profile == ProfileKind.Company ? GdprCompany : GdprIndividual);

    /// <summary>Reads and validates a questionnaire.</summary>
    /// <param name="json">The JSON text.</param>
    /// <param name="name">Name of the file, for the error message.</param>
    /// <returns>The questionnaire.</returns>
    /// <exception cref="InvalidDataException">The JSON is not a valid questionnaire.</exception>
    internal static Questionnaire Parse(string json, string name)
    {
        Questionnaire questionnaire;
        try
        {
            questionnaire = JsonSerializer.Deserialize<Questionnaire>(json, Options)
                ?? throw new InvalidDataException($"{name}: empty.");
        }
        catch (JsonException e)
        {
            throw new InvalidDataException($"{name}: {e.Message}", e);
        }

        var errors = Validate(questionnaire).ToArray();
        return errors.Length == 0 ? questionnaire : throw new InvalidDataException($"{name}: {string.Join(" ", errors)}");
    }

    /// <summary>What is wrong with a questionnaire.</summary>
    /// <param name="q">The questionnaire.</param>
    /// <returns>One message per problem; none when it is valid.</returns>
    internal static IEnumerable<string> Validate(Questionnaire q)
    {
        if (string.IsNullOrWhiteSpace(q.Id) || string.IsNullOrWhiteSpace(q.Version))
        {
            yield return "id and version are required.";
        }

        if (q.Area is not (CheckArea.Gdpr or CheckArea.Nis2))
        {
            yield return $"area {q.Area} is not a questionnaire area.";
        }

        foreach (var message in Texts("title", q.Title).Concat(Texts("notice", q.Notice)))
        {
            yield return message;
        }

        if (q.Questions.Count == 0)
        {
            yield return "no questions.";
        }

        foreach (var duplicate in q.Questions.GroupBy(x => x.Id).Where(g => g.Count() > 1))
        {
            yield return $"question id {duplicate.Key} is repeated.";
        }

        foreach (var question in q.Questions)
        {
            foreach (var message in Validate(question))
            {
                yield return $"{question.Id}: {message}";
            }
        }
    }

    private static IEnumerable<string> Validate(Question x)
    {
        if (!Finding.IsCheckId(x.Id))
        {
            yield return "the id is not in the AREA-TOPIC-NNN form.";
        }

        foreach (var message in Texts("label", x.Label).Concat(Texts("text", x.Text)))
        {
            yield return message;
        }

        if (x.References.Any(string.IsNullOrWhiteSpace))
        {
            yield return "a reference is blank.";
        }

        if (x.AskIf is not (null or Question.Conditions.Nis2InScope))
        {
            yield return $"unknown condition '{x.AskIf}'.";
        }

        if (x.Kind == QuestionKind.Choice)
        {
            if (x.Options.Count < 2)
            {
                yield return "a choice needs at least two options.";
            }

            if (x.Options.Select(o => o.Id).Distinct().Count() != x.Options.Count || x.Options.Any(o => string.IsNullOrWhiteSpace(o.Id)))
            {
                yield return "option ids must be unique and not blank.";
            }

            foreach (var message in x.Options.SelectMany(o => Texts("option " + o.Id, o.Text)))
            {
                yield return message;
            }

            if (x.Severity is not null || x.Finding is not null)
            {
                yield return "a choice raises no finding.";
            }

            yield break;
        }

        if (x.Severity is null)
        {
            yield return "severity is required.";
        }

        foreach (var message in Texts("finding", x.Finding).Concat(Texts("risk", x.Risk)).Concat(Texts("fix", x.Fix)))
        {
            yield return message;
        }

        if (x.Options.Count > 0)
        {
            yield return "only a choice has options.";
        }

        if ((x.Kind == QuestionKind.Technical) != (x.MinimumSeverity is not null))
        {
            yield return "minimumSeverity is required for a technical question, and only there.";
        }
    }

    private static IEnumerable<string> Texts(string name, LocalizedText? text)
    {
        if (text is null)
        {
            yield return $"{name} is required.";
        }
        else if (string.IsNullOrWhiteSpace(text.En) || string.IsNullOrWhiteSpace(text.It))
        {
            yield return $"{name} needs both English and Italian.";
        }
    }

    private static IReadOnlyList<Questionnaire> LoadAll()
    {
        var assembly = typeof(QuestionnaireCatalog).Assembly;
        return assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .Select(n =>
            {
                using var stream = assembly.GetManifestResourceStream(n)!;
                using var reader = new StreamReader(stream);
                return Parse(reader.ReadToEnd(), n);
            })
            .ToArray();
    }
}
