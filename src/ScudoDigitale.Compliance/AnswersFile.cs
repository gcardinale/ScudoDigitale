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
using System.Text.Json;
using ScudoDigitale.Compliance.Resources;

namespace ScudoDigitale.Compliance;

/// <summary>
/// A file of answers (ADR-008): a JSON object from question id to answer, for example
/// <c>{ "GDPR-ART30-001": "yes", "NIS2-SECTOR-001": "annex2-food" }</c>. The same file gives the same
/// result, so an assessment can be repeated and compared.
/// </summary>
public static class AnswersFile
{
    /// <summary>Reads the answers.</summary>
    /// <param name="json">The JSON text.</param>
    /// <returns>Answers by question id.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="json"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidDataException">The text is not a JSON object of strings.</exception>
    public static IReadOnlyDictionary<string, string> Read(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            var answers = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
            return answers is null || answers.Values.Any(v => v is null)
                ? throw new InvalidDataException(Strings.AnswersNotAnObject)
                : answers;
        }
        catch (JsonException e)
        {
            // The message of System.Text.Json is in English only: the user gets the position instead.
            throw new InvalidDataException(Format(Strings.AnswersNotJson, (e.LineNumber ?? 0) + 1, (e.BytePositionInLine ?? 0) + 1), e);
        }
    }

    /// <summary>
    /// What is wrong with the answers for the questionnaires of an assessment: ids that belong to none of
    /// them, and values a question does not accept. A typo must not turn silently into "don't know".
    /// </summary>
    /// <param name="answers">The answers.</param>
    /// <param name="questionnaires">The questionnaires of the assessment.</param>
    /// <returns>One message per problem, in the current UI language; none when the answers are valid.</returns>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    public static IReadOnlyList<string> Validate(IReadOnlyDictionary<string, string> answers, IEnumerable<Questionnaire> questionnaires)
    {
        ArgumentNullException.ThrowIfNull(answers);
        ArgumentNullException.ThrowIfNull(questionnaires);
        var questions = questionnaires.SelectMany(q => q.Questions).ToDictionary(q => q.Id);
        var errors = new List<string>();
        foreach (var (id, value) in answers.OrderBy(a => a.Key, StringComparer.Ordinal))
        {
            if (!questions.TryGetValue(id, out var question))
            {
                errors.Add(Format(Strings.AnswerUnknownQuestion, id));
            }
            else if (!Accepted(question).Contains(value))
            {
                errors.Add(Format(Strings.AnswerNotAccepted, id, value, string.Join(", ", Accepted(question))));
            }
        }

        return errors;
    }

    private static string Format(string format, params object?[] arguments) => string.Format(CultureInfo.CurrentCulture, format, arguments);

    /// <summary>The answers a question accepts.</summary>
    /// <param name="question">The question.</param>
    /// <returns>The option ids of a choice; yes, no, unknown (and notApplicable when allowed) otherwise; nothing for a technical question.</returns>
    public static IReadOnlyList<string> Accepted(Question question)
    {
        ArgumentNullException.ThrowIfNull(question);
        return question.Kind switch
        {
            QuestionKind.Choice => question.Options.Select(o => o.Id).ToArray(),
            QuestionKind.YesNo when question.AllowNotApplicable => [Answers.Yes, Answers.No, Answers.Unknown, Answers.NotApplicable],
            QuestionKind.YesNo => [Answers.Yes, Answers.No, Answers.Unknown],
            _ => [],
        };
    }
}
