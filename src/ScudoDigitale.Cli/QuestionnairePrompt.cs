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
using ScudoDigitale.Cli.Resources;
using ScudoDigitale.Compliance;

namespace ScudoDigitale.Cli;

/// <summary>
/// Asks the questions of the questionnaires in the terminal, one by one (ADR-008). The NIS2
/// obligations are asked only after the scope questions say the company is not probably out of
/// scope. When the input ends (Ctrl+Z, Ctrl+D, a closed pipe), the questions left count as
/// "don't know": the report marks them "to be verified", never as fine.
/// </summary>
internal static class QuestionnairePrompt
{
    /// <summary>Asks every question that applies.</summary>
    /// <param name="questionnaires">The questionnaires, in the order to ask them.</param>
    /// <param name="input">Where the answers come from.</param>
    /// <param name="output">Where the questions go.</param>
    /// <param name="culture">Language of the questions.</param>
    /// <returns>The answers by question id; a question not answered is missing.</returns>
    public static Dictionary<string, string> Ask(IReadOnlyList<Questionnaire> questionnaires, TextReader input, TextWriter output, CultureInfo culture)
    {
        var answers = new Dictionary<string, string>();
        foreach (var questionnaire in questionnaires)
        {
            output.WriteLine();
            output.WriteLine(string.Format(CultureInfo.CurrentCulture, Strings.QuestionnaireIntro, questionnaire.Title.In(culture)));
            var number = 0;
            foreach (var question in questionnaire.Questions)
            {
                var scope = questionnaire.Area == Core.CheckArea.Nis2 ? Nis2Scope.Assess(answers) : (Nis2Outcome?)null;
                if (question.Kind == QuestionKind.Technical || !QuestionnaireEvaluator.IsAsked(question, scope))
                {
                    continue;
                }

                output.WriteLine();
                output.WriteLine($"[{++number}] {question.Text.In(culture)}");
                var answer = AskOne(question, input, output, culture);
                if (answer is null)
                {
                    output.WriteLine();
                    output.WriteLine(Strings.PromptEnded);
                    return answers;
                }

                answers[question.Id] = answer;
            }
        }

        return answers;
    }

    /// <summary>Reads what the user typed as an answer to a question.</summary>
    /// <param name="question">The question.</param>
    /// <param name="typed">The line typed.</param>
    /// <returns>The answer, or <see langword="null"/> when the line is not an answer to this question.</returns>
    internal static string? Parse(Question question, string typed)
    {
        var text = typed.Trim().ToLowerInvariant();
        if (question.Kind == QuestionKind.Choice)
        {
            if (text == "?" && question.Options.Any(o => o.Id == Answers.Unknown))
            {
                return Answers.Unknown;
            }

            return int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n >= 1 && n <= question.Options.Count
                ? question.Options[n - 1].Id
                : null;
        }

        return text switch
        {
            "y" or "yes" or "s" or "si" or "sì" => Answers.Yes,
            "n" or "no" => Answers.No,
            "?" or "non so" or "unknown" => Answers.Unknown,
            "na" or "n/a" when question.AllowNotApplicable => Answers.NotApplicable,
            _ => null,
        };
    }

    private static string? AskOne(Question question, TextReader input, TextWriter output, CultureInfo culture)
    {
        if (question.Kind == QuestionKind.Choice)
        {
            for (var i = 0; i < question.Options.Count; i++)
            {
                output.WriteLine($"  {i + 1}) {question.Options[i].Text.In(culture)}");
            }

            output.WriteLine(Strings.PromptChoice);
        }
        else
        {
            output.WriteLine(Strings.PromptYesNo + (question.AllowNotApplicable ? Strings.PromptNotApplicable : string.Empty));
        }

        while (true)
        {
            output.Write("> ");
            var line = input.ReadLine();
            if (line is null)
            {
                return null;
            }

            if (Parse(question, line) is { } answer)
            {
                return answer;
            }

            output.WriteLine(Strings.PromptInvalid);
        }
    }
}
