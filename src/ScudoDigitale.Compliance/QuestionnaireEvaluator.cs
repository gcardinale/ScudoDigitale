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
using ScudoDigitale.Compliance.Resources;
using ScudoDigitale.Core;

namespace ScudoDigitale.Compliance;

/// <summary>
/// Turns the answers to a questionnaire into ordinary <see cref="Finding"/>s (ADR-005, ADR-008):
/// "no" is a problem marked certain, "don't know" or no answer is the same problem marked "to be
/// verified", "yes" and an accepted "not applicable" go in the list of questions without problems.
/// The NIS2 questionnaire also gives the estimated scope, and asks the obligations only when the
/// company is not probably out of scope.
/// </summary>
public static class QuestionnaireEvaluator
{
    /// <summary>Id of the NIS2 scope finding.</summary>
    public const string Nis2ScopeFinding = "NIS2-SCOPE-001";

    /// <summary>Most technical findings listed in the evidence of a technical question.</summary>
    internal const int MaxListed = 10;

    /// <summary>Evaluates a questionnaire.</summary>
    /// <param name="questionnaire">The questionnaire.</param>
    /// <param name="answers">Answers by question id; missing ones count as "don't know".</param>
    /// <param name="subject">Who the findings are about: the company name, or the person.</param>
    /// <param name="technicalFindings">
    /// The prioritized findings of the technical checks of the same assessment, for the technical
    /// questions; <see langword="null"/> when no technical check ran, and then those questions are left out.
    /// </param>
    /// <param name="culture">Language of the texts.</param>
    /// <returns>The findings and the questions without problems.</returns>
    /// <exception cref="ArgumentNullException">An argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="subject"/> is empty or blank.</exception>
    public static QuestionnaireOutcome Evaluate(
        Questionnaire questionnaire,
        IReadOnlyDictionary<string, string> answers,
        string subject,
        IReadOnlyList<PrioritizedFinding>? technicalFindings,
        CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(questionnaire);
        ArgumentNullException.ThrowIfNull(answers);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        ArgumentNullException.ThrowIfNull(culture);

        var findings = new List<Finding>();
        var passed = new List<AnsweredQuestion>();
        Nis2Outcome? scope = null;
        if (questionnaire.Area == CheckArea.Nis2)
        {
            scope = Nis2Scope.Assess(answers);
            findings.Add(ScopeFinding(questionnaire, answers, scope.Value, subject, culture));
        }

        foreach (var question in questionnaire.Questions)
        {
            if (question.Kind == QuestionKind.Choice || !IsAsked(question, scope))
            {
                continue;
            }

            if (question.Kind == QuestionKind.Technical)
            {
                if (technicalFindings is not null)
                {
                    EvaluateTechnical(questionnaire, question, technicalFindings, subject, culture, findings, passed);
                }

                continue;
            }

            var answer = answers.GetValueOrDefault(question.Id);
            if (answer == Answers.Yes)
            {
                passed.Add(new AnsweredQuestion(question.Id, question.Label.In(culture)));
            }
            else if (answer == Answers.NotApplicable && question.AllowNotApplicable)
            {
                passed.Add(new AnsweredQuestion(question.Id, question.Label.In(culture), Text(nameof(Strings.NotApplicable), culture)));
            }
            else
            {
                var evidence = answer switch
                {
                    Answers.No => Text(nameof(Strings.AnswerNo), culture),
                    null => Text(nameof(Strings.NoAnswer), culture),
                    _ => Text(nameof(Strings.AnswerUnknown), culture),
                };
                findings.Add(FindingOf(questionnaire, question, subject, culture, answer == Answers.No ? Confidence.Certain : Confidence.ToBeVerified, evidence));
            }
        }

        return new QuestionnaireOutcome(questionnaire, findings, passed, scope);
    }

    /// <summary>Whether a question is asked, given the NIS2 scope assessed so far.</summary>
    /// <param name="question">The question.</param>
    /// <param name="scope">The NIS2 outcome, <see langword="null"/> outside NIS2.</param>
    /// <returns><see langword="true"/> when the question has no condition or its condition holds.</returns>
    public static bool IsAsked(Question question, Nis2Outcome? scope)
    {
        ArgumentNullException.ThrowIfNull(question);
        return question.AskIf != Question.Conditions.Nis2InScope || (scope is { } s && Nis2Scope.AsksObligations(s));
    }

    /// <summary>Title of the NIS2 scope finding.</summary>
    /// <param name="outcome">The outcome.</param>
    /// <param name="culture">Language.</param>
    /// <returns>The text.</returns>
    public static string ScopeTitle(Nis2Outcome outcome, CultureInfo culture) => Text("Nis2Title" + outcome, culture);

    private static void EvaluateTechnical(
        Questionnaire questionnaire,
        Question question,
        IReadOnlyList<PrioritizedFinding> technicalFindings,
        string subject,
        CultureInfo culture,
        List<Finding> findings,
        List<AnsweredQuestion> passed)
    {
        var relevant = technicalFindings
            .Where(f => f.EffectiveSeverity >= question.MinimumSeverity && f.Finding.Area is not (CheckArea.Gdpr or CheckArea.Nis2))
            .ToArray();
        if (relevant.Length == 0)
        {
            passed.Add(new AnsweredQuestion(question.Id, question.Label.In(culture)));
            return;
        }

        var listed = string.Join(", ", relevant.Take(MaxListed).Select(f => $"{f.Finding.Id} ({f.Finding.Target})"));
        var more = relevant.Length > MaxListed ? " " + string.Format(culture, Text(nameof(Strings.AndMore), culture), relevant.Length - MaxListed) : string.Empty;
        var evidence = string.Format(culture, Text(nameof(Strings.TechnicalEvidence), culture), relevant.Length, listed + more);
        findings.Add(FindingOf(questionnaire, question, subject, culture, Confidence.Probable, evidence));
    }

    private static Finding FindingOf(Questionnaire questionnaire, Question question, string subject, CultureInfo culture, Confidence confidence, string evidence) =>
        new(question.Id, questionnaire.Area, question.Finding!.In(culture), question.Severity!.Value, confidence, subject)
        {
            Evidence = evidence,
            Risk = question.Risk!.In(culture),
            Fix = question.Fix!.In(culture),
            References = question.References,
        };

    private static Finding ScopeFinding(Questionnaire questionnaire, IReadOnlyDictionary<string, string> answers, Nis2Outcome outcome, string subject, CultureInfo culture)
    {
        // The evidence repeats the answers the outcome comes from, with the texts the user read.
        var parts = Nis2Scope.Questions
            .Select(id => questionnaire.Questions.FirstOrDefault(q => q.Id == id))
            .OfType<Question>()
            .Select(q => $"{q.Label.In(culture)}: {OptionText(q, answers.GetValueOrDefault(q.Id), culture)}");

        return new Finding(Nis2ScopeFinding, CheckArea.Nis2, ScopeTitle(outcome, culture), Severity.Info, outcome == Nis2Outcome.ToBeVerified ? Confidence.ToBeVerified : Confidence.Probable, subject)
        {
            Evidence = string.Join("; ", parts),
            Risk = Text(nameof(Strings.Nis2ScopeRisk), culture),
            Fix = Text("Nis2Fix" + outcome, culture),
            References = ["D.Lgs. 138/2024 art. 3", "D.Lgs. 138/2024 art. 6", "Raccomandazione 2003/361/CE"],
        };
    }

    private static string OptionText(Question question, string? answer, CultureInfo culture) =>
        question.Options.FirstOrDefault(o => o.Id == answer)?.Text.In(culture) ?? Text(nameof(Strings.NoAnswerShort), culture);

    private static string Text(string name, CultureInfo culture) => Strings.ResourceManager.GetString(name, culture) ?? name;
}

/// <summary>What a questionnaire gave.</summary>
/// <param name="Questionnaire">The questionnaire.</param>
/// <param name="Findings">The problems, in the order of the questions (the report sorts them).</param>
/// <param name="Passed">The questions answered without problems.</param>
/// <param name="Nis2Scope">The NIS2 outcome; <see langword="null"/> for the other questionnaires.</param>
public sealed record QuestionnaireOutcome(
    Questionnaire Questionnaire,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<AnsweredQuestion> Passed,
    Nis2Outcome? Nis2Scope);

/// <summary>A question answered without problems.</summary>
/// <param name="Id">Id of the question.</param>
/// <param name="Label">Its short name.</param>
/// <param name="Detail">"not applicable" when that was the answer; otherwise <see langword="null"/>.</param>
public sealed record AnsweredQuestion(string Id, string Label, string? Detail = null);
