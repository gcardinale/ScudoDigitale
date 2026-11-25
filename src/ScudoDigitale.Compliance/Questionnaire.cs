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
using System.Text.Json.Serialization;
using ScudoDigitale.Core;

namespace ScudoDigitale.Compliance;

/// <summary>
/// A questionnaire, as defined in its JSON file (ADR-008): an id, a version, the area and the profile
/// it is for, and its questions with their texts in English and Italian.
/// </summary>
public sealed record Questionnaire
{
    /// <summary>Stable id, for example <c>gdpr-company</c>.</summary>
    public required string Id { get; init; }

    /// <summary>Version of the questions, a date such as <c>2026-11-25</c>; written in the report.</summary>
    public required string Version { get; init; }

    /// <summary>Area of the findings: <see cref="CheckArea.Gdpr"/> or <see cref="CheckArea.Nis2"/>.</summary>
    public required CheckArea Area { get; init; }

    /// <summary>The profile the questionnaire is for.</summary>
    public required ProfileKind Profile { get; init; }

    /// <summary>Title.</summary>
    public required LocalizedText Title { get; init; }

    /// <summary>What the results are worth, printed in the notes of the report.</summary>
    public required LocalizedText Notice { get; init; }

    /// <summary>The questions, in the order they are asked.</summary>
    public required IReadOnlyList<Question> Questions { get; init; }
}

/// <summary>Kind of question.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<QuestionKind>))]
public enum QuestionKind
{
    /// <summary>Yes, no, don't know (and "not applicable" when allowed): "no" is a problem.</summary>
    YesNo,

    /// <summary>One option out of a list; it describes the organization and raises no problem by itself.</summary>
    Choice,

    /// <summary>
    /// Not asked: answered by the technical findings of the same assessment (ADR-008, art. 32 GDPR).
    /// A problem when at least one finding of <see cref="Question.MinimumSeverity"/> or above exists.
    /// </summary>
    Technical,
}

/// <summary>A question of a questionnaire.</summary>
public sealed record Question
{
    /// <summary>Id of the question, also the id of its finding, for example <c>GDPR-ART30-001</c>.</summary>
    public required string Id { get; init; }

    /// <summary>Kind of question.</summary>
    public required QuestionKind Kind { get; init; }

    /// <summary>Short name, shown in the list of questions answered without problems.</summary>
    public required LocalizedText Label { get; init; }

    /// <summary>The question as asked; for a technical question, what it looks at.</summary>
    public required LocalizedText Text { get; init; }

    /// <summary>Title of the finding when the answer is a problem; <see langword="null"/> for a choice.</summary>
    public LocalizedText? Finding { get; init; }

    /// <summary>Severity of the finding; <see langword="null"/> for a choice.</summary>
    public Severity? Severity { get; init; }

    /// <summary>What can happen; <see langword="null"/> for a choice.</summary>
    public LocalizedText? Risk { get; init; }

    /// <summary>What to do; <see langword="null"/> for a choice.</summary>
    public LocalizedText? Fix { get; init; }

    /// <summary>Laws and standards the question refers to.</summary>
    public IReadOnlyList<string> References { get; init; } = [];

    /// <summary>Whether "not applicable" is an accepted answer (for example the DPO, required only in some cases).</summary>
    public bool AllowNotApplicable { get; init; }

    /// <summary>
    /// When the question is asked; <see langword="null"/> for always. The only condition in v0.1 is
    /// <see cref="Conditions.Nis2InScope"/>.
    /// </summary>
    public string? AskIf { get; init; }

    /// <summary>The options of a choice; empty for the other kinds.</summary>
    public IReadOnlyList<QuestionOption> Options { get; init; } = [];

    /// <summary>For a technical question, the lowest effective severity that counts.</summary>
    public Severity? MinimumSeverity { get; init; }

    /// <summary>The conditions a question can be asked under.</summary>
    public static class Conditions
    {
        /// <summary>Asked when the NIS2 scope is not "probably out of scope".</summary>
        public const string Nis2InScope = "nis2InScope";
    }
}

/// <summary>An option of a choice question.</summary>
/// <param name="Id">Stable id of the option, the value written in an answers file.</param>
/// <param name="Text">What the user reads.</param>
public sealed record QuestionOption(string Id, LocalizedText Text);

/// <summary>A text in English and Italian (ADR-008).</summary>
/// <param name="En">English.</param>
/// <param name="It">Italian.</param>
public sealed record LocalizedText(string En, string It)
{
    /// <summary>The text in a language: Italian for any Italian culture, English otherwise.</summary>
    /// <param name="culture">The language wanted.</param>
    /// <returns>The text.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="culture"/> is <see langword="null"/>.</exception>
    public string In(CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(culture);
        return culture.TwoLetterISOLanguageName == "it" ? It : En;
    }
}
