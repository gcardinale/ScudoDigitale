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
using ScudoDigitale.Core;

namespace ScudoDigitale.Compliance.Tests;

/// <summary>Sets the UI culture for the current async flow and restores it on dispose.</summary>
internal sealed class UiCulture : IDisposable
{
    private readonly CultureInfo previous = CultureInfo.CurrentUICulture;

    public UiCulture(string name) => CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name);

    public void Dispose() => CultureInfo.CurrentUICulture = previous;
}

/// <summary>Builders for test objects.</summary>
internal static class Make
{
    public static readonly CultureInfo English = CultureInfo.GetCultureInfo("en-US");

    public static readonly CultureInfo Italian = CultureInfo.GetCultureInfo("it-IT");

    /// <summary>Answers from pairs; a null value is left out, as a question nobody answered.</summary>
    public static Dictionary<string, string> Answers(params (string Id, string? Value)[] pairs) =>
        pairs.Where(p => p.Value is not null).ToDictionary(p => p.Id, p => p.Value!);

    /// <summary>Every yes/no question of a questionnaire answered the same way.</summary>
    public static Dictionary<string, string> AllYesNo(Questionnaire questionnaire, string value) =>
        questionnaire.Questions.Where(q => q.Kind == QuestionKind.YesNo).ToDictionary(q => q.Id, _ => value);

    public static PrioritizedFinding Technical(string id, Severity severity, CheckArea area = CheckArea.Email, string target = "example.com") =>
        new(new Finding(id, area, "Title of " + id, severity, Confidence.Certain, target), severity);

    /// <summary>A valid one-question questionnaire as JSON, with a placeholder to break it.</summary>
    public static string Json(string question = DefaultQuestion, string extra = "", string area = "Gdpr") => $$"""
        {
          "id": "test",
          "version": "2026-11-25",
          "area": "{{area}}",
          "profile": "Company",
          "title": { "en": "Title", "it": "Titolo" },
          "notice": { "en": "Notice", "it": "Avviso" },
          {{extra}}
          "questions": [ {{question}} ]
        }
        """;

    public const string DefaultQuestion = """
        {
          "id": "GDPR-TEST-001",
          "kind": "YesNo",
          "label": { "en": "Label", "it": "Etichetta" },
          "text": { "en": "Question?", "it": "Domanda?" },
          "finding": { "en": "Problem", "it": "Problema" },
          "severity": "High",
          "risk": { "en": "Risk", "it": "Rischio" },
          "fix": { "en": "Fix", "it": "Correzione" },
          "references": ["GDPR art. 30"]
        }
        """;
}
