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

using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace ScudoDigitale.Reporting;

/// <summary>
/// The JSON form of a <see cref="ReportDocument"/> (ADR-005): property names in camel case, enums
/// as their names (<c>"High"</c>, <c>"Email"</c>, as in spec §3), indented for people who open it.
/// Reading refuses another schema version, missing required values and nulls where a value is due,
/// so that a comparison between two runs never works on a half-read document.
/// </summary>
public static class ReportJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        // Findings quote what sites and DNS servers return: keep the text readable (no è), it is not HTML.
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        RespectNullableAnnotations = true,
        RespectRequiredConstructorParameters = true,
        Converters = { new JsonStringEnumConverter(allowIntegerValues: false) },
    };

    /// <summary>Writes the document as JSON.</summary>
    /// <param name="document">The report.</param>
    /// <returns>The JSON text, with LF line endings.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="document"/> is <see langword="null"/>.</exception>
    public static string Write(ReportDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);
        return JsonSerializer.Serialize(document, Options).ReplaceLineEndings("\n");
    }

    /// <summary>Reads a document written by <see cref="Write"/>.</summary>
    /// <param name="json">The JSON text.</param>
    /// <returns>The report.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="json"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidDataException">
    /// The text is not JSON, its schema version is not <see cref="ReportDocument.CurrentSchemaVersion"/>,
    /// or a required value is missing or invalid.
    /// </exception>
    public static ReportDocument Read(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            // The version is checked first: a document of another version may not even fit the types of this one.
            var version = JsonNode.Parse(json) is JsonObject root ? root["schemaVersion"] : null;
            if (version is not JsonValue value || !value.TryGetValue<int>(out var number) || number != ReportDocument.CurrentSchemaVersion)
            {
                throw new InvalidDataException($"Unsupported report schema version: {version?.ToJsonString() ?? "missing"}; this program reads version {ReportDocument.CurrentSchemaVersion}.");
            }

            var document = JsonSerializer.Deserialize<ReportDocument>(json, Options)
                ?? throw new InvalidDataException("The report is empty.");

            // The serializer checks the properties, not the items of the lists nor the ranges.
            var problems = Problems(document).ToArray();
            return problems.Length == 0 ? document : throw new InvalidDataException($"The report is not valid: {string.Join(" ", problems)}");
        }
        catch (JsonException e)
        {
            throw new InvalidDataException($"The report is not valid: {e.Message}", e);
        }
    }

    /// <summary>What makes a document impossible to render or to compare, beyond what the serializer checks.</summary>
    /// <param name="d">The document.</param>
    /// <returns>One message per problem.</returns>
    internal static IEnumerable<string> Problems(ReportDocument d)
    {
        if (Blank(d.Program) || Blank(d.ProgramVersion) || Blank(d.Language))
        {
            yield return "program, programVersion and language are required.";
        }

        if (Blank(d.Declaration.OperatorName) || d.Declaration.Targets.Any(t => t is null || Blank(t.Value)))
        {
            yield return "the declaration needs an operator and targets with a value.";
        }

        if (d.Notes.Any(n => n is null))
        {
            yield return "a note is null.";
        }

        for (var i = 0; i < d.Sections.Count; i++)
        {
            var s = d.Sections[i];
            if (s is null)
            {
                yield return $"section {i} is null.";
                continue;
            }

            if (s.Passed.Concat(s.Skipped).Concat(s.Failed).Any(c => c is null || Blank(c.Id) || Blank(c.Title)))
            {
                yield return $"section {i}: a check is null or has no id or title.";
            }

            foreach (var f in s.Findings)
            {
                if (f is null)
                {
                    yield return $"section {i}: a finding is null.";
                }
                else if (!Core.Finding.IsCheckId(f.Id) || Blank(f.Title) || Blank(f.Target)
                    || f.Cve.Any(c => c is null) || f.References.Any(r => r is null)
                    || f.Cvss is < 0 or > 10 || f.Epss is < 0 or > 1)
                {
                    yield return $"section {i}: finding {f.Id} has a bad id, title, target, list, CVSS or EPSS.";
                }
            }
        }
    }

    private static bool Blank(string? text) => string.IsNullOrWhiteSpace(text);
}
