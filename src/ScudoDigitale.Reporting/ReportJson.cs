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

            return JsonSerializer.Deserialize<ReportDocument>(json, Options)
                ?? throw new InvalidDataException("The report is empty.");
        }
        catch (JsonException e)
        {
            throw new InvalidDataException($"The report is not valid: {e.Message}", e);
        }
    }
}
