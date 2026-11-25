# Reporting — status

- **Content:** HTML, PDF, JSON (v0.1); comparison between two runs (v0.2)
- **Release:** v0.1
- **Status:** 🟢 HTML, PDF and JSON implemented (25/11/2026), branch `feature/v0.1-reporting`; comparison to do
- **Test coverage:** 100% lines (611/611), 96.1% branches (123/128) — 78 tests

## Done
- `ReportDocument` (ADR-005): the versioned DTO written to JSON, `schemaVersion` 1. Declaration, profile, notes, program version, CVE database version (`null` in v0.1), language of the texts, and one `ReportSection` per area and target with findings (assigned and effective severity), checks passed, skipped (with the reason) and failed (with the error).
- `ReportBuilder.Build(scope, profile, runs, version, generatedAt, notes, questionnaires)`: sections in the order of spec §4 (network, Wi-Fi, websites, email, Bluetooth, GDPR, NIS2), then in declaration order; findings sorted by `FindingPrioritizer`. `ReportBuilder.QuestionnaireSection` is where the Compliance findings go in: ordinary `Finding`s, no target.
- `ReportJson`: camel case, enums as names, indented, LF, accents not escaped. Reading checks `schemaVersion` first and refuses missing required values, nulls where a value is due, enums as numbers and unknown enum names (`InvalidDataException`); unknown properties are ignored. A golden test pins the format of version 1 (`tests/.../GoldenJson.cs`).
- `ReportSummary`: counts by severity (zeros included) and by area, checks passed/skipped/failed, the 5 most urgent actions (Info excluded, same order as the sections). Computed, never stored in the JSON.
- `HtmlReport`: one file, no external resources (no scripts, images, fonts or links), printable; the attribution footer is repeated on every printed page (`position: fixed` in `@media print`). **Every text is HTML-escaped before the template** (`HtmlEncoder`, accents kept): findings quote what remote sites and DNS servers return. Tested with a hostile string in 13 fields.
- `PdfReport` (MigraDoc 6.2.4): A4, same content as the HTML; attribution and "Page X of Y" in the primary footer of the only section, no different first or even page. The DejaVu Sans font is embedded (`EmbeddedFontResolver`): PdfSharp finds no system fonts on Linux and macOS.
- Labels in English and Italian in the language of the document, whatever the language of the computer that renders it. `Attribution.ReportFooter(version, culture)` added to Core for this.
- `ReportFiles.WriteAsync`: `scudo-report-yyyyMMdd-HHmmss.{html,pdf,json}`, folder created if missing, rendering before writing, an existing file is never overwritten (`FileMode.CreateNew`), no BOM.
- Run on 25/11/2026 with `scudo scan --mail gcardinale.it --web gcardinale.it --report …`: 25 checks in 9.6 s, three files written, PDF of 2 pages with the footer on both.

## Known limits
- The PDF shows the severity as coloured text (`[HIGH]`): MigraDoc has no background for a run of text.
- Two findings with the same title (e.g. two `ptr` in a provider's SPF include) appear as two identical actions in the summary; the evidence tells them apart in the section.
- `System.Security.Cryptography.Pkcs` is raised to 10.0.15 by a direct reference: PDFsharp 6.2.4 asks for 8.0.1, which has two advisories (GHSA-846f-f764-76mx, GHSA-2fmv-rv2c-59x7).

## To do
- Comparison between two JSON reports (`scudo report diff`) — v0.2.
- Packaging: ship `Fonts/DejaVu-LICENSE.txt` next to the executables.
