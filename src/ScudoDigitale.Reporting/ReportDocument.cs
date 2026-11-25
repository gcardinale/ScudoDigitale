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

using ScudoDigitale.Core;

namespace ScudoDigitale.Reporting;

/// <summary>
/// Everything a report says, in the form that is written to the JSON file (ADR-005). The HTML and the
/// PDF are rendered from this document, so the three formats always say the same thing, and a JSON
/// written today can be rendered again or compared with a later run. The format changes only through
/// <see cref="SchemaVersion"/>.
/// </summary>
public sealed record ReportDocument
{
    /// <summary>The version of the format written by this program.</summary>
    public const int CurrentSchemaVersion = 1;

    /// <summary>Version of the format; <see cref="CurrentSchemaVersion"/> for documents written by this program.</summary>
    public int SchemaVersion { get; init; } = CurrentSchemaVersion;

    /// <summary>Name of the program that wrote the report.</summary>
    public string Program { get; init; } = Attribution.ProductName;

    /// <summary>Version of the program that wrote the report, for example <c>0.1.0</c>.</summary>
    public required string ProgramVersion { get; init; }

    /// <summary>Version of the CVE database used; <see langword="null"/> when no database was used.</summary>
    public string? VulnerabilityDatabaseVersion { get; init; }

    /// <summary>When the report was generated.</summary>
    public required DateTimeOffset GeneratedAt { get; init; }

    /// <summary>
    /// Culture name of the texts in the report, for example <c>it-IT</c> or <c>en-US</c>. The findings
    /// are written in this language, so the labels of the HTML and PDF use it too.
    /// </summary>
    public required string Language { get; init; }

    /// <summary>Who ran the assessment, in what role, when, and on what.</summary>
    public required ReportDeclaration Declaration { get; init; }

    /// <summary>Who the assessment is for.</summary>
    public required ReportProfile Profile { get; init; }

    /// <summary>Things the reader must know to interpret the results (for example a proxy in the way).</summary>
    public IReadOnlyList<string> Notes { get; init; } = [];

    /// <summary>One section per area and target, in the order of spec §4 (network, Wi-Fi, websites, email, Bluetooth, GDPR, NIS2).</summary>
    public IReadOnlyList<ReportSection> Sections { get; init; } = [];
}

/// <summary>The scope declaration, as printed in the report.</summary>
public sealed record ReportDeclaration
{
    /// <summary>Name of the person who ran the assessment.</summary>
    public required string OperatorName { get; init; }

    /// <summary>Declared role of that person.</summary>
    public required OperatorRole OperatorRole { get; init; }

    /// <summary>When the declaration was made.</summary>
    public required DateTimeOffset DeclaredAt { get; init; }

    /// <summary>What was checked; empty for an assessment made only of questionnaires.</summary>
    public IReadOnlyList<ReportTarget> Targets { get; init; } = [];
}

/// <summary>Something that was checked.</summary>
/// <param name="Kind">Kind of target.</param>
/// <param name="Value">The domain, site, address or network.</param>
public sealed record ReportTarget(TargetKind Kind, string Value);

/// <summary>The profile of whoever the assessment is for.</summary>
public sealed record ReportProfile
{
    /// <summary>Individual or company.</summary>
    public required ProfileKind Kind { get; init; }

    /// <summary>Company name; <see langword="null"/> for an individual.</summary>
    public string? CompanyName { get; init; }

    /// <summary>VAT number, if given.</summary>
    public string? VatNumber { get; init; }

    /// <summary>ATECO sector code, if given.</summary>
    public string? AtecoCode { get; init; }

    /// <summary>Number of employees, if given.</summary>
    public int? Employees { get; init; }

    /// <summary>Annual turnover in euro, if given.</summary>
    public decimal? AnnualTurnoverEur { get; init; }
}

/// <summary>The results of one area on one target, or of one questionnaire.</summary>
public sealed record ReportSection
{
    /// <summary>The area.</summary>
    public required CheckArea Area { get; init; }

    /// <summary>The target checked; <see langword="null"/> for a questionnaire, which has none.</summary>
    public string? Target { get; init; }

    /// <summary>The problems found, most urgent first.</summary>
    public IReadOnlyList<ReportFinding> Findings { get; init; } = [];

    /// <summary>The checks that ran and found nothing.</summary>
    public IReadOnlyList<ReportCheck> Passed { get; init; } = [];

    /// <summary>The checks that could not run here, each with the reason.</summary>
    public IReadOnlyList<ReportCheck> Skipped { get; init; } = [];

    /// <summary>The checks that tried to run and failed, each with the error.</summary>
    public IReadOnlyList<ReportCheck> Failed { get; init; } = [];
}

/// <summary>A check that did not produce findings: passed, skipped or failed.</summary>
/// <param name="Id">Check id, for example <c>MAIL-SPF-001</c>.</param>
/// <param name="Title">User-facing name of the check.</param>
/// <param name="Detail">Why it was skipped, or why it failed; <see langword="null"/> for a check that passed.</param>
public sealed record ReportCheck(string Id, string Title, string? Detail = null);

/// <summary>A finding, with the severity it has in the report (spec §3).</summary>
public sealed record ReportFinding
{
    /// <summary>Check id, for example <c>MAIL-DMARC-001</c>.</summary>
    public required string Id { get; init; }

    /// <summary>Area of the check.</summary>
    public required CheckArea Area { get; init; }

    /// <summary>Short title.</summary>
    public required string Title { get; init; }

    /// <summary>Severity assigned by the check.</summary>
    public required Severity Severity { get; init; }

    /// <summary>Severity in the report, after KEV, CVSS and EPSS (<see cref="FindingPrioritizer"/>).</summary>
    public required Severity EffectiveSeverity { get; init; }

    /// <summary>How sure the check is.</summary>
    public required Confidence Confidence { get; init; }

    /// <summary>What the finding refers to.</summary>
    public required string Target { get; init; }

    /// <summary>What was observed, if anything.</summary>
    public string? Evidence { get; init; }

    /// <summary>Related CVE identifiers.</summary>
    public IReadOnlyList<string> Cve { get; init; } = [];

    /// <summary>CVSS base score, if known.</summary>
    public double? Cvss { get; init; }

    /// <summary>EPSS probability of exploitation, if known.</summary>
    public double? Epss { get; init; }

    /// <summary>Whether a related CVE is in the CISA KEV catalog.</summary>
    public bool Kev { get; init; }

    /// <summary>What can happen if the problem is not fixed.</summary>
    public string? Risk { get; init; }

    /// <summary>How to fix it.</summary>
    public string? Fix { get; init; }

    /// <summary>Standards and laws the finding refers to.</summary>
    public IReadOnlyList<string> References { get; init; } = [];
}
