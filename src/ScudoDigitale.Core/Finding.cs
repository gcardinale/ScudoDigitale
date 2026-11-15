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

using System.Text.RegularExpressions;

namespace ScudoDigitale.Core;

/// <summary>
/// A problem, or a fact worth knowing, found by a check (docs/00-functional-spec.md §3).
/// </summary>
public sealed partial record Finding
{
    private readonly double? cvss;
    private readonly double? epss;
    private readonly IReadOnlyList<string> cve = [];
    private readonly IReadOnlyList<string> references = [];

    /// <summary>
    /// Creates a finding.
    /// </summary>
    /// <param name="id">Stable check id in the form <c>AREA-TOPIC-NNN</c>, for example <c>MAIL-DMARC-001</c>.</param>
    /// <param name="area">Area of the check that produced the finding.</param>
    /// <param name="title">Short, user-facing title.</param>
    /// <param name="severity">Severity assigned by the check, before prioritization.</param>
    /// <param name="confidence">How sure the check is.</param>
    /// <param name="target">What the finding refers to (domain, host, network, ...).</param>
    /// <exception cref="ArgumentException">The id is not in the <c>AREA-TOPIC-NNN</c> form, or a text is empty or blank.</exception>
    /// <exception cref="ArgumentOutOfRangeException">An enum argument is not a defined value.</exception>
    public Finding(
        string id,
        CheckArea area,
        string title,
        Severity severity,
        Confidence confidence,
        string target)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(title);
        ArgumentException.ThrowIfNullOrWhiteSpace(target);
        if (!IsCheckId(id))
        {
            throw new ArgumentException($"'{id}' is not a check id in the AREA-TOPIC-NNN form.", nameof(id));
        }

        Id = id;
        Area = Defined(area, nameof(area));
        Title = title;
        Severity = Defined(severity, nameof(severity));
        Confidence = Defined(confidence, nameof(confidence));
        Target = target;
    }

    /// <summary>Stable check id, for example <c>MAIL-DMARC-001</c>. Never reused for a different check.</summary>
    public string Id { get; }

    /// <summary>Area of the check that produced the finding.</summary>
    public CheckArea Area { get; }

    /// <summary>Short, user-facing title.</summary>
    public string Title { get; }

    /// <summary>
    /// Severity assigned by the check. It never changes: the severity used to sort the report is
    /// <see cref="PrioritizedFinding.EffectiveSeverity"/>, computed by <see cref="FindingPrioritizer"/>.
    /// </summary>
    public Severity Severity { get; }

    /// <summary>How sure the check is.</summary>
    public Confidence Confidence { get; }

    /// <summary>What the finding refers to.</summary>
    public string Target { get; }

    /// <summary>What was observed (a DNS record, a header, a banner), if any.</summary>
    public string? Evidence { get; init; }

    /// <summary>Related CVE identifiers in the <c>CVE-YYYY-NNNN</c> form; never <see langword="null"/>.</summary>
    /// <exception cref="ArgumentNullException">The list is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">An item is not a CVE identifier.</exception>
    public IReadOnlyList<string> Cve
    {
        get => cve;
        init => cve = CopyOf(value, nameof(Cve), static item => CvePattern().IsMatch(item));
    }

    /// <summary>CVSS base score, from 0 to 10, if known.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is outside 0-10 or not a number.</exception>
    public double? Cvss
    {
        get => cvss;
        init => cvss = InRange(value, 10.0, nameof(Cvss));
    }

    /// <summary>EPSS probability of exploitation, from 0 to 1, if known.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is outside 0-1 or not a number.</exception>
    public double? Epss
    {
        get => epss;
        init => epss = InRange(value, 1.0, nameof(Epss));
    }

    /// <summary>Whether a related CVE is in the CISA Known Exploited Vulnerabilities catalog.</summary>
    public bool Kev { get; init; }

    /// <summary>What can happen if the problem is not fixed, in plain language.</summary>
    public string? Risk { get; init; }

    /// <summary>How to fix the problem.</summary>
    public string? Fix { get; init; }

    /// <summary>Standards and laws the finding refers to (RFCs, GDPR articles, ...); never <see langword="null"/>.</summary>
    /// <exception cref="ArgumentNullException">The list is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">An item is empty or blank.</exception>
    public IReadOnlyList<string> References
    {
        get => references;
        init => references = CopyOf(value, nameof(References), static item => !string.IsNullOrWhiteSpace(item));
    }

    /// <summary>
    /// Whether <paramref name="id"/> is a check id in the <c>AREA-TOPIC-NNN</c> form.
    /// </summary>
    /// <param name="id">The candidate id.</param>
    /// <returns><see langword="true"/> if the id is well formed.</returns>
    public static bool IsCheckId(string? id) => id is not null && IdPattern().IsMatch(id);

    /// <summary>
    /// Pattern of a check id. Anchored with <c>\A</c> and <c>\z</c>: in .NET <c>$</c> would also accept a trailing newline.
    /// </summary>
    [GeneratedRegex(@"\A[A-Z][A-Z0-9]*-[A-Z][A-Z0-9]*-[0-9]{3}\z", RegexOptions.CultureInvariant)]
    private static partial Regex IdPattern();

    /// <summary>Pattern of a CVE identifier, for example <c>CVE-2024-3094</c>.</summary>
    [GeneratedRegex(@"\ACVE-[0-9]{4}-[0-9]{4,}\z", RegexOptions.CultureInvariant)]
    private static partial Regex CvePattern();

    private static T Defined<T>(T value, string name)
        where T : struct, Enum =>
        Enum.IsDefined(value) ? value : throw new ArgumentOutOfRangeException(name, value, "Undefined value.");

    private static string[] CopyOf(IEnumerable<string>? value, string name, Func<string, bool> isValid)
    {
        ArgumentNullException.ThrowIfNull(value, name);
        var items = value.ToArray();
        foreach (var item in items)
        {
            if (item is null || !isValid(item))
            {
                throw new ArgumentException($"Invalid item: '{item}'.", name);
            }
        }

        return items;
    }

    private static double? InRange(double? value, double max, string name) =>
        value is null || (value >= 0.0 && value <= max)
            ? value
            : throw new ArgumentOutOfRangeException(name, value, $"Must be between 0 and {max}.");
}
