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
using ScudoDigitale.Core;

namespace ScudoDigitale.Cli;

/// <summary>
/// Text output of <c>scudo scan</c>: banner, warning and declaration, then for every target the
/// problems most urgent first (with evidence, risk and fix), the checks passed, skipped and failed,
/// and a summary. The attribution closes the output. The HTML and PDF reports come with Reporting.
/// </summary>
internal sealed class ScanReport(TextWriter output)
{
    private const string Indent = "      ";

    /// <summary>Banner, warning, declaration and what is about to run.</summary>
    /// <param name="scope">The declaration.</param>
    /// <param name="checksPerTarget">How many checks run on each target.</param>
    public void WriteHeader(ScopeDeclaration scope, int checksPerTarget)
    {
        output.WriteLine(Attribution.Banner);
        output.WriteLine();
        output.WriteLine(Strings.Disclaimer);
        output.WriteLine();
        output.WriteLine(Format(Strings.Declaration, scope.OperatorName, RoleLabel(scope.OperatorRole), scope.DeclaredAt.ToString("g", CultureInfo.CurrentCulture)));
        output.WriteLine(Format(Strings.Checking, string.Join(", ", scope.Targets.Select(t => t.Value)), checksPerTarget));
    }

    /// <summary>The results of every target, the summary and the attribution.</summary>
    /// <param name="scope">The declaration, for the order of the targets.</param>
    /// <param name="runs">What the engine returned.</param>
    public void WriteResults(ScopeDeclaration scope, IReadOnlyList<CheckRun> runs)
    {
        var all = new List<PrioritizedFinding>();
        foreach (var target in scope.Targets)
        {
            var mine = runs.Where(r => r.Target == target).ToArray();
            var findings = FindingPrioritizer.Prioritize(mine.Select(r => r.Result).OfType<CheckResult.Executed>().SelectMany(r => r.Findings));
            all.AddRange(findings);

            output.WriteLine();
            output.WriteLine($"== {Strings.AreaEmail} — {target.Value} ==");
            WriteFindings(findings);
            WriteList(Strings.ChecksPassed, mine.Where(r => r.Result is CheckResult.Executed { Findings.Count: 0 }), "OK", _ => null);
            WriteList(Strings.ChecksSkipped, mine.Where(r => r.Result is CheckResult.Skipped), "--", r => ((CheckResult.Skipped)r.Result).Reason);
            WriteList(Strings.ChecksFailed, mine.Where(r => r.Result is CheckResult.Failed), "!!", r => ((CheckResult.Failed)r.Result).Error);
        }

        output.WriteLine();
        output.WriteLine(Format(
            Strings.Summary,
            Count(all, Severity.Critical),
            Count(all, Severity.High),
            Count(all, Severity.Medium),
            Count(all, Severity.Low),
            Count(all, Severity.Info),
            runs.Count(r => r.Result is CheckResult.Executed { Findings.Count: 0 }),
            runs.Count(r => r.Result is CheckResult.Skipped),
            runs.Count(r => r.Result is CheckResult.Failed)));
        output.WriteLine(Attribution.Notice);
    }

    /// <summary>User-facing label of a severity, in upper case.</summary>
    /// <param name="severity">The severity.</param>
    /// <returns>The label.</returns>
    internal static string SeverityLabel(Severity severity) => severity switch
    {
        Severity.Critical => Strings.SeverityCritical,
        Severity.High => Strings.SeverityHigh,
        Severity.Medium => Strings.SeverityMedium,
        Severity.Low => Strings.SeverityLow,
        _ => Strings.SeverityInfo,
    };

    /// <summary>User-facing label of a confidence.</summary>
    /// <param name="confidence">The confidence.</param>
    /// <returns>The label.</returns>
    internal static string ConfidenceLabel(Confidence confidence) => confidence switch
    {
        Confidence.Certain => Strings.ConfidenceCertain,
        Confidence.Probable => Strings.ConfidenceProbable,
        _ => Strings.ConfidenceToBeVerified,
    };

    /// <summary>User-facing label of a role.</summary>
    /// <param name="role">The role.</param>
    /// <returns>The label.</returns>
    internal static string RoleLabel(OperatorRole role) => role switch
    {
        OperatorRole.SecurityOfficer => Strings.RoleSecurityOfficer,
        OperatorRole.AppointedPerson => Strings.RoleAppointedPerson,
        _ => Strings.RoleOwner,
    };

    private void WriteFindings(IReadOnlyList<PrioritizedFinding> findings)
    {
        if (findings.Count == 0)
        {
            output.WriteLine(Strings.NoProblems);
            return;
        }

        output.WriteLine(Strings.ProblemsFound);
        foreach (var (finding, severity) in findings)
        {
            output.WriteLine($"  [{SeverityLabel(severity)}] {finding.Id}  {finding.Title}");
            WriteDetail(Strings.EvidenceLabel, finding.Evidence);
            WriteDetail(Strings.RiskLabel, finding.Risk);
            WriteDetail(Strings.FixLabel, finding.Fix);
            WriteDetail(Strings.ConfidenceLabel, ConfidenceLabel(finding.Confidence));
            WriteDetail(Strings.ReferencesLabel, finding.References.Count == 0 ? null : string.Join(", ", finding.References));
        }
    }

    private void WriteDetail(string label, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            output.WriteLine($"{Indent}{label}: {value}");
        }
    }

    private void WriteList(string heading, IEnumerable<CheckRun> runs, string mark, Func<CheckRun, string?> detail)
    {
        var list = runs.ToArray();
        if (list.Length == 0)
        {
            return;
        }

        output.WriteLine(heading);
        foreach (var run in list)
        {
            var text = detail(run);
            output.WriteLine(text is null ? $"  {mark} {run.CheckId}  {run.CheckTitle}" : $"  {mark} {run.CheckId}  {run.CheckTitle}: {text}");
        }
    }

    private static int Count(IEnumerable<PrioritizedFinding> findings, Severity severity) => findings.Count(f => f.EffectiveSeverity == severity);

    private static string Format(string format, params object?[] arguments) => string.Format(CultureInfo.CurrentCulture, format, arguments);
}
