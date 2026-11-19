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

using ScudoDigitale.Checks.Email.Resources;

namespace ScudoDigitale.Checks.Email;

/// <summary>Result of trying the DKIM selectors on a domain.</summary>
/// <param name="DnsError">Set when every selector query failed.</param>
/// <param name="SelectorsTried">The selectors that were queried, in order.</param>
/// <param name="Keys">The DKIM keys found, revoked ones included, in selector order.</param>
/// <param name="Unanswered">The selectors whose query failed, so a key there may have been missed.</param>
internal sealed record DkimAnalysis(
    string? DnsError,
    IReadOnlyList<string> SelectorsTried,
    IReadOnlyList<DkimKey> Keys,
    IReadOnlyList<string> Unanswered)
{
    /// <summary>The keys that are not revoked.</summary>
    public IEnumerable<DkimKey> ActiveKeys => Keys.Where(k => !k.Revoked);
}

/// <summary>Queries the common and the user-supplied DKIM selectors of a domain.</summary>
internal static class DkimAnalyzer
{
    /// <summary>
    /// Queries <c>&lt;selector&gt;._domainkey.&lt;domain&gt;</c> for every selector, a few at a time.
    /// Selectors cannot be listed from the DNS, so what is not found may still exist.
    /// </summary>
    /// <param name="inspector">Shared DNS answers and options.</param>
    /// <param name="domain">Normalized domain.</param>
    /// <returns>The analysis.</returns>
    public static async Task<DkimAnalysis> AnalyzeAsync(EmailDomainInspector inspector, string domain)
    {
        var selectors = EmailCheckOptions.CommonDkimSelectors
            .Concat(inspector.Options.DkimSelectors)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        // A resolver that drops these queries could keep the analysis busy beyond the timeout of
        // the check, and a timed-out check tells the user nothing. Within the budget whatever has
        // not answered is reported as unanswered.
        var budgetSeconds = inspector.Options.DkimTimeBudget.TotalSeconds;
        using var budget = new CancellationTokenSource(inspector.Options.DkimTimeBudget);
        using var gate = new SemaphoreSlim(inspector.Options.MaxConcurrentDnsQueries);
        var answers = await Task.WhenAll(selectors.Select(async selector =>
        {
            // Once the budget is over, the queries still waiting here fail at once in GetTxtAsync.
            await gate.WaitAsync().ConfigureAwait(false);
            try
            {
                return await inspector.GetTxtAsync($"{selector}._domainkey.{domain}", budget.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return OverBudget(budgetSeconds);
            }
            finally
            {
                gate.Release();
            }
        })).ConfigureAwait(false);

        if (answers.All(a => a.Status == DnsStatus.Error))
        {
            return new DkimAnalysis(answers[0].Error, selectors, [], selectors);
        }

        var keys = selectors
            .Zip(answers)
            .Select(pair => pair.Second.Records.Select(txt => DkimKey.TryParse(pair.First, txt)).FirstOrDefault(key => key is not null))
            .OfType<DkimKey>()
            .ToArray();
        var unanswered = selectors.Zip(answers).Where(pair => pair.Second.Status == DnsStatus.Error).Select(pair => pair.First).ToArray();
        return new DkimAnalysis(null, selectors, keys, unanswered);
    }

    private static DnsAnswer<string> OverBudget(double seconds) =>
        DnsAnswer<string>.Failed(EmailFinding.Format(Strings.DnsNoAnswerInTime, seconds));
}
