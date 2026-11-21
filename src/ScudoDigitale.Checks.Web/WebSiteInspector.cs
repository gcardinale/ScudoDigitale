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

using System.Collections.Concurrent;
using ScudoDigitale.Checks.Web.Resources;

namespace ScudoDigitale.Checks.Web;

/// <summary>
/// Visits each site once per run and shares the visit among the checks, so fifteen checks cost one
/// visit. The visit runs without the token of the first caller (it is bounded by its own time
/// budget); every caller waits with its own token, so a check that is cancelled never cancels the
/// others.
/// </summary>
internal sealed class WebSiteInspector
{
    private readonly ConcurrentDictionary<string, Lazy<Task<SiteVisit>>> cache = new(StringComparer.Ordinal);
    private readonly ISiteFetcher fetcher;
    private readonly WebCheckOptions options;

    /// <summary>Creates the inspector.</summary>
    /// <param name="fetcher">Visits the sites.</param>
    /// <param name="options">The time budget of a visit.</param>
    public WebSiteInspector(ISiteFetcher fetcher, WebCheckOptions options)
    {
        this.fetcher = fetcher;
        this.options = options;
    }

    /// <summary>The visit of a site, made once per run.</summary>
    /// <param name="host">Normalized host name.</param>
    /// <param name="cancellationToken">Stops waiting.</param>
    /// <returns>The visit.</returns>
    /// <exception cref="TimeoutException">The visit did not end within its time budget.</exception>
    public async Task<SiteVisit> GetAsync(string host, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var lazy = cache.GetOrAdd(host, name => new Lazy<Task<SiteVisit>>(() => VisitAsync(name)));
        return await lazy.Value.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<SiteVisit> VisitAsync(string host)
    {
        // A site that answers slowly at every step could keep the visit busy beyond the timeout of
        // the check, and a timed-out check tells the user nothing.
        using var budget = new CancellationTokenSource(options.VisitBudget);
        try
        {
            // WaitAsync: the budget holds even if the fetcher ignores the token.
            return await fetcher.VisitAsync(host, budget.Token).WaitAsync(budget.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw new TimeoutException(WebFinding.Format(Strings.VisitOverBudget, host, options.VisitBudget.TotalSeconds));
        }
    }
}
