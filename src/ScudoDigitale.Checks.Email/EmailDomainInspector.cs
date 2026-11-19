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

namespace ScudoDigitale.Checks.Email;

/// <summary>
/// Runs each DNS analysis once per domain and shares it among the checks of a run, so the eleven
/// checks do not repeat the same queries. The analyses run without the token of the first caller
/// (they are bounded by the DNS timeouts); every caller waits with its own token, so a check that is
/// cancelled never cancels the others.
/// </summary>
internal sealed class EmailDomainInspector
{
    private readonly ConcurrentDictionary<(string Kind, string Name), Lazy<Task<object>>> cache = new();

    /// <summary>Creates the inspector.</summary>
    /// <param name="resolver">Where the DNS answers come from.</param>
    /// <param name="options">DNS concurrency and DKIM selectors.</param>
    public EmailDomainInspector(IDnsResolver resolver, EmailCheckOptions options)
    {
        Resolver = resolver;
        Options = options;
    }

    /// <summary>Where the DNS answers come from.</summary>
    public IDnsResolver Resolver { get; }

    /// <summary>DNS concurrency and DKIM selectors.</summary>
    public EmailCheckOptions Options { get; }

    /// <summary>TXT records of a name, queried once per run.</summary>
    /// <param name="name">Name to query.</param>
    /// <param name="cancellationToken">Stops waiting.</param>
    /// <returns>The answer.</returns>
    public Task<DnsAnswer<string>> GetTxtAsync(string name, CancellationToken cancellationToken) =>
        MemoizeAsync("txt", name, () => Resolver.QueryTxtAsync(name, CancellationToken.None), cancellationToken);

    /// <summary>SPF analysis of a domain.</summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="cancellationToken">Stops waiting.</param>
    /// <returns>The analysis.</returns>
    public Task<SpfAnalysis> GetSpfAsync(string domain, CancellationToken cancellationToken) =>
        MemoizeAsync("spf", domain, () => SpfAnalyzer.AnalyzeAsync(this, domain), cancellationToken);

    /// <summary>DMARC analysis of a domain.</summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="cancellationToken">Stops waiting.</param>
    /// <returns>The analysis.</returns>
    public Task<DmarcAnalysis> GetDmarcAsync(string domain, CancellationToken cancellationToken) =>
        MemoizeAsync("dmarc", domain, () => DmarcAnalyzer.AnalyzeAsync(this, domain), cancellationToken);

    /// <summary>DKIM analysis of a domain.</summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="cancellationToken">Stops waiting.</param>
    /// <returns>The analysis.</returns>
    public Task<DkimAnalysis> GetDkimAsync(string domain, CancellationToken cancellationToken) =>
        MemoizeAsync("dkim", domain, () => DkimAnalyzer.AnalyzeAsync(this, domain), cancellationToken);

    /// <summary>MX records of a domain, queried once per run.</summary>
    /// <param name="domain">Normalized domain.</param>
    /// <param name="cancellationToken">Stops waiting.</param>
    /// <returns>The answer.</returns>
    public Task<DnsAnswer<MailExchange>> GetMxAsync(string domain, CancellationToken cancellationToken) =>
        MemoizeAsync("mx", domain, () => Resolver.QueryMxAsync(domain, CancellationToken.None), cancellationToken);

    private async Task<T> MemoizeAsync<T>(string kind, string name, Func<Task<T>> analyze, CancellationToken cancellationToken)
        where T : class
    {
        cancellationToken.ThrowIfCancellationRequested();
        var lazy = cache.GetOrAdd((kind, name), _ => new Lazy<Task<object>>(async () => await analyze().ConfigureAwait(false)));
        return (T)await lazy.Value.WaitAsync(cancellationToken).ConfigureAwait(false);
    }
}
