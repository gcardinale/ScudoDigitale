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

namespace ScudoDigitale.Checks.Web;

/// <summary>One request and its response.</summary>
/// <param name="Url">The address requested.</param>
/// <param name="Status">The HTTP status code.</param>
/// <param name="Headers">The response headers as sent, one entry per header line.</param>
/// <param name="Body">The text of the response, only when it was asked for and had the expected type.</param>
internal sealed record Hop(Uri Url, int Status, IReadOnlyList<KeyValuePair<string, string>> Headers, string? Body = null)
{
    /// <summary>The values of a header, in the order they were sent.</summary>
    /// <param name="name">Header name, in any letter case.</param>
    /// <returns>The values; empty when the header is absent.</returns>
    public IEnumerable<string> Values(string name) =>
        Headers.Where(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Select(h => h.Value);
}

/// <summary>Why a chain of redirects stopped.</summary>
internal enum TrailEnd
{
    /// <summary>The last hop is the answer: it does not redirect anywhere.</summary>
    Response,

    /// <summary>The last hop redirects to the other scheme (HTTP to HTTPS, or HTTPS to HTTP).</summary>
    ChangedScheme,

    /// <summary>The last hop redirects outside the declared site, which is never followed.</summary>
    LeftSite,

    /// <summary>More redirects than a visit follows.</summary>
    TooManyRedirects,

    /// <summary>A request failed: no connection, no answer in time, broken TLS.</summary>
    Error,
}

/// <summary>The requests made from one starting address, following redirects inside the site.</summary>
/// <param name="Hops">The responses received, in order.</param>
/// <param name="End">Why the chain stopped.</param>
/// <param name="Next">Where the last hop redirects to, when it was not followed.</param>
/// <param name="Error">What went wrong, when <paramref name="End"/> is <see cref="TrailEnd.Error"/>.</param>
/// <param name="Refused">Whether the error is a refused connection: nothing listens on that port.</param>
/// <param name="Unanswered">Whether the error is a DNS that did not answer: nothing is known about the site.</param>
internal sealed record Trail(IReadOnlyList<Hop> Hops, TrailEnd End, Uri? Next = null, string? Error = null, bool Refused = false, bool Unanswered = false)
{
    /// <summary>The addresses visited and the one not followed, for the evidence of a finding.</summary>
    public string Path => string.Join(" → ", Hops.Select(h => SafeUrl.Show(h.Url)).Concat(Next is null ? [] : [SafeUrl.Show(Next)]));

    /// <summary>A chain whose first request failed.</summary>
    /// <param name="error">What went wrong.</param>
    /// <param name="refused">Whether the connection was refused.</param>
    /// <returns>The chain.</returns>
    public static Trail Failed(string error, bool refused = false) => new([], TrailEnd.Error, null, error, refused);
}

/// <summary>
/// Addresses as they are shown in a report. A site that receives no cookie may put the session
/// identifier in the address instead (<c>;jsessionid=…</c>, <c>?sid=…</c>): path parameters and the
/// query string are therefore never shown.
/// </summary>
internal static class SafeUrl
{
    /// <summary>The address without path parameters, query string, fragment and user information.</summary>
    /// <param name="url">An absolute address.</param>
    /// <returns>The text to show.</returns>
    public static string Show(Uri url)
    {
        var path = url.AbsolutePath;
        var parameters = path.IndexOf(';', StringComparison.Ordinal);
        if (parameters >= 0)
        {
            path = path[..parameters] + ";…";
        }

        return $"{url.Scheme}://{url.Authority}{path}{(url.Query.Length > 0 ? "?…" : string.Empty)}";
    }
}

/// <summary>How the certificate chain of a server was judged.</summary>
internal enum ChainState
{
    /// <summary>The chain ends at an authority this computer trusts.</summary>
    Trusted,

    /// <summary>The issuer of a certificate was not sent by the server and is not known here.</summary>
    Incomplete,

    /// <summary>Self-signed, issued by an unknown authority, or otherwise not valid.</summary>
    Untrusted,
}

/// <summary>The certificate a host presented, as judged during the TLS handshake.</summary>
/// <param name="Host">The host that presented it.</param>
/// <param name="Names">The DNS names the certificate is for.</param>
/// <param name="NotBefore">Start of validity.</param>
/// <param name="NotAfter">End of validity.</param>
/// <param name="NameMatches">Whether the certificate covers <paramref name="Host"/>.</param>
/// <param name="Chain">How the chain was judged, ignoring the validity dates of the certificate itself.</param>
/// <param name="ChainDetail">The chain status flags, for the evidence of a finding.</param>
internal sealed record CertificateInfo(
    string Host,
    IReadOnlyList<string> Names,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    bool NameMatches,
    ChainState Chain,
    string ChainDetail);

/// <summary>Everything one visit to a site collected; the checks of a run share it.</summary>
/// <param name="Host">The declared host name.</param>
/// <param name="VisitedAt">When the visit ended, to judge certificate and security.txt dates.</param>
/// <param name="Http">The requests starting from <c>http://host/</c>.</param>
/// <param name="Https">The requests starting from <c>https://host/</c>; the last hop is the home page.</param>
/// <param name="Certificates">The certificates of the hosts contacted over HTTPS, the declared one first.</param>
/// <param name="SecurityTxt">The requests for security.txt; <see langword="null"/> when HTTPS does not answer.</param>
internal sealed record SiteVisit(
    string Host,
    DateTimeOffset VisitedAt,
    Trail Http,
    Trail Https,
    IReadOnlyList<CertificateInfo> Certificates,
    Trail? SecurityTxt);

/// <summary>Visits a site the way a browser would on a first visit.</summary>
internal interface ISiteFetcher
{
    /// <summary>
    /// Requests the home page over HTTP and HTTPS and the security.txt file. Network problems are
    /// reported inside the <see cref="SiteVisit"/>; only cancellation throws.
    /// </summary>
    /// <param name="host">Normalized host name.</param>
    /// <param name="cancellationToken">Stops the visit.</param>
    /// <returns>What the visit collected.</returns>
    Task<SiteVisit> VisitAsync(string host, CancellationToken cancellationToken);
}
