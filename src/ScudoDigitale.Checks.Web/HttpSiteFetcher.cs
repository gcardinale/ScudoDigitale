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
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ScudoDigitale.Checks.Web.Resources;
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Web;

/// <summary>
/// <see cref="ISiteFetcher"/> on <see cref="HttpClient"/>. A visit is what a browser does on a first
/// visit and nothing more: the home page over HTTP and over HTTPS, and the security.txt file at its
/// two standard addresses. Redirects are followed only inside the declared site; no cookie is sent
/// back, no form is submitted, no other path is requested. The certificate is read from the same
/// connection, without downloading missing certificates and without asking the authority whether it
/// was revoked: both would be connections to servers that were not declared.
/// </summary>
internal sealed class HttpSiteFetcher : ISiteFetcher
{
    /// <summary>At most this many redirects are followed from one starting address.</summary>
    public const int MaxRedirects = 5;

    /// <summary>At most this many bytes of a page or of security.txt are read.</summary>
    public const int MaxBodyBytes = 512 * 1024;

    private const string WellKnownPath = "/.well-known/security.txt";
    private const string LegacyPath = "/security.txt";

    private readonly WebCheckOptions options;

    /// <summary>Creates the fetcher.</summary>
    /// <param name="options">Timeouts.</param>
    public HttpSiteFetcher(WebCheckOptions options)
    {
        this.options = options;
    }

    /// <summary>
    /// The user agent of every request: it says who is visiting and where to read about it. The
    /// <c>Mozilla/5.0 (compatible; …)</c> form is the usual one for declared automatic visitors; sites
    /// that refuse unknown clients accept it.
    /// </summary>
    public static string UserAgent { get; } =
        $"Mozilla/5.0 (compatible; ScudoDigitale/{typeof(HttpSiteFetcher).Assembly.GetName().Version!.ToString(2)}; +{Attribution.Website})";

    /// <inheritdoc />
    public async Task<SiteVisit> VisitAsync(string host, CancellationToken cancellationToken)
    {
        var certificates = new ConcurrentDictionary<string, CertificateInfo>(StringComparer.OrdinalIgnoreCase);
        using var handler = CreateHandler(certificates);
        using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        http.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        http.DefaultRequestHeaders.Accept.ParseAdd("text/html,text/plain;q=0.9,*/*;q=0.8");

        // Two connections at once, as a browser would open.
        var plain = FollowAsync(http, host, new Uri($"http://{host}/"), null, cancellationToken);
        var secure = await FollowAsync(http, host, new Uri($"https://{host}/"), "text/html", cancellationToken).ConfigureAwait(false);
        Trail? securityTxt = null;
        if (secure.End != TrailEnd.Error)
        {
            securityTxt = await FollowAsync(http, host, new Uri($"https://{host}{WellKnownPath}"), "text/plain", cancellationToken).ConfigureAwait(false);
            if (securityTxt is { End: TrailEnd.Response, Hops: [.., { Body: null }] })
            {
                // RFC 9116 §3: the top-level path is the fallback for the well-known one.
                var legacy = await FollowAsync(http, host, new Uri($"https://{host}{LegacyPath}"), "text/plain", cancellationToken).ConfigureAwait(false);
                securityTxt = legacy is { End: TrailEnd.Response, Hops: [.., { Body: not null }] } ? legacy : securityTxt;
            }
        }

        return new SiteVisit(
            host,
            options.Clock(),
            await plain.ConfigureAwait(false),
            secure,
            [.. certificates.Values.OrderBy(c => c.Host != host).ThenBy(c => c.Host, StringComparer.Ordinal)],
            securityTxt);
    }

    /// <summary>The handler of a visit: no automatic redirects, no cookies kept, certificates recorded.</summary>
    /// <param name="certificates">Where the certificate of each host contacted over HTTPS is recorded.</param>
    /// <returns>The handler.</returns>
    internal SocketsHttpHandler CreateHandler(ConcurrentDictionary<string, CertificateInfo> certificates)
    {
        var policy = new X509ChainPolicy
        {
            RevocationMode = X509RevocationMode.NoCheck,
            DisableCertificateDownloads = true,
        };
        if (options.TrustedRoots is { } roots)
        {
            policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            policy.CustomTrustStore.AddRange(roots);
        }

        return new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = options.RequestTimeout,
            ConnectCallback = ConnectAsync,
            SslOptions = new SslClientAuthenticationOptions
            {
                CertificateChainPolicy = policy,

                // The handshake is always accepted: a wrong certificate is a finding, and the headers
                // of the page are still worth reading. Nothing confidential is ever sent.
                RemoteCertificateValidationCallback = (sender, certificate, chain, errors) =>
                    Record(certificates, ((SslStream)sender).TargetHostName, certificate, chain, errors),
            },
        };
    }

    /// <summary>
    /// Records the certificate a host presented. A certificate that cannot be read is not recorded,
    /// and the certificate checks say so: an exception here would break the handshake and make a site
    /// that does answer over HTTPS look as if it did not.
    /// </summary>
    /// <param name="certificates">Where the certificate is recorded; the first one of a host is kept.</param>
    /// <param name="host">The host that was contacted.</param>
    /// <param name="certificate">Its certificate, if it sent one.</param>
    /// <param name="chain">The chain built during the handshake.</param>
    /// <param name="errors">The errors found during the handshake.</param>
    /// <returns>Always <see langword="true"/>: the handshake goes on.</returns>
    internal static bool Record(
        ConcurrentDictionary<string, CertificateInfo> certificates,
        string host,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors errors)
    {
        try
        {
            certificates.TryAdd(host, CertificateInspector.Describe(host, (X509Certificate2)certificate!, chain!, errors));
        }
        catch (Exception)
        {
            // Not recorded: see the summary.
        }

        return true;
    }

    /// <summary>Requests an address and follows its redirects while they stay inside the site and on the same scheme.</summary>
    /// <param name="http">The client of the visit.</param>
    /// <param name="site">The declared host name.</param>
    /// <param name="start">The first address.</param>
    /// <param name="bodyType">Media type whose text is read from a 200 response; <see langword="null"/> to read none.</param>
    /// <param name="cancellationToken">Stops the visit.</param>
    /// <returns>The chain of responses.</returns>
    internal async Task<Trail> FollowAsync(HttpClient http, string site, Uri start, string? bodyType, CancellationToken cancellationToken)
    {
        var hops = new List<Hop>();
        var url = start;
        try
        {
            while (true)
            {
                var hop = await GetAsync(http, url, bodyType, cancellationToken).ConfigureAwait(false);
                hops.Add(hop);
                if (Redirect(hop) is not { } next)
                {
                    return new Trail(hops, TrailEnd.Response);
                }

                if (next.Scheme != url.Scheme)
                {
                    return new Trail(hops, TrailEnd.ChangedScheme, next);
                }

                // Another port of the same host is not the website: browsers refuse most of them too.
                if (!next.IsDefaultPort || !HostName.IsInSite(site, next.IdnHost))
                {
                    return new Trail(hops, TrailEnd.LeftSite, next);
                }

                if (hops.Count > MaxRedirects)
                {
                    return new Trail(hops, TrailEnd.TooManyRedirects, next);
                }

                url = next;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return new Trail(hops, TrailEnd.Error, null, WebFinding.Format(Strings.NoAnswerInTime, SafeUrl.Show(url), options.RequestTimeout.TotalSeconds));
        }
        catch (Exception ex)
        {
            var cause = ex.GetBaseException();
            return new Trail(
                hops,
                TrailEnd.Error,
                null,
                $"{SafeUrl.Show(url)}: {cause.Message}",
                cause is SocketException { SocketErrorCode: SocketError.ConnectionRefused });
        }
    }

    /// <summary>Where a response redirects to, if it does and the address is an HTTP or HTTPS one.</summary>
    /// <param name="hop">The response.</param>
    /// <returns>The absolute address, or <see langword="null"/>.</returns>
    internal static Uri? Redirect(Hop hop)
    {
        if (hop.Status is not (301 or 302 or 303 or 307 or 308)
            || hop.Values("Location").FirstOrDefault() is not { } location
            || !Uri.TryCreate(hop.Url, location.Trim(), out var next))
        {
            return null;
        }

        return next.Scheme == Uri.UriSchemeHttp || next.Scheme == Uri.UriSchemeHttps ? next : null;
    }

    private async Task<Hop> GetAsync(HttpClient http, Uri url, string? bodyType, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(options.RequestTimeout);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        // WaitAsync: the deadline holds even if the connection ignores the token.
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token)
            .WaitAsync(deadline.Token)
            .ConfigureAwait(false);
        var headers = response.Headers.NonValidated.Concat(response.Content.Headers.NonValidated)
            .SelectMany(header => header.Value.Select(value => KeyValuePair.Create(header.Key, value)))
            .ToArray();
        string? body = null;
        if (bodyType is not null
            && response.StatusCode == HttpStatusCode.OK
            && string.Equals(response.Content.Headers.ContentType?.MediaType, bodyType, StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
                var buffer = new byte[MaxBodyBytes];
                var read = await stream.ReadAtLeastAsync(buffer, buffer.Length, throwOnEndOfStream: false, deadline.Token).ConfigureAwait(false);
                body = Encoding.UTF8.GetString(buffer, 0, read);
            }
            catch (Exception) when (!cancellationToken.IsCancellationRequested)
            {
                // The headers arrived: a page that is slow or breaks off is still an answer, and its
                // headers are still evaluated. Only what the page itself would have added is lost.
            }
        }

        return new Hop(url, (int)response.StatusCode, headers, body);
    }

    private async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(options.Route(context.DnsEndPoint), cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
