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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ScudoDigitale.Checks.Web.Tests;

/// <summary>A request received by <see cref="FakeWebServer"/>.</summary>
internal sealed record FakeRequest(string Path, string Host, bool Secure, IReadOnlyDictionary<string, string> Headers);

/// <summary>A response of <see cref="FakeWebServer"/>.</summary>
internal sealed record FakeResponse(int Status, string? ContentType = null, string Body = "", params (string Name, string Value)[] Headers)
{
    public static FakeResponse Redirect(string location, int status = 301) => new(status, null, string.Empty, ("Location", location));

    public static FakeResponse NotFound { get; } = new(404, "text/html", "<h1>Not found</h1>");

    /// <summary>Whether the body breaks off: more is announced than is ever sent.</summary>
    public bool Stalls { get; init; }
}

/// <summary>
/// A minimal web server on loopback, with one plain HTTP port and one HTTPS port, so the real
/// <see cref="HttpSiteFetcher"/> is tested on real connections and real TLS handshakes without
/// touching the network. A handler that returns <see langword="null"/> never answers.
/// </summary>
internal sealed class FakeWebServer : IAsyncDisposable
{
    private readonly TcpListener plain = new(IPAddress.Loopback, 0);
    private readonly TcpListener secure = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly Func<FakeRequest, FakeResponse?> handler;
    private readonly SslStreamCertificateContext certificate;
    private readonly Task[] loops;

    public FakeWebServer(X509Certificate2 certificate, Func<FakeRequest, FakeResponse?> handler)
    {
        this.handler = handler;

        // offline: no intermediate certificate is looked up, downloaded or stored anywhere.
        this.certificate = SslStreamCertificateContext.Create(certificate, additionalCertificates: null, offline: true);
        plain.Start();
        secure.Start();
        loops = [Task.Run(() => AcceptAsync(plain, false)), Task.Run(() => AcceptAsync(secure, true))];
    }

    public int HttpPort => ((IPEndPoint)plain.LocalEndpoint).Port;

    public int HttpsPort => ((IPEndPoint)secure.LocalEndpoint).Port;

    public ConcurrentQueue<FakeRequest> Requests { get; } = new();

    /// <summary>A loopback port on which nothing listens.</summary>
    public static int ClosedPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        plain.Stop();
        secure.Stop();
        await Task.WhenAll(loops);
        stop.Dispose();
    }

    private async Task AcceptAsync(TcpListener listener, bool isSecure)
    {
        while (!stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(stop.Token);
            }
            catch (Exception) when (stop.IsCancellationRequested)
            {
                return;
            }

            _ = Task.Run(() => ServeAsync(client, isSecure));
        }
    }

    private async Task ServeAsync(TcpClient client, bool isSecure)
    {
        try
        {
            using var owned = client;
            Stream stream = client.GetStream();
            if (isSecure)
            {
                var tls = new SslStream(stream);
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificateContext = certificate }, stop.Token);
                stream = tls;
            }

            var request = await ReadRequestAsync(stream, isSecure);
            Requests.Enqueue(request);
            if (handler(request) is not { } response)
            {
                await Task.Delay(Timeout.Infinite, stop.Token);
                return;
            }

            var body = Encoding.UTF8.GetBytes(response.Body);
            var announced = response.Stalls ? body.Length + 10_000 : body.Length;
            var head = new StringBuilder($"HTTP/1.1 {response.Status} Status\r\nConnection: close\r\nContent-Length: {announced}\r\n");
            if (response.ContentType is not null)
            {
                head.Append($"Content-Type: {response.ContentType}\r\n");
            }

            foreach (var (name, value) in response.Headers)
            {
                head.Append($"{name}: {value}\r\n");
            }

            await stream.WriteAsync(Encoding.ASCII.GetBytes(head + "\r\n"), stop.Token);
            await stream.WriteAsync(body, stop.Token);
            await stream.FlushAsync(stop.Token);
            if (response.Stalls)
            {
                await Task.Delay(Timeout.Infinite, stop.Token);
            }

            if (stream is SslStream ssl)
            {
                await ssl.ShutdownAsync();
            }
        }
        catch (Exception)
        {
            // A client that goes away, or the server stopping: nothing to report to the test.
        }
    }

    private async Task<FakeRequest> ReadRequestAsync(Stream stream, bool isSecure)
    {
        var text = new StringBuilder();
        var buffer = new byte[1];
        while (!text.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
        {
            await stream.ReadExactlyAsync(buffer, stop.Token);
            text.Append((char)buffer[0]);
        }

        var lines = text.ToString().Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        var headers = lines.Skip(1)
            .Select(line => line.Split(':', 2, StringSplitOptions.TrimEntries))
            .ToDictionary(parts => parts[0], parts => parts[1], StringComparer.OrdinalIgnoreCase);
        return new FakeRequest(lines[0].Split(' ')[1], headers["Host"], isSecure, headers);
    }
}

/// <summary>
/// A certificate authority that exists only inside the tests: nothing is installed on the computer,
/// the checks trust it through <see cref="WebCheckOptions.TrustedRoots"/>.
/// </summary>
public sealed class TestPki : IDisposable
{
    private readonly List<IDisposable> owned = [];
    private readonly ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa intermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly X509Certificate2 intermediate;

    public TestPki()
    {
        var now = DateTimeOffset.UtcNow;
        Root = Authority("CN=Scudo Digitale Test Root", rootKey).CreateSelfSigned(now.AddYears(-1), now.AddYears(5));
        using var unsigned = Authority("CN=Scudo Digitale Test Intermediate", intermediateKey).Create(Root, now.AddYears(-1), now.AddYears(4), [2]);
        intermediate = unsigned.CopyWithPrivateKey(intermediateKey);
        owned.AddRange([Root, intermediate, rootKey, intermediateKey]);

        Good = Issue(Root, now.AddDays(-10), now.AddDays(80), "site.test", "www.site.test");
        Expired = Issue(Root, now.AddDays(-90), now.AddDays(-1), "site.test");
        WrongName = Issue(Root, now.AddDays(-10), now.AddDays(80), "other.test");
        MissingIssuer = Issue(intermediate, now.AddDays(-10), now.AddDays(80), "site.test");
        SelfSigned = Issue(null, now.AddDays(-10), now.AddDays(80), "site.test");
    }

    /// <summary>The root to trust in the tests.</summary>
    public X509Certificate2 Root { get; }

    /// <summary>Issued by the root for site.test and www.site.test, valid for 80 more days.</summary>
    public X509Certificate2 Good { get; }

    /// <summary>Issued by the root for site.test, expired yesterday.</summary>
    public X509Certificate2 Expired { get; }

    /// <summary>Issued by the root for other.test.</summary>
    public X509Certificate2 WrongName { get; }

    /// <summary>Issued by an intermediate authority that the server does not send.</summary>
    public X509Certificate2 MissingIssuer { get; }

    /// <summary>Signed by itself.</summary>
    public X509Certificate2 SelfSigned { get; }

    public void Dispose()
    {
        foreach (var item in owned)
        {
            item.Dispose();
        }
    }

    private static CertificateRequest Authority(string name, ECDsa key)
    {
        var request = new CertificateRequest(name, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        return request;
    }

    private X509Certificate2 Issue(X509Certificate2? issuer, DateTimeOffset notBefore, DateTimeOffset notAfter, params string[] names)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=" + names[0], key, HashAlgorithmName.SHA256);
        var alternativeNames = new SubjectAlternativeNameBuilder();
        foreach (var name in names)
        {
            alternativeNames.AddDnsName(name);
        }

        request.CertificateExtensions.Add(alternativeNames.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));

        X509Certificate2 withKey;
        if (issuer is null)
        {
            withKey = request.CreateSelfSigned(notBefore, notAfter);
        }
        else
        {
            using var unsigned = request.Create(issuer, notBefore, notAfter, RandomNumberGenerator.GetBytes(8));
            withKey = unsigned.CopyWithPrivateKey(key);
        }

        // Windows can use a server certificate for TLS only when its key is stored, not in memory:
        // going through a PFX stores it for as long as the certificate object lives. No certificate
        // goes into any store; the key file is removed on Dispose, so a test run that is killed can
        // leave an orphan key file in the user's key container (harmless, a test key).
        using (withKey)
        {
            var stored = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx), null);
            owned.Add(stored);
            return stored;
        }
    }
}

/// <summary>
/// A configurable site on a <see cref="FakeWebServer"/>, well configured by default, and the options
/// that send the checks to it whatever the host name.
/// </summary>
internal sealed class TestSite : IAsyncDisposable
{
    public const string Host = "site.test";

    private readonly TestPki pki;
    private readonly FakeWebServer server;
    private readonly int closedPort = FakeWebServer.ClosedPort();

    public TestSite(TestPki pki, X509Certificate2? certificate = null)
    {
        this.pki = pki;
        server = new FakeWebServer(certificate ?? pki.Good, Handle);
    }

    /// <summary>Whether plain HTTP redirects to HTTPS (otherwise it serves the page).</summary>
    public bool HttpRedirects { get; set; } = true;

    /// <summary>Whether anything listens on the HTTPS port.</summary>
    public bool HttpsListens { get; set; } = true;

    /// <summary>Headers of the home page.</summary>
    public List<(string Name, string Value)> Headers { get; } = [.. Site.GoodHeaders.Where(h => h.Name != "Content-Type")];

    /// <summary>Text of /.well-known/security.txt; <see langword="null"/> for none.</summary>
    public string? SecurityTxt { get; set; } = "Contact: mailto:security@site.test\nExpires: 2099-01-01T00:00:00Z\n";

    /// <summary>Answers before the defaults when it returns something.</summary>
    public Func<FakeRequest, FakeResponse?>? Override { get; set; }

    /// <summary>Requests that must never be answered.</summary>
    public Func<FakeRequest, bool> Silent { get; set; } = _ => false;

    public IReadOnlyCollection<FakeRequest> Requests => server.Requests;

    public WebCheckOptions Options(TimeSpan? timeout = null, bool trustTestRoot = true) => new()
    {
        RequestTimeout = timeout ?? TimeSpan.FromSeconds(10),
        TrustedRoots = trustTestRoot ? [pki.Root] : [],
        Proxy = new NoProxy(),
        SystemAddresses = (_, _) => Task.FromException<IPAddress[]>(new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.HostNotFound)),
        Route = endpoint => new IPEndPoint(
            IPAddress.Loopback,
            endpoint.Port != 443 ? server.HttpPort : HttpsListens ? server.HttpsPort : closedPort),
    };

    public WebCheckOptions Remove(string header)
    {
        Headers.RemoveAll(h => h.Name == header);
        return Options();
    }

    public WebCheckOptions Set(string header, string value)
    {
        Headers.RemoveAll(h => h.Name == header);
        Headers.Add((header, value));
        return Options();
    }

    public ValueTask DisposeAsync() => server.DisposeAsync();

    private FakeResponse? Handle(FakeRequest request)
    {
        if (Silent(request))
        {
            return null;
        }

        if (Override?.Invoke(request) is { } custom)
        {
            return custom;
        }

        if (!request.Secure)
        {
            return HttpRedirects
                ? FakeResponse.Redirect($"https://{request.Host}{request.Path}")
                : new FakeResponse(200, "text/html", "<html>plain</html>");
        }

        return request.Path switch
        {
            "/" => new FakeResponse(200, "text/html; charset=utf-8", "<html><head><title>Home</title></head></html>", [.. Headers]),
            "/.well-known/security.txt" when SecurityTxt is not null => new FakeResponse(200, "text/plain", SecurityTxt),
            _ => FakeResponse.NotFound,
        };
    }
}

/// <summary>No proxy at all: the proxy settings of the computer running the tests are never read.</summary>
internal sealed class NoProxy : IWebProxy
{
    public ICredentials? Credentials { get; set; }

    public Uri? GetProxy(Uri destination) => null;

    public bool IsBypassed(Uri host) => true;
}
