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
using System.Net;
using System.Text;
using System.Text.Json;
using ScudoDigitale.Core.Resources;

namespace ScudoDigitale.Core.Dns;

/// <summary>
/// <see cref="IDnsResolver"/> on the JSON API of a public DNS over HTTPS service (Cloudflare, Google).
/// HTTPS on port 443 cannot be intercepted or slowed down by a home router the way plain DNS on
/// port 53 is. Only the name and the record type are sent; the request carries no cookie and a
/// generic user agent.
/// </summary>
internal sealed class DohResolver : IDnsResolver
{
    /// <summary>JSON API of Cloudflare.</summary>
    public static readonly Uri Cloudflare = new("https://cloudflare-dns.com/dns-query");

    /// <summary>JSON API of Google Public DNS.</summary>
    public static readonly Uri Google = new("https://dns.google/resolve");

    private const int TypeA = 1;
    private const int TypeMx = 15;
    private const int TypeTxt = 16;
    private const int TypeAaaa = 28;

    private readonly HttpClient http;
    private readonly Uri endpoint;
    private readonly TimeSpan timeout;

    /// <summary>Creates the resolver.</summary>
    /// <param name="http">Client used for the requests; it is not disposed.</param>
    /// <param name="endpoint">The JSON endpoint, for example <see cref="Cloudflare"/>.</param>
    /// <param name="options">Its <see cref="DnsOptions.Timeout"/>, tripled to leave room for the TLS handshake, limits each request.</param>
    public DohResolver(HttpClient http, Uri endpoint, DnsOptions options)
    {
        this.http = http;
        this.endpoint = endpoint;
        timeout = options.Timeout * 3;
    }

    /// <inheritdoc />
    public Task<DnsAnswer<string>> QueryTxtAsync(string name, CancellationToken cancellationToken) =>
        QueryAsync(name, TypeTxt, ParseTxt, cancellationToken);

    /// <inheritdoc />
    public Task<DnsAnswer<MailExchange>> QueryMxAsync(string name, CancellationToken cancellationToken) =>
        QueryAsync(name, TypeMx, ParseMx, cancellationToken);

    /// <inheritdoc />
    public async Task<DnsAnswer<IPAddress>> QueryAddressesAsync(string name, CancellationToken cancellationToken)
    {
        var v4 = await QueryAsync(name, TypeA, ParseAddress, cancellationToken).ConfigureAwait(false);
        var v6 = await QueryAsync(name, TypeAaaa, ParseAddress, cancellationToken).ConfigureAwait(false);
        return DnsClientResolver.Combine(v4, v6);
    }

    /// <summary>
    /// The text of a TXT record as returned by the JSON API: one or more quoted strings with
    /// <c>\"</c>, <c>\\</c> and <c>\DDD</c> escapes, joined; a value without quotes is taken as it is
    /// (Google omits them for some records).
    /// </summary>
    /// <param name="data">The <c>data</c> field.</param>
    /// <returns>The record text.</returns>
    internal static string? ParseTxt(string data)
    {
        if (!data.StartsWith('"'))
        {
            return data;
        }

        var text = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < data.Length; i++)
        {
            var c = data[i];
            if (c == '"')
            {
                quoted = !quoted;
            }
            else if (!quoted)
            {
                // Spaces between the strings of one record.
            }
            else if (c == '\\' && i + 3 < data.Length && char.IsAsciiDigit(data[i + 1]) && char.IsAsciiDigit(data[i + 2]) && char.IsAsciiDigit(data[i + 3]))
            {
                text.Append((char)int.Parse(data.AsSpan(i + 1, 3), CultureInfo.InvariantCulture));
                i += 3;
            }
            else if (c == '\\' && i + 1 < data.Length)
            {
                text.Append(data[++i]);
            }
            else
            {
                text.Append(c);
            }
        }

        return text.ToString();
    }

    /// <summary>An MX record from the <c>data</c> field, for example <c>10 mx.example.com.</c>.</summary>
    /// <param name="data">The <c>data</c> field.</param>
    /// <returns>The record, or <see langword="null"/> when it cannot be read.</returns>
    internal static MailExchange? ParseMx(string data)
    {
        var parts = data.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts.Length == 2 && int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var preference)
            ? new MailExchange(preference, parts[1].TrimEnd('.'))
            : null;
    }

    private static IPAddress? ParseAddress(string data) => IPAddress.TryParse(data, out var address) ? address : null;

    private async Task<DnsAnswer<T>> QueryAsync<T>(string name, int type, Func<string, T?> parse, CancellationToken cancellationToken)
        where T : class
    {
        cancellationToken.ThrowIfCancellationRequested();
        var uri = new Uri($"{endpoint}?name={Uri.EscapeDataString(name)}&type={type.ToString(CultureInfo.InvariantCulture)}");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Accept.ParseAdd("application/dns-json");
            using var response = await http.SendAsync(request, deadline.Token).WaitAsync(deadline.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return DnsAnswer<T>.Failed($"{endpoint.Host}: HTTP {(int)response.StatusCode}");
            }

            await using var body = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
            using var json = await JsonDocument.ParseAsync(body, cancellationToken: deadline.Token).ConfigureAwait(false);
            return Read(json.RootElement, type, parse);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            return DnsAnswer<T>.Failed($"{endpoint.Host}: {string.Format(CultureInfo.CurrentCulture, Strings.DnsNoAnswerInTime, timeout.TotalSeconds)}");
        }
        catch (Exception ex)
        {
            return DnsAnswer<T>.Failed($"{endpoint.Host}: {ex.Message}");
        }
    }

    private DnsAnswer<T> Read<T>(JsonElement root, int type, Func<string, T?> parse)
        where T : class
    {
        var status = root.GetProperty("Status").GetInt32();
        if (status == 3)
        {
            return DnsAnswer<T>.NonExistentDomain();
        }

        if (status != 0)
        {
            return DnsAnswer<T>.Failed($"{endpoint.Host}: DNS response code {status.ToString(CultureInfo.InvariantCulture)}");
        }

        if (!root.TryGetProperty("Answer", out var answers))
        {
            return DnsAnswer<T>.NoRecords();
        }

        // The answer also lists the CNAME records of the chain: only the requested type counts.
        return DnsAnswer<T>.Found(answers.EnumerateArray()
            .Where(a => a.GetProperty("type").GetInt32() == type)
            .Select(a => parse(a.GetProperty("data").GetString() ?? string.Empty))
            .OfType<T>());
    }
}
