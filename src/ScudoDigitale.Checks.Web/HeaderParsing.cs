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
using System.Text.RegularExpressions;

namespace ScudoDigitale.Checks.Web;

/// <summary>Reads the <c>Strict-Transport-Security</c> header (RFC 6797).</summary>
internal static class Hsts
{
    /// <summary>The <c>max-age</c> of a header value, in seconds.</summary>
    /// <param name="value">The header value.</param>
    /// <returns>The seconds, or <see langword="null"/> when there is no valid <c>max-age</c>.</returns>
    public static long? MaxAge(string value)
    {
        foreach (var directive in value.Split(';'))
        {
            var parts = directive.Split('=', 2);
            if (parts.Length == 2 && parts[0].Trim().Equals("max-age", StringComparison.OrdinalIgnoreCase))
            {
                return long.TryParse(parts[1].Trim().Trim('"'), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
                    ? seconds
                    : null;
            }
        }

        return null;
    }
}

/// <summary>A parsed Content-Security-Policy: directive names in lower case and their values.</summary>
internal sealed class ContentSecurityPolicy
{
    private readonly Dictionary<string, string[]> directives = new(StringComparer.Ordinal);

    private ContentSecurityPolicy()
    {
    }

    /// <summary>Whether the policy has no directive at all.</summary>
    public bool IsEmpty => directives.Count == 0;

    /// <summary>
    /// The policies in the values of the header: a value can list several policies separated by
    /// commas. Empty policies are left out.
    /// </summary>
    /// <param name="values">Header values, or the contents of <c>meta</c> elements.</param>
    /// <returns>The policies.</returns>
    public static IReadOnlyList<ContentSecurityPolicy> Parse(IEnumerable<string> values) =>
        [.. values.SelectMany(value => value.Split(',')).Select(ParseOne).Where(policy => !policy.IsEmpty)];

    /// <summary>The values of a directive, in lower case.</summary>
    /// <param name="name">Directive name, in lower case.</param>
    /// <returns>The values, or <see langword="null"/> when the policy does not have the directive.</returns>
    public IReadOnlyList<string>? Sources(string name) => directives.GetValueOrDefault(name);

    /// <summary>
    /// Whether the policy really limits which scripts run: it has <c>script-src</c> (or
    /// <c>default-src</c>) without <c>'unsafe-eval'</c>, without <c>'unsafe-inline'</c> unless a nonce
    /// or a hash takes its place, and without sources as wide as <c>*</c> or <c>https:</c> unless
    /// <c>'strict-dynamic'</c> makes browsers ignore them.
    /// </summary>
    /// <returns><see langword="true"/> if scripts are limited.</returns>
    public bool RestrictsScripts()
    {
        if (!directives.TryGetValue("script-src", out var sources) && !directives.TryGetValue("default-src", out sources))
        {
            return false;
        }

        var strictDynamic = sources.Contains("'strict-dynamic'");
        var noncesOrHashes = strictDynamic || sources.Any(s => s.StartsWith("'nonce-", StringComparison.Ordinal) || s.StartsWith("'sha", StringComparison.Ordinal));
        return !sources.Contains("'unsafe-eval'")
            && (noncesOrHashes || !sources.Contains("'unsafe-inline'"))
            && (strictDynamic || !sources.Any(s => s is "*" or "http:" or "https:" or "data:"));
    }

    private static ContentSecurityPolicy ParseOne(string text)
    {
        var policy = new ContentSecurityPolicy();
        foreach (var directive in text.Split(';'))
        {
            var tokens = directive.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length > 0)
            {
                // A repeated directive is ignored: the first one counts.
                policy.directives.TryAdd(tokens[0].ToLowerInvariant(), [.. tokens.Skip(1).Select(t => t.ToLowerInvariant())]);
            }
        }

        return policy;
    }
}

/// <summary>Finds <c>meta</c> elements in a page: some sites set their policies there instead of in headers.</summary>
internal static partial class HtmlMeta
{
    /// <summary>The <c>content</c> of the <c>meta</c> elements whose attribute has the given value.</summary>
    /// <param name="html">The page, or <see langword="null"/> when it was not read.</param>
    /// <param name="attribute">Attribute name in lower case: <c>http-equiv</c> or <c>name</c>.</param>
    /// <param name="value">The value to look for, in any letter case.</param>
    /// <returns>The contents, in page order.</returns>
    public static IEnumerable<string> Contents(string? html, string attribute, string value)
    {
        foreach (Match tag in MetaTag().Matches(html ?? string.Empty))
        {
            var attributes = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (Match match in Attribute().Matches(tag.Value))
            {
                var text = match.Groups[2].Success ? match.Groups[2].Value : match.Groups[3].Success ? match.Groups[3].Value : match.Groups[4].Value;
                attributes.TryAdd(match.Groups[1].Value.ToLowerInvariant(), WebUtility.HtmlDecode(text));
            }

            if (attributes.TryGetValue(attribute, out var found)
                && found.Trim().Equals(value, StringComparison.OrdinalIgnoreCase)
                && attributes.TryGetValue("content", out var content))
            {
                yield return content;
            }
        }
    }

    [GeneratedRegex(@"<meta\b[^>]*>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MetaTag();

    [GeneratedRegex("""([a-zA-Z-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))""", RegexOptions.CultureInvariant)]
    private static partial Regex Attribute();
}

/// <summary>A cookie set by a response (RFC 6265): its name and attributes, never its value.</summary>
/// <param name="Name">The cookie name.</param>
/// <param name="Attributes">The attributes as sent, for the evidence of a finding.</param>
/// <param name="Secure">Whether it has <c>Secure</c>.</param>
/// <param name="HttpOnly">Whether it has <c>HttpOnly</c>.</param>
/// <param name="SameSite">The <c>SameSite</c> value in lower case, when present.</param>
internal sealed partial record SetCookie(string Name, IReadOnlyList<string> Attributes, bool Secure, bool HttpOnly, string? SameSite)
{
    /// <summary>
    /// The cookie as shown in a report: its name and the names of its attributes. The value can be a
    /// session token and is never shown; of the attributes only <c>SameSite</c> and <c>Max-Age</c>
    /// keep their value, and only when it is a plain word or number, so nothing a server puts in a
    /// header can end up in the report by way of an attribute.
    /// </summary>
    public string Display => string.Join("; ", Attributes.Select(ShowAttribute).OfType<string>().Prepend(Name + "=…"));

    /// <summary>
    /// Whether the name looks like that of a session or login cookie. Anti-forgery tokens are left
    /// out: the scripts of the page are meant to read them.
    /// </summary>
    public bool LooksLikeSession =>
        SessionName().IsMatch(Name) && !Name.Contains("srf", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The cookies of a <c>Set-Cookie</c> header line. Some proxies join several cookies into one
    /// line separated by commas: they are told apart, so each one is judged on its own attributes.
    /// </summary>
    /// <param name="header">The header value.</param>
    /// <returns>The cookies that could be read.</returns>
    public static IEnumerable<SetCookie> ParseAll(string header) =>
        NextCookie().Split(header).Select(TryParse).OfType<SetCookie>();

    /// <summary>Parses a <c>Set-Cookie</c> header value.</summary>
    /// <param name="header">The header value.</param>
    /// <returns>The cookie, or <see langword="null"/> when the value has no name.</returns>
    public static SetCookie? TryParse(string header)
    {
        var parts = header.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        var equals = parts.Length == 0 ? -1 : parts[0].IndexOf('=', StringComparison.Ordinal);
        if (equals <= 0)
        {
            return null;
        }

        // A stray comma can be left by whatever joined several cookies into one line.
        var attributes = parts.Skip(1).Select(a => a.Trim(',', ' ')).Where(a => a.Length > 0).ToArray();
        var sameSite = attributes
            .Select(a => a.Split('=', 2, StringSplitOptions.TrimEntries))
            .Where(a => a.Length == 2 && a[0].Equals("SameSite", StringComparison.OrdinalIgnoreCase))
            .Select(a => a[1].ToLowerInvariant())
            .FirstOrDefault();
        return new SetCookie(
            parts[0][..equals].Trim(),
            attributes,
            attributes.Any(a => a.Equals("Secure", StringComparison.OrdinalIgnoreCase)),
            attributes.Any(a => a.Equals("HttpOnly", StringComparison.OrdinalIgnoreCase)),
            sameSite);
    }

    private static string? ShowAttribute(string attribute)
    {
        var parts = attribute.Split('=', 2, StringSplitOptions.TrimEntries);
        if (!Word().IsMatch(parts[0]))
        {
            return null;
        }

        var keepsValue = parts.Length == 2
            && (parts[0].Equals("SameSite", StringComparison.OrdinalIgnoreCase) || parts[0].Equals("Max-Age", StringComparison.OrdinalIgnoreCase))
            && Word().IsMatch(parts[1]);
        return keepsValue ? $"{parts[0]}={parts[1]}" : parts[0];
    }

    [GeneratedRegex("sess|sid|auth|token|login", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SessionName();

    /// <summary>A comma followed by <c>name=</c>: the start of another cookie, not the comma of an <c>Expires</c> date.</summary>
    [GeneratedRegex(@",\s*(?=[^;,=\s]+=)", RegexOptions.CultureInvariant)]
    private static partial Regex NextCookie();

    [GeneratedRegex(@"\A[A-Za-z0-9-]+\z", RegexOptions.CultureInvariant)]
    private static partial Regex Word();
}
