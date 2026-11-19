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
using System.Globalization;
using System.Net;
using ScudoDigitale.Core;

namespace ScudoDigitale.Checks.Email.Tests;

/// <summary>Sets the culture and UI culture for the current async flow and restores it on dispose.</summary>
internal sealed class UiCulture : IDisposable
{
    private readonly CultureInfo previous = CultureInfo.CurrentCulture;
    private readonly CultureInfo previousUi = CultureInfo.CurrentUICulture;

    public UiCulture(string name)
    {
        CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name);
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name);
    }

    public void Dispose()
    {
        CultureInfo.CurrentCulture = previous;
        CultureInfo.CurrentUICulture = previousUi;
    }
}

/// <summary>
/// In-memory DNS. Unknown names have no records. A name can be made to throw, or to hang forever
/// while ignoring the cancellation token (as a rude real resolver would).
/// </summary>
internal sealed class FakeDnsResolver : IDnsResolver
{
    public Dictionary<string, DnsAnswer<string>> Txt { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, DnsAnswer<MailExchange>> Mx { get; } = new(StringComparer.Ordinal);

    public Dictionary<string, DnsAnswer<IPAddress>> Addresses { get; } = new(StringComparer.Ordinal);

    public HashSet<string> Throwing { get; } = new(StringComparer.Ordinal);

    public HashSet<string> Hanging { get; } = new(StringComparer.Ordinal);

    public ConcurrentQueue<string> Queries { get; } = new();

    public FakeDnsResolver WithTxt(string name, params string[] records)
    {
        Txt[name] = DnsAnswer<string>.Found(records);
        return this;
    }

    public FakeDnsResolver WithMx(string name, params (int Preference, string Host)[] records)
    {
        Mx[name] = DnsAnswer<MailExchange>.Found(records.Select(r => new MailExchange(r.Preference, r.Host)));
        return this;
    }

    public FakeDnsResolver WithAddress(string name, string address)
    {
        Addresses[name] = DnsAnswer<IPAddress>.Found([IPAddress.Parse(address)]);
        return this;
    }

    public Task<DnsAnswer<string>> QueryTxtAsync(string name, CancellationToken cancellationToken) => Answer("TXT", name, Txt);

    public Task<DnsAnswer<MailExchange>> QueryMxAsync(string name, CancellationToken cancellationToken) => Answer("MX", name, Mx);

    public Task<DnsAnswer<IPAddress>> QueryAddressesAsync(string name, CancellationToken cancellationToken) => Answer("ADDR", name, Addresses);

    public int Count(string query) => Queries.Count(q => q == query);

    private Task<DnsAnswer<T>> Answer<T>(string type, string name, Dictionary<string, DnsAnswer<T>> map)
    {
        Queries.Enqueue($"{type} {name}");
        if (Throwing.Contains(name))
        {
            throw new InvalidOperationException("resolver exploded on " + name);
        }

        if (Hanging.Contains(name))
        {
            return new TaskCompletionSource<DnsAnswer<T>>().Task;
        }

        return Task.FromResult(map.TryGetValue(name, out var answer) ? answer : DnsAnswer<T>.NoRecords());
    }
}

/// <summary>Builders and runners shared by the tests.</summary>
internal static class Make
{
    public static readonly DateTimeOffset DeclaredAt = new(2026, 11, 19, 10, 0, 0, TimeSpan.Zero);

    public static CheckContext Context(string domain = "example.com", TargetKind kind = TargetKind.Domain)
    {
        var target = new Target(kind, domain);
        return new CheckContext(target, Profile.Individual(), new ScopeDeclaration("Mario Rossi", OperatorRole.Owner, [target], DeclaredAt));
    }

    public static ICheck Check(FakeDnsResolver dns, string id, EmailCheckOptions? options = null) =>
        EmailChecks.Create(dns, options ?? new EmailCheckOptions()).Single(c => c.Id == id);

    public static Task<CheckResult> RunAsync(FakeDnsResolver dns, string id, string domain = "example.com", EmailCheckOptions? options = null) =>
        Check(dns, id, options).RunAsync(Context(domain), CancellationToken.None);

    public static async Task<IReadOnlyList<Finding>> FindingsAsync(FakeDnsResolver dns, string id, string domain = "example.com", EmailCheckOptions? options = null)
    {
        var result = await RunAsync(dns, id, domain, options);
        return Assert.IsType<CheckResult.Executed>(result).Findings;
    }

    public static async Task<Finding> SingleFindingAsync(FakeDnsResolver dns, string id, string domain = "example.com", EmailCheckOptions? options = null)
    {
        var finding = Assert.Single(await FindingsAsync(dns, id, domain, options));
        Assert.Equal(id, finding.Id);
        Assert.Equal(CheckArea.Email, finding.Area);
        Assert.Equal(domain, finding.Target);
        Assert.False(string.IsNullOrWhiteSpace(finding.Title));
        Assert.False(string.IsNullOrWhiteSpace(finding.Risk));
        Assert.False(string.IsNullOrWhiteSpace(finding.Fix));
        Assert.NotEmpty(finding.References);
        return finding;
    }
}
