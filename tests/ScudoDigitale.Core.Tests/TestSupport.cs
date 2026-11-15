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
using ScudoDigitale.Core;

namespace ScudoDigitale.Core.Tests;

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

/// <summary>Builders for valid test objects.</summary>
internal static class Make
{
    public static readonly DateTimeOffset DeclaredAt = new(2026, 11, 15, 10, 0, 0, TimeSpan.Zero);

    public static Finding Finding(
        string id = "MAIL-DMARC-001",
        Severity severity = Severity.Medium,
        Confidence confidence = Confidence.Certain,
        string target = "example.com") =>
        new(id, CheckArea.Email, "DMARC in monitoring mode", severity, confidence, target);

    public static ScopeDeclaration Scope(params Target[] targets) =>
        new("Mario Rossi", OperatorRole.Owner, targets, DeclaredAt);
}

/// <summary>A configurable check double.</summary>
internal sealed class FakeCheck(
    string id,
    TargetKind appliesTo,
    Func<CheckContext, CancellationToken, Task<CheckResult>> run,
    ScopeRequirement scope = ScopeRequirement.Passive) : ICheck
{
    private int calls;

    public string Id => id;

    public CheckArea Area => CheckArea.Email;

    public TargetKind AppliesTo => appliesTo;

    public ScopeRequirement Scope => scope;

    public int Calls => calls;

    public List<Target> SeenTargets { get; } = [];

    public Task<CheckResult> RunAsync(CheckContext context, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref calls);
        lock (SeenTargets)
        {
            SeenTargets.Add(context.Target);
        }

        return run(context, cancellationToken);
    }

    public static FakeCheck Returning(string id, TargetKind kind, CheckResult result, ScopeRequirement scope = ScopeRequirement.Passive) =>
        new(id, kind, (_, _) => Task.FromResult(result), scope);
}

/// <summary>A configurable scope guard double.</summary>
internal sealed class FakeScopeGuard(Func<Target, CancellationToken, Task<bool>> decide) : IScopeGuard
{
    private int calls;

    public int Calls => calls;

    public Task<bool> IsAuthorizedAsync(Target target, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref calls);
        return decide(target, cancellationToken);
    }

    public static FakeScopeGuard Allowing() => new((_, _) => Task.FromResult(true));

    public static FakeScopeGuard Denying() => new((_, _) => Task.FromResult(false));
}
