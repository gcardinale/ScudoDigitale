# Project patterns

## Check (`ICheck`)
```csharp
public sealed class DmarcCheck : ICheck
{
    public string Id => "MAIL-DMARC-001";
    public CheckArea Area => CheckArea.Email;
    public TargetKind AppliesTo => TargetKind.Domain;
    public ScopeRequirement Scope => ScopeRequirement.Passive;
    public Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct) { /* ... */ }
}
```
- `CheckResult` = `Executed(findings)` | `Skipped(reason)` | `Failed(error)`. A check never throws exceptions towards the engine; if it does anyway, `CheckEngine` turns the exception into `Failed`.
- `CheckEngine` runs each check on every declared target of its `AppliesTo` kind, with a concurrency limit and a per-check timeout (`CheckEngineOptions`, defaults 4 and 60 s). The timeout is enforced by the engine even if the check ignores its token.

## Per-OS adapter
`IWifiProvider`, `IBluetoothProvider`, `INeighborTableProvider` with `Windows*`, `Linux*`, `MacOs*` implementations, chosen by a factory on `OperatingSystem.IsWindows()` etc. Missing implementation → `Skipped("not available on <OS>")`.

## Scope guard
Checks with `ScopeRequirement.ActiveOwnedOnly` receive the target only after `IScopeGuard.IsAuthorizedAsync(target)` returns `true`; if the guard throws or times out the check is not run (fail closed). Allowed targets: the PC's local network, or a domain with a TXT record `scudo-digitale-verify=<token>` or a file `/.well-known/scudo-digitale.txt`.

## Prioritization
`KEV` → Critical and at the top; otherwise CVSS → severity (qualitative CVSS rating); EPSS ≥ 0.1 raises it by one level; final ordering by KEV, severity, EPSS, confidence, then id and target so the order is always the same (`FindingPrioritizer`).
