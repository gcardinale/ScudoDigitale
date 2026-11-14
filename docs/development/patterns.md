# Project patterns

## Check (`ICheck`)
```csharp
public sealed class DmarcCheck : ICheck
{
    public string Id => "MAIL-DMARC-001";
    public CheckArea Area => CheckArea.Email;
    public ScopeRequirement Scope => ScopeRequirement.Passive;
    public Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct) { /* ... */ }
}
```
- `CheckResult` = `Executed(findings)` | `Skipped(reason)` | `Failed(error)`. A check never throws exceptions towards the engine.

## Per-OS adapter
`IWifiProvider`, `IBluetoothProvider`, `INeighborTableProvider` with `Windows*`, `Linux*`, `MacOs*` implementations, chosen by a factory on `OperatingSystem.IsWindows()` etc. Missing implementation → `Skipped("not available on <OS>")`.

## Scope guard
Checks with `ScopeRequirement.ActiveOwnedOnly` receive the target only after `IScopeGuard.IsAuthorizedAsync(target)`: the PC's local network, or a domain with a TXT record `scudo-digitale-verify=<token>` or a file `/.well-known/scudo-digitale.txt`.

## Prioritization
`KEV` → Critical and at the top; otherwise CVSS → severity; EPSS ≥ 0.1 raises it by one level; final ordering by severity, then EPSS, then confidence.
