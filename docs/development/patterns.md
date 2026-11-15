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
- `CheckEngine` validates the check definitions before running anything (id in the `AREA-TOPIC-NNN` form, defined enum values, unique ids, properties that do not throw): a definition error is a programming error and stops the call.
- It then runs each check on every declared target of its `AppliesTo` kind, with a concurrency limit and a per-check timeout (`CheckEngineOptions`, defaults 4 and 60 s, at most 1 hour). The timeout is enforced by the engine even if the check ignores its token; such a check keeps its concurrency slot until it really ends, for at most another timeout, so slow checks cannot exceed the limit. Checks must honour their token anyway.
- A cancellation raised by the check itself (for example an `HttpClient` timeout) is reported as the check's own error, not as an engine timeout.

## Per-OS adapter
`IWifiProvider`, `IBluetoothProvider`, `INeighborTableProvider` with `Windows*`, `Linux*`, `MacOs*` implementations, chosen by a factory on `OperatingSystem.IsWindows()` etc. Missing implementation → `Skipped("not available on <OS>")`.

## Scope guard
Checks with `ScopeRequirement.ActiveOwnedOnly` receive the target only after `IScopeGuard.IsAuthorizedAsync(target)` returns `true`; if the guard throws, returns nothing or times out, the check is not run and the result is `Skipped` (fail closed); the guard is asked for every target. Allowed targets: the PC's local network, or a domain with a TXT record `scudo-digitale-verify=<token>` or a file `/.well-known/scudo-digitale.txt`.

## Prioritization
`KEV` → Critical and at the top; otherwise CVSS → severity (qualitative CVSS rating); EPSS ≥ 0.1 raises it by one level; final ordering by KEV, severity, EPSS, confidence, then id and target so the order is always the same (`FindingPrioritizer`). The result is a list of `PrioritizedFinding` (finding + effective severity): the finding keeps the severity assigned by the check, so prioritizing again never raises it twice.
