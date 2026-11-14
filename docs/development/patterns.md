# Pattern del progetto

## Controllo (`ICheck`)
```csharp
public sealed class DmarcCheck : ICheck
{
    public string Id => "MAIL-DMARC-001";
    public CheckArea Area => CheckArea.Email;
    public ScopeRequirement Scope => ScopeRequirement.Passive;
    public Task<CheckResult> RunAsync(CheckContext context, CancellationToken ct) { /* ... */ }
}
```
- `CheckResult` = `Executed(findings)` | `Skipped(reason)` | `Failed(error)`. Un controllo non lancia mai eccezioni verso il motore.

## Adattatore per sistema operativo
`IWifiProvider`, `IBluetoothProvider`, `INeighborTableProvider` con implementazioni `Windows*`, `Linux*`, `MacOs*`, scelte da una factory su `OperatingSystem.IsWindows()` ecc. Implementazione mancante → `Skipped("non disponibile su <OS>")`.

## Guardia del perimetro
I controlli con `ScopeRequirement.ActiveOwnedOnly` ricevono il bersaglio solo dopo `IScopeGuard.IsAuthorizedAsync(target)`: rete locale del PC oppure dominio con record TXT `scudo-digitale-verify=<token>` o file `/.well-known/scudo-digitale.txt`.

## Priorità
`KEV` → Critica e in cima; altrimenti CVSS → severità; EPSS ≥ 0,1 alza di un livello; ordinamento finale per severità, poi EPSS, poi confidenza.
