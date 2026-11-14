# 01 — Architettura e stack

## Soluzione `ScudoDigitale.sln` (.NET 10)
| Progetto | Ruolo |
|---|---|
| `ScudoDigitale.Core` | modelli (`Finding`, `Severity`, `Confidence`, `Profile`, `ScopeDeclaration`), interfaccia `ICheck`, motore di esecuzione, calcolo priorità |
| `ScudoDigitale.Checks.Email` | SPF, DMARC, DKIM, MTA-STS, DNSSEC, STARTTLS, DNSBL |
| `ScudoDigitale.Checks.Web` | TLS, header, cookie, CMS, GDPR indicativo; controlli attivi dietro `IScopeGuard` |
| `ScudoDigitale.Checks.Network` | scoperta LAN, scansione TCP, servizi, UPnP |
| `ScudoDigitale.Checks.Wireless` | Wi-Fi e Bluetooth, con adattatori per sistema operativo (`IWifiProvider`, `IBluetoothProvider`) |
| `ScudoDigitale.Vulnerabilities` | database locale SQLite: NVD (CVE/CPE/CVSS), CISA KEV, EPSS, OSV; aggiornamento incrementale |
| `ScudoDigitale.Compliance` | questionari GDPR/NIS2 definiti in JSON versionato (si aggiornano senza ricompilare) |
| `ScudoDigitale.Reporting` | HTML (template Scriban, unico file), PDF (PdfSharp/MigraDoc, MIT), JSON, confronto tra esecuzioni |
| `ScudoDigitale.Cli` | `System.CommandLine`: `scudo scan --profile --mail --web --lan --wifi --bt`, `scudo db update`, `scudo report diff` |
| `ScudoDigitale.App` | interfaccia Avalonia (v0.2+), stessa logica della CLI |
| `tests/*` | xUnit per ogni progetto, server DNS/HTTP/TLS finti in-process; copertura >90% |

## Principi
- **Ogni controllo è un `ICheck`** con id, area, prerequisiti (privilegi, rete, piattaforma) e `ScopeRequirement` (Passivo / AttivoSoloPropri). Il motore salta i controlli non eseguibili e lo scrive nel report («saltato: serve Linux con BlueZ»).
- **`IScopeGuard`**: nessun controllo attivo parte senza un perimetro dichiarato e, per i domini, senza la prova di proprietà (record TXT `scudo-digitale-verify=<token>` oppure file `/.well-known/scudo-digitale.txt`).
- **Niente rete in uscita oltre ai bersagli e alle fonti dati pubbliche** (NVD, KEV, EPSS, OSV, eventuale HIBP). Nessuna telemetria. Una opzione `--offline` usa solo il database già scaricato.
- **Prestazioni di rete prudenti**: limite di concorrenza e timeout configurabili, per non disturbare apparati domestici fragili.

## Librerie (tutte compatibili con AGPL)
DnsClient.NET (Apache-2.0), Microsoft.Data.Sqlite (MIT), System.CommandLine (MIT), Avalonia (MIT), PdfSharp/MigraDoc 6 (MIT), Scriban (BSD-2), xUnit (Apache-2.0). **Escluse:** QuestPDF (licenza commerciale sopra una soglia), Npcap (non ridistribuibile gratis), SharpPcap (dipende da Npcap/libpcap).

## Multipiattaforma
| Funzione | Windows | Linux | macOS |
|---|---|---|---|
| ARP/vicini | `GetIpNetTable2` / `arp -a` | `/proc/net/arp`, `ip neigh` | `arp -an` |
| Wi-Fi | `netsh wlan` / WinRT | `nmcli` | CoreWLAN (`system_profiler`) |
| Bluetooth | WinRT `BluetoothLEAdvertisementWatcher` | BlueZ via D-Bus (Tmds.DBus) | CoreBluetooth (binding nativo, ultimo) |
| ICMP (facoltativo) | ok senza admin | serve `cap_net_raw` o root | ok |

## Distribuzione
- Build `dotnet publish` self-contained, single-file per `win-x64`, `win-arm64`, `linux-x64`, `linux-arm64`, `osx-x64`, `osx-arm64` su **GitHub Actions**.
- Release con SHA-256 e **attestazione di provenienza** (`actions/attest-build-provenance`).
- Firma Windows con **SignPath Foundation** (gratis per OSS), domanda dopo la prima release pubblica.
- Linux: anche `.tar.gz` e in futuro Flatpak. macOS: `.zip` non notarizzato + istruzioni; in futuro tap Homebrew.
- Il database CVE **non** sta nell'eseguibile: si scarica al primo avvio (`scudo db update`) e pesa qualche centinaio di MB.
