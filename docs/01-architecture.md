# 01 — Architecture and stack

## Solution `ScudoDigitale.sln` (.NET 10)
| Project | Role |
|---|---|
| `ScudoDigitale.Core` | models (`Finding`, `Severity`, `Confidence`, `Profile`, `ScopeDeclaration`), `ICheck` interface, execution engine, priority calculation |
| `ScudoDigitale.Checks.Email` | SPF, DMARC, DKIM, MTA-STS, DNSSEC, STARTTLS, DNSBL |
| `ScudoDigitale.Checks.Web` | TLS, headers, cookies, CMS, indicative GDPR; active checks behind `IScopeGuard` |
| `ScudoDigitale.Checks.Network` | LAN discovery, TCP scan, services, UPnP |
| `ScudoDigitale.Checks.Wireless` | Wi-Fi and Bluetooth, with per-OS adapters (`IWifiProvider`, `IBluetoothProvider`) |
| `ScudoDigitale.Vulnerabilities` | local SQLite database: NVD (CVE/CPE/CVSS), CISA KEV, EPSS, OSV; incremental update |
| `ScudoDigitale.Compliance` | GDPR/NIS2 questionnaires defined in versioned JSON (updatable without recompiling); evaluates the answers, together with the technical findings, into ordinary `Finding`s (ADR-005) |
| `ScudoDigitale.Reporting` | HTML (Scriban template, single file), PDF (PdfSharp/MigraDoc, MIT), JSON (its own versioned schema, ADR-005), comparison between runs |
| `ScudoDigitale.Cli` | `System.CommandLine`: `scudo scan --profile --mail --web --lan --wifi --bt`, `scudo db update`, `scudo report diff` |
| `ScudoDigitale.App` | Avalonia interface (v0.2+), same logic as the CLI |
| `tests/*` | xUnit for every project, fake in-process DNS/HTTP/TLS servers; coverage >90% |

## Principles
- **Every check is an `ICheck`** with id, area, prerequisites (privileges, network, platform) and `ScopeRequirement` (Passive / ActiveOwnedOnly). The engine skips checks that cannot run and says so in the report ("skipped: requires Linux with BlueZ").
- **`IScopeGuard`**: no active check starts without a declared scope and, for domains, without proof of ownership (TXT record `scudo-digitale-verify=<token>` or file `/.well-known/scudo-digitale.txt`).
- **No outbound network beyond the targets and public data sources** (NVD, KEV, EPSS, OSV, optional HIBP). No telemetry. An `--offline` option uses only the already downloaded database.
- **Cautious network behavior**: configurable concurrency limit and timeouts, so as not to disturb fragile home devices.
- **Localization**: user-facing strings live in `.resx` resource files in English and Italian; Italian is selected automatically when the OS language is Italian. XML docs and identifiers are in English.

## Libraries (all AGPL-compatible)
DnsClient.NET (Apache-2.0), Microsoft.Data.Sqlite (MIT), System.CommandLine (MIT), Avalonia (MIT), PdfSharp/MigraDoc 6 (MIT), Scriban (BSD-2), xUnit (Apache-2.0). **Excluded:** QuestPDF (commercial license above a threshold), Npcap (not freely redistributable), SharpPcap (depends on Npcap/libpcap).

## Cross-platform
| Function | Windows | Linux | macOS |
|---|---|---|---|
| ARP/neighbors | `GetIpNetTable2` / `arp -a` | `/proc/net/arp`, `ip neigh` | `arp -an` |
| Wi-Fi | `netsh wlan` / WinRT | `nmcli` | CoreWLAN (`system_profiler`) |
| Bluetooth | WinRT `BluetoothLEAdvertisementWatcher` | BlueZ via D-Bus (Tmds.DBus) | CoreBluetooth (native binding, last) |
| ICMP (optional) | ok without admin | needs `cap_net_raw` or root | ok |

## Distribution
- Self-contained, single-file `dotnet publish` builds for `win-x64`, `win-arm64`, `linux-x64`, `linux-arm64`, `osx-x64`, `osx-arm64` on **GitHub Actions**.
- Release with SHA-256 and **build provenance attestation** (`actions/attest-build-provenance`).
- Windows signing with **SignPath Foundation** (free for OSS), application after the first public release.
- Linux: also `.tar.gz` and Flatpak in the future. macOS: non-notarized `.zip` + instructions; Homebrew tap in the future.
- The CVE database is **not** inside the executable: it is downloaded on first run (`scudo db update`) and weighs a few hundred MB.
