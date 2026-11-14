# 03 — Roadmap (accelerated)

> Goal: **public v1.0 in about 3 weeks** instead of 3 months.
> How: the contracts in `ScudoDigitale.Core` are fixed right away, then the modules are developed **in parallel** (one worktree per module) and everything not needed for the first release is deferred to v1.1.

## Day-by-day plan (actual working days)
| Days | Release | Content | In parallel | Done when |
|---|---|---|---|---|
| **1** | **v0.0 — skeleton** | solution, empty projects, `Core` with `ICheck`, `Finding`, `Severity`, `Confidence`, `Profile`, `ScopeDeclaration`, `IScopeGuard`, `Attribution`; `build/check-headers.ps1`; GitHub Actions (build + test + coverage on Windows/Linux/macOS) | — | CI green on all 3 systems, `Core` contracts 100% tested |
| **2-4** | **v0.1 — passive** | `Checks.Email`, `Checks.Web` (passive + indicative GDPR), `Compliance` (GDPR/NIS2 in JSON), `Reporting` (HTML/PDF/JSON), `Cli` | 4 worktrees: Email · Web · Compliance · Reporting; legal verification of references in a separate session | complete report on a real domain and on a test domain, coverage >90% |
| **5-8** | **v0.2 — network and CVE** | `Vulnerabilities` (NVD/KEV/EPSS/OSV in SQLite), `Checks.Network`, domain ownership proof + active web checks, minimal Avalonia `App` (guided procedure + report opening) | 3 worktrees: Vulnerabilities · Network · App | real LAN scan with at least one linked CVE and correct confidence |
| **9-11** | **v0.3 — wireless** | `Checks.Wireless`: Wi-Fi (3 systems) and Bluetooth (Windows + Linux) | 2 worktrees: Wi-Fi · Bluetooth | test BT devices and Wi-Fi networks classified correctly |
| **12-14** | **v1.0 — public** | security and code review, single-file executables for 6 platforms, SHA-256 + provenance attestation, final README, signing request to SignPath Foundation | — | downloadable release on GitHub, download page published |

SignPath signing arrives after the Foundation's approval (external timing): v1.0 ships **with attestation and hashes**, signing is added in a v1.0.x.

## Three scenarios
| Scenario | v0.1 | v1.0 |
|---|---|---|
| Optimistic | day 3 | 2 weeks |
| Realistic | day 4-5 | 3 weeks |
| Pessimistic | day 7 | 5 weeks (Bluetooth and CVE database slower) |

## What is deferred to v1.1 if running late
In this order: Bluetooth on macOS → comparison between two reports → Have I Been Pwned → Flatpak/Homebrew packages → full Avalonia interface (the minimal guided procedure stays).

## Checklist
- [x] Name, license, platforms, scope decided (14/11/2026)
- [x] Repository created with documentation, ADRs, LICENSE, NOTICE (14/11/2026)
- [ ] v0.0 skeleton + CI
- [ ] v0.1 passive
- [ ] v0.2 network and CVE
- [ ] v0.3 wireless
- [ ] v1.0 public
