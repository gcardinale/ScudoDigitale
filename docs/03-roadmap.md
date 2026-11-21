# 03 — Roadmap (accelerated)

> Goal: **a downloadable beta 0.1 on Tuesday 1 December 2026** (latest Friday 4 December), then **v1.0 by 15 December 2026** at the latest.
> How: the contracts in `ScudoDigitale.Core` are fixed right away, then the modules are developed **in parallel** (one worktree per module) and everything not needed for the first release is deferred to v1.1.
> Change of 17/11/2026: packaging (single-file executables + SHA-256) moves **forward from v1.0 to the beta 0.1**, so that people can download and try the passive checks as early as possible.

## Calendar
| Date | Milestone | Done when |
|---|---|---|
| 15/11/2026 | v0.0 skeleton | ✅ CI green on Windows, Linux and macOS |
| from 17/11/2026 | v0.1 work starts | 4 worktrees: Email · Web · Compliance · Reporting |
| 20/11/2026 | checkpoint 1 | email and website checks work on a real domain; if not, decide what to cut |
| 27/11/2026 | checkpoint 2 | v0.1 complete (email, website, GDPR/NIS2, reports) with coverage >90%; if not, cut now |
| 29/11/2026 | release candidate | executables for Windows, Linux and macOS, SHA-256, tested on a clean PC, release page and download page ready |
| **01/12/2026** | **beta 0.1 published** | GitHub pre-release downloadable (latest 04/12/2026) |
| 01/12 → 15/12/2026 | v0.2, v0.3, v1.0 | network and CVE, wireless, review and final release |

## Day-by-day plan (actual working days)
| Days | Release | Content | In parallel | Done when |
|---|---|---|---|---|
| **1** | **v0.0 — skeleton** | solution, empty projects, `Core` with `ICheck`, `Finding`, `Severity`, `Confidence`, `Profile`, `ScopeDeclaration`, `IScopeGuard`, `Attribution`; `build/check-headers.ps1`; GitHub Actions (build + test + coverage on Windows/Linux/macOS) | — | CI green on all 3 systems, `Core` contracts 100% tested |
| **2-4** | **v0.1 — passive, released as beta** | `Checks.Email`, `Checks.Web` (passive + indicative GDPR), `Compliance` (GDPR/NIS2 in JSON), `Reporting` (HTML/PDF/JSON), `Cli`; **single-file executables for Windows, Linux and macOS (x64) with SHA-256, GitHub pre-release** | 4 worktrees: Email · Web · Compliance · Reporting; legal verification of references in a separate session | complete report on a real domain and on a test domain, coverage >90%, executables run on a clean PC |
| **5-8** | **v0.2 — network and CVE** | `Vulnerabilities` (NVD/KEV/EPSS/OSV in SQLite), `Checks.Network`, domain ownership proof + active web checks, minimal Avalonia `App` (guided procedure + report opening) | 3 worktrees: Vulnerabilities · Network · App | real LAN scan with at least one linked CVE and correct confidence |
| **9-11** | **v0.3 — wireless** | `Checks.Wireless`: Wi-Fi (3 systems) and Bluetooth (Windows + Linux) | 2 worktrees: Wi-Fi · Bluetooth | test BT devices and Wi-Fi networks classified correctly |
| **12-14** | **v1.0 — public** | security and code review, executables extended to 6 platforms (x64 + arm64), SHA-256 + provenance attestation, final README, signing request to SignPath Foundation | — | downloadable release on GitHub, download page published, by 15/12/2026 |

SignPath signing arrives after the Foundation's approval (external timing): v1.0 ships **with attestation and hashes**, signing is added in a v1.0.x.

## Three scenarios
| Scenario | beta 0.1 | v1.0 |
|---|---|---|
| Optimistic | 29/11/2026 | 11/12/2026 |
| Realistic | 01/12/2026 | 15/12/2026 |
| Pessimistic | 04/12/2026, with less in it (cuts decided at the checkpoints) | 15/12/2026 with wireless and Bluetooth moved to v1.1 |

## What is deferred to v1.1 if running late
In this order: Bluetooth on macOS → comparison between two reports → Have I Been Pwned → Flatpak/Homebrew packages → full Avalonia interface (the minimal guided procedure stays).

## Checklist
- [x] Name, license, platforms, scope decided (14/11/2026)
- [x] Repository created with documentation, ADRs, LICENSE, NOTICE (14/11/2026)
- [x] v0.0 skeleton + CI (15/11/2026, CI green on Windows, Linux and macOS)
- [x] Roadmap updated: beta 0.1 on 01/12/2026 with downloadable executables (17/11/2026)
- [x] `Checks.Email`: SPF, DMARC, DKIM, MX, 11 checks (19/11/2026, [ADR-006](decisions/ADR-006-check-granularity-and-dns-for-email.md)); MTA-STS, DNSSEC, STARTTLS, DNSBL and BIMI moved after the beta
- [x] `Checks.Web`, first pass: HTTPS, certificate, security headers, cookies, security.txt, 15 passive checks (21/11/2026; checkpoint 1 of 20/11 was missed for websites by one day)
- [ ] `Checks.Web`, second pass: TLS versions and ciphers (needs ADR-007: same result on the 3 systems), CMS detection, indicative GDPR
- [ ] `Compliance`, `Reporting` (not started on 21/11/2026)
- [x] `Cli`: `scudo scan --mail` with text output (19/11/2026)
- [x] `Cli`: `scudo scan --web`, alone or together with `--mail` (21/11/2026)
- [ ] `Cli`: report files, together with `Reporting`
- [ ] v0.1 passive, published as beta 0.1 (01/12/2026)
- [ ] v0.2 network and CVE
- [ ] v0.3 wireless
- [ ] v1.0 public (by 15/12/2026)
