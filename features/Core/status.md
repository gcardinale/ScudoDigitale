# Core — status

- **Content:** contracts, engine, prioritization, Attribution
- **Release:** v0.0
- **Status:** 🟢 v0.0 done (15/11/2026), review fixes applied; shared DNS resolver added on 21/11/2026
- **Test coverage:** 99.8% lines (538/539), 97.8% branches (178/182) — 240 tests

## Done
- Contracts: `ICheck`, `CheckContext`, `CheckResult` (`Executed` / `Skipped` / `Failed`), `Finding`, `PrioritizedFinding`, `Severity`, `Confidence`, `CheckArea`, `ScopeRequirement`, `Target` / `TargetKind`, `Profile` / `ProfileKind`, `ScopeDeclaration` / `OperatorRole`, `IScopeGuard`.
- `Finding` validates the id (`AREA-TOPIC-NNN`, anchored with `\A…\z`), CVSS 0-10, EPSS 0-1, CVE ids (`CVE-YYYY-NNNN`) and references (no blanks), and copies its lists. Its severity is the one assigned by the check and never changes.
- `Target` normalizes domains (lower case, no trailing dot), also in email addresses, so the same domain is never checked twice. `ScopeDeclaration` requires the declaration date.
- `CheckEngine`: validates check definitions up front (well-formed and unique ids, defined enums, properties that do not throw); matches checks to targets by `AppliesTo`; concurrency limit and per-check timeout (`CheckEngineOptions`, defaults 4 and 60 s, at most 1 hour); timeout enforced even when a check ignores its token, and such a check keeps its slot until it really ends (at most another timeout); every exception turned into `Failed`, a check's own cancellation reported as its own error; caller cancellation propagated. Active checks run only after `IScopeGuard` says yes for that target: guard errors, missing answers and timeouts deny with `Skipped` (fail closed).
- `FindingPrioritizer`: KEV → Critical, CVSS qualitative rating, EPSS ≥ 0.1 raises one level, total ordering; returns `PrioritizedFinding`, so prioritizing again gives the same result.
- `Attribution`: `Notice`, `Banner`, `ReportFooter(version)` (only the leading words are localized).
- Localized engine messages in `Resources/Strings.resx` + `Strings.it.resx`.
- `ScudoDigitale.Core.Dns` (21/11/2026, moved from `Checks.Email` so that the website checks can use it too, ADR-006): `IDnsResolver` (TXT, MX, addresses) with `DnsAnswer` / `DnsStatus`, `DnsOptions` (source, timeout, retries), `DnsSource`, and `DnsResolvers.Create`: Cloudflare and then Google over DNS over HTTPS, then the DNS of the computer through DnsClient.NET; `DnsSource.System` uses only the latter. Core now references DnsClient.NET. Tested on real DNS packets with an in-process UDP DNS server.
- ADR-005 (15/11/2026): `ICheck.Title` (validated, carried by `CheckRun.CheckTitle`); `ScopeDeclaration` accepts no targets for a questionnaire-only assessment.
- Counter-checks: 11 at v0.0 and 13 after the review fixes, each one turning the expected test red. 3 more for ADR-005.

## Known limits
- Record equality compares list members (CVE, references, targets, findings) by reference.
- A check that never ends keeps running in the background after its slot is given back: checks must honour their cancellation token.

## To do
- `IScopeGuard` implementation (local network + domain ownership proof) — v0.2, with the active web checks.
- Enrichment of findings by `Vulnerabilities` — v0.2.
