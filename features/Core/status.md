# Core — status

- **Content:** contracts, engine, prioritization, Attribution
- **Release:** v0.0
- **Status:** 🟢 v0.0 done (15/11/2026)
- **Test coverage:** 100% lines (182/182), 100% branches (70/70) — 123 tests

## Done
- Contracts: `ICheck`, `CheckContext`, `CheckResult` (`Executed` / `Skipped` / `Failed`), `Finding`, `Severity`, `Confidence`, `CheckArea`, `ScopeRequirement`, `Target` / `TargetKind`, `Profile` / `ProfileKind`, `ScopeDeclaration` / `OperatorRole`, `IScopeGuard`.
- `Finding` validates the id (`AREA-TOPIC-NNN`, anchored with `\A…\z`), CVSS 0-10, EPSS 0-1, and copies its lists.
- `CheckEngine`: matches checks to targets by `AppliesTo`, concurrency limit and per-check timeout (`CheckEngineOptions`, defaults 4 and 60 s), timeout enforced even when a check ignores its token, every exception turned into `Failed`, caller cancellation propagated. Active checks run only after `IScopeGuard` says yes: guard errors and timeouts deny (fail closed).
- `FindingPrioritizer`: KEV → Critical, CVSS qualitative rating, EPSS ≥ 0.1 raises one level, total ordering (KEV, severity, EPSS, confidence, id, target).
- `Attribution`: `Notice`, `Banner`, `ReportFooter(version)` (only the leading words are localized).
- Localized engine messages in `Resources/Strings.resx` + `Strings.it.resx`.
- Counter-checks (15/11/2026): 11 deliberate regressions (missing timeout, inverted scope test, guard error allowing, EPSS `>` instead of `>=`, regex `$` instead of `\z`, no de-duplication, no tiebreak, swallowed cancellation, altered notice, removed concurrency gate, removed test file) — each one turns the expected tests red, the last one trips the coverage gate.

## To do
- `IScopeGuard` implementation (local network + domain ownership proof) — v0.2, with the active web checks.
- Enrichment of findings by `Vulnerabilities` — v0.2.
