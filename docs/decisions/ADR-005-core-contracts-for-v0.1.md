# ADR-005 — Core contracts for questionnaires, JSON output and check names
> **Status:** proposed · **Decision maker:** Gaetano Cardinale · **Date:** 2026-11-15

## Context
v0.1 is developed in four parallel worktrees (Email, Web, Compliance, Reporting) that all depend on `ScudoDigitale.Core`. The review of v0.0 found three gaps in the Core contracts. If they are not settled before the parallel work starts, each worktree will change Core on its own.

1. **Questionnaires.** GDPR and NIS2 questionnaires (spec §2.6, §2.7) do not check a target: they turn answers into findings. `ICheck` and `CheckContext` cannot carry answers, and `ScopeDeclaration` requires at least one target. A GDPR-only assessment for an individual would need a fake target. The questionnaire also needs the technical findings, because the evidence (TLS, DMARC, cookies) is linked to GDPR art. 32.
2. **JSON output.** The JSON report is the input of the comparison between two runs (spec §4), so it is a public, versioned format. Today the Core types do not serialize well. `CheckResult` is abstract, so its findings disappear. `Profile` has only a private constructor. Enums come out as numbers, while the spec shows strings.
3. **Check names.** A check that was skipped or failed is reported only with its id (`MAIL-DMARC-001`). The report must declare skipped checks in a form the user understands (`docs/01-architecture.md`: the engine skips checks that cannot run "and says so in the report").

## Options considered
### 1. Questionnaires
- **A — Questionnaires as `ICheck`**: answers carried in `CheckContext`, one check per question. It reuses the engine, but it mixes two different things. Concurrency, timeouts and the scope guard make no sense for an answer, and `CheckContext` would grow a field that every other check ignores.
- **B — A separate evaluation in `Compliance`**: `Evaluate(questionnaire, answers, profile, technicalFindings) → IReadOnlyList<Finding>`. The questionnaire definitions stay in versioned JSON, as already decided in the architecture. Core only has to allow a `ScopeDeclaration` with no targets, for a questionnaire-only assessment.

### 2. JSON output
- **A — Serialization attributes in Core** (`[JsonPolymorphic]` on `CheckResult`, a JSON constructor on `Profile`, enums as strings). It is quick, but every internal refactor of Core then changes the public format.
- **B — Report DTOs in `Reporting`**: a `ReportDocument` with an explicit `schemaVersion`, built from the Core types and read back for the comparison. Core stays free to change; the format changes only on purpose.

### 3. Check names
- **A — `ICheck.Title`**: a localized, user-facing name that each module takes from its own `.resx`. The engine copies it into `CheckRun`.
- **B — A catalog in `Reporting`** mapping ids to names. Every module would have to update a file it does not own, in a fifth place, for every new check.

## Decision (proposed)
**1B, 2B, 3A.**
- Questionnaires are evaluated by `Compliance` and produce ordinary `Finding`s, which are prioritized and reported together with the technical ones. `ScopeDeclaration` accepts an empty list of targets.
- The JSON report is a versioned DTO owned by `Reporting`. Enums are written as strings, as in spec §3.
- `ICheck` gets a localized `Title`. The engine rejects a blank title together with the other definition errors, and `CheckRun` carries the title.

## Consequences
- ✅ Core changes once, before the parallel work: `ScopeDeclaration` (empty targets allowed), `ICheck.Title`, `CheckRun.CheckTitle`.
- ✅ The JSON format can only change through `schemaVersion`, so comparing two runs stays possible across versions.
- ⚠️ `Reporting` maintains its own DTOs and their tests, including a round trip (write, read back, compare).
- ⚠️ Every check must provide a title in English and Italian.
- 🔍 Open point for the Compliance worktree: how each technical finding is linked to an article (by area, or by a list in the questionnaire JSON). It does not change Core.
