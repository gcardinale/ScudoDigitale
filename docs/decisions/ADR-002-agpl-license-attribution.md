# ADR-002 — AGPL-3.0 license with mandatory attribution
> **Status:** accepted · **Decision maker:** Gaetano Cardinale · **Date:** 2026-11-14

## Context
The program is free, but the author wants his name to stay visible in every copy and nobody to resell it as a closed product under another name.

## Options considered
- **A — Apache-2.0**: maximum adoption; only requires keeping `NOTICE` and source headers, not showing the author in the program; allows closed versions.
- **B — MIT**: like A, with even fewer obligations.
- **C — AGPL-3.0-or-later + additional terms under section 7**: 7(b) requires keeping the attribution in the notices shown to the user; 7(c) requires modified versions to be distinguished; 7(e) excludes rights over the name; the copyleft prevents closed versions even when offered over a network.

## Decision
**C**, because it is the only OSI-approved option that makes visible attribution mandatory in copies and prevents closed versions.

## Consequences
- ✅ Guaranteed visible attribution (CLI banner, About screen, report footer); authorship is protected anyway by art. 20 of Italian Copyright Law (L. 633/1941, moral right of authorship).
- ⚠️ Companies that want to embed it in closed products cannot do so (accepted: it is not the goal).
- 🔍 The text of the additional terms must be compared with the official FSF wording before v1.0; all dependencies must be AGPL-compatible.
