# ADR-004 — Passive checks everywhere, active checks only on one's own scope
> **Status:** accepted · **Decision maker:** Gaetano Cardinale · **Date:** 2026-11-14

## Context
The user can enter any website or domain. Active scans on other people's systems may amount to criminal offenses (Italian Criminal Code art. 615-ter c.p., unauthorized access to computer systems, and following articles) and expose both user and author.

## Options considered
- **A — Everything active on any target**: more results, unacceptable legal risk.
- **B — Passive only**: safe, but useless on the local network.
- **C — Passive on any target; active only on the PC's local network and on domains with verified ownership, with the executor's declaration in the report.**

## Decision
**C**, because it gives the owner everything they need on their own systems without ever actively touching other people's.

## Consequences
- ✅ `IScopeGuard` is mandatory for every `ActiveOwnedOnly` check; the scope declaration (who, role, what) is printed in the report.
- ⚠️ Active checks on a domain need an extra step (TXT record or `.well-known` file).
- 🔍 No check may attempt login, bruteforce, exploits, deauth or forced pairing: rule verified in code review.
