# ADR-003 — Cross-platform with no recurring costs
> **Status:** accepted · **Decision maker:** Gaetano Cardinale · **Date:** 2026-11-14

## Context
The tool must run on Windows, macOS and Linux and be given away for free: no recurring expenses for signing or distribution.

## Options considered
- **A — Windows only, WPF**: simpler, excludes Mac and Linux.
- **B — .NET 10 + Avalonia, CLI first**: one codebase for the three systems; free Windows signing through SignPath Foundation; macOS not notarized.
- **C — Electron/Tauri**: cross-platform, but a stack different from the author's and less direct network/system access.

## Decision
**B**, because it covers the three systems with the author's main stack and at no cost.

## Consequences
- ✅ A single codebase, self-contained single-file executables for 6 platforms via GitHub Actions; free provenance attestation and SHA-256.
- ⚠️ macOS: without notarization (Apple account €99/year) Gatekeeper blocks the first launch → "right-click → Open" instructions; Bluetooth on macOS requires a native binding (can be deferred).
- 🔍 SignPath approval times; antivirus false positives to be reported to the vendors.
