# ADR-001 — Why Scudo Digitale exists
> **Status:** accepted · **Decision maker:** Gaetano Cardinale · **Date:** 2026-11-14

## Context
Attacks on public bodies, SMEs and individuals are constant, but the most common problems are basic: email without DMARC, outdated TLS, services exposed on the local network, devices not updated. Existing tools are online (data leaves the PC), paid, or too technical and unconnected to GDPR and NIS2 obligations.

## Options considered
- **A — Online service**: convenient, but the data of the checked systems passes through a third-party server and it cannot see the local network.
- **B — Guide/checklist**: zero development, but no technical evidence.
- **C — Free, open-source local program**: sees the local network, Wi-Fi and Bluetooth, sends no data, the code is verifiable.

## Decision
**C**, because it is the only option that also checks the local network without data leaving the computer, and open code makes a security tool credible.

## Consequences
- ✅ Trust (inspectable code, no telemetry), coverage of local network/Wi-Fi/Bluetooth.
- ⚠️ Cross-platform distribution and executable signing are the project's responsibility.
- 🔍 The CVE database and the regulatory questionnaires must be kept up to date over time.
