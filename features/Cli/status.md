# Cli — status

- **Content:** scan, db update, report commands
- **Release:** v0.1
- **Status:** 🟡 skeleton (v0.0, 15/11/2026)
- **Test coverage:** 100% lines (15/15); no branches yet — 5 tests

## Done
- `scudo` executable (System.CommandLine 3): without arguments prints the banner, the attribution and the self-assessment warning in English or Italian; `--help`, `--version`.

## To do
- `scan`, `db update`, `report diff` — v0.1 onwards (see `docs/00-functional-spec.md`).
- Remove `<CoverageThresholdTypes>line</CoverageThresholdTypes>` from `tests/ScudoDigitale.Cli.Tests` as soon as `CliApp` has its first branch: with no branches coverlet reports 0% and the branch gate cannot pass.
