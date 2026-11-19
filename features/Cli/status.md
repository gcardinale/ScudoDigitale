# Cli — status

- **Content:** scan, db update, report commands
- **Release:** v0.1
- **Status:** 🟡 `scan --mail` working (19/11/2026, branch `feature/v0.1-cli-scan`); `--web`, report files, `db update`, `report diff` to do
- **Test coverage:** 100% lines (156/156), 100% branches (41/41) — 23 tests, 16 of 16 counter-checks caught

## Done
- `scudo` executable (System.CommandLine 3): without arguments prints the banner, the attribution and the self-assessment warning in English or Italian; `--help`, `--version`.
- `scudo scan --mail <domain> [--mail …] [--dkim-selector <s> …] [--system-dns] [--operator <name>] [--role Owner|SecurityOfficer|AppointedPerson]`:
  - prints banner, warning and the scope declaration (operator, role, date; operator defaults to the user name of the computer);
  - runs the 11 email checks through `CheckEngine`, with a scope guard that refuses every active check until ownership can be proven (v0.2);
  - for every domain: problems most urgent first (`FindingPrioritizer`) with evidence, risk, fix, confidence and references; then checks passed, skipped (with the reason) and failed (with the error); summary by severity; attribution last;
  - exit code 0 when the checks ran (whatever they found), 1 for a wrong command line, 2 when there is no domain or a selector is not valid.
- Commands receive the checks, the clock and the user name through `CliServices`, so tests run with no network.

## To do
- `--web` when `Checks.Web` exists; HTML/PDF/JSON report files when `Reporting` exists.
- Profile options (individual / company) when Compliance needs them.
- `db update`, `report diff` (v0.2+).
