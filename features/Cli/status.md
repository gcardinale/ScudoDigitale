# Cli — status

- **Content:** scan, db update, report commands
- **Release:** v0.1
- **Status:** 🟡 `scan --mail` (19/11/2026) and `scan --web` (21/11/2026, branch `feature/v0.1-web`) working; report files, `db update`, `report diff` to do
- **Test coverage:** 100% lines (217/217), 100% branches (63/63) — 36 tests

## Done
- `scudo` executable (System.CommandLine 3): without arguments prints the banner, the attribution and the self-assessment warning in English or Italian; `--help`, `--version`.
- `scudo scan [--mail <domain> …] [--web <domain> …] [--dkim-selector <s> …] [--system-dns] [--operator <name>] [--role Owner|SecurityOfficer|AppointedPerson]`:
  - `--mail` declares a target of kind `Domain` for the 11 email checks, `--web` a target of kind `Website` for the 15 website checks; the two can be given together, also for the same domain, and each area runs only on its own targets;
  - `--web` accepts a domain name or an `http`/`https` URL (only the host is used); the same site given twice is checked once;
  - prints banner, warning and the scope declaration (operator, role, date; operator defaults to the user name of the computer), then what is about to be checked with the number of checks for each target;
  - `--system-dns` applies to both areas; when the computer reaches a site through a proxy, a note before the results says so and warns that a proxy inspecting encrypted traffic shows its own certificate;
  - runs the checks through `CheckEngine`, with a scope guard that refuses every active check until ownership can be proven (v0.2);
  - for every target a section named after its area (Email, Websites): problems most urgent first (`FindingPrioritizer`) with evidence, risk, fix, confidence and references; then checks passed, skipped (with the reason) and failed (with the error); summary by severity; attribution last;
  - exit code 0 when the checks ran (whatever they found), 1 for a wrong command line, 2 when there is nothing to check, a selector is not valid or a website is not valid.
- Commands receive the checks, the clock and the user name through `CliServices`, so tests run with no network.

## To do
- HTML/PDF/JSON report files when `Reporting` exists.
- Profile options (individual / company) when Compliance needs them.
- `db update`, `report diff` (v0.2+).
