# Cli — status

- **Content:** scan, db update, report commands
- **Release:** v0.1
- **Status:** 🟡 `scan --mail` (19/11/2026), `scan --web` (21/11/2026), `scan --report` and the questionnaires (25/11/2026) working; `db update`, `report diff` to do
- **Test coverage:** 100% lines (403/403), 97.4% branches (184/189) — 75 tests

## Done
- `scudo` executable (System.CommandLine 3): without arguments prints the banner, the attribution and the self-assessment warning in English or Italian; `--help`, `--version`.
- Release executables: `dotnet publish src/ScudoDigitale.Cli -c Release -r <rid>` gives one self-contained file (.NET included, not trimmed, compressed), without the .pdb and .xml of the libraries; `.github/workflows/release.yml` builds win-x64, linux-x64, osx-x64 and osx-arm64 on a tag and prepares a draft pre-release with SHA-256 (28/11/2026). win-x64 tried on this PC without .NET on the PATH: report in Italian with `programVersion` 0.1.0-beta.
- `scudo scan [--mail <domain> …] [--web <domain> …] [--dkim-selector <s> …] [--system-dns] [--operator <name>] [--role Owner|SecurityOfficer|AppointedPerson]`:
  - `--mail` declares a target of kind `Domain` for the 11 email checks, `--web` a target of kind `Website` for the 15 website checks; the two can be given together, also for the same domain, and each area runs only on its own targets;
  - `--web` accepts a domain name or an `http`/`https` URL (only the host is used); the same site given twice is checked once;
  - prints banner, warning and the scope declaration (operator, role, date; operator defaults to the user name of the computer), then what is about to be checked with the number of checks for each target;
  - `--system-dns` applies to both areas; when the computer reaches a site through a proxy, a note before the results says so and warns that a proxy inspecting encrypted traffic shows its own certificate;
  - runs the checks through `CheckEngine`, with a scope guard that refuses every active check until ownership can be proven (v0.2);
  - for every target a section named after its area (Email, Websites): problems most urgent first (`FindingPrioritizer`) with evidence, risk, fix, confidence and references; then checks passed, skipped (with the reason) and failed (with the error); summary by severity; attribution last;
  - exit code 0 when the checks ran (whatever they found), 1 for a wrong command line, 2 when there is nothing to check, a selector is not valid or a website is not valid.
- `--report <folder>` (25/11/2026): after the text output writes the report as HTML, PDF and JSON (`Reporting`) and prints the three paths; the proxy notes go into the report too; the version written is the informational version without the commit id (`ProgramVersion`). A blank folder is a wrong option (exit 2, nothing runs); a folder that cannot be written gives exit 3, with the results already on screen.
- Questionnaires (25/11/2026, ADR-008): `--profile Individual|Company`, `--company <name>` (required for a company), `--gdpr`, `--nis2` (companies only), `--answers <file>`. Without a file the questions are asked in the terminal before the checks start (`s`/`y`, `n`, `?`, `na` where allowed; choices by number); the NIS2 obligations only when the company is not probably out of scope; when the input ends the rest counts as "don't know". A file with unknown ids or answers not accepted is refused with the list (exit 2). A questionnaire-only assessment needs no target. The art. 32 question gets the findings of the checks that were executed (`TechnicalEvidence.Of`), and is left out when none was. Any error while writing the report (also from the template or the PDF library) gives exit 3, never a crash. The questionnaires get a section in the text output and in the report, and their notice goes into the notes of the report.
- Commands receive the checks, the clock and the user name through `CliServices`, so tests run with no network.

## To do
- `db update`, `report diff` (v0.2+).
