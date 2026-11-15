# Reporting — status

- **Content:** HTML, PDF, JSON, comparison
- **Release:** v0.1
- **Status:** ⚪ not started (empty project and test project created in v0.0)
- **Test coverage:** —

## Done
- (nothing)

## To do
- see `docs/00-functional-spec.md` and `docs/03-roadmap.md`
- per ADR-005: the JSON report is a DTO owned by Reporting, with `schemaVersion`, enums as strings, and a round-trip test (write, read back, compare); prioritize with `FindingPrioritizer` (returns `PrioritizedFinding`); name checks with `CheckRun.CheckTitle`
- remove `<ModuleNotStarted>true</ModuleNotStarted>` from the test project together with the first test
