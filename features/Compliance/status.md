# Compliance — status

- **Content:** GDPR and NIS2 questionnaires
- **Release:** v0.1
- **Status:** ⚪ not started (empty project and test project created in v0.0)
- **Test coverage:** —

## Done
- (nothing)

## To do
- see `docs/00-functional-spec.md` and `docs/03-roadmap.md`
- per ADR-005: `Evaluate(questionnaire, answers, profile, technicalFindings)` returns ordinary `Finding`s; it is not an `ICheck`. Open point: how technical findings are linked to articles (by area, or listed in the questionnaire JSON)
- remove `<ModuleNotStarted>true</ModuleNotStarted>` from the test project together with the first test
