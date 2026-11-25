# Compliance — status

- **Content:** GDPR and NIS2 questionnaires
- **Release:** v0.1
- **Status:** 🟢 implemented (25/11/2026), branch `feature/v0.1-compliance`; legal review of the texts to do before the beta
- **Test coverage:** 100% lines (326/326), 98.5% branches (193/196) — 75 tests

## Done
- [ADR-008](../../docs/decisions/ADR-008-questionnaires-in-json.md): questionnaires in versioned JSON with texts in English and Italian, answers in the terminal or in a file, technical findings linked to art. 32 by area.
- `Questionnaires/*.json`, embedded, version `2026-11-25`:
  - `gdpr-individual`: 5 good practices (backup, passwords, two-factor authentication, updates, shared devices); the notice says the GDPR does not apply to purely personal activities (art. 2(2)(c));
  - `gdpr-company`: records (art. 30), notices (arts. 13-14), processors (art. 28), security measures (art. 32), breaches (arts. 33-34), DPIA (art. 35), DPO (art. 37), plus `GDPR-ART32-002`, answered by the technical findings of Medium severity or above;
  - `nis2`: 5 scope questions (sector of Annexes I-II, categories in scope whatever their size, employees, turnover, balance sheet total) and 5 obligations asked only when the company is not probably out of scope (registration art. 7, management bodies art. 23, measures and supply chain art. 24, incident notification art. 25).
- `QuestionnaireCatalog`: loads and validates every questionnaire (both languages for every text, ids in the `AREA-TOPIC-NNN` form and unique, finding texts and severity for yes/no questions, at least two unique options for a choice, no unknown property).
- `QuestionnaireEvaluator.Evaluate`: "no" → finding marked certain; "don't know" or no answer → the same finding "to be verified"; "yes" or an allowed "not applicable" → question without problems. NIS2 adds `NIS2-SCOPE-001` (Info) with the outcome and the answers it comes from.
- `Nis2Scope.Assess`: size per Recommendation 2003/361/CE (headcount, turnover **and** balance sheet total) as arts. 3 and 6 of D.Lgs. 138/2024 require; "out of scope" only with a clear "no" to the categories in scope whatever their size.
- `AnswersFile`: reads `{ "id": "answer" }` and lists unknown ids and answers a question does not accept, so a typo never becomes a silent "don't know".
- Counter-checks run on 25/11/2026: obligations asked when out of scope, "not applicable" accepted where not allowed, NIS2 obligations prompted when out of scope (CLI): each turned a test red.

## Legal references
- Verified on Normattiva on 25/11/2026 (text in force since 16/10/2024): D.Lgs. 138/2024 arts. 3, 6, 7, 23, 24, 25.
- Sectors of Annexes I-II read on the Gazzetta Ufficiale; the HTML page of Annex I shows the heading of the draft decree: to be checked on the PDF of GU n. 230 of 1/10/2024.
- To verify before the beta: GDPR articles on EUR-Lex; the claims about the Garante (template of the record, list of processings that require a DPIA).

## To do
- Legal review of all texts (27/11/2026).
- Questionnaires loaded from a user folder, with the same validation (after the beta).
- Annex III (public administrations) and linked enterprises: today they come out as "to be verified".
