# Compliance — status

- **Content:** GDPR and NIS2 questionnaires
- **Release:** v0.1
- **Status:** 🟢 implemented (25/11/2026), branch `feature/v0.1-compliance`; legal review of the texts done on 27/11/2026
- **Test coverage:** 100% lines (341/341), 98.5% branches (195/198) — 78 tests

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
- Independent review on 25/11/2026 (separate agent, 34 counter-checks), fixed the same day:
  - art. 32 was "fine" when every technical check had been skipped or failed: now `TechnicalEvidence.Of(runs)` keeps only executed checks, and the question says which areas it covers;
  - the messages of `AnswersFile` were in English only: now in English and Italian, with line and position for a JSON error;
  - NIS2: turnover and balance sheet are now asked with linked and partner enterprises added, as the headcount already was (art. 3, paragraph 4); notice and ADR-008 aligned.
- Counter-checks run on 25/11/2026: obligations asked when out of scope, "not applicable" accepted where not allowed, NIS2 obligations prompted when out of scope (CLI): each turned a test red.

## Legal references
- Verified on Normattiva on 25/11/2026 and again on 27/11/2026 (text in force since 16/10/2024): D.Lgs. 138/2024 arts. 3, 6, 7, 23, 24, 25.
- Annexes I-II read on the PDF of GU n. 230 of 1/10/2024 (27/11/2026): the published PDF itself carries the heading «SCHEMA DI DECRETO LEGISLATIVO…» and the title «Settori ad altra criticità», so the HTML page was faithful to the Gazzetta.
- GDPR read on EUR-Lex, Italian text (27/11/2026): arts. 2(2)(c), 13(1), 14(3), 28(3), 30(1) and (5), 32(1), 33(1) and (5), 34(1), 35(1), (3) and (4), 37(1) and (7).
- Garante (27/11/2026): simplified record templates for SMEs (controller and processor) in the FAQ on the record; list of processings that require a DPIA, decision no. 467 of 11/10/2018 (GU n. 269 of 19/11/2018), docweb 9058979, Annex 1 read in full.

## Legal review of 27/11/2026
Questionnaires `gdpr-company` and `nis2` moved to version `2026-11-27`; `gdpr-individual` unchanged. Every statement was checked on the source; no wrong obligation was found, nine texts were made precise:
- `GDPR-ART30-001`: the exemption under 250 employees also falls with data on criminal convictions (art. 10), and the risk is the risk "to the rights and freedoms"; the Garante template is the simplified one for SMEs.
- `GDPR-ART13-001`: when data are not collected from the person, the notice is due within a reasonable time and at the latest within one month (art. 14(3)).
- `GDPR-ART35-001`: the fix names the Garante decision no. 467/2018 and says the list adds to the cases of art. 35(3).
- `GDPR-ART37-001`: data on criminal convictions on a large scale also require a DPO (art. 37(1)(c)).
- `nis2` notice: art. 3, paragraph 10 (enterprises linked to an essential or important entity) is automatic, not identified by ACN; the notice now keeps it apart from paragraphs 8, 9 and 13.
- `NIS2-SECTOR-001`, health: only EU reference laboratories are in Annex I, not every laboratory; added R&D of medicinal products and basic pharmaceutical manufacturers; devices are the ones critical in a public health emergency.
- `NIS2-SECTOR-001`, food: Annex II covers only industrial production and processing and wholesale distribution, so a retailer no longer picks it by mistake; waste: only as the main economic activity.
- `NIS2-SECTOR-001`, digital providers: added domain name registration services (Annex II, point 6).
- `NIS2-ART25-001`: the final report is due one month from the notification, not from the incident (art. 25(5)(d)).

## To do
- Questionnaires loaded from a user folder, with the same validation (after the beta).
- Annex III (public administrations) and linked enterprises: today they come out as "to be verified".
