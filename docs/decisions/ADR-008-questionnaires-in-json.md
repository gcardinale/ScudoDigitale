# ADR-008 — GDPR and NIS2 questionnaires: texts in versioned JSON, answers in the terminal or in a file
> **Status:** accepted · **Decision maker:** Gaetano Cardinale · **Date:** 2026-11-25

## Context
ADR-005 decided that the questionnaires are evaluated by `Compliance` and give ordinary `Finding`s. Three things were still open for v0.1:

1. **Where the texts live.** The architecture says the questionnaires are "defined in versioned JSON (updatable without recompiling)". The coding rules say that user-facing strings go through `.resx` files in English and Italian. A question, its finding, its risk, its fix and its legal references belong together: split across a JSON (structure) and two `.resx` (texts), each question would live in three files, and the legal review would have to read all three.
2. **How the answers are given.** v0.1 has only the command line; the Avalonia interface comes in v0.2.
3. **How the technical findings are linked to the articles** (open point of ADR-005).

## Options considered
### 1. Texts
- **A — Structure in JSON, texts in `.resx`**: follows the rule as written, but three files per question and keys that must stay in step by hand.
- **B — One JSON per questionnaire with the texts in both languages** (`{"en": "…", "it": "…"}`): a question is read and reviewed in one place; a test refuses a questionnaire with a missing language, a bad id or a duplicate. The `.resx` rule stays for the labels of the program (answers, scope outcomes).

### 2. Answers
- **A — Interactive only**: simple, but a run cannot be repeated and a test needs a fake terminal.
- **B — Interactive, or a JSON file of answers (`--answers`)**: the same file gives the same result, and the tests use it.

### 3. Link to the technical findings
- **A — Listed per question in the JSON**: precise, but every new check would mean editing a questionnaire.
- **B — By area**: the company GDPR questionnaire turns every technical finding of Medium severity or above (email, websites, later network) into one art. 32 finding that lists them.

## Decision
**1B, 2B, 3B.**
- The questionnaires are JSON files embedded in `ScudoDigitale.Compliance` (`Questionnaires/*.json`), each with an `id` and a `version`, texts in English and Italian. Loading them from a folder of the user ("updatable without recompiling") is deferred: in v0.1 a new version comes with a new release.
- Answers: `yes`, `no`, `unknown`, `notApplicable` (only where the question allows it), or the id of an option. "No" gives a finding marked certain; "unknown" or no answer gives the same finding marked "to be verified", so that nothing unanswered looks fine.
- NIS2: the scope is assessed first (sector of Annexes I-II, size per Recommendation 2003/361/CE: employees, turnover **and** balance sheet total, as art. 3 and 6 of D.Lgs. 138/2024 require), with the outcome "probably essential / probably important / probably out of scope / to be verified". The obligations are asked only when the outcome is not "out of scope".
- Every finding of a questionnaire is indicative: the report says so, and the legal references are verified on Normattiva and the Gazzetta Ufficiale before the beta (spec §2.7).

## Consequences
- ✅ A question is reviewed in one file, by a lawyer too.
- ✅ A run with `--answers` is repeatable; the tests need no terminal.
- ⚠️ The texts of the questionnaires are an exception to the `.resx` rule, written here; a test checks that both languages are present for every text.
- ⚠️ The NIS2 scope is an estimate: group companies (linked and partner enterprises), the entities identified by ACN regardless of size (art. 3, paragraphs 8-10) and public administrations (Annex III) come out as "to be verified", never as "out of scope" with certainty.
- 🔍 To do after the beta: questionnaires loaded from a user folder, with the same validation.
