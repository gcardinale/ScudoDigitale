# ADR-004 — Controlli passivi ovunque, attivi solo sul perimetro proprio
> **Stato:** accettata · **Decisore:** Gaetano Cardinale · **Data:** 2026-11-14

## Contesto
L'utente può indicare qualunque sito o dominio. Scansioni attive su sistemi altrui possono configurare reati (art. 615-ter c.p. e seguenti) ed espongono utente e autore.

## Opzioni considerate
- **A — Tutto attivo su qualunque bersaglio**: più risultati, rischio legale inaccettabile.
- **B — Solo passivo**: sicuro, ma inutile sulla rete locale.
- **C — Passivo su qualunque bersaglio; attivo solo su rete locale del PC e domini con proprietà verificata, con dichiarazione dell'esecutore nel report.**

## Decisione
**C**, perché dà al titolare tutto ciò che gli serve sui propri sistemi senza mai toccare attivamente quelli altrui.

## Conseguenze
- ✅ `IScopeGuard` obbligatorio per ogni controllo `ActiveOwnedOnly`; la dichiarazione di perimetro (chi, ruolo, cosa) è stampata nel report.
- ⚠️ Per i controlli attivi su un dominio serve un passaggio in più (record TXT o file `.well-known`).
- 🔍 Nessun controllo può tentare login, bruteforce, exploit, deauth o pairing forzato: regola verificata in code review.
