# ADR-002 — Licenza AGPL-3.0 con attribuzione obbligatoria
> **Stato:** accettata · **Decisore:** Gaetano Cardinale · **Data:** 2026-11-14

## Contesto
Il programma è gratuito, ma l'autore vuole che il suo nome resti visibile in ogni copia e che nessuno lo rivenda chiuso con un altro nome.

## Opzioni considerate
- **A — Apache-2.0**: massima diffusione; obbliga solo a conservare `NOTICE` e intestazioni nei sorgenti, non a mostrare l'autore nel programma; permette versioni chiuse.
- **B — MIT**: come A, con obblighi ancora minori.
- **C — AGPL-3.0-or-later + termini aggiuntivi della sezione 7**: 7(b) impone di conservare l'attribuzione negli avvisi mostrati all'utente; 7(c) impone di distinguere le versioni modificate; 7(e) esclude i diritti sul nome; il copyleft impedisce versioni chiuse anche se offerte in rete.

## Decisione
**C**, perché è l'unica opzione OSI che rende obbligatoria l'attribuzione visibile nelle copie e impedisce le versioni chiuse.

## Conseguenze
- ✅ Attribuzione visibile garantita (banner CLI, schermata Informazioni, piè di pagina dei report); paternità comunque tutelata dall'art. 20 L. 633/1941.
- ⚠️ Le aziende che vogliono incorporarlo in prodotti chiusi non possono farlo (accettato: non è l'obiettivo).
- 🔍 Il testo dei termini aggiuntivi va confrontato con la formulazione ufficiale FSF prima della v1.0; tutte le dipendenze devono essere compatibili con AGPL.
