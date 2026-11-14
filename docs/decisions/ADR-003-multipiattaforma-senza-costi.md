# ADR-003 — Multipiattaforma senza costi ricorrenti
> **Stato:** accettata · **Decisore:** Gaetano Cardinale · **Data:** 2026-11-14

## Contesto
Lo strumento deve girare su Windows, macOS e Linux ed essere regalato: niente spese ricorrenti per firma o distribuzione.

## Opzioni considerate
- **A — Solo Windows, WPF**: più semplice, esclude Mac e Linux.
- **B — .NET 10 + Avalonia, CLI prima**: un solo codice per i tre sistemi; firma Windows gratuita tramite SignPath Foundation; macOS non notarizzato.
- **C — Electron/Tauri**: multipiattaforma, ma stack diverso da quello dell'autore e accesso di rete/sistema meno diretto.

## Decisione
**B**, perché copre i tre sistemi con lo stack principale dell'autore e senza costi.

## Conseguenze
- ✅ Un unico codice, eseguibili single-file self-contained per 6 piattaforme via GitHub Actions; attestazione di provenienza e SHA-256 gratuiti.
- ⚠️ macOS: senza notarizzazione (account Apple €99/anno) Gatekeeper blocca il primo avvio → istruzioni «tasto destro → Apri»; Bluetooth su macOS richiede binding nativo (rimandabile).
- 🔍 Tempi di approvazione SignPath; falsi positivi antivirus da segnalare ai produttori.
