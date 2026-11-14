# ADR-001 — Perché esiste Scudo Digitale
> **Stato:** accettata · **Decisore:** Gaetano Cardinale · **Data:** 2026-11-14

## Contesto
Gli attacchi a enti pubblici, PMI e privati sono continui, ma i problemi più comuni sono di base: posta senza DMARC, TLS vecchio, servizi esposti in rete locale, dispositivi non aggiornati. Gli strumenti esistenti sono online (i dati escono dal PC), a pagamento, oppure troppo tecnici e senza collegamento con gli obblighi GDPR e NIS2.

## Opzioni considerate
- **A — Servizio online**: comodo, ma i dati dei sistemi verificati passano da un server terzo e non può vedere la rete locale.
- **B — Guida/checklist**: zero sviluppo, ma nessuna prova tecnica.
- **C — Programma locale gratuito e open source**: vede rete locale, Wi-Fi e Bluetooth, non invia dati, il codice è verificabile.

## Decisione
**C**, perché è l'unica che verifica anche la rete locale senza che i dati escano dal computer, e un codice aperto rende credibile uno strumento di sicurezza.

## Conseguenze
- ✅ Fiducia (codice ispezionabile, niente telemetria), copertura di rete locale/Wi-Fi/Bluetooth.
- ⚠️ Distribuzione multipiattaforma e firma degli eseguibili a carico del progetto.
- 🔍 Aggiornamento del database CVE e dei questionari normativi nel tempo.
