# 03 — Roadmap (accelerata)

> Obiettivo: **v1.0 pubblica in circa 3 settimane** invece di 3 mesi.
> Come: si fissano subito i contratti in `ScudoDigitale.Core`, poi i moduli si sviluppano **in parallelo** (un worktree per modulo) e si rimanda alla v1.1 tutto ciò che non serve al primo rilascio.

## Piano giorno per giorno (giorni di lavoro effettivo)
| Giorni | Rilascio | Contenuto | In parallelo | Fatto quando |
|---|---|---|---|---|
| **1** | **v0.0 — scheletro** | soluzione, progetti vuoti, `Core` con `ICheck`, `Finding`, `Severity`, `Confidence`, `Profile`, `ScopeDeclaration`, `IScopeGuard`, `Attribution`; `build/check-headers.ps1`; GitHub Actions (build + test + copertura su Windows/Linux/macOS) | — | CI verde sui 3 sistemi, contratti `Core` testati al 100% |
| **2-4** | **v0.1 — passivo** | `Checks.Email`, `Checks.Web` (passivo + GDPR indicativo), `Compliance` (GDPR/NIS2 in JSON), `Reporting` (HTML/PDF/JSON), `Cli` | 4 worktree: Email · Web · Compliance · Reporting; verifica legale dei riferimenti in sessione separata | report completo su un dominio reale e su un dominio di test, copertura >90% |
| **5-8** | **v0.2 — rete e CVE** | `Vulnerabilities` (NVD/KEV/EPSS/OSV in SQLite), `Checks.Network`, prova di proprietà dei domini + controlli web attivi, `App` Avalonia minima (procedura guidata + apertura report) | 3 worktree: Vulnerabilities · Network · App | scansione LAN reale con almeno una CVE collegata e confidenza corretta |
| **9-11** | **v0.3 — senza fili** | `Checks.Wireless`: Wi-Fi (3 sistemi) e Bluetooth (Windows + Linux) | 2 worktree: Wi-Fi · Bluetooth | dispositivi BT e reti Wi-Fi di prova classificati correttamente |
| **12-14** | **v1.0 — pubblica** | revisione di sicurezza e del codice, eseguibili single-file per 6 piattaforme, SHA-256 + attestazione di provenienza, README finale, richiesta di firma a SignPath Foundation | — | release su GitHub scaricabile, pagina download pubblicata |

La firma SignPath arriva dopo l'approvazione della Foundation (tempi esterni): la v1.0 esce **con attestazione e hash**, la firma si aggiunge in una v1.0.x.

## Tre scenari
| Scenario | v0.1 | v1.0 |
|---|---|---|
| Ottimistico | giorno 3 | 2 settimane |
| Realistico | giorno 4-5 | 3 settimane |
| Pessimistico | giorno 7 | 5 settimane (Bluetooth e database CVE più lenti) |

## Cosa si rimanda alla v1.1 se si è in ritardo
In quest'ordine: Bluetooth su macOS → confronto tra due report → Have I Been Pwned → pacchetti Flatpak/Homebrew → interfaccia Avalonia completa (resta la procedura guidata minima).

## Checklist
- [x] Nome, licenza, piattaforme, perimetro decisi (14/11/2026)
- [x] Repository creato con documentazione, ADR, LICENSE, NOTICE (14/11/2026)
- [ ] v0.0 scheletro + CI
- [ ] v0.1 passivo
- [ ] v0.2 rete e CVE
- [ ] v0.3 senza fili
- [ ] v1.0 pubblica
