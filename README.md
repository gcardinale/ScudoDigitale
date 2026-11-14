<p align="center"><strong>🛡️ SCUDO DIGITALE</strong><br>
Verifica gratuita della tua sicurezza: rete, Wi-Fi, siti, posta, Bluetooth, GDPR e NIS2</p>

<p align="center">
<a href="LICENSE"><img alt="Licenza AGPL-3.0" src="https://img.shields.io/badge/licenza-AGPL--3.0%20%2B%207(b)-blue"></a>
<img alt="Piattaforme" src="https://img.shields.io/badge/piattaforme-Windows%20%7C%20macOS%20%7C%20Linux-informational">
<img alt="Stato" src="https://img.shields.io/badge/stato-in%20sviluppo-orange">
</p>

> **Scudo Digitale** è un programma **gratuito e open source** che il titolare o il responsabile della sicurezza esegue **sul proprio PC** per verificare i propri sistemi. Produce un **report diviso per area e ordinato per severità**, con **CVE**, probabilità di sfruttamento e **correzione da fare**.
> **Tutto resta sul tuo computer**: niente cloud, niente telemetria, nessun dato inviato all'autore.

## Cosa verifica
| Area | Esempi di controlli |
|---|---|
| 🌐 **Rete locale** | dispositivi presenti, porte e servizi esposti (Telnet, SMBv1, RDP, UPnP), versioni con CVE note |
| 📶 **Wi-Fi** | protocollo (WEP/WPA/WPA2/WPA3), WPS attivo, reti aperte |
| 🖥️ **Siti web** | certificato e TLS, header di sicurezza, cookie, CMS obsoleti, cookie prima del consenso |
| ✉️ **Posta** | SPF, DKIM, DMARC, MTA-STS, DNSSEC, STARTTLS, blacklist |
| 🔵 **Bluetooth** | dispositivi visibili e rilevabili, chipset con vulnerabilità note |
| ⚖️ **GDPR** | autovalutazione guidata per **privati** e **società** |
| 🇪🇺 **NIS2** | sei dentro il D.Lgs. 138/2024? Quali obblighi ti mancano? |

Ogni problema nel report riporta: **severità**, **CVE e punteggio CVSS**, **EPSS** (probabilità di sfruttamento), il marchio **«sfruttata attivamente»** (catalogo CISA KEV), **confidenza** del rilevamento e **come correggere**.

## Uso responsabile
- Sui **siti e domini di terzi** Scudo Digitale esegue solo **controlli passivi**: legge le informazioni pubbliche che chiunque vede visitando il sito o interrogando il DNS.
- I **controlli attivi** (scansione porte, file esposti) funzionano solo sulla **tua rete locale** o su **domini di cui dimostri la proprietà**.
- Non tenta mai login, non sfrutta vulnerabilità, non attacca reti Wi-Fi o dispositivi Bluetooth.
- È uno strumento di **autovalutazione**: non sostituisce un penetration test professionale né un parere legale. Possono esserci falsi positivi e falsi negativi.

## Download
In arrivo nelle [Releases](https://github.com/gcardinale/ScudoDigitale/releases) per Windows, macOS e Linux, con hash SHA-256 e attestazione di provenienza della build.

## Stato del progetto
In sviluppo. Vedi la [roadmap](docs/03-roadmap.md) e la [specifica](docs/00-specifica-funzionale.md).

## Compilare dal sorgente
Servono .NET SDK 10 o successivo.
```bash
git clone https://github.com/gcardinale/ScudoDigitale.git
cd ScudoDigitale
dotnet build
dotnet test
```

## Licenza e attribuzione
© 2026 **Gaetano Cardinale** — [gcardinale.it](https://gcardinale.it)

Distribuito con licenza **GNU AGPL-3.0-or-later** con termini aggiuntivi (sezione 7) descritti nel file [NOTICE](NOTICE): chi ridistribuisce o modifica il programma **deve mantenere visibile l'attribuzione all'autore** nell'interfaccia e nei report, e non può presentare versioni modificate come quella ufficiale.

## Segnalare una vulnerabilità
Vedi [SECURITY.md](SECURITY.md).

---
<sub>English: <b>Scudo Digitale</b> ("Digital Shield") is a free, open-source, offline security self-assessment tool for local networks, Wi-Fi, websites, email domains and Bluetooth, with GDPR and NIS2 (EU Directive 2022/2555) checklists. Reports are grouped by area and ordered by severity, with CVE, EPSS and CISA KEV data. Licensed under AGPL-3.0-or-later with attribution terms (see NOTICE).</sub>
