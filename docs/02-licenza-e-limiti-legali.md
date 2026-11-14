# 02 — Licenza, attribuzione e limiti legali

## 1. Paternità: vale per legge
Art. 20 L. 633/1941: l'autore *«conserva il diritto di rivendicare la paternità dell'opera»* anche dopo la cessione dei diritti economici. È un diritto morale che non si può cedere. Il software è protetto come opera (art. 2, n. 8).
Fonte: https://www.normattiva.it/uri-res/N2Ls?urn:nir:stato:legge:1941;633~art20.

## 2. Perché AGPL-3.0 e non Apache 2.0
| | Apache 2.0 | AGPL-3.0 + 7(b) |
|---|---|---|
| Intestazioni nei sorgenti | da conservare (art. 4c) | da conservare |
| Nome visibile nel programma | **no**: basta il file NOTICE | **sì**: la sezione 7(b) permette di imporre la conservazione delle attribuzioni negli avvisi mostrati all'utente |
| Versione chiusa rivenduta da altri | possibile | vietata: chi distribuisce, o offre il programma in rete, deve pubblicare il codice |
| Uso da parte di chi lo esegue soltanto | nessun obbligo | nessun obbligo (nessuna licenza può imporlo) |

## 3. File `NOTICE` e termini aggiuntivi
Il testo in vigore è nel file [`NOTICE`](../NOTICE). Bozza di partenza:
```
Scudo Digitale
Copyright (C) 2026 Gaetano Cardinale — https://gcardinale.it

Questo programma è software libero: puoi ridistribuirlo e/o modificarlo
secondo i termini della GNU Affero General Public License versione 3
o successiva, con i seguenti TERMINI AGGIUNTIVI ai sensi della sezione 7:

7(b) Chiunque distribuisca, o renda disponibile in rete, questo programma
     o un'opera basata su di esso deve conservare, in forma leggibile:
     a) l'avviso «Scudo Digitale — © Gaetano Cardinale — https://gcardinale.it»
        nella schermata "Informazioni", nel banner di avvio della riga di comando
        e nel piè di pagina di ogni report generato;
     b) le intestazioni di copyright presenti in ogni file sorgente.
7(c) Le versioni modificate devono essere contrassegnate come diverse
     dall'originale e non presentarsi come la versione ufficiale.
7(e) La licenza non concede diritti sul nome "Scudo Digitale" né su
     eventuali marchi o loghi del progetto.
```
⚠️ Il testo si basa sulla sezione 7 della GPLv3/AGPLv3. Prima della pubblicazione: rilettura legale e confronto con la formulazione ufficiale FSF.

## 4. Intestazione ASCII di ogni file sorgente
Il testo esatto è in [`build/header.txt`](../build/header.txt); quella qui sotto è indicativa.
```
// ╔══════════════════════════════════════════════════════════════╗
// ║   ███████╗ ██████╗██╗   ██╗██████╗  ██████╗                  ║
// ║   ██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗                 ║
// ║   ███████╗██║     ██║   ██║██║  ██║██║   ██║                 ║
// ║   ╚════██║██║     ██║   ██║██║  ██║██║   ██║                 ║
// ║   ███████║╚██████╗╚██████╔╝██████╔╝╚██████╔╝  DIGITALE        ║
// ║   ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝                  ║
// ║   Verifica sicurezza: rete, Wi-Fi, siti, posta, Bluetooth,    ║
// ║   GDPR e NIS2.  © 2026 Gaetano Cardinale — gcardinale.it      ║
// ╠══════════════════════════════════════════════════════════════╣
// ║ SPDX-License-Identifier: AGPL-3.0-or-later                    ║
// ║ Attribuzione obbligatoria (AGPL sez. 7(b)): vedi NOTICE       ║
// ╚══════════════════════════════════════════════════════════════╝
```
Controllo automatico in CI: la build fallisce se un file `.cs` non ha l'intestazione.

## 5. Limiti legali dei controlli
- **Rischio:** scansioni attive su sistemi altrui possono configurare l'accesso abusivo (art. 615-ter c.p.) o reati vicini (artt. 615-quater/quinquies c.p.). Da verificare sulle fonti ufficiali prima della v0.1.
- **Passivi (consentiti su qualunque bersaglio):** lettura di DNS pubblico, handshake TLS, header e cookie di una normale visita, blacklist pubbliche.
- **Attivi (solo perimetro proprio):** rete locale del PC; domini con proprietà verificata; dichiarazione dell'esecutore (titolare / responsabile sicurezza) registrata nel report.
- **Mai:** login, bruteforce, sfruttamento, deauth Wi-Fi, pairing forzato Bluetooth.
- **Avvertenza** al primo avvio e nel report: autovalutazione, possibili falsi positivi e negativi, nessuna garanzia (AGPL sezioni 15-16), non sostituisce penetration test né parere legale.

## 6. Marchio
- «Scudo Digitale»: nessun prodotto omonimo trovato (ricerca del 14/11/2026). Prima di registrarlo: ricerca UIBM + EUIPO, classi 9 e 42.
- «Antares Program Technology»: **non usare** senza verifica, rischio di conflitto con Antares Audio Technologies (software).
