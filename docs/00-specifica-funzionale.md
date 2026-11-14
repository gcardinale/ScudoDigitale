# 00 — Specifica funzionale

## 1. Flusso d'uso
1. **Avvio** → banner con attribuzione e avvertenza («strumento di autovalutazione, non sostituisce un penetration test né un parere legale»).
2. **Profilo** → *Privato* oppure *Società* (ragione sociale, P.IVA facoltativa, settore ATECO, dipendenti, fatturato). Il profilo decide quali domande GDPR/NIS2 compaiono.
3. **Dichiarazione di perimetro** → chi esegue (nome, ruolo: titolare / responsabile sicurezza / incaricato), cosa verifica (reti, domini, indirizzi email). La dichiarazione finisce nel report.
4. **Scelta delle aree** → si possono eseguire tutte o solo alcune.
5. **Esecuzione** con avanzamento per area; ogni controllo può fallire senza fermare gli altri.
6. **Report** HTML + PDF + JSON (il JSON permette di confrontare due esecuzioni nel tempo).

## 2. Aree e controlli

### 2.1 Posta (passivo, qualunque dominio)
| Controllo | Severità tipica se manca o è errato |
|---|---|
| SPF presente, unico, ≤10 lookup, termina con `-all`/`~all` | Alta |
| DMARC presente; `p=none` / `quarantine` / `reject`; `rua` configurato | Alta (assente) / Media (`none`) |
| DKIM sui selettori comuni (`default`, `selector1/2`, `google`, `k1`, `s1`…) + selettori indicati dall'utente | Media (marcata «da verificare»: i selettori non si possono elencare) |
| MTA-STS + TLS-RPT | Bassa |
| DNSSEC sul dominio | Bassa |
| MX: STARTTLS, versione TLS, certificato valido | Alta se niente TLS |
| Presenza in blacklist DNSBL principali | Alta |
| BIMI | Info |
| Violazioni note dell'indirizzo (Have I Been Pwned) | solo con chiave API dell'utente; altrimenti saltato e scritto nel report |

### 2.2 Siti web
**Passivo (qualunque sito):** certificato (scadenza, catena, nome), protocolli TLS offerti (1.0/1.1 = Alta), cifrari deboli, HSTS, CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie senza `Secure`/`HttpOnly`/`SameSite`, redirect HTTP→HTTPS, CMS e versione dichiarata (generator, file noti) confrontati con le CVE, `security.txt`.
**GDPR indicativo (passivo):** link a informativa privacy e cookie policy, banner cookie presente, cookie di terze parti impostati **prima** del consenso (Alta), risorse caricate da domini extra-UE (Google Fonts, analytics) segnalate come Info/Media.
**Attivo (solo domini verificati, §4 del doc 02):** file esposti (`/.git/`, `/.env`, backup `.zip/.sql`, `phpinfo`), elenco directory, pannelli admin esposti, metodi HTTP pericolosi.

### 2.3 Rete locale (attivo, solo LAN del PC)
- Scoperta dispositivi: tabella ARP, mDNS, SSDP/UPnP, NetBIOS — **senza privilegi**. Modalità avanzata facoltativa con privilegi (ping sweep ICMP).
- Scansione TCP connect delle porte più comuni (top 100 + quelle note per IoT/NAS/stampanti).
- Servizi a rischio: Telnet, FTP in chiaro, SMBv1, RDP esposto, VNC senza password, UPnP IGD che permette port mapping, pannelli web del router con credenziali di fabbrica note (**solo verifica del modello**, mai tentativi di login).
- Banner e versioni → CPE → CVE (con confidenza).
- Esposizione verso internet: IP pubblico e porte inoltrate rilevate via UPnP.

### 2.4 Wi-Fi (passivo, rete a cui si è connessi + reti visibili)
WEP/WPA (Critica), WPA2-TKIP (Alta), WPS attivo (Alta), reti aperte, SSID nascosto come falsa sicurezza (Info). Su Windows `netsh wlan`, su Linux `nmcli`, su macOS `system_profiler`/CoreWLAN.

### 2.5 Bluetooth (passivo)
Dispositivi visibili BLE/classico, stato «rilevabile», produttore (OUI / company ID) e, dove si può dedurre, chipset → vulnerabilità note (BlueBorne, BrakTooth, KNOB, BLURtooth, SweynTooth). Confidenza quasi sempre «probabile»: va scritto chiaramente.

### 2.6 Questionario GDPR (privato e società)
- **Privato:** backup, password manager, 2FA sugli account principali, aggiornamenti automatici, dispositivi condivisi.
- **Società:** registro dei trattamenti (art. 30), informative (artt. 13-14), nomina DPO se obbligatoria (art. 37), nomine dei responsabili (art. 28), procedura data breach (artt. 33-34, 72 ore), valutazione d'impatto (art. 35), misure di sicurezza (art. 32). Le prove tecniche raccolte (TLS, DMARC, cookie) vengono collegate all'art. 32.

### 2.7 Questionario NIS2 (solo società)
- **Ambito:** settore (Allegati I-IV del D.Lgs. 138/2024), dimensione (media impresa: ≥50 dipendenti o >€10 mln di fatturato) → esito *probabilmente essenziale / importante / fuori ambito / da verificare*.
- **Obblighi:** registrazione sulla piattaforma ACN, misure di gestione del rischio, formazione degli organi di amministrazione, notifica incidenti (preallarme 24 h, notifica 72 h, relazione finale entro un mese), sicurezza della catena di fornitura.
- Ogni risposta «no» diventa un problema con riferimento all'articolo.
- ⚠️ Riferimenti normativi da verificare sulle fonti ufficiali (Normattiva, ACN) **prima della v0.1**.

## 3. Formato di un problema
```json
{
  "id": "MAIL-DMARC-001",
  "area": "Posta",
  "titolo": "DMARC in modalità monitoraggio (p=none)",
  "severita": "Media",
  "confidenza": "Certa",
  "bersaglio": "esempio.it",
  "prove": "v=DMARC1; p=none; rua=...",
  "cve": [],
  "cvss": null, "epss": null, "kev": false,
  "rischio": "Chiunque può inviare email a nome del dominio senza che vengano bloccate.",
  "correzione": "Portare la policy a p=quarantine dopo 2-4 settimane di report puliti, poi a p=reject.",
  "riferimenti": ["RFC 7489", "GDPR art. 32", "D.Lgs. 138/2024"]
}
```
**Severità:** Critica / Alta / Media / Bassa / Info. Se c'è un CVSS si parte da lì; **KEV = sale sempre a Critica** e va in cima; EPSS ≥ 0,1 aumenta la priorità di un livello.
**Confidenza:** Certa / Probabile / Da verificare.

## 4. Report
- **Intestazione:** profilo, dichiarazione di perimetro, data e ora, versione del programma e del database CVE.
- **Sintesi:** conteggio per severità e per area + i 5 interventi più urgenti.
- **Sezioni per area** (Rete, Wi-Fi, Siti, Posta, Bluetooth, GDPR, NIS2), dentro ognuna ordine Critica → Info, poi per EPSS.
- **Piè di pagina su ogni pagina:** «Report generato con Scudo Digitale vX.Y — © Gaetano Cardinale — https://gcardinale.it — Licenza AGPL-3.0».
- **Formati:** HTML (unico file, niente risorse esterne), PDF, JSON.
- **Confronto:** se si fornisce un JSON precedente, mostra cosa è stato risolto, cosa è nuovo e cosa resta.

## 5. Fuori perimetro (dichiarato)
Sfruttamento delle vulnerabilità, tentativi di login o bruteforce, scansioni attive di siti non propri, attacchi Wi-Fi/Bluetooth (deauth, pairing forzato), invio di dati a server di Scudo Digitale.
