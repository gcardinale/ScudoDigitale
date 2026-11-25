# 00 — Functional specification

## 1. Usage flow
1. **Start** → banner with attribution and a warning ("self-assessment tool, does not replace a penetration test or legal advice").
2. **Profile** → *Individual* or *Company* (company name, VAT number optional, ATECO sector code, employees, turnover). The profile decides which GDPR/NIS2 questions appear.
3. **Scope declaration** → who is running it (name, role: owner / security officer / appointed person), what is being checked (networks, domains, email addresses). The declaration ends up in the report.
4. **Area selection** → all areas or only some can be run.
5. **Execution** with progress per area; any check can fail without stopping the others.
6. **Report** HTML + PDF + JSON (the JSON allows comparing two runs over time).

## 2. Areas and checks

### 2.1 Email (passive, any domain)
| Check | Typical severity if missing or wrong |
|---|---|
| SPF present, unique, ≤10 lookups, ends with `-all`/`~all` | High |
| DMARC present; `p=none` / `quarantine` / `reject`; `rua` configured | High (missing) / Medium (`none`) |
| DKIM on common selectors (`default`, `selector1/2`, `google`, `k1`, `s1`…) + selectors supplied by the user | Medium (marked "to be verified": selectors cannot be enumerated) |
| MTA-STS + TLS-RPT | Low |
| DNSSEC on the domain | Low |
| MX: STARTTLS, TLS version, valid certificate | High if no TLS |
| Listed on the main DNSBL blacklists | High |
| BIMI | Info |
| Known breaches of the address (Have I Been Pwned) | only with the user's API key; otherwise skipped and stated in the report |

### 2.2 Websites
**Passive (any site):** certificate (expiry, chain, name), TLS protocols offered (1.0/1.1 = High), weak ciphers, HSTS, CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookies without `Secure`/`HttpOnly`/`SameSite`, HTTP→HTTPS redirect, CMS and declared version (generator, known files) matched against CVEs, `security.txt`.
**Indicative GDPR (passive):** links to the privacy notice and cookie policy, cookie banner present, third-party cookies set **before** consent (High), resources loaded from non-EU domains (Google Fonts, analytics) flagged as Info/Medium.
**Active (verified domains only, §5 of doc 02):** exposed files (`/.git/`, `/.env`, `.zip/.sql` backups, `phpinfo`), directory listing, exposed admin panels, dangerous HTTP methods.

### 2.3 Local network (active, the PC's LAN only)
- Device discovery: ARP table, mDNS, SSDP/UPnP, NetBIOS — **without privileges**. Optional advanced mode with privileges (ICMP ping sweep).
- TCP connect scan of the most common ports (top 100 + those known for IoT/NAS/printers).
- Risky services: Telnet, cleartext FTP, SMBv1, exposed RDP, VNC without password, UPnP IGD allowing port mapping, router web panels with known factory credentials (**model check only**, never login attempts).
- Banners and versions → CPE → CVE (with confidence).
- Exposure to the internet: public IP and forwarded ports detected via UPnP.

### 2.4 Wi-Fi (passive, the connected network + visible networks)
WEP/WPA (Critical), WPA2-TKIP (High), WPS enabled (High), open networks, hidden SSID as false security (Info). On Windows `netsh wlan`, on Linux `nmcli`, on macOS `system_profiler`/CoreWLAN.

### 2.5 Bluetooth (passive)
Visible BLE/classic devices, "discoverable" state, manufacturer (OUI / company ID) and, where it can be inferred, chipset → known vulnerabilities (BlueBorne, BrakTooth, KNOB, BLURtooth, SweynTooth). Confidence is almost always "probable": this must be stated clearly.

### 2.6 GDPR questionnaire (individual and company)
- **Individual:** backups, password manager, 2FA on the main accounts, automatic updates, shared devices.
- **Company:** record of processing activities (art. 30), privacy notices (arts. 13-14), DPO appointment if mandatory (art. 37), processor appointments (art. 28), data breach procedure (arts. 33-34, 72 hours), impact assessment (art. 35), security measures (art. 32). The technical evidence collected (TLS, DMARC, cookies) is linked to art. 32.

### 2.7 NIS2 questionnaire (companies only)
- **Scope:** sector (Annexes I-IV of Legislative Decree 138/2024, Italy's NIS2 transposition), size per Recommendation 2003/361/CE (art. 3 and 6 of the decree): above a small enterprise means 50 or more people, or turnover **and** balance sheet total both above €10 million; above a medium enterprise means 250 or more people, or turnover above €50 million **and** balance sheet total above €43 million. Some categories are in scope whatever their size (art. 3, paragraph 5). → outcome *probably essential / important / in scope (category to verify) / out of scope / to be verified* ([ADR-008](decisions/ADR-008-questionnaires-in-json.md)).
- **Obligations:** registration on the ACN platform (Italy's National Cybersecurity Agency), risk-management measures, training of management bodies, incident notification (early warning 24 h, notification 72 h, final report within one month), supply-chain security.
- Every "no" answer becomes a finding with an article reference.
- ⚠️ Legal references to be verified against official sources (Normattiva, ACN) **before v0.1**. Done on 25/11/2026 for arts. 3, 6, 7, 23, 24 and 25 of D.Lgs. 138/2024 (Normattiva, text in force since 16/10/2024) and for the sectors of Annexes I-II (Gazzetta Ufficiale, to be checked on the PDF of GU n. 230 of 1/10/2024); the GDPR articles are still to be checked on EUR-Lex.

## 3. Finding format
```json
{
  "id": "MAIL-DMARC-001",
  "area": "Email",
  "title": "DMARC in monitoring mode (p=none)",
  "severity": "Medium",
  "confidence": "Certain",
  "target": "example.com",
  "evidence": "v=DMARC1; p=none; rua=...",
  "cve": [],
  "cvss": null, "epss": null, "kev": false,
  "risk": "Anyone can send email on behalf of the domain without it being blocked.",
  "fix": "Move the policy to p=quarantine after 2-4 weeks of clean reports, then to p=reject.",
  "references": ["RFC 7489", "GDPR art. 32", "D.Lgs. 138/2024"]
}
```
**Severity:** Critical / High / Medium / Low / Info. If there is a CVSS score, start from it; **KEV = always raised to Critical** and placed at the top; EPSS ≥ 0.1 raises priority by one level.
**Confidence:** Certain / Probable / To be verified.

## 4. Report
- **Header:** profile, scope declaration, date and time, program version and CVE database version.
- **Summary:** counts by severity and by area + the 5 most urgent actions.
- **Sections per area** (Network, Wi-Fi, Websites, Email, Bluetooth, GDPR, NIS2), within each ordered Critical → Info, then by EPSS.
- **Footer on every page:** "Report generated with Scudo Digitale vX.Y — © Gaetano Cardinale — https://gcardinale.it — AGPL-3.0 license".
- **Formats:** HTML (single file, no external resources), PDF, JSON.
- **Comparison:** if a previous JSON is supplied, it shows what was fixed, what is new and what remains.

## 5. Out of scope (declared)
Exploiting vulnerabilities, login attempts or bruteforce, active scans of sites that are not the user's own, Wi-Fi/Bluetooth attacks (deauth, forced pairing), sending data to Scudo Digitale servers.
