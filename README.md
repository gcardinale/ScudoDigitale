<p align="center"><strong>🛡️ SCUDO DIGITALE</strong> ("Digital Shield")<br>
Free check of your own security: network, Wi-Fi, websites, email, Bluetooth, GDPR and NIS2</p>

<p align="center">
<a href="LICENSE"><img alt="AGPL-3.0 license" src="https://img.shields.io/badge/license-AGPL--3.0%20%2B%207(b)-blue"></a>
<img alt="Platforms" src="https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-informational">
<img alt="Status" src="https://img.shields.io/badge/status-in%20development-orange">
</p>

> **Scudo Digitale** is a **free and open-source** program that an owner or security officer runs **on their own PC** to check their own systems. It produces a **report split by area and sorted by severity**, with **CVEs**, likelihood of exploitation and **the fix to apply**.
> **Everything stays on your computer**: no cloud, no telemetry, no data sent to the author. The only outside services are public sources, such as the vulnerability databases and the DNS resolvers of Cloudflare and Google, which see only the public domain names being checked.

## What it checks
| Area | Example checks |
|---|---|
| 🌐 **Local network** | devices present, exposed ports and services (Telnet, SMBv1, RDP, UPnP), versions with known CVEs |
| 📶 **Wi-Fi** | protocol (WEP/WPA/WPA2/WPA3), WPS enabled, open networks |
| 🖥️ **Websites** | certificate and TLS, security headers, cookies, outdated CMS, cookies set before consent |
| ✉️ **Email** | SPF, DKIM, DMARC, MTA-STS, DNSSEC, STARTTLS, blacklists |
| 🔵 **Bluetooth** | visible and discoverable devices, chipsets with known vulnerabilities |
| ⚖️ **GDPR** | guided self-assessment for **individuals** and **companies** |
| 🇪🇺 **NIS2** | are you in scope of Legislative Decree 138/2024 (Italy's NIS2 transposition)? Which obligations are you missing? |

Every issue in the report lists: **severity**, **CVE and CVSS score**, **EPSS** (likelihood of exploitation), the **"actively exploited"** flag (CISA KEV catalog), the **confidence** of the detection and **how to fix it**.

## Responsible use
- On **third-party websites and domains** Scudo Digitale runs **passive checks only**: it reads public information that anyone can see by visiting the site or querying DNS.
- **Active checks** (port scanning, exposed files) work only on **your own local network** or on **domains whose ownership you prove**.
- It never attempts logins, never exploits vulnerabilities, never attacks Wi-Fi networks or Bluetooth devices.
- It is a **self-assessment** tool: it does not replace a professional penetration test or legal advice. False positives and false negatives are possible.

## Download
A first **beta 0.1** (email, website, GDPR/NIS2 questionnaires and reports) is planned for **1 December 2026** in [Releases](https://github.com/gcardinale/ScudoDigitale/releases), for Windows, macOS and Linux with SHA-256 hashes. Version 1.0 follows by mid-December 2026 with build provenance attestation.

## Project status
In development, towards the beta of 1 December 2026. See the [roadmap](docs/03-roadmap.md), the [functional specification](docs/00-functional-spec.md) and the weekly [build journal](docs/journal/README.md).

| Area | Status |
|---|---|
| ✉️ Email (SPF, DMARC, DKIM, MX) | ✅ working — 11 passive checks, `scudo scan --mail` |
| 🔒 Websites (HTTPS, certificate, security headers, cookies, security.txt) | ✅ working — 15 passive checks, `scudo scan --web` |
| 🔒 Websites: TLS versions and ciphers, CMS, cookies before consent | 🚧 in progress for the beta |
| 📋 GDPR/NIS2 questionnaires, HTML/PDF/JSON report | 🚧 in progress for the beta |
| 🌐 Local network, CVE database, 📶 Wi-Fi, 🔵 Bluetooth | 🗓️ after the beta (v0.2, v0.3) |

## Try the email checks (from source)
Until the beta executables are out, the email checks run from the source code (see *Build from source* below):
```bash
dotnet run --project src/ScudoDigitale.Cli -- scan --mail example.com
dotnet run --project src/ScudoDigitale.Cli -- scan --mail example.com --dkim-selector myselector   # your own DKIM selector
dotnet run --project src/ScudoDigitale.Cli -- scan --help
```
The output lists the problems most urgent first, each with evidence, risk and fix, in English or Italian depending on the system language. The email checks read only public DNS records and send no email, so they work on any domain. DNS queries, for email and for websites, go to Cloudflare and then Google over DNS over HTTPS (they see only the domain names being checked); `--system-dns` uses the DNS of your computer instead.

## Build from source
Requires .NET SDK 10 or later (pinned in `global.json`).
```bash
git clone https://github.com/gcardinale/ScudoDigitale.git
cd ScudoDigitale
dotnet build
dotnet test                              # runs every test project with the 90% coverage gate
pwsh build/check-headers.ps1             # verifies the license header on every .cs file
dotnet run --project src/ScudoDigitale.Cli -- scan --mail example.com
```

## License and attribution
© 2026 **Gaetano Cardinale** — [gcardinale.it](https://gcardinale.it)

Distributed under the **GNU AGPL-3.0-or-later** with additional terms (section 7) described in the [NOTICE](NOTICE) file: anyone who redistributes or modifies the program **must keep the attribution to the author visible** in the interface and in the reports, and may not present modified versions as the official one.

## Reporting a vulnerability
See [SECURITY.md](SECURITY.md).
