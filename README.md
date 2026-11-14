<p align="center"><strong>🛡️ SCUDO DIGITALE</strong> ("Digital Shield")<br>
Free check of your own security: network, Wi-Fi, websites, email, Bluetooth, GDPR and NIS2</p>

<p align="center">
<a href="LICENSE"><img alt="AGPL-3.0 license" src="https://img.shields.io/badge/license-AGPL--3.0%20%2B%207(b)-blue"></a>
<img alt="Platforms" src="https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-informational">
<img alt="Status" src="https://img.shields.io/badge/status-in%20development-orange">
</p>

> **Scudo Digitale** is a **free and open-source** program that an owner or security officer runs **on their own PC** to check their own systems. It produces a **report split by area and sorted by severity**, with **CVEs**, likelihood of exploitation and **the fix to apply**.
> **Everything stays on your computer**: no cloud, no telemetry, no data sent to the author.

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
Coming soon in [Releases](https://github.com/gcardinale/ScudoDigitale/releases) for Windows, macOS and Linux, with SHA-256 hashes and build provenance attestation.

## Project status
In development. See the [roadmap](docs/03-roadmap.md) and the [functional specification](docs/00-functional-spec.md).

## Build from source
Requires .NET SDK 10 or later.
```bash
git clone https://github.com/gcardinale/ScudoDigitale.git
cd ScudoDigitale
dotnet build
dotnet test
```

## License and attribution
© 2026 **Gaetano Cardinale** — [gcardinale.it](https://gcardinale.it)

Distributed under the **GNU AGPL-3.0-or-later** with additional terms (section 7) described in the [NOTICE](NOTICE) file: anyone who redistributes or modifies the program **must keep the attribution to the author visible** in the interface and in the reports, and may not present modified versions as the official one.

## Reporting a vulnerability
See [SECURITY.md](SECURITY.md).
