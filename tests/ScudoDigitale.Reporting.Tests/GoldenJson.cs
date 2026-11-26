// ╔═══════════════════════════════════════════════════════════════╗
// ║   ███████╗ ██████╗██╗   ██╗██████╗  ██████╗                   ║
// ║   ██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗                  ║
// ║   ███████╗██║     ██║   ██║██║  ██║██║   ██║                  ║
// ║   ╚════██║██║     ██║   ██║██║  ██║██║   ██║                  ║
// ║   ███████║╚██████╗╚██████╔╝██████╔╝╚██████╔╝  D I G I T A L E ║
// ║   ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝                   ║
// ║   Security check: network, Wi-Fi, websites, email, Bluetooth, ║
// ║   GDPR and NIS2.   © 2026 Gaetano Cardinale — gcardinale.it   ║
// ╠═══════════════════════════════════════════════════════════════╣
// ║ SPDX-License-Identifier: AGPL-3.0-or-later                    ║
// ║ Attribution required (AGPL sec. 7(b)): see NOTICE file        ║
// ╚═══════════════════════════════════════════════════════════════╝

namespace ScudoDigitale.Reporting.Tests;

/// <summary>
/// The JSON of <see cref="Make.Document"/> in schema version 1, read and checked by hand on 2026-11-25.
/// It pins the public format: change it only together with <see cref="ReportDocument.SchemaVersion"/>.
/// </summary>
internal static class GoldenJson
{
    public const string Version1 =
        """
        {
          "schemaVersion": 1,
          "program": "Scudo Digitale",
          "programVersion": "0.1.0",
          "vulnerabilityDatabaseVersion": null,
          "generatedAt": "2026-11-25T10:31:05+01:00",
          "language": "en-US",
          "declaration": {
            "operatorName": "Mario Rossi",
            "operatorRole": "SecurityOfficer",
            "declaredAt": "2026-11-25T10:30:00+01:00",
            "targets": [
              {
                "kind": "Domain",
                "value": "example.com"
              },
              {
                "kind": "Website",
                "value": "www.example.com"
              }
            ]
          },
          "profile": {
            "kind": "Company",
            "companyName": "Rossi SRL",
            "vatNumber": "IT01234567890",
            "atecoCode": null,
            "employees": 12,
            "annualTurnoverEur": 1500000
          },
          "notes": [
            "The site is reached through a proxy."
          ],
          "sections": [
            {
              "area": "Web",
              "target": "www.example.com",
              "findings": [
                {
                  "id": "WEB-CMS-001",
                  "area": "Web",
                  "title": "Outdated CMS",
                  "severity": "Low",
                  "effectiveSeverity": "Critical",
                  "confidence": "Probable",
                  "target": "www.example.com",
                  "evidence": "generator: WordPress 5.0",
                  "cve": [
                    "CVE-2019-8942"
                  ],
                  "cvss": 8.8,
                  "epss": 0.97,
                  "kev": true,
                  "risk": null,
                  "fix": "Update WordPress.",
                  "references": [
                    "CISA KEV"
                  ]
                },
                {
                  "id": "WEB-HSTS-001",
                  "area": "Web",
                  "title": "Title of WEB-HSTS-001",
                  "severity": "Info",
                  "effectiveSeverity": "Info",
                  "confidence": "Certain",
                  "target": "www.example.com",
                  "evidence": "evidence of WEB-HSTS-001",
                  "cve": [],
                  "cvss": null,
                  "epss": null,
                  "kev": false,
                  "risk": "risk of WEB-HSTS-001",
                  "fix": "fix of WEB-HSTS-001",
                  "references": [
                    "RFC 7489"
                  ]
                }
              ],
              "passed": [],
              "skipped": [],
              "failed": []
            },
            {
              "area": "Email",
              "target": "example.com",
              "findings": [
                {
                  "id": "MAIL-DMARC-001",
                  "area": "Email",
                  "title": "Title of MAIL-DMARC-001",
                  "severity": "Medium",
                  "effectiveSeverity": "Medium",
                  "confidence": "Certain",
                  "target": "example.com",
                  "evidence": "evidence of MAIL-DMARC-001",
                  "cve": [],
                  "cvss": null,
                  "epss": null,
                  "kev": false,
                  "risk": "risk of MAIL-DMARC-001",
                  "fix": "fix of MAIL-DMARC-001",
                  "references": [
                    "RFC 7489"
                  ]
                }
              ],
              "passed": [
                {
                  "id": "MAIL-SPF-001",
                  "title": "Check MAIL-SPF-001",
                  "detail": null
                }
              ],
              "skipped": [
                {
                  "id": "MAIL-DKIM-002",
                  "title": "Check MAIL-DKIM-002",
                  "detail": "no key to look at"
                }
              ],
              "failed": [
                {
                  "id": "MAIL-MX-001",
                  "title": "Check MAIL-MX-001",
                  "detail": "DNS timeout"
                }
              ]
            },
            {
              "area": "Gdpr",
              "target": null,
              "findings": [
                {
                  "id": "GDPR-ART30-001",
                  "area": "Gdpr",
                  "title": "Title of GDPR-ART30-001",
                  "severity": "High",
                  "effectiveSeverity": "High",
                  "confidence": "Certain",
                  "target": "Rossi SRL",
                  "evidence": "evidence of GDPR-ART30-001",
                  "cve": [],
                  "cvss": null,
                  "epss": null,
                  "kev": false,
                  "risk": "risk of GDPR-ART30-001",
                  "fix": "fix of GDPR-ART30-001",
                  "references": [
                    "RFC 7489"
                  ]
                }
              ],
              "passed": [
                {
                  "id": "GDPR-ART32-001",
                  "title": "Security measures",
                  "detail": null
                }
              ],
              "skipped": [],
              "failed": []
            }
          ]
        }
        """;
}
