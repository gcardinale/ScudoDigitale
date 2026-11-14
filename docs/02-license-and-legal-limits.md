# 02 — License, attribution and legal limits

## 1. Authorship: protected by law
Art. 20 of Italian Copyright Law (L. 633/1941): the author *"retains the right to claim authorship of the work"* even after transferring the economic rights. It is a moral right that cannot be assigned. Software is protected as a work (art. 2, no. 8).
Source (Italian text): https://www.normattiva.it/uri-res/N2Ls?urn:nir:stato:legge:1941;633~art20.

## 2. Why AGPL-3.0 and not Apache 2.0
| | Apache 2.0 | AGPL-3.0 + 7(b) |
|---|---|---|
| Headers in source files | must be kept (art. 4c) | must be kept |
| Name visible in the program | **no**: the NOTICE file is enough | **yes**: section 7(b) allows requiring that attributions be preserved in the notices shown to the user |
| Closed version resold by others | possible | forbidden: whoever distributes the program, or offers it over a network, must publish the code |
| Use by someone who only runs it | no obligation | no obligation (no license can impose one) |

## 3. `NOTICE` file and additional terms
The text in force is in the [`NOTICE`](../NOTICE) file (English text prevails; a full Italian translation follows it). Starting draft:
```
Scudo Digitale
Copyright (C) 2026 Gaetano Cardinale — https://gcardinale.it

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License version 3
or later, with the following ADDITIONAL TERMS under section 7:

7(b) Anyone who conveys, or makes available over a network, this program
     or a work based on it must preserve, in readable form:
     a) the notice "Scudo Digitale — © Gaetano Cardinale — https://gcardinale.it"
        in the "About" screen, in the command-line startup banner
        and in the footer of every generated report;
     b) the copyright headers present in every source file.
7(c) Modified versions must be marked as different from the original
     and must not present themselves as the official version.
7(e) The license grants no rights over the name "Scudo Digitale" nor
     over any marks or logos of the project.
```
⚠️ The text is based on section 7 of GPLv3/AGPLv3. Before publication: legal review and comparison with the official FSF wording.

## 4. ASCII header of every source file
The exact text is in [`build/header.txt`](../build/header.txt); copy below for reference.
```
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
```
Automatic check in CI: the build fails if a `.cs` file lacks the header.

## 5. Legal limits of the checks
- **Risk:** active scans on other people's systems may amount to unauthorized access to a computer system (Italian Criminal Code art. 615-ter c.p.) or related offenses (arts. 615-quater/quinquies c.p., possession and distribution of hacking tools and malicious software). To be verified against official sources before v0.1.
- **Passive (allowed on any target):** reading public DNS, TLS handshake, headers and cookies of a normal visit, public blacklists.
- **Active (own scope only):** the PC's local network; domains with verified ownership; declaration of the person running the tool (owner / security officer) recorded in the report.
- **Never:** login, bruteforce, exploitation, Wi-Fi deauth, forced Bluetooth pairing.
- **Warning** at first start and in the report: self-assessment, possible false positives and negatives, no warranty (AGPL sections 15-16), does not replace a penetration test or legal advice.

## 6. Trademark
- "Scudo Digitale": no product with the same name found (search of 14/11/2026). Before registering it: UIBM (Italian Patent and Trademark Office) + EUIPO search, classes 9 and 42.
- "Antares Program Technology": **do not use** without checking, risk of conflict with Antares Audio Technologies (software).
