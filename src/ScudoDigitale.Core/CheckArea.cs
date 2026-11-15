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

namespace ScudoDigitale.Core;

/// <summary>
/// Area a check belongs to. The declaration order is the order of the report sections.
/// </summary>
public enum CheckArea
{
    /// <summary>Local network: devices, ports, services, UPnP.</summary>
    Network,

    /// <summary>Wi-Fi: the connected network and the visible ones.</summary>
    Wifi,

    /// <summary>Websites: TLS, headers, cookies, CMS, indicative GDPR.</summary>
    Web,

    /// <summary>Email: SPF, DMARC, DKIM, MTA-STS, DNSSEC, STARTTLS, DNSBL.</summary>
    Email,

    /// <summary>Bluetooth: visible devices and known chipset vulnerabilities.</summary>
    Bluetooth,

    /// <summary>GDPR questionnaire.</summary>
    Gdpr,

    /// <summary>NIS2 questionnaire (Legislative Decree 138/2024).</summary>
    Nis2,
}
