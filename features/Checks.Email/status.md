# Checks.Email — status

- **Content (v0.1):** SPF, DMARC, DKIM on common selectors, MX — passive, public DNS only, no mail is sent
- **Deferred:** MTA-STS + TLS-RPT, DNSSEC, STARTTLS/TLS of the MX, DNSBL, BIMI → v0.2 or later (see below)
- **Release:** v0.1
- **Status:** 🟢 implemented (19/11/2026), branch `feature/v0.1-email`
- **Test coverage:** 100% lines (704/704), 98% branches (428/436); 329 tests; 45 of 46 counter-checks caught

## Checks
One check per kind of problem ([ADR-006](../../docs/decisions/ADR-006-check-granularity-and-dns-for-email.md)). A check whose subject is missing is `Skipped` and points to the check that reports it.

| Id | Title | Finds | Severity |
|---|---|---|---|
| `MAIL-SPF-001` | SPF record | missing; more than one record | High |
| `MAIL-SPF-002` | SPF final rule (all) | `+all` / `?all` or no `all` (after following `redirect=`) | High / Medium |
| `MAIL-SPF-003` | SPF limit of 10 DNS lookups | more than 10 lookups, includes and redirects followed | High |
| `MAIL-SPF-004` | SPF syntax and includes | invalid term; include/redirect to a domain without one SPF record, or a loop; include not checkable (DNS error); `ptr` | High / Low (to be verified) / Low |
| `MAIL-DMARC-001` | DMARC policy | missing; invalid or duplicated; `p=none`; `pct` < 100. A subdomain without a record inherits the parent's `sp`/`p` (probable) | High / High / Medium / Low |
| `MAIL-DMARC-002` | DMARC aggregate reports | no `rua` | Low |
| `MAIL-DMARC-003` | DMARC policy for subdomains | `sp=none` while `p` is enforced | Low |
| `MAIL-DKIM-001` | DKIM on common selectors | no key on 27 common selectors + the user's own; lists the selectors the DNS did not answer for | Medium, to be verified |
| `MAIL-DKIM-002` | DKIM keys | RSA < 1024 bits; < 2048 bits; key not readable; test mode `t=y` | High / Medium / Medium / Low |
| `MAIL-MX-001` | Mail servers (MX) | no MX (null MX `0 .` is fine) | Low |
| `MAIL-MX-002` | Names of the mail servers | host without A/AAAA (High if none resolves); MX pointing to an IP; host not checkable | High / Medium / Medium / Low |

## Done
- `EmailChecks.Create(EmailCheckOptions?)`: the 11 checks; `EmailCheckOptions` for extra DKIM selectors, DNS timeout (2 s), retries (1) and concurrency (4). The DKIM analysis has a 25-second budget, so a resolver that drops queries cannot push the check past its 60-second timeout.
- DNS through DnsClient.NET on the resolvers of the computer only; DnsClient's fallback to Google Public DNS is switched off (zero telemetry).
- The checks of a run share their DNS answers: each name is queried once.
- Every check validates the target (URLs, addresses, IPs rejected; internationalized names become punycode), fails with a clear message if the domain does not exist, and never throws towards the engine except to honour cancellation.
- Titles, risk and fix in English and Italian (`Resources/Strings*.resx`); a test checks that both languages have the same keys and placeholders.
- Tests on real DNS packets with an in-process UDP DNS server; no real network in tests.
- Proof on real domains on 19/11/2026 (see the build journal, week 47).

## To do
- CLI: `scudo scan --mail <domain> [--dkim-selector <s>]` (owner of the CLI to be decided, see roadmap).
- Link findings to GDPR art. 32 through Compliance (ADR-005, open point).
- v0.2+: MTA-STS + TLS-RPT, DNSSEC, DNSBL, BIMI (DNS only, passive). STARTTLS and the certificate of the MX need a TCP connection to port 25 of someone else's server: decide first whether it counts as passive (ADR-004).
