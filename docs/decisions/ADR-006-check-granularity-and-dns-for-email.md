# ADR-006 — One check per kind of problem, and DNS through public resolvers over HTTPS
> **Status:** accepted · **Decision maker:** Gaetano Cardinale · **Date:** 2026-11-19

## Context
`Checks.Email` is the first module with real checks, so it sets two conventions the other modules will copy.

1. **How big is a check?** The spec has one table row per topic (SPF, DMARC, ...), but each row hides several problems with different severities: no SPF record (High), `?all` (Medium), more than 10 lookups (High). `Finding.Id` is documented as "the stable check id", the engine rejects two checks with the same id, and the coding rules say that risk and fix live with the id. The comparison between two reports (spec §4) will match findings by id and target.
2. **Which DNS servers?** The checks need TXT and MX records. The DNS of a home router is often slow and drops queries: on 19/11/2026 the author's router lost most TXT queries, timed out on others, and turned a run on `example.com` into 25-50 seconds. It also intercepted plain DNS sent to 1.1.1.1 and 8.8.8.8 on port 53 (answers in 12 ms with "refused" or with the wrong query id), so asking a public resolver the usual way did not help. A tool that says "the check failed" because of the user's router looks broken.

## Options considered
### 1. Granularity
- **A — One check per topic** (`MAIL-SPF-001` covers every SPF problem). Few ids, but one id would mean "missing", "too many lookups" and "+all" at once. The comparison between two runs could not tell that "missing" became "+all", and one risk/fix text per id would no longer be possible.
- **B — One check per kind of problem.** `MAIL-SPF-001` is "SPF record present and unique", `MAIL-SPF-003` is "10-lookup limit". A check may still return several findings of its own kind (two weak DKIM keys, two unreachable MX hosts), told apart by their evidence. The checks of one domain share their DNS answers, so splitting costs no extra queries.

### 2. DNS servers
- **A — The DNS of the computer only.** No third party sees the domains, but results depend on the router.
- **B — Public resolvers on port 53** (1.1.1.1, 8.8.8.8). Simple, but routers can intercept it, as measured above.
- **C — Public resolvers over DNS over HTTPS** (Cloudflare, then Google), with the DNS of the computer as the last resort. HTTPS on port 443 cannot be intercepted, the queries are encrypted, and companies that block outgoing DNS still work through the last step.

## Decision
**1B and 2C** (decided by Gaetano Cardinale on 19/11/2026).
- 11 email checks for v0.1: `MAIL-SPF-001…004`, `MAIL-DMARC-001…003`, `MAIL-DKIM-001…002`, `MAIL-MX-001…002`. A check whose subject is missing (no SPF record, no valid DMARC record, no DKIM key, no MX) is `Skipped` and points to the check that reports it, so the report never shows a misleading "OK".
- DNS goes to Cloudflare (`cloudflare-dns.com`) and then Google (`dns.google`) over DNS over HTTPS, using their JSON API; only when both fail, to the DNS of the computer. `EmailCheckOptions.DnsSource = DnsSource.System` uses only the DNS of the computer, for whoever prefers it. Requests carry only the name and the record type, no cookies and a generic user agent. After the switch, every test domain answered in 0.4-1.3 seconds.
- The defaults stay cautious: 2-second timeout (tripled for HTTPS, to leave room for the TLS handshake), 1 retry on the DNS of the computer, at most 4 queries in flight per check, and a 25-second budget for the 27 DKIM queries, so a check always ends before the 60-second timeout of the engine.

## Consequences
- ✅ Every id has one risk and one fix text in the module's `.resx`, in English and Italian.
- ✅ The comparison between two runs can show that a problem changed, not just that "SPF" still has one.
- ⚠️ More ids to keep stable: an id is never reused for a different kind of problem.
- ⚠️ Cloudflare and Google see the domain names being checked. They are public names, and no personal data is sent; the list of external sources in `docs/01-architecture.md` now includes them.
- ⚠️ If every resolver fails, the checks fail with the DNS errors, instead of reporting problems that were not observed.
- ➕ **Extended to websites on 21/11/2026** (decided by Gaetano Cardinale). The website checks first used the DNS of the computer; on the same day one run out of a dozen failed with "unknown host" on a name that exists, the weakness measured above. The resolver (`IDnsResolver`, DNS over HTTPS, fallback, DnsClient) moved from `Checks.Email` to `ScudoDigitale.Core.Dns`, because no `Checks.*` project may depend on another, and the website checks ask it for the address of the site before connecting. `--system-dns` applies to both areas; for a website it leaves the name to the operating system, as for any connection. When the computer reaches the site through a proxy, the proxy resolves the name and the resolver is not asked.
- 🔍 Without the public suffix list, a subdomain without its own DMARC record inherits the record of the nearest parent with one (the DMARC tree walk), reported as "probable".
