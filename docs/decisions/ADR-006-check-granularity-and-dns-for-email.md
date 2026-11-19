# ADR-006 — One check per kind of problem, and DNS through the user's own resolver
> **Status:** proposed · **Decision maker:** Gaetano Cardinale · **Date:** 2026-11-19

## Context
`Checks.Email` is the first module with real checks, so it sets two conventions the other modules will copy.

1. **How big is a check?** The spec has one table row per topic (SPF, DMARC, ...), but each row hides several problems with different severities: no SPF record (High), `?all` (Medium), more than 10 lookups (High). `Finding.Id` is documented as "the stable check id", the engine rejects two checks with the same id, and the coding rules say that risk and fix live with the id. The comparison between two reports (spec §4) will match findings by id and target.
2. **Which DNS servers?** The checks need TXT and MX records. DnsClient.NET falls back to Google Public DNS when it finds no configured server. That would be a connection the user did not choose: no outbound network beyond the targets and the declared public sources (`docs/01-architecture.md`, Principles).

## Options considered
### 1. Granularity
- **A — One check per topic** (`MAIL-SPF-001` covers every SPF problem). Few ids, but one id would mean "missing", "too many lookups" and "+all" at once. The comparison between two runs could not tell that "missing" became "+all", and one risk/fix text per id would no longer be possible.
- **B — One check per kind of problem.** `MAIL-SPF-001` is "SPF record present and unique", `MAIL-SPF-003` is "10-lookup limit". A check may still return several findings of its own kind (two weak DKIM keys, two unreachable MX hosts), told apart by their evidence. The checks of one domain share their DNS answers, so splitting costs no extra queries.

### 2. DNS servers
- **A — DnsClient defaults**: system servers, then Google Public DNS as a fallback.
- **B — System servers only**, with the fallback switched off. With no server, every check fails and says why.
- **C — A fixed public resolver** (1.1.1.1, 8.8.8.8): stable results, but every user's domain list goes to a third party.

## Decision
**1B and 2B.**
- 11 email checks for v0.1: `MAIL-SPF-001…004`, `MAIL-DMARC-001…003`, `MAIL-DKIM-001…002`, `MAIL-MX-001…002`. A check whose subject is missing (no SPF record, no valid DMARC record, no DKIM key, no MX) is `Skipped` and points to the check that reports it, so the report never shows a misleading "OK".
- DNS uses only the resolvers configured on the computer. The defaults are cautious: 2-second timeout, 1 retry, at most 4 queries in flight per check. On 2026-11-19 the DNS forwarder of a home router dropped most queries once they arrived 8 at a time. The 27 DKIM queries share a 25-second budget: what has not answered by then is reported as unanswered, so the check ends well before the 60-second timeout of the engine.

## Consequences
- ✅ Every id has one risk and one fix text in the module's `.resx`, in English and Italian.
- ✅ The comparison between two runs can show that a problem changed, not just that "SPF" still has one.
- ⚠️ More ids to keep stable: an id is never reused for a different kind of problem.
- ⚠️ With a slow or lossy resolver some checks fail. They fail honestly, with the DNS error in the report, instead of reporting problems that were not observed.
- 🔍 Without the public suffix list, a subdomain without its own DMARC record inherits the record of the nearest parent with one (the DMARC tree walk), reported as "probable".
