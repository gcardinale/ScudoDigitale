# Checks.Web — status

- **Content (v0.1, first pass):** HTTPS, certificate, security headers, cookies, security.txt — passive, only the requests of a normal first visit
- **Second pass (not started, to be agreed):** TLS versions and weak ciphers, CMS and declared version, indicative GDPR (see below)
- **Release:** v0.1 (passive) / v0.2 (active, behind `IScopeGuard`)
- **Status:** 🟡 first pass implemented and merged (21/11/2026, PR #8); independent review done the same day, fixes on branch `fix/v0.1-web-review` (PR #9)
- **Test coverage:** 100% lines (797/797), 98.6% branches (341/346); 397 tests; 30 of 30 counterproofs (one site with the problem and one without, for each check); 49 deliberate bugs, 47 caught at the first run and 49 after adding one test and removing one redundant line

## Checks
One check per kind of problem ([ADR-006](../../docs/decisions/ADR-006-check-granularity-and-dns-for-email.md)). A check whose subject is missing is `Skipped` and says why: without HTTPS the certificate, header and cookie checks point to `WEB-HTTPS-001`; without cookies on a first visit the three cookie checks say so.

| Id | Title | Finds | Severity |
|---|---|---|---|
| `WEB-HTTPS-001` | Site reachable over HTTPS | connection refused on port 443; the HTTPS site redirects back to HTTP; HTTPS not reachable for another reason (no answer in time, handshake failed: to be verified) | High |
| `WEB-HTTPS-002` | Redirect from HTTP to HTTPS | page served in clear with no redirect; HTTPS reached only through another address in clear | Medium / Low |
| `WEB-CERT-001` | Certificate expiry | expired or not yet valid; fewer than 14 days left; at most 30 days left | High / Medium / Low |
| `WEB-CERT-002` | Certificate chain | self-signed, unknown authority or broken chain; issuer not sent by the server | High / Medium (probable) |
| `WEB-CERT-003` | Name in the certificate | the certificate does not cover the name of the site | High |
| `WEB-HSTS-001` | HSTS | header missing, without `max-age`, or `max-age=0`; `max-age` below 6 months | Medium / Low |
| `WEB-HDR-001` | Content-Security-Policy | no policy (header or `meta`); report-only; policy that does not limit scripts (`unsafe-inline` without nonce or hash, `unsafe-eval`, `*`, `https:`) | Medium / Low / Low |
| `WEB-HDR-002` | Protection from clickjacking | neither `X-Frame-Options` nor a `frame-ancestors` that names who may frame the site (`*` or `https:` do not count); a value browsers ignore (`ALLOW-FROM`…), which protects as little as no header | Medium |
| `WEB-HDR-003` | X-Content-Type-Options | missing, or not `nosniff` | Low |
| `WEB-HDR-004` | Referrer-Policy | none (header or `meta`); `unsafe-url` or `no-referrer-when-downgrade` | Low |
| `WEB-HDR-005` | Permissions-Policy | missing | Info |
| `WEB-COOKIE-001` | Cookies without Secure | one finding per cookie | Medium |
| `WEB-COOKIE-002` | Cookies without HttpOnly | cookie whose name looks like a session; other cookies (anti-forgery tokens count as "other") | Medium / Low (probable) |
| `WEB-COOKIE-003` | Cookies without SameSite | `SameSite=None` without `Secure`; attribute missing or not valid | Medium / Low |
| `WEB-SECTXT-001` | security.txt file | no `Contact`, `Expires` missing, unreadable or past; file missing; file redirected to another address (not followed, to be verified) | Low / Info / Info |

## Done
- `WebChecks.Create(WebCheckOptions?)`: the 15 checks, for targets of kind `Website`. `WebChecks.TryNormalizeTarget` turns a domain name or an `http`/`https` URL into the host to check (internationalized names become punycode; IP addresses and non-standard ports are rejected).
- **One visit per site, shared by the checks**: `GET http://host/`, `GET https://host/`, `GET https://host/.well-known/security.txt` and, only when that one has no file, `GET https://host/security.txt` (the two addresses of RFC 9116). Nothing else: no other path, no form, no cookie sent back, no login.
- **Redirects** are followed only inside the declared site (the same name, with or without `www.`, and its subdomains) and only on the standard port, at most 5. A redirect to another domain is not followed: the page checks are skipped and say to run the check on that domain.
- **Certificate** read from the same HTTPS connection and judged with the authorities of the operating system. Downloading missing intermediate certificates and asking the authority about revocation are switched off, because both would be connections to servers that were not declared. **Revocation is therefore not checked.** An invalid certificate does not stop the visit: it is a finding, and the headers are still read.
- **User agent** declared: `Mozilla/5.0 (compatible; ScudoDigitale/<version>; +https://gcardinale.it)`.
- **Limits**: 10 seconds per request (`WebCheckOptions.RequestTimeout`, at most 30), 40 seconds for the whole visit, 512 KB read from a page. When the site answers neither over HTTP nor over HTTPS every check fails with the error, instead of reporting problems that were not observed. A home page that answers 400 or more is not evaluated.
- The address of the site is asked to the resolver of ADR-006, shared with the email checks (`ScudoDigitale.Core.Dns`): Cloudflare and then Google over DNS over HTTPS, then the DNS of the computer; With `WebCheckOptions.DnsSource = DnsSource.System` (`--system-dns`) the name is left to the operating system, as for any connection (asking the router directly was tried on 21/11/2026 and gave "Server Failure" on a name that exists). The addresses are tried in order, IPv4 first. A name that does not exist, has no address, or that no resolver answers for gives "could not run" with the reason, never a finding.
- Nothing that can identify a session appears in the evidence: of a cookie only the name and the names of its attributes; of an address only scheme, host and path, without path parameters (`;jsessionid=…`) and query string. Several cookies joined in one header line are told apart.
- Titles, risk and fix in English and Italian (`Resources/Strings*.resx`, 122 strings); a test checks that both languages have the same keys and placeholders.
- Tests on real connections and real TLS handshakes with a local HTTP/HTTPS server and a certificate authority that exists only inside the tests (nothing is installed on the computer); no real network in tests.
- No check is skipped on a platform. The chain of a certificate is built by each system's own library (the tests run on Windows, Linux and macOS in CI), and that gives one known difference, see the limits below.

## Known limits (found by the review of 21/11/2026)
- **System proxy: kept and declared** (decided by the author on 21/11/2026). The requests go through the proxy configured on the computer, if there is one (on Windows also the automatic proxy discovery), as a browser's do and as the DNS over HTTPS already does: without it the tool would not work where a proxy is mandatory. Behind a proxy that inspects TLS, the certificate checks judge the certificate of the proxy, not that of the site, so the report says before the results that the site is reached through a proxy and what that means (`WebChecks.SystemProxyFor`). Through a proxy the name of the site is resolved by the proxy, not by the resolver above.
- **Incomplete chain on Windows.** Windows keeps the intermediate certificates it has already seen. When the server forgets to send one that Windows knows, the chain is complete for Windows and `WEB-CERT-002` reports nothing; Linux reports it. Deciding from the certificates the server really sent would make the three systems agree, but cross-signed authorities make it easy to get false alarms: it goes with ADR-007.
- **Root certificates on Windows.** When the authority of a site is in Microsoft's list but not yet on the computer, Windows itself downloads it from Windows Update while the chain is built. .NET has no switch for it. It is a connection made by the operating system, not to a server chosen by the site.
- **DNS of the home router: fixed on 21/11/2026.** One run out of a dozen had failed with "unknown host" on a name that exists, the weakness already measured for email. The website checks now use the same resolver as the email checks (see above). With `--system-dns` the weakness is still there by choice: the same day three runs in a row failed that way, and the next one worked.
- Proof on real sites on 21/11/2026 (see the build journal, week 47).

## To do
- **Second pass, each needs a decision first:**
  - TLS versions offered (1.0/1.1 = High) and weak ciphers: what a client can offer depends on the operating system (and on its policy), so the same site could give different results on Windows, Linux and macOS. Needs a decision on how to make them equal → draft ADR-007. Ids `WEB-TLS-…` are reserved.
  - CMS and declared version (generator, known files): detection only in v0.1, the match against CVEs arrives with `Vulnerabilities` (v0.2). Looking for "known files" means requesting other paths: decide whether it still counts as a normal visit (ADR-004).
  - Indicative GDPR: privacy notice and cookie policy links, cookie banner, cookies before consent, resources from non-EU domains. It needs the page body (already read) and, for the resources, a decision on whether third-party addresses are only listed or also contacted.
- HSTS on the bare domain when the site lives on `www`, `includeSubDomains` and preload: not evaluated yet.
- Link findings to GDPR art. 32 through Compliance (ADR-005, open point).
- v0.2: active checks (exposed files, directory listing, admin panels, HTTP methods) behind `IScopeGuard`, after the proof of ownership.
