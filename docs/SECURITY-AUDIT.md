# Security audit

Inspection date: 2026-11-23. Scope: this checkout, its active inner Nginx,
application systemd unit and outer vhost. This is a source/configuration review
with bounded local verification, not a host-wide penetration test.

## Original findings

| Severity | Finding | Evidence and consequence |
| --- | --- | --- |
| High | Stored XSS | Original `app.lua` concatenates DNS, WHOIS, HTTP headers and CT results directly into HTML. An attacker-controlled response can execute script in a viewer's session. |
| High | SSRF / DNS rebinding | `validator.lua` checks only literal RFC1918/loopback addresses. A valid domain can resolve to internal services; special IPv4 ranges are incomplete. HTTP and OpenSSL resolve names again at connection time. |
| High | Unverified upstream HTTPS | `ssl_verify = false` in both HTTP modules permits interception and false reports. |
| High | Worker exhaustion | `io.popen` invokes WHOIS/OpenSSL synchronously inside the single Nginx worker. Unbounded upstream response bodies and no application-wide concurrency control amplify denial of service. |
| Medium | Incorrect rate limiting | Every GET increments the counter; refreshing/polling blocks scans. The application directly consumes `X-Real-IP`, with no explicit trust boundary in its own config. The active outer proxy overwrites this header, mitigating remote spoofing through that route. |
| Medium | Missing request integrity | POST has no CSRF protection or Origin checks. Basic authentication does not prevent CSRF. |
| Medium | Shared report disclosure | `/?format=json` and rendered history expose every stored scan to any authenticated viewer; there is no per-workspace authorization. |
| Medium | Incomplete validation | Input is silently rewritten, malformed domain labels are accepted, tables from repeated form parameters can crash validation, and URL credentials/ports are not consistently handled. The shell calls are a dangerous sink, but arbitrary command execution through the original validator was not demonstrated. |
| Medium | Stuck/incorrect jobs | No exception guard or stale-job recovery; failed upstream checks are still labeled completed; SQLite step/exec errors are ignored. |
| Medium | Unbounded retention | History reads 50 rows but records are never pruned. Database growth and sensitive reports have no lifecycle. |
| Medium | Alternate config exposes origin | `app/conf/nginx.conf` listens on all interfaces, although the active deploy config correctly binds loopback. |
| Low | Weak browser policy in outer proxy | CSP permits inline scripts/styles and injected analytics; the application has no independent response policy. |
| Low | Delivery gaps | No Git history, reproducible verification, CI, operating guide or versioned production config snapshot. |

## Existing protections verified

- Outer HTTPS vhost restricts Cloudflare origin peers, requires Basic auth,
  sets TLS 1.2/1.3 and HSTS, and sends `X-Robots-Tag: noindex`.
- Active application listens only on `127.0.0.1:8084`.
- Service is unprivileged with filesystem isolation, no capabilities,
  `NoNewPrivileges`, memory/task limits and a restrictive umask.
- Daily backup service/timer exists; actual restore recovery was not tested.
- No credentials, reports, logs or runtime keys belong in Git.

## Remediation verification

The release removes HTML concatenation of remote values and all shell execution.
Every outbound HTTP connection uses a vetted pinned public IPv4, standard ports,
verified HTTPS, bounded headers/body and an absolute deadline. RDAP redirects are
revalidated. Signed browser workspaces, ownership-bound queries, CSRF checks,
scan-only quotas, job leases, stale-job recovery, safe SQLite errors and retention
are implemented. The original six ownerless rows are preserved offline.

The origin and outer vhost enforce a strict local-script CSP. The outer vhost's
analytics injection is removed. Its `X-Robots-Tag` was moved to server level:
the original location-level `add_header` prevented inheritance of the other
server-level policies, including HSTS, on that location. This was confirmed by
the original public 401 response lacking HSTS. Both configurations pass Nginx
validation. API traffic also has a separate 10 requests/second budget with a
40-request burst, independent of the scan quota.

Verification completed locally:

- **60 Lua regressions:** strict input, mixed DNS answers, pinned destinations,
  refused private IPs, redirect behavior, verified TLS, response limits, time
  budgets, SQL-bound values, workspace ownership, nullable scores, retention and
  legacy preservation, and conservative header observations.
- **5 JavaScript regressions:** spreadsheet formula neutralization, CSV quoting,
  export errors, meaningful comparisons and unavailable scores.
- **5 browser scenarios against isolated Nginx:** request integrity, forged
  cookies, authorization on read/update/delete, scans, favorites, comparison,
  JSON/CSV downloads, malicious upstream text rendered inert, scan-only quotas,
  partial failures, deep provider results, themes, keyboard/dialogs and mobile
  widths 360/390/768/1024/1440. No page-level horizontal overflow or JavaScript
  exceptions in these scenarios.
- Real-provider smoke testing in a separate temporary database returned DNS,
  verified HTTPS and RDAP for `example.com`; unavailable crt.sh produced a
  partial report rather than an invented result.
- `npm audit` reported **0 advisories** for the locked development dependency
  tree. There are no production npm dependencies. This does not audit system
  packages, Lua modules or upstream services against all known advisories.
- Backup script shell syntax, logrotate configuration and workflow YAML were
  validated. Upstream `Alexandru2984/lua` was subsequently linked as `origin`;
  both the original upstream history and the local release history are retained.

Production verification on 2026-11-23:

- Graceful reload of both Nginx services succeeded; the origin health endpoint
  returns `ok`, and SQLite `quick_check` returns `ok`.
- The public Cloudflare route still returns 401 without credentials and now
  includes HSTS, strict CSP, DENY framing, nosniff and noindex headers.
- A temporary production scan of `example.com` completed with verified HTTPS
  and ten DNS observations. Its report was then deleted from its test workspace.
- The six legacy rows remain intact; no test workspace reports remain live.
- The backup service completed successfully. Its compressed database was
  extracted into a temporary directory and passed SQLite integrity checking;
  the paired 32-byte key has mode 0600, and both checksums match. The daily timer
  remains active. This verifies the snapshot, not a full application restore.

## Remaining limits

This is not proof that all vulnerabilities are absent. No host-wide penetration
test, external authenticated browser test, full production restore, load test,
Firefox/Safari verification, dedicated service-user migration or OS-wide CVE
remediation was performed. The service shares the existing `micu` Unix identity;
a compromised process with that identity can access its runtime data. A dedicated
account and egress firewall are recommended future host work.

Basic auth and noindex remain deliberate. Public signup, ownership verification,
abuse controls and account recovery need a separate release before opening the
dashboard to general users. Browser cookies are currently the workspace identity;
there is no account recovery. Provider data can be unavailable or incomplete,
IPv6-only targets are unsupported, and header scores do not certify security.
The matching signing key is now included in private daily backups so that a
database restore does not silently strand browser workspaces.

## References

- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Nginx trusted real-IP configuration](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
- [lua-resty-http streaming and explicit connections](https://github.com/ledgetech/lua-resty-http)

## Release 2.1 verification

The hosted CI ownership issue was reproduced under an account different from
the checkout owner. Trust is scoped to the current checkout for the single Git
command; no global ownership protection is disabled. The corrected 2.0 workflow
[passed on GitHub](https://github.com/Alexandru2984/lua/actions/runs/45136224992).

Additional checks cover saved-domain isolation, duplicate updates, atomic
capacity enforcement, expiry, and ownership of linked report metadata. Labels
use bounded UTF-8 validation and render as text. Domain-filtered history retains
owner predicates and bound parameters. Saving a domain triggers no DNS or web
request. The table is additive and the existing database backup includes it.

Direct DNS observation states prevent lookup failures from appearing as absent
policies. Tests cover multiple SPF/DMARC records, permissive SPF, modern DMARC
testing mode, legacy percentage tags, missing inherited policy, null MX and
ambiguous policy tags. They are observations, not a complete mail validator.

HTML exports escape all untrusted fields, load no remote assets and execute no
scripts. Browser tests open the downloaded file offline with injected hostile
header content and verify no executable elements, no outbound HTTP requests and
successful PDF output. Markdown fences withstand hostile backticks; CSV retains
formula protection and now includes MX priority. The frontend also remains
usable with a 2.0 bootstrap during a graceful backend reload.

Local release checks now total 109: 90 Lua, 11 JavaScript and eight browser
scenarios. The existing residual limits above remain applicable.
