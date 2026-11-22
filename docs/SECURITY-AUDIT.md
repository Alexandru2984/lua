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

Updated after implementation with actual test outcomes and remaining limits.

## References

- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Nginx trusted real-IP configuration](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
- [lua-resty-http streaming and explicit connections](https://github.com/ledgetech/lua-resty-http)
