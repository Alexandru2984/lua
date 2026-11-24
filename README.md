# LuaLens

A private domain intelligence workspace at **https://lua.micutu.com**. Lua handles
requests and background jobs inside Nginx; the browser uses native JavaScript,
HTML and CSS. There is no frontend build or production Node server.

## What works

- Quick/deep scans with live job status and explicit partial results.
- DNS A, AAAA, MX, NS, TXT, CAA and DMARC observations.
- Contextual direct SPF, DMARC, CAA and MX observations, separating unavailable
  lookups from missing direct records and distinguishing modern DMARC test mode.
- Verified HTTPS, seven explained header checks and a configuration score.
- Certificate validity dates, issuer/subject common names, SHA-256 fingerprint
  and the protocol/cipher negotiated by the verified connection.
- Private domain timelines with cursor pagination, score gaps for unknown results,
  and comparisons that separate configuration changes from request-specific noise.
- Availability checks for robots.txt, sitemap.xml and security.txt.
- Deep scans: historical certificate hostnames from crt.sh and registration events
  through HTTPS RDAP, with validated redirects.
- Private browser workspaces, favorites, searchable/paginated history, status
  filters, DNS filtering and report comparisons across domain-specific history.
- Up to 50 saved domains per workspace, with labels, preferred scan depth,
  latest-report shortcuts and manual scan controls.
- JSON, spreadsheet-safe CSV, Markdown and complete offline HTML exports,
  printable HTML/PDF layout, and copyable report summaries.
- Dark/light themes, mobile layouts, accessible tabs/dialogs, keyboard shortcuts
  and a clearly labeled example report that consumes no scan quota.

A score is an observation about the initial root response, not a security
certification. IPv6 records are displayed, but outbound connections currently use
public IPv4. Certificate expiry is shown from the latest retained snapshot, with
7/30-day warnings; a manual scan checks the certificate currently served.
Revocation and full server protocol/cipher grading are not implemented.
There are no accounts, schedules or notifications yet.

## Layout

- `app/app.lua`: session-authorized JSON API.
- `app/modules/`: validation, bounded network client, jobs, SQLite and analysis.
- `app/static/`: dependency-free frontend.
- `deploy/`: active origin config, outer vhost, backup and log rotation.
- `scripts/preview.py`: disposable local server, isolated DB and signing key.
- `docs/`: [security audit](docs/SECURITY-AUDIT.md), [plan](docs/PLAN.md) and
  [operating guide](docs/OPERATIONS.md).

## Develop and verify

Production uses Ubuntu 26.04, Nginx with `libnginx-mod-http-lua`, Lua 5.1/LuaJIT,
`lua-lsqlite3`, `lua-cjson`, and `lua-resty-dns` 0.21-1. Development additionally
needs Node 20+, Python 3, Busted, Playwright and the OpenSSL CLI for disposable
test certificates. The running application uses existing OpenSSL public APIs
through LuaJIT FFI; it does not execute OpenSSL, WHOIS or other subprocesses.
See [TLS snapshot scope](docs/TLS-SNAPSHOTS.md).

```sh
npm ci --ignore-scripts
npx playwright install chromium
bash scripts/check.sh
```

The check script runs Lua/JS syntax checks, security/storage regressions, export
and comparison tests, two native TLS integration cases (1.2 and 1.3), and ten
browser scenarios against a real isolated Nginx with deterministic provider
responses. It never needs production
credentials or production data. CI uses a container matching the production
Ubuntu distribution, a pinned checkout action and read-only repository access.

For an isolated preview with **real** DNS/provider queries:

```sh
python3 scripts/preview.py
```

Open `http://127.0.0.1:18084`. For offline provider fixtures, add `--fixtures`.
Secure cookies work on loopback in Chromium. Do not expose the preview port.

## Privacy and indexing

Keep `app/data`, logs, keys, backups and `.env` files out of Git. The existing
outer Nginx Basic auth and Cloudflare origin restriction remain required. A
signed HttpOnly/Secure/SameSite cookie identifies a workspace for 30 days;
clearing or losing it loses access to those reports. New reports are retained up
to 30 days, with a global ceiling of 5,000 finished reports. Favorites do not
extend retention. Saved domains are capped at 50 per workspace and 5,000 globally,
and expire 30 days after their last edit. Downloaded reports are local copies
outside server retention. Encrypted storage and user accounts are not provided.

The dashboard remains `noindex` and private. Its semantic structure, description,
viewport and favicon are in place; it is intentionally not in a sitemap. A public
landing page and signup/abuse policy are prerequisites for acquisition through
SEO. The phased product roadmap records those follow-ups.
