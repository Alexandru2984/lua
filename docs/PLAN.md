# LuaLens: product and security plan

## Scope and order

The existing service is Lua 5.1/LuaJIT on Nginx with ngx_lua, SQLite, a loopback
origin on port 8084, and an authenticated HTTPS vhost. Preserve that deployment
and the six existing records. No framework migration is necessary.

1. **Baseline and audit:** initialize Git, exclude runtime data, take a SQLite
   backup, inspect the actual service and proxy configuration, record findings.
2. **Security and engine:** strict input parsing, resolve and pin public IPs,
   verified TLS, bounded asynchronous network calls, remove shell execution,
   private signed browser workspaces, CSRF, scan-only rate limiting, concurrency
   caps, retention, robust SQLite operations and explicit partial failures.
3. **Product and interface:** responsive dark/light dashboard, quick/deep scans,
   DNS A/AAAA/MX/NS/TXT/CAA and DMARC, HTTP security observations, TLS verification,
   public resource discovery, certificate transparency and RDAP, live progress,
   searchable/filterable history, favorites, comparison, JSON/CSV exports,
   keyboard shortcuts, accessible controls and reduced-motion support.
4. **Verification and delivery:** regression tests, isolated integration/browser
   tests, mobile layout checks, CI without production credentials, operational
   documentation, SEO metadata and deliberate indexing policy. Reload only this
   application's Nginx after checks pass.

## Acceptance criteria

- No target or external response is inserted as executable HTML.
- Outbound target connections use a vetted, pinned public IPv4; redirects never
  silently lead to internal addresses. HTTPS certificate verification is on.
- A page refresh or polling does not spend a scan allowance.
- Mutations require a valid workspace cookie, CSRF token and same-origin context.
- One browser cannot read, compare, export or delete another browser's reports.
- Network stalls, exceptions and worker restarts leave a meaningful terminal
  status. Reports distinguish missing controls from unavailable observations.
- Mobile widths of 360px and up have no page-level horizontal overflow.
- Existing authentication, Cloudflare ingress restrictions and noindex survive.
- Each completed stage has a separate commit using the existing owner's identity,
  without assistant attribution or coauthor trailers.

## Follow-up roadmap

After the verified foundation: authenticated accounts and persistent workspaces,
domain ownership verification, opt-in scheduled checks, meaningful change alerts,
teams and roles, report sharing with expiring tokens, DNS propagation views,
scheduled certificate expiry monitoring, and localization. These need separate product and
data-lifecycle decisions; they must not be represented as working features yet.

Public acquisition needs a separate public educational landing page and a
deliberate decision about signup and scan abuse controls. The existing private
dashboard should remain outside search results.

## Delivered release

LuaLens 2.0 is installed on the existing VPS service. Stages 1–4 are implemented:
the regression suite passes (60 Lua tests, five JavaScript tests and five browser
scenarios), desktop/mobile layouts were inspected, both Nginx layers were
validated and gracefully reloaded, a live scan completed, the original six
records were preserved, and the new paired-key backup was integrity-checked.
GitHub CI is versioned and the same checks run locally. The original upstream
`Alexandru2984/lua` is configured as `origin`, with both histories retained.
Public SEO acquisition and the roadmap items above remain
future releases, since authentication and noindex are intentionally retained.

## Release 2.1

- Fixed the hosted CI container's Git ownership mismatch; the complete 2.0 suite
  passed on GitHub after scoping trust to the checkout for the whitespace check.
- Added private saved domains with labels, default depth, latest-report access,
  manual scans, deduplication, ownership checks and bounded storage.
- Added domain-filtered history for comparisons across mixed-domain pages.
- Added contextual direct SPF, DMARC, CAA and MX observations. Lookup failures
  remain unavailable, inherited policy is not guessed, and these observations do
  not alter the HTTP header score.
- Added offline complete HTML reports, browser printing/PDF, Markdown exports,
  and clipboard summaries. CSV now preserves MX priorities.
- Local release checks: 94 Lua tests, 11 JavaScript tests and eight browser
  scenarios, including offline HTML/PDF, malicious content and old-bootstrap
  compatibility. The release is installed on the VPS; a real scan verified saved
  domains, report links and all four DNS observations. GitHub checks run on push.


## Release 2.2

- Capture public leaf-certificate metadata from the existing verified TLS session:
  validity dates, common names, SHA-256, negotiated protocol and cipher. No extra
  provider request, runtime subprocess or dependency is needed.
- Show certificate snapshots, copyable fingerprints and 7/30-day expiry warnings
  in reports and saved domains. Anchor relative expiry to the bootstrap server
  clock; export the same metadata in HTML, Markdown, CSV and JSON.
- Add private per-domain timelines with 50-row cursor pages and accessible report
  links. Unknown scores leave chart gaps; partial reports remain explicit.
- Compare known observations only. Separate request-specific headers behind an
  opt-in control; certificate rotations, resource statuses and registration/DNS
  changes remain visible. Failed/truncated observations do not imply removals.
- Treat resource and metadata collection failures as partial reports while
  retaining independently successful HTTPS verification.
- Release checks: 101 Lua tests, 19 JavaScript tests, two native TLS scenarios
  and ten browser scenarios, including mobile layouts, hostile certificate text,
  unknown observations, clock skew, cursor navigation and workspace isolation.
- Automatic monitoring, revocation, exhaustive TLS grading, accounts and public
  acquisition remain follow-up work; manual scan snapshots are available now.
