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
certificate expiry monitoring, and localization. These need separate product and
data-lifecycle decisions; they must not be represented as working features yet.

Public acquisition needs a separate public educational landing page and a
deliberate decision about signup and scan abuse controls. The existing private
dashboard should remain outside search results.
