# Operating LuaLens

## Production routing

Cloudflare reaches the HTTPS vhost for `lua.micutu.com`. The vhost requires Basic
auth and proxies to **127.0.0.1:8084**, managed by `lua-recon-canary.service`.
The service's Nginx prefix is `app/` and its active config is
`deploy/inner-nginx.conf`. `app/conf/nginx.conf` is a compatibility include of that
same config, so it cannot accidentally open a public origin listener.

The inner server trusts `X-Real-IP` only from loopback and uses the normalized
Nginx address as the limiter identity. The outer vhost must always overwrite
that header from its own validated client address. Host-local processes remain
inside the proxy trust boundary; this is not an isolation boundary against a
compromised VPS account.

## Update

1. Back up SQLite using `.backup`, not a raw copy of a live WAL database. Keep
   the signing key paired with the database and never put it in Git.
2. Run `bash scripts/check.sh`. Tests create their own temporary databases.
3. Run `python3 scripts/setup.py` as the service account when setting up a new
   deployment or refreshing the denylist after host IP changes. It does not
   overwrite an existing key. `data/denied-ips` additionally blocks this VPS's
   interface IPv4 addresses, beyond the built-in special-range exclusions.
4. Validate the origin:
   `nginx -p /srv/canary/lua.micutu.com/app/ -c /srv/canary/lua.micutu.com/deploy/inner-nginx.conf -t`.
5. Reload with `sudo systemctl reload lua-recon-canary`. Check
   `curl -fsS http://127.0.0.1:8084/api/health` and the service journal/error log.
6. If changing the outer vhost, install `deploy/outer-nginx.conf` into its existing
   `/etc/nginx/sites-available/lua.micutu.com`, run `sudo nginx -t`, then gracefully
   reload the system Nginx. Preserve authentication and Cloudflare restrictions.

Schema additions run idempotently on worker startup. SQLite uses WAL, bounded
busy waits and prepared statements. Pending jobs older than 120 seconds become
failed; normal jobs have request-specific deadlines and a 40-second analysis
budget. Limits are one job per workspace and three leased global slots. Leases
expire after interruptions. There is no durable job queue across restarts.

## Original records

The six original shared reports have `owner IS NULL` and remain in the database
as an offline legacy archive. They are excluded from new-workspace queries and
from automatic retention deletion. Do not expose or assign these records to an
arbitrary browser. The pre-upgrade database/config snapshots are in
`/home/micu/backups/lualens-before-upgrade`, directory mode 0700.

## Backup and restore

The existing daily `lua-recon-backup.timer` invokes
`/usr/local/sbin/lua-recon-backup`; its versioned source is
`deploy/lua-recon-backup.sh`. It uses SQLite's online backup API, checks database
integrity before and after compression, stores the matching 32-byte workspace
key and checksums, and retains snapshots/logs for 14 days in
`/srv/backups/lua-recon` (root only). Deletion from the live workspace does not
immediately erase backup copies. Versioned log rotation is
`deploy/lua-recon.logrotate`, installed at `/etc/logrotate.d/lua-recon`.

A restore requires the database **and matching signing key**, the same domain,
and a still-valid browser cookie. Stop the app, verify checksums and SQLite
integrity, restore them with owner `micu:micu` and mode 0600 under a 0700 data
directory, then start the app and verify health. Keep any existing WAL/SHM files
with their original database until a clean shutdown; never pair them with a
different restored database. A full production restore was not performed as part
of this upgrade.

## Rollback

Restore a known commit's source/config, validate Nginx and reload. The additive
schema remains readable by the original application, but reverting to the
original application also reintroduces its shared-history and security problems.
Do not roll back only the signing key. Database rollback discards newer reports,
so take a fresh backup before doing it.

## Security and service limits

- No shell execution; outbound requests use public pinned IPv4 and only ports
  80/443. HTTPS verifies trust and hostname. Initial target redirects are shown
  rather than followed; RDAP HTTPS redirects are revalidated at every hop.
- Headers: 32 KiB total, 8 KiB per line, at most 100 lines. Bodies are bounded
  per provider. DNS alias chains and CT/RDAP collections are capped.
- Reports are private to signed browser workspaces. Mutation requests require
  CSRF; repeated IDs and malformed targets cannot bypass ownership checks.
- Three scan creations per client per minute; reads and cached results do not
  consume scan quota. Rate state is in Nginx shared memory and resets on a full
  service restart.
- CSP allows local scripts/styles only; external analytics injection is removed
  from this private vhost. Both Nginx layers enforce browser policies. Upstream
  strings are rendered through text nodes.
- DNS and data providers learn queried domains. Provider outages produce partial
  results. NXDOMAIN for an optional DNS record is absence, not a provider outage.
- Service continues to run as `micu`, shared with other host services. A dedicated
  Unix account and outbound firewall policy are useful later host-hardening work;
  changing that shared deployment identity was outside this app upgrade.

The upstream repository is `https://github.com/Alexandru2984/lua`, configured as
`origin`; local `main` publishes there. Its original `recon-dashboard/` sources
now live under `app/`. Both histories are preserved in a merge commit, and the
workflow runs on pushes and pull requests. Production deployment is deliberately
separate from CI and requires the existing VPS operating access.

## Release 2.1

The additive `saved_targets` table uses workspace ownership, a unique
`(owner,target)` constraint and a single-statement capacity-checked upsert.
Each workspace can save 50 domains; global storage is bounded at 5,000 entries
with 30-day expiry measured from the last edit. Saving does not resolve or scan
the domain. Latest-report metadata is joined only within the same workspace.
The existing SQLite backup automatically includes this table.

`GET /api/targets`, `POST /api/targets` and `DELETE /api/targets/:id` provide the
saved-domain API. Mutations use the existing cookie/CSRF/origin requirements.
`GET /api/scans?target=example.com` filters all history before pagination, so a
comparison is not limited to the current mixed-domain history page.

The bootstrap advertises capabilities. The frontend hides saved-domain controls
when an older backend does not advertise them, allowing a graceful reload with
mixed old/new requests. Old clients continue to use the unchanged scan API.

DNS/email observations reuse the existing queries and keep explicit query
outcomes. See [observation scope](DNS-OBSERVATIONS.md). They do not change the
header score. HTML/Markdown exports and clipboard summaries are generated in
the browser; HTML exports escape all report values, contain no scripts or remote
assets, and include a restrictive standalone CSP. Browser Print can save the
whole HTML report as PDF. Downloaded copies are outside server retention.
