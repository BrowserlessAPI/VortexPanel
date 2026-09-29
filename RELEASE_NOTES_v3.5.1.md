# VortexPanel v3.5.1

New site controls, a table toolbox for every database engine, current App Store
versions, and an emoji-free interface.

## Websites
- **Denser website list**: each row shows PHP, backups (count plus one-click
  backup), SSL expiry, WAF status, today's requests, and a Manage / Backup /
  Delete icon rail.
- **Stop / start a site**: the Status column is now a Running / Stopped toggle.
  Stopping keeps the vhost and answers every request with a 503 "site stopped"
  page, so the domain never falls through to another site. Starting restores
  the config byte-for-byte. nginx sites.
- **Disable SSL**: new button on the SSL tab. Removes the HTTPS server block and
  the HTTP-to-HTTPS redirect, whether SSL was added by VortexPanel or by
  certbot. Certificate files stay on disk so SSL can be turned back on.
- **SSL summary banner**: certificate brand, domain and expiry countdown (red at
  14 days or less), with Renew and Disable buttons. The Let's Encrypt button
  reads "Renew Certificate" once a certificate exists.
- **Site drawer**: fade on open and on every tab switch; the tab list's padding
  and hover states are fixed.

## Databases
- **Table toolbox for every engine** (Tables / Collections button on each
  database):
  - MySQL / MariaDB: engine, collation, rows, size; Repair, Optimize,
    Convert InnoDB / MyISAM.
  - PostgreSQL: schema, rows, size; Reindex, Vacuum, Analyze.
  - MongoDB: documents, size; Validate, Compact.
- Database, table and collection names are validated before they reach a query.

## App Store: current upstream versions
| App | Now offered |
|---|---|
| Nginx | 1.30.5 stable, 1.31.6 mainline (both fix CVE-2026-90439, HTTP/3 heap overflow) |
| PHP | 8.5.11, 8.4.26, 8.3.35 (security only), 8.2.34 (security only, EOL Dec 2026); 8.1 / 7.4 marked EOL |
| MariaDB | 13.0.2 (new series), 12.3.3, 11.8.9 LTS, 11.4.13 LTS, 10.11.19 LTS |
| PostgreSQL | 18.6 (new), 17.11, 16.15, 15.19 |
| MongoDB | 8.0.32 LTS, 8.2.12 (new), 7.0.43 LTS |
| Python | 3.14 (new), 3.13, 3.12, 3.11, 3.10 (EOL Oct 2026) |
| Redis | 8.10.2, 8.8.3 (Sep 17 security releases), 7.4.11 |
| Node.js | v24 LTS (24.21), v22 LTS (22.23), v26 Current (26.10) |
| OpenLiteSpeed | 1.9.2, 1.8.5, 1.8.4 (also in the version switcher) |
| phpMyAdmin | 5.2.3 |
| Roundcube | 1.7.4, 1.6.19 LTS |
| Composer | 2.10 |
| Fail2ban | 1.1.1 |
| Docker | 29.8.1 (v29 is the only supported release; v28 ended May 2026) |
| BIND 9 | 9.20 stable; 9.18 marked upstream EOL (June 2026) |

`app_catalog.json` is regenerated (catalog v2), so panels on 3.5.0 pick up the
new labels through **Update App List** even before they update.

## Interface
- Every emoji in the panel is replaced with a consistent line-icon set (sidebar,
  drawer tabs, file manager, service and cron lists, CDN providers, database
  engines) or removed from text.
- `theme.css` is now cache-busted with the panel version, so style changes reach
  browsers right after an update.

## Fixes
- **Security Updates kept showing as pending after they were applied**: the
  card re-read a check that is cached for 4 hours, and the apply job never
  refreshed it. The apply job now refreshes the cache when it finishes, and a
  "Check again" button forces a live check. Also:
  - apt runs fully non-interactive (no hanging config-file or
    "restart services?" prompts), and waits for a dpkg lock instead of failing
  - output streams into the card while it runs, and a page reload resumes the
    progress view
  - a job left "running" by a panel restart is recovered instead of blocking
    every later attempt with "already in progress"
- **Panel SSL (self-signed / Let's Encrypt / Disable)**:
  - the certificate is test-started on a spare local port before the real
    service is touched
  - the switch runs in a detached helper that checks the panel answers on the
    new scheme and restores the previous settings automatically if it doesn't,
    so a bad certificate can no longer leave the panel unreachable
  - the page now reliably redirects: requests over the old scheme used to hang
    instead of failing, so the redirect never fired
  - the self-signed certificate now carries the correct IP / domain names
- **PHP Webshell Scanner**:
  - scans run in the background with live progress; they used to run inside
    the request, so any real site outlived the worker timeout and returned
    nothing
  - you can scan the whole web root or a single site
  - rule fixes: stock WordPress went from 111 findings (77 critical) to 1 minor
    item to review, while every test webshell is still caught. The false
    positives came from backticks in doc comments, `$_REQUEST` mentioned in
    comments, `$pdo->exec()` / `curl_exec()` being treated as shell exec, and
    short hex runs in libraries.
- **Manual and Cloudflare-DNS SSL could break nginx for every site**: the old
  HTTP-to-HTTPS redirect was inserted in the middle of the `server_name` line,
  which failed `nginx -t` and left the broken file in place. The HTTPS block it
  created also had no PHP handling, so PHP sites served their source code over
  HTTPS. Both paths now clone the full site block (PHP and rewrites included),
  are validated with `nginx -t`, and are restored automatically on failure.
  Disable SSL also repairs configs damaged by the old bug.
- Removed an orphaned closing `</div>` on the Settings page.

## Upgrading
Installed panels see **Update Available** for 3.5.1. After updating, hard-refresh
the browser once (Ctrl+Shift+R).
