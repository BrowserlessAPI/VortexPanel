# VortexPanel v3.8.1

A small fix release on top of 3.8.0.

- **Updating from 3.6.0 or older no longer stops with "untracked working tree files would be overwritten by checkout: web/static/js/i18n.js".** Panels that had a language pack applied by hand kept a copy of that file outside git, and the update of those versions refused to replace it. The language script is now called `vp-lang.js`, so the update goes through. Nothing has to be done on the server.
- **Hosting Module:** after buying or activating a licence, the Hosting Accounts page and its menu entry appear right away; reloading the panel is no longer needed.
- Compiled Python files are no longer part of the repository.

Everything below is from 3.8.0.

## VortexPanel v3.8.0

New tools from the aaPanel feature list (Python projects, Git deploy, site clone, malware scan, SSH sign-in alerts, site statistics, database recycle bin, global search), a plugin system, and a layout pass over the whole panel.

## Layout fixes

- **Buttons that did nothing**: Alpine 3.15 treats an empty `:disabled` value as "disabled". PHP extension Install/Uninstall and about 160 other buttons, checkboxes and selects were affected; every boolean binding is now explicit.
- **Broken windows and empty bars**: a text `:style` binding replaced the element's own style (including the hidden state), so closed error boxes showed as empty red bars, toggles grew into page-wide blocks and windows lost their layout. All style bindings now merge instead of replace, and elements shown again keep their flex/grid layout.
- **PHP settings** opens as a window with a side menu (Service, Extensions, Settings, Disabled functions, Upload limit, Timeouts, Configuration, Load status, FPM log, Slow log, phpinfo). **Switch version** shows the current version, the installed versions and a clear switch button.
- The website window and the app settings windows share one window layout, with a close button that is always visible.
- **Tables on phones** show each row as a card with the column names, so action buttons are never cut off; wide tables scroll inside their card on larger screens.
- Top bar on phones: search, theme and update buttons fit; the language picker is in the side menu there.
- Dark mode contrast fixes for badges, inputs and code blocks.

## New

- **Python projects**: virtualenv per project, Gunicorn, Uvicorn or a custom command, systemd service running as a normal user, served on a domain through the web server, clone from Git and pull, install Python versions (3.10 to 3.14).
- **Git deploy** (website window > Git Deploy): repository and branch, a deploy key for private repositories, deploy now, a webhook for GitHub/GitLab (signature checked), a command to run after each deploy as the site owner. The repository data is kept outside the web root (no `.git` folder is published) and files that are not in the repository (uploads, `.env`) are kept.
- **Clone site** (website window > Clone Site): copies the files, the database (new name, user and password) and the rewrite rules to a new domain; WordPress URLs are replaced. The original site is not touched.
- **Site statistics** (website window > Statistics): page views, unique visitors, requests, bots, status codes, top pages, referrers, visitor addresses and browsers for 7 to 90 days, collected from the access logs together with bandwidth (no tracking script).
- **Malware scan** (Security > Malware scan): webshell signatures, PHP files in upload folders and ClamAV when installed. Quarantine (restorable), mark as "not a threat", daily or weekly schedule with an alert when something is found.
- **SSH sign-ins** (Security > SSH sign-ins): accepted and failed logins from the journal or auth log, the addresses with the most failures and a block button (Fail2ban, or the firewall). New alert rule: every successful SSH sign-in, and many failed attempts within a few minutes.
- **Database recycle bin**: a dropped database is kept as a compressed dump for 7 days and can be restored from Databases > Recycle bin.
- **Global search** (Ctrl+K or the search box in the top bar): pages, websites, installed apps and Node.js, Go and Python projects.
- **DNS**: edit a record in place; new zones can use your own nameservers (ns1/ns2.yourdomain) instead of ns1.<customer domain>.
- **Plugins**: add-ons live in `/opt/vortexpanel/plugins/<name>`, add their own pages, never replace panel files and are skipped (not fatal) if they fail to load or do not match the panel version. Settings > Plugins and `vortexpanel plugins list|enable|disable|safe-mode`. The Hosting Module 3.0 is a plugin.
- Alert rules for Git deploys and malware findings.
- **Server migration** (Migration page): move websites (files, website settings, SSL certificates), MySQL/MariaDB and PostgreSQL databases (with their users and passwords) and the websites' cron jobs to another VortexPanel server. The new server shows a migration key; the old one sends. The websites keep running during the copy (files are read at low priority, databases are exported without table locks) and the copy on the new server is only switched in when complete. "Sync again" refreshes the copy right before the DNS change. All data is encrypted with the key, also when the panel runs without HTTPS. MySQL 8 to MariaDB is converted automatically.
- **SSL through your DNS provider** (website window > SSL): validation with a DNS record instead of port 80, so it works behind Cloudflare or a closed port 80, and can include all subdomains (*.example.com). Providers: this server's own DNS, Cloudflare, DigitalOcean, Amazon Route 53, Hetzner, GoDaddy, Namecheap, Porkbun, Linode, Vultr, Gandi, OVHcloud, Bunny, deSEC, Duck DNS, Alibaba Cloud, DNSPod, Tencent Cloud. Renewed automatically.
- **Let's Encrypt for the panel's IP address** (Settings > Panel SSL): enter the server's IP instead of a domain. These certificates are valid for 6 days and are renewed automatically every few days.
- **Adminer** in the App Store (port 8084): manage MySQL/MariaDB, PostgreSQL and MongoDB in the browser; the PHP database drivers it needs are installed with it.
- **Bot protection with Anubis** (App Store > Security > Anubis Bot Protection, then website window > Bot Protection): stops AI scrapers and bad bots with a short browser check, turned on per website (Nginx websites). Each protected website runs its own small Anubis service with its own settings. Search engines are never checked: Google (including AdSense, Ads and Search Console), Bing, Apple and DuckDuckGo are recognised by their published addresses, which are updated every night; a fake Googlebot from another address gets the check. robots.txt, sitemaps, feeds, ads.txt, `.well-known`, verification files, icons, CSS, JavaScript, fonts and (unless you choose otherwise) images are never checked either. Separate switches block AI training crawlers (on by default) and AI search and assistants (off by default). Levels Standard, Strict and Under attack; pause for an hour; extra open paths for callbacks such as payment webhooks. A search engine test runs after every change and every night, and a watchdog removes the protection from a website whose service stops answering (the website keeps working) and sends an alert. Password-protected folders keep their password prompt. Websites behind Cloudflare get the real visitor address set up first.
- **Maintenance mode for all websites** (Websites > Maintenance mode): one switch shows a maintenance page on every website, Node.js, Go, Python and Docker site, with an allow list of IP addresses that still see the sites; certificate renewals keep working.

## App Store

- OpenLiteSpeed 1.9 (recommended) and 1.8.5; Apache 2.4.69 (recommended) and 2.4.68.

## Security

- wp-cli runs as the site's owner for sites of hosting accounts (never as root), with the owner's own home folder.
- Installing Node.js packages runs as the folder's owner, so a project's install scripts cannot run as root; `git pull` of Node.js projects runs as the project user.
- A WordPress install always creates a new, empty database (it no longer reuses an existing database of the same name).
- Password-protected folders also protect the PHP files in them (they were reachable without the password before).
- WordPress clone, backup, restore and staging push work for sites owned by hosting accounts; a failed clone removes what it created.
- Plugin, theme and path values sent to the WP Toolkit are validated; site managers can only act on their own site's WordPress.
- Adding an email forwarder without the mail server installed returns a message instead of an error page.
- Mail: sending through port 587 (STARTTLS) and 465 (TLS) with login, and every mailbox can only send as itself (no sending in the name of other mailboxes or domains on the server).
- New websites and Git deploys never publish dot files (`.git`, `.env`); the repository data of a Git deploy is kept outside the web root.
- DNS: adding a record that already exists is refused.
- PostgreSQL installs from the distribution when the PostgreSQL package repository cannot be reached.

## Hosting Module

The Hosting Module is now version 3.1, a plugin installed with its own script (`vortex_hosting_module_3.1.0.py`). Servers that run module 1.x or 2.x: run the module installer after this update (the update runs it automatically when it is next to the update script). Accounts, sites, databases, mailboxes and FTP users are kept.

**Buying the Hosting Module from the panel.** The new Hosting Module page (Overview menu) lets you choose the number of servers, the server type and monthly or yearly billing, shows the total with any pack saving, takes a discount code and opens the payment page (Dodo Payments). The order progress (payment confirmed, licence active, module installed) is shown on the same page, and once the payment is confirmed the panel activates the licence on this server and downloads and installs the module by itself (signed package, checked against the key built into the panel; backup and rollback like the installer script). "I already have a licence key" activates a key, also when moving to a new server (once every 30 days). The panel checks the licence every 12 hours and keeps working for 14 days when the licence server cannot be reached. When a licence ends, only the module's admin side locks (new accounts and package changes); customer websites, mail and the customer portal keep running. Register on the VortexPanel forum with the licence email to get the License Holder badge. Questions: support@vortexpanel.dev; refunds: refund@vortexpanel.dev.

Bot protection for hosting customers: the package decides whether customers may use it, on how many websites, the highest level, and whether they may add open paths or check images; it can also be turned on automatically for new websites. Each account can follow its package or have bot protection turned off, and the administrator can lock a customer website's settings. Customers turn it on in the portal (Websites > Bot protection) for their own websites only. Suspending an account stops the protection of its websites and reactivating it restores it; terminating removes it. The server-wide switch is in App Store > Anubis > Defaults.
