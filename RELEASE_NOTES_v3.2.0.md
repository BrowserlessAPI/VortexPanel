# VortexPanel v3.2.0 — Panel Security Hardening, ModSecurity Overhaul, Settings Redesign

**Release date:** June 2026

This release focuses entirely on the panel's own security posture and operational reliability — bringing it in line with OWASP recommendations and fixing several critical bugs found during live deployment testing.

---

## 🛡 Panel Security Hardening

- **Argon2id password hashing** (OWASP's #1 recommendation, replacing bcrypt/SHA-256) with transparent 3-step migration: existing SHA-256 and bcrypt hashes upgrade silently to Argon2id on next successful login — no action needed, no lockouts.
- **2FA / TOTP** — full setup flow: generate secret → scan QR code (any authenticator app) → verify → enabled. Login now shows a second step requiring the 6-digit code once enabled. Disable requires current password confirmation.
- **Brute-force lockout** — 5 failed login attempts from the same IP → 15-minute lockout (HTTP 429), with remaining-attempts countdown shown in the error message. Lockout state persists across panel restarts (not just in-memory).
- **IP allowlist** — now enforced on *every* API request via a `before_request` hook, not just at login. A stolen session cookie used from an unlisted IP is rejected mid-session. Localhost is always exempt.
- **Session fingerprinting** — sessions are bound to a hash of IP + User-Agent; a session reused from a different browser/IP is invalidated.
- **Login audit log** — every attempt (success/failure) logged with timestamp, IP, username, and outcome. Viewable from Settings.
- **Auto-generated 64-byte secret key**, persisted to disk on first run — no more shared default Flask secret key across installs.
- **Security headers** on every response: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.

## 🔐 Panel HTTPS — done right

Earlier attempts at this feature had a critical flaw: enabling HTTPS made the panel listen on the well-known port 443, defeating the entire point of running on a custom port. This is now fixed properly:

- HTTPS is served on your **existing custom port** — never 443. Self-signed or Let's Encrypt, your choice.
- The actual cutover (switching gunicorn to loopback-only + nginx taking over the public port with TLS) is performed by an **atomic external script** — stop gunicorn, confirm the port is genuinely free, reload nginx, start gunicorn — eliminating a nasty race condition where nginx would silently fail to bind the port while still reporting "reload successful."
- The panel restart itself no longer self-terminates mid-restart: the delayed restart now runs as an independent `systemd-run` transient unit, immune to systemd's cgroup-kill-on-restart behaviour that could previously abort its own restart command.
- After enabling/disabling HTTPS, the browser is automatically redirected to the correct protocol — no more stuck "Inactive" badges or broken AJAX calls from a stale tab still talking over the old protocol.
- A plain HTTP request to the now-HTTPS-only port shows a clear "this port now requires HTTPS" message instead of nginx's raw, confusing 400 error.

## 🔑 SSH Hardening — full panel UI

- **Create sudo user** directly from the panel (username + password and/or SSH public key), automatically added to `sudo`/`wheel` depending on distro.
- **SSH key management** — detect existing keys, add new ones to `authorized_keys` with deduplication.
- **Disable root login** and **disable password authentication** toggles — both include built-in safety checks: root login can't be disabled until a sudo user exists; password auth can't be disabled until an SSH key is present. You cannot lock yourself out through the UI.
- **SSH port change** — automatically updates the firewall rule for the new port.
- `sshd -t` config validation before any change is applied.

## 🔥 ModSecurity WAF — major overhaul

- **RHEL/Fedora/AlmaLinux/Rocky/CentOS/Oracle/CloudLinux install support** — was previously `apt-get` only and completely broken on all 7 RHEL-family distros. Now uses `dnf` + EPEL correctly.
- Install now fetches the **latest OWASP CRS release** from GitHub at install time instead of a hardcoded old version.
- **3-state engine mode**: Blocking / Detection Only / Disabled (was a simple on/off).
- **Paranoia level selector** (1–4) with plain-language descriptions of the tradeoffs.
- **One-click CRS update** + **weekly auto-update cron**, installed automatically.
- **Custom rule editor** — write and save your own `SecRule` directives, validated with `nginx -t` before applying.
- **Audit log viewer** — parses `modsec_audit.log` into a readable table (timestamp, IP, method, URI, rule ID, severity, message).
- **Per-site override** — disable WAF for specific sites without touching the global setting.

## 🦠 PHP Webshell Scanner *(new)*

Scans PHP files in any site directory for known webshell patterns: `eval(base64_decode())`, `system($_GET)`, `preg_replace` with the `/e` modifier, dynamic function calls with user input, reverse-shell patterns, obfuscation markers, and more. Results are severity-coded (Critical/High/Medium) with file, line number, and code snippet shown for each finding.

## ⚙ Settings Page — complete redesign

Rebuilt from a tabbed layout into an aaPanel-style card grid:

- **Network & Access**, **Panel SSL**, **Authentication & Security**, **PHP Webshell Scanner**, **Panel Settings**, **System Information**, **AI Assistant** — each its own card with inline controls, no more digging through tabs.
- Security Score now correctly checks **firewalld** in addition to UFW (was always failing on RHEL-family before), plus new checks for Argon2id/bcrypt usage, default password, 2FA status, and secret key generation.
- (Fixed a markup bug from the initial redesign where a missing closing tag caused 5 of the 7 cards to render nested inside the Panel SSL card instead of as grid siblings — now verified correct via direct DOM inspection.)

## 🔧 Bug fixes

- `update.py` reported a hardcoded stale `v3.0.0` as the fallback version string, inconsistent with the actual running version — fixed.
- Dashboard pages no longer require a hard browser refresh after login (`vortex-logged-in` event listener was missing on the `databasesPage` component specifically, due to a regex pattern mismatch on a no-space `init(){` variant).

---

## Upgrading

```bash
cd /your/vortexpanel/source
git pull
cp -r panel/ web/ app.py /opt/vortexpanel/
pip install -r requirements.txt   # adds argon2-cffi, pyotp
systemctl restart vortexpanel
```

Or fresh install:
```bash
wget -O install.sh https://raw.githubusercontent.com/BrowserlessAPI/VortexPanel/main/install.sh && bash install.sh
```

**Recommended after upgrading:** Settings → Authentication & Security → enable 2FA. Security → SSH → create a sudo user and disable root login/password auth. Settings → Panel SSL → enable HTTPS.

---

## What's next (v3.3 roadmap)

- Disk usage analyzer
- Per-site website analytics (nginx access log → traffic/top-URIs/status-codes dashboard)
- Alerting — CPU/RAM/SSL-expiry push notifications
- Let's Encrypt auto-renewal cron
- Multi-user / RBAC
