# VortexPanel v3.4.18

Security, correctness, and full multi-distro App Store coverage.

## Security
- Validate domain names before they reach shell commands / filesystem paths
  (site + WordPress create/clone, and imported-site paths).
- Reject non-version-tag input in the panel self-updater (`git checkout`).
- Enforce the IP allowlist on the terminal WebSocket (`/ws/…`), not just `/api/`.
- Return a clean 403 (not a 500) for disallowed IPs; set `SESSION_COOKIE_SECURE`
  for HTTPS deployments; require auth on `/api/settings/webroot`.
- Remove the hardcoded `admin/admin123` fallback (random password instead).

## App Store — all 9 distros (Ubuntu, Debian, AlmaLinux, Rocky, RHEL, Oracle,
## CentOS Stream, CloudLinux, Fedora)
- RHEL/dnf-yum install paths added: apache2 (httpd), php (Remi), python, nodejs
  (rpm.nodesource), redis, supervisor, ddns (EPEL), mariadb (package-manager
  agnostic), phpMyAdmin (portable fetch); Fedora nginx via base repo.
- Family-agnostic uninstalls for every app (apt + dnf + yum).
- Service-name resolver so start/stop/status use the real unit per distro
  (httpd / supervisord / mysqld).

## Correctness / logic
- PostgreSQL DB listing crash; MongoDB create/drop; maintenance-mode vhost
  corruption + rollback; RHEL sudo group; CDN config-save crash; SSL `www.`
  only for apex domains; Cloudflare proxied flag preserved + retry; monotonic
  DNS serial; Docker proxy cleanup on remove; HTTP/3 duplicate reuseport;
  Go/Node default service user; PHP extension + php.ini paths on RHEL;
  RHEL log-viewer paths; per-distro deploy web-user/unzip; AI disabled guard.
- Includes the WP Toolkit OpenLiteSpeed fixes (lsphp detection, vhRoot/
  restrained, lswsctrl reload, log-dir creation) and install-path fix.
