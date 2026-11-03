#!/bin/bash
# Remove the program; /etc/apache2 or /etc/httpd (sites, certificates) and the logs are kept.
# On a failed switch (VP_ACTION=abort) nothing else is needed here: the engine reinstalls the
# removed OS packages and puts /etc/apache2 and /etc/modsecurity back exactly (keep_on_switch),
# which also brings back mod_php and the MPM as they were.
. "$(dirname "$0")/lib.sh"
# a failed switch: put back the PHP files the mod_php -> PHP-FPM conversion changed outside
# /etc/apache2 (.htaccess, .user.ini, the vortex-modphp and website pools)
if [ "$VP_ACTION" = abort ] && [ -f "${VP_SWITCH_STATE:-/var/lib/vortex-apache-switch}/changes.json" ]; then
  python3 "$(dirname "$0")/php_fpm_switch.py" undo || true
  if has_systemd; then
    for u in $(systemctl list-units --type=service --all --plain --no-legend 'php*-fpm.service' 2>/dev/null | awk '{print $1}'); do
      systemctl restart "$u" 2>/dev/null || true
    done
  fi
fi
for s in apache2 httpd; do
  svc_stop $s
  has_systemd && systemctl disable $s >/dev/null 2>&1 || true
done
for p in /run/apache2/apache2.pid /run/httpd/httpd.pid; do
  [ -s "$p" ] && kill -TERM "$(cat "$p")" 2>/dev/null || true
done
rm -f /etc/systemd/system/apache2.service /etc/systemd/system/httpd.service
has_systemd && systemctl daemon-reload || true
for f in /usr/sbin/apache2 /usr/sbin/apache2ctl /usr/sbin/apachectl /usr/sbin/httpd /usr/lib/apache2/modules /etc/httpd/modules \
         /usr/sbin/a2enmod /usr/sbin/a2dismod /usr/sbin/a2ensite /usr/sbin/a2dissite /usr/sbin/a2enconf /usr/sbin/a2disconf /usr/sbin/a2query; do
  unlink_ours "$f"
done
for u in ab htpasswd htdigest htdbm htcacheclean logresolve rotatelogs httxt2dbm checkgid fcgistarter; do unlink_ours "/usr/bin/$u"; done
true
