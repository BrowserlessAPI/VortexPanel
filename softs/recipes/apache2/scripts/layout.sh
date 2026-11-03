#!/bin/bash
# First install only: write the distribution's Apache configuration layout.
#   layout.sh deb   -> /etc/apache2 (Debian/Ubuntu layout)
#   layout.sh rpm   -> /etc/httpd   (RHEL layout)
# Existing files are never overwritten.
. "$(dirname "$0")/lib.sh"
set -e
MODS="$VP_PREFIX/modules"
MIME=/etc/mime.types; [ -r "$MIME" ] || MIME="$VP_CURRENT/conf/mime.types"
put() { [ -e "$1" ] || { install -d "$(dirname "$1")"; cat > "$1"; }; }   # put FILE  (text on stdin)
deps_of() {  # Debian-style "# Depends:" for a module
  case "$1" in
    ssl) echo "setenvif mime socache_shmcb" ;;
    proxy) echo "" ;;
    proxy_balancer) echo "proxy alias slotmem_shm" ;;
    proxy_*) echo "proxy" ;;
    lbmethod_*) echo "proxy_balancer" ;;
    cache_disk|cache_socache) echo "cache" ;;
    authnz_ldap) echo "ldap" ;;
    authnz_fcgi) echo "" ;;
    http2) echo "" ;;
    md) echo "" ;;
    *) echo "" ;;
  esac
}

if [ "$1" = deb ]; then
  E=/etc/apache2
  install -d $E/mods-available $E/mods-enabled $E/sites-available $E/sites-enabled $E/conf-available $E/conf-enabled
  put $E/envvars <<'EOF'
# envvars - default environment variables for apache2ctl (VortexPanel build)
unset HOME
export APACHE_RUN_USER=www-data
export APACHE_RUN_GROUP=www-data
export APACHE_PID_FILE=/run/apache2/apache2.pid
export APACHE_RUN_DIR=/run/apache2
export APACHE_LOCK_DIR=/var/lock/apache2
export APACHE_LOG_DIR=/var/log/apache2
export LANG=C
export LANG
EOF
  put $E/apache2.conf <<'EOF'
# Apache main configuration (VortexPanel build, Debian layout)
DefaultRuntimeDir ${APACHE_RUN_DIR}
PidFile ${APACHE_PID_FILE}
Timeout 300
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5
User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}
HostnameLookups Off
ErrorLog ${APACHE_LOG_DIR}/error.log
LogLevel warn
Mutex file:${APACHE_LOCK_DIR} default

IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf
Include ports.conf

<Directory />
	Options FollowSymLinks
	AllowOverride None
	Require all denied
</Directory>
<Directory /usr/share>
	AllowOverride None
	Require all granted
</Directory>
<Directory /var/www/>
	Options Indexes FollowSymLinks
	AllowOverride None
	Require all granted
</Directory>

AccessFileName .htaccess
<FilesMatch "^\.ht">
	Require all denied
</FilesMatch>

LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent

IncludeOptional conf-enabled/*.conf
IncludeOptional sites-enabled/*.conf
EOF
  put $E/ports.conf <<'EOF'
Listen 80

<IfModule ssl_module>
	Listen 443
</IfModule>
EOF
  # one .load per module, like Debian
  for so in "$MODS"/mod_*.so; do
    m="$(basename "$so" .so)"; m="${m#mod_}"
    d="$(deps_of "$m")"
    { [ -n "$d" ] && echo "# Depends: $d"
      [[ "$m" == mpm_* ]] && echo "# Conflicts: $(ls "$MODS" | sed -n 's/^mod_\(mpm_[a-z]*\)\.so$/\1/p' | grep -vx "$m" | tr '\n' ' ')"
      echo "LoadModule ${m}_module /usr/lib/apache2/modules/mod_${m}.so"; } | put "$E/mods-available/$m.load"
  done
  put $E/mods-available/mpm_event.conf <<'EOF'
<IfModule mpm_event_module>
	StartServers             2
	MinSpareThreads          25
	MaxSpareThreads          75
	ThreadLimit              64
	ThreadsPerChild          25
	MaxRequestWorkers        150
	MaxConnectionsPerChild   0
</IfModule>
EOF
  put $E/mods-available/mpm_prefork.conf <<'EOF'
<IfModule mpm_prefork_module>
	StartServers             5
	MinSpareServers          5
	MaxSpareServers          10
	MaxRequestWorkers        150
	MaxConnectionsPerChild   0
</IfModule>
EOF
  put $E/mods-available/mpm_worker.conf <<'EOF'
<IfModule mpm_worker_module>
	StartServers             2
	MinSpareThreads          25
	MaxSpareThreads          75
	ThreadLimit              64
	ThreadsPerChild          25
	MaxRequestWorkers        150
	MaxConnectionsPerChild   0
</IfModule>
EOF
  put $E/mods-available/dir.conf <<'EOF'
<IfModule mod_dir.c>
	DirectoryIndex index.html index.cgi index.pl index.php index.xhtml index.htm
</IfModule>
EOF
  put $E/mods-available/mime.conf <<EOF
<IfModule mod_mime.c>
	TypesConfig $MIME
	AddType application/x-compress .Z
	AddType application/x-gzip .gz .tgz
	AddType application/x-bzip2 .bz2
	AddLanguage en .en
	AddCharset UTF-8 .utf8
	AddHandler type-map var
	AddType text/html .shtml
	<IfModule mod_include.c>
		AddOutputFilter INCLUDES .shtml
	</IfModule>
</IfModule>
EOF
  put $E/mods-available/ssl.conf <<'EOF'
<IfModule mod_ssl.c>
	SSLRandomSeed startup builtin
	SSLRandomSeed connect builtin
	AddType application/x-x509-ca-cert .crt
	AddType application/x-pkcs7-crl .crl
	SSLPassPhraseDialog exec:/bin/echo
	SSLSessionCache shmcb:${APACHE_RUN_DIR}/ssl_scache(512000)
	SSLSessionCacheTimeout 300
	SSLCipherSuite HIGH:!aNULL
	SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
	SSLHonorCipherOrder off
</IfModule>
EOF
  put $E/mods-available/status.conf <<'EOF'
<IfModule mod_status.c>
	<Location /server-status>
		SetHandler server-status
		Require local
	</Location>
	ExtendedStatus On
</IfModule>
EOF
  put $E/mods-available/http2.conf <<'EOF'
<IfModule mod_http2.c>
	Protocols h2 h2c http/1.1
</IfModule>
EOF
  put $E/conf-available/security.conf <<'EOF'
ServerTokens Prod
ServerSignature Off
TraceEnable Off
<DirectoryMatch "/\.git">
	Require all denied
</DirectoryMatch>
EOF
  put $E/conf-available/charset.conf <<'EOF'
#AddDefaultCharset UTF-8
EOF
  put $E/sites-available/000-default.conf <<'EOF'
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF
  if [ -z "$(ls -A $E/mods-enabled 2>/dev/null)" ]; then
    for m in access_compat alias auth_basic authn_core authn_file authz_core authz_host authz_user autoindex deflate dir env \
             filter mime mpm_event negotiation reqtimeout setenvif status; do
      for f in load conf; do [ -e "$E/mods-available/$m.$f" ] && ln -sfn "../mods-available/$m.$f" "$E/mods-enabled/$m.$f"; done
    done
    for c in security charset; do ln -sfn "../conf-available/$c.conf" "$E/conf-enabled/$c.conf"; done
    [ -z "$(ls -A $E/sites-enabled 2>/dev/null)" ] && ln -sfn ../sites-available/000-default.conf $E/sites-enabled/000-default.conf
  fi
  install -d -m 0755 /var/www/html /var/log/apache2
  chown root:adm /var/log/apache2 2>/dev/null || true
  [ -e /var/www/html/index.html ] || echo '<h1>Apache</h1>' > /var/www/html/index.html
  exit 0
fi

# ------------------------------------------------------------------- RHEL layout
H=/etc/httpd
ensure_user apache /usr/share/httpd
install -d $H/conf $H/conf.d $H/conf.modules.d /var/log/httpd /var/www/html /var/www/cgi-bin
chmod 0700 /var/log/httpd
[ -e $H/logs ] || ln -s ../../var/log/httpd $H/logs
[ -e $H/run ] || ln -s /run/httpd $H/run
put $H/conf/httpd.conf <<EOF
# Apache main configuration (VortexPanel build, RHEL layout)
ServerRoot "/etc/httpd"
Listen 80
Include conf.modules.d/*.conf
User apache
Group apache
ServerAdmin root@localhost
PidFile /run/httpd/httpd.pid
DefaultRuntimeDir /run/httpd

<Directory />
    AllowOverride none
    Require all denied
</Directory>
DocumentRoot "/var/www/html"
<Directory "/var/www">
    AllowOverride None
    Require all granted
</Directory>
<Directory "/var/www/html">
    Options Indexes FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>
<IfModule dir_module>
    DirectoryIndex index.html index.php
</IfModule>
<Files ".ht*">
    Require all denied
</Files>

ErrorLog "logs/error_log"
LogLevel warn
<IfModule log_config_module>
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %b" common
    CustomLog "logs/access_log" combined
</IfModule>
<IfModule mime_module>
    TypesConfig $MIME
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz
    AddType text/html .shtml
</IfModule>
AddDefaultCharset UTF-8
EnableSendfile on
ServerTokens Prod
ServerSignature Off
TraceEnable Off

IncludeOptional conf.d/*.conf
EOF
if [ ! -e $H/conf.modules.d/00-vortex.conf ]; then
  {
    echo "# Modules loaded by default (VortexPanel build). Every module is in /etc/httpd/modules."
    for m in mpm_event authz_core authz_host authz_user authn_core authn_file auth_basic access_compat alias dir mime env \
             setenvif filter deflate headers rewrite expires remoteip reqtimeout autoindex negotiation status \
             socache_shmcb ssl http2 proxy proxy_fcgi proxy_http proxy_wstunnel; do
      [ -e "$MODS/mod_$m.so" ] && echo "LoadModule ${m}_module modules/mod_${m}.so"
    done
    cat <<'EOF'

<IfModule http2_module>
    Protocols h2 h2c http/1.1
</IfModule>
EOF
  } > $H/conf.modules.d/00-vortex.conf
fi
# HTTPS like the distribution's mod_ssl package: port 443 with a self-signed localhost
# certificate for the default server (websites get their own certificates)
if [ ! -e $H/conf.d/ssl.conf ]; then
  install -d -m 0755 /etc/pki/tls/certs; install -d -m 0700 /etc/pki/tls/private
  if [ ! -e /etc/pki/tls/certs/localhost.crt ]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 -subj "/CN=$(hostname -f 2>/dev/null || echo localhost)" \
      -keyout /etc/pki/tls/private/localhost.key -out /etc/pki/tls/certs/localhost.crt >/dev/null 2>&1
    chmod 0600 /etc/pki/tls/private/localhost.key
  fi
  cat > $H/conf.d/ssl.conf <<'EOF'
<IfModule ssl_module>
Listen 443 https
SSLPassPhraseDialog exec:/bin/echo
SSLSessionCache shmcb:/run/httpd/sslcache(512000)
SSLSessionCacheTimeout 300
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite HIGH:!aNULL
<VirtualHost _default_:443>
    ErrorLog logs/ssl_error_log
    CustomLog logs/ssl_access_log combined
    SSLEngine on
    SSLCertificateFile /etc/pki/tls/certs/localhost.crt
    SSLCertificateKeyFile /etc/pki/tls/private/localhost.key
</VirtualHost>
</IfModule>
EOF
fi
[ -e /var/www/html/index.html ] || echo '<h1>Apache</h1>' > /var/www/html/index.html
exit 0
