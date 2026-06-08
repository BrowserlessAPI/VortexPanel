from flask import Blueprint, jsonify, request, session, Response
import subprocess, os, threading, time, json, uuid, re

modules_bp = Blueprint('modules', __name__)
def req(): return 'user' in session
_jobs = {}

def sh(c, t=10):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()
    except: return ''

def get_version(mod_id):
    cmds = {
        'caddy':        "caddy version 2>/dev/null | awk '{print $1}' | tr -d v",
        'nginx':        "nginx -v 2>&1 | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'apache2':      "apache2 -v 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'openlitespeed':"cat /usr/local/lsws/VERSION 2>/dev/null || /usr/local/lsws/bin/lshttpd -v 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+'",
        'mysql':        "mysql --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'mariadb':      "mariadb --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1 || mysqld --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'mongodb':      "mongod --version 2>/dev/null | grep -oP 'v[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'postgresql':   "psql --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+' | head -1",
        'php':          "for v in 8.5 8.4 8.3 8.2 8.1 8.0 7.4; do if which php$v >/dev/null 2>&1; then php$v --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1; break; fi; done",
        'redis':        "redis-server --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'nodejs':       "node --version 2>/dev/null | tr -d 'v'",
        'python':       "python3 --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+'",
        'docker':       "docker --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'composer':     "composer --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'fail2ban':     "fail2ban-client --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'pure-ftpd':    "pure-ftpd --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'clamav':       "clamscan --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'bind9':        "named -v 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'supervisor':   "supervisord --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+'",
        'redis':        "redis-server --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'opendkim':     "opendkim --version 2>&1 | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'phpmyadmin':   "cat /usr/share/phpmyadmin/README 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1 || cat /usr/share/phpmyadmin/ChangeLog 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1 || grep -oP \"'PMA_VERSION','[^']+'\" /usr/share/phpmyadmin/libraries/classes/Config/Settings.php 2>/dev/null | grep -oP \"[0-9]+\\.[0-9]+\\.[0-9]+\" | head -1",
        'mariadb':      "mysql --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'pure-ftpd':    "pure-ftpd --help 2>&1 | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1 || dpkg -l pure-ftpd 2>/dev/null | grep '^ii' | awk '{print $3}' | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+'",
        'mongodb':      "mongod --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'openlitespeed':"cat /usr/local/lsws/VERSION 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1 || /usr/local/lsws/bin/lshttpd -v 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
    }
    cmd = cmds.get(mod_id, '')
    if not cmd: return ''
    v = sh(cmd)
    return v[:20] if v else ''

def is_installed(check_cmd):
    try:
        r = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, timeout=5)
        out = r.stdout.strip()
        if out in ('', '0', 'inactive', 'unknown', 'failed', 'activating'): return False
        return r.returncode == 0
    except: return False

MODULES = [
    # ── Web Servers ──────────────────────────────────────────────────────────
    {
        'id':'nginx', 'name':'Nginx', 'icon':'🌐', 'category':'Web Server',
        'desc':'High-performance HTTP & reverse proxy server',
        'check':'which nginx 2>/dev/null',
        'versions':[
            {'label':'1.30.2 (Stable)',   'value':'stable'},
            {'label':'1.31.1 (Mainline)', 'value':'mainline'},
        ],
        'install_tpl':'''apt-get install -y curl gnupg2 ca-certificates lsb-release && \
curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --batch --yes --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg && \
REPO="http://nginx.org/packages/{ver}/ubuntu" && \
[ "{ver}" = "stable" ] && REPO="http://nginx.org/packages/ubuntu" || true && \
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] $REPO $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list && \
apt-get update -o APT::Update::Error-Mode=any 2>/dev/null && \
apt-get install -y nginx && systemctl enable --now nginx''',
        'install':'(apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y nginx && systemctl enable --now nginx',
        'uninstall':'apt-get remove -y --purge nginx nginx-common nginx-full nginx-core && apt-get autoremove -y && rm -rf /etc/nginx',
        'service':'nginx', 'manage':True,
    },
    {
        'id':'apache2', 'name':'Apache2', 'icon':'🔴', 'category':'Web Server',
        'desc':'Apache HTTP Server — widely-used web server',
        'check':'which apache2 2>/dev/null',
        'versions':[
            {'label':'2.4.67 (Latest Stable)', 'value':'2.4'},
        ],
        'install':'apt-get install -y apache2 && systemctl enable apache2 && systemctl start apache2',
        'uninstall':'apt-get remove -y --purge apache2 apache2-utils apache2-bin && apt-get autoremove -y',
        'service':'apache2', 'manage':True,
    },
    {
        'id':'openlitespeed', 'name':'OpenLiteSpeed', 'icon':'⚡', 'category':'Web Server',
        'desc':'LiteSpeed open source web server',
        'check':'test -f /usr/local/lsws/bin/lshttpd && echo found',
        'versions':[
            {'label':'1.8.4 (Stable)',  'value':'1.8.4'},
            {'label':'1.8.5 (Stable)',  'value':'1.8.5'},
            {'label':'1.9.0 (Latest)',  'value':'1.9.0'},
        ],
        'install_tpl':'''wget -q https://repo.litespeed.sh -O ls_repo.sh && bash ls_repo.sh && \
(apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y openlitespeed={ver} 2>/dev/null || \
apt-get install -y openlitespeed && \
systemctl enable lsws && systemctl start lsws''',
        'install':'''wget -q https://repo.litespeed.sh -O ls_repo.sh && bash ls_repo.sh && \
(apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y openlitespeed && \
systemctl enable lsws && systemctl start lsws''',
        'uninstall':'/usr/local/lsws/admin/misc/uninstall.sh 2>/dev/null; apt-get remove -y openlitespeed 2>/dev/null; rm -rf /usr/local/lsws',
        'service':'lsws', 'manage':True,
    },
    # ── Databases ────────────────────────────────────────────────────────────
    {
        'id':'caddy', 'name':'Caddy', 'icon':'🟩', 'category':'Web Server',
        'desc':'Auto-HTTPS web server — HTTP/3, zero-config TLS via Lets Encrypt',
        'check':'which caddy 2>/dev/null',
        'versions':[
            {'label':'v2.11.3 (Latest Stable)', 'value':'2.11.3'},
            {'label':'v2.11.2 (Stable)',         'value':'2.11.2'},
        ],
        'install_tpl':'''apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl && \
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
  gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && \
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
  tee /etc/apt/sources.list.d/caddy-stable.list && \
chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg && \
chmod o+r /etc/apt/sources.list.d/caddy-stable.list && \
(apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y caddy && \
systemctl enable caddy && systemctl start caddy''',
        'install':'''apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl && \
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
  gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && \
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
  tee /etc/apt/sources.list.d/caddy-stable.list && \
chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg && \
chmod o+r /etc/apt/sources.list.d/caddy-stable.list && \
(apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y caddy && \
systemctl enable caddy && systemctl start caddy''',
        'uninstall':'apt-get remove -y --purge caddy && apt-get autoremove -y && rm -rf /etc/caddy',
        'service':'caddy', 'manage':True,
    },
    {
        'id':'mysql', 'name':'MySQL', 'icon':'🐬', 'category':'Database',
        'desc':'The world\'s most popular open source database',
        'check':'dpkg -l mysql-server 2>/dev/null | grep -c "^ii"',
        'versions':[
            {'label':'8.0.41 (LTS)',   'value':'8.0'},
            {'label':'8.4.4 (LTS)',    'value':'8.4'},
            {'label':'9.3.0 (Latest)', 'value':'9.0'},
        ],
        'install_tpl':'''apt-get install -y wget lsb-release gnupg && \
wget -q https://dev.mysql.com/get/mysql-apt-config_0.8.33-1_all.deb -O /tmp/mysql-apt.deb && \
DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/mysql-apt.deb && \
apt-get update -q && \
DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server-{ver} 2>/dev/null || \
DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server && \
systemctl enable --now mysql''',
        'install':'DEBIAN_FRONTEND=noninteractive apt-get install -y mysql-server && systemctl enable mysql && systemctl start mysql',
        'uninstall':'apt-get remove -y --purge mysql-server mysql-client mysql-common mysql-server-core-* mysql-client-core-* && apt-get autoremove -y && rm -rf /etc/mysql /var/lib/mysql',
        'service':'mysql', 'manage':True,
    },
    {
        'id':'mariadb', 'name':'MariaDB', 'icon':'🦭', 'category':'Database',
        'desc':'Community-developed MySQL fork by MariaDB Foundation',
        'check':'dpkg -l mariadb-server 2>/dev/null | grep -c "^ii"',
        'versions':[
            {'label':'10.11.11 (LTS)',  'value':'10.11'},
            {'label':'11.4.5 (LTS)',    'value':'11.4'},
            {'label':'11.7.2 (Latest)', 'value':'11.7'},
        ],
        'install_tpl':'''curl -LsS https://downloads.mariadb.com/MariaDB/mariadb_repo_setup -o /tmp/mariadb_repo.sh && \
bash /tmp/mariadb_repo.sh --mariadb-server-version="mariadb-{ver}" && \
apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server && \
systemctl enable --now mariadb''',
        'install':'DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server && systemctl enable mariadb && systemctl start mariadb',
        'uninstall':'apt-get remove -y --purge mariadb-server mariadb-client mariadb-common && apt-get autoremove -y && rm -rf /etc/mysql /var/lib/mysql',
        'service':'mariadb', 'manage':True,
    },
    {
        'id':'mongodb', 'name':'MongoDB', 'icon':'🍃', 'category':'Database',
        'desc':'Document-oriented NoSQL database',
        'check':'which mongod 2>/dev/null',
        'versions':[
            {'label':'7.0 (LTS)',    'value':'7.0'},
            {'label':'8.0 (Latest)', 'value':'8.0'},
        ],
        'install_tpl':'''apt-get install -y gnupg curl && \
curl -fsSL https://www.mongodb.org/static/pgp/server-{ver}.asc | gpg -o /usr/share/keyrings/mongodb-server-{ver}.gpg --dearmor 2>/dev/null && \
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-{ver}.gpg ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/{ver} multiverse" | tee /etc/apt/sources.list.d/mongodb-org-{ver}.list && \
(apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y mongodb-org && systemctl enable mongod && systemctl start mongod''',
        'install':'',  # always uses install_tpl
        'uninstall':'apt-get remove -y --purge mongodb-org mongodb-org-* && apt-get autoremove -y && rm -rf /var/lib/mongodb /var/log/mongodb',
        'service':'mongod', 'manage':True,
    },
    {
        'id':'postgresql', 'name':'PostgreSQL', 'icon':'🐘', 'category':'Database',
        'desc':'Advanced open source relational database',
        'check':'which psql 2>/dev/null',
        'versions':[
            {'label':'15 (Stable)', 'value':'15'},
            {'label':'16 (Stable)', 'value':'16'},
            {'label':'17 (Latest)', 'value':'17'},
        ],
        'install_tpl':'''apt-get install -y gnupg2 curl lsb-release && \
curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /usr/share/keyrings/postgresql.gpg && \
echo "deb [signed-by=/usr/share/keyrings/postgresql.gpg] http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" | tee /etc/apt/sources.list.d/pgdg.list && \
(apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y postgresql-{ver} && systemctl enable postgresql && systemctl start postgresql''',
        'install':'apt-get install -y postgresql postgresql-contrib && systemctl enable postgresql && systemctl start postgresql',
        'uninstall':'apt-get remove -y --purge postgresql postgresql-* && apt-get autoremove -y && rm -rf /etc/postgresql /var/lib/postgresql',
        'service':'postgresql', 'manage':True,
    },
    # ── PHP ──────────────────────────────────────────────────────────────────
    {
        'id':'php', 'name':'PHP', 'icon':'🐘', 'category':'PHP',
        'desc':'PHP-FPM — multiple versions supported side by side',
        'check':'which php8.5 php8.4 php8.3 php8.2 php8.1 php8.0 2>/dev/null | head -1',
        'versions':[
            {'label':'7.4 (Legacy)',    'value':'7.4'},
            {'label':'8.1 (Security)',  'value':'8.1'},
            {'label':'8.2 (Active)',    'value':'8.2'},
            {'label':'8.3 (Active)',    'value':'8.3'},
            {'label':'8.4 (Current)',   'value':'8.4'},
            {'label':'8.5 (Latest)',    'value':'8.5'},
        ],
        'install_tpl':'''apt-get install -y software-properties-common && \
add-apt-repository -y ppa:ondrej/php && apt-get update -q && \
apt-get install -y php{ver} php{ver}-fpm php{ver}-common php{ver}-mysql php{ver}-xml \
php{ver}-curl php{ver}-gd php{ver}-mbstring php{ver}-zip php{ver}-bcmath php{ver}-intl \
php{ver}-soap php{ver}-cli php{ver}-readline && \
systemctl enable php{ver}-fpm && systemctl start php{ver}-fpm && \
WEB_USER=$(grep -oP '^user\\s+\\K\\S+' /etc/nginx/nginx.conf 2>/dev/null | tr -d ';' | head -1) && \
WEB_USER=${WEB_USER:-www-data} && \
POOL=/etc/php/{ver}/fpm/pool.d/www.conf && \
grep -q '^listen.owner' $POOL && sed -i "s|^listen.owner.*|listen.owner = $WEB_USER|" $POOL || echo "listen.owner = $WEB_USER" >> $POOL && \
grep -q '^listen.group' $POOL && sed -i "s|^listen.group.*|listen.group = $WEB_USER|" $POOL || echo "listen.group = $WEB_USER" >> $POOL && \
systemctl restart php{ver}-fpm''',
        'install':'',
        'uninstall_tpl':'''systemctl stop php{ver}-fpm 2>/dev/null || true && \
systemctl disable php{ver}-fpm 2>/dev/null || true && \
apt-get remove -y --purge php{ver} php{ver}-fpm php{ver}-common php{ver}-mysql \
php{ver}-xml php{ver}-curl php{ver}-gd php{ver}-mbstring php{ver}-zip php{ver}-bcmath \
php{ver}-intl php{ver}-soap php{ver}-cli php{ver}-readline php{ver}-* 2>/dev/null || true && \
apt-get autoremove -y 2>/dev/null || true''',
        'uninstall':'''for ver in 7.4 8.1 8.2 8.3 8.4; do
  systemctl stop php$ver-fpm 2>/dev/null || true
  apt-get remove -y --purge php$ver php$ver-* 2>/dev/null || true
done
apt-get autoremove -y 2>/dev/null || true''',
        'manage':False,
    },
    # ── FTP ──────────────────────────────────────────────────────────────────
    {
        'id':'pure-ftpd', 'name':'Pure-FTPd', 'icon':'📂', 'category':'FTP',
        'desc':'Simple, fast and secure FTP server',
        'check':'which pure-ftpd 2>/dev/null',
        'versions':[
            {'label':'1.0.52 (Latest Stable)', 'value':'latest'},
        ],
        'install':'apt-get install -y pure-ftpd pure-ftpd-common && systemctl enable pure-ftpd && systemctl start pure-ftpd',
        'uninstall':'apt-get remove -y --purge pure-ftpd pure-ftpd-common && apt-get autoremove -y',
        'service':'pure-ftpd', 'manage':True,
    },
    # ── Admin Tools ──────────────────────────────────────────────────────────
    {
        'id':'phpmyadmin', 'name':'phpMyAdmin', 'icon':'🗄', 'category':'Admin Tools',
        'desc':'Web-based MySQL/MariaDB admin — auto-configured at port 8082',
        'check':'test -d /usr/share/phpmyadmin && echo found',
        'versions':[
            {'label':'5.2.2 (Latest)', 'value':'5.2.2'},
        ],
        'install':(
            'DEBIAN_FRONTEND=noninteractive apt-get install -y wget && '
            'wget -q https://files.phpmyadmin.net/phpMyAdmin/5.2.2/'
            'phpMyAdmin-5.2.2-all-languages.tar.gz -O /tmp/pma.tar.gz && '
            'mkdir -p /usr/share/phpmyadmin && '
            'tar -xzf /tmp/pma.tar.gz -C /usr/share/phpmyadmin --strip-components=1 && '
            'cp /usr/share/phpmyadmin/config.sample.inc.php /usr/share/phpmyadmin/config.inc.php && '
            # phpMyAdmin 5.2 supports PHP 7.2-8.4 only, prefer compatible version
            'SOCK="" && '
            'for v in 8.4 8.3 8.2 8.1 8.0 7.4 8.5; do '
            '  if [ -S /run/php/php${v}-fpm.sock ]; then SOCK=/run/php/php${v}-fpm.sock; break; fi; '
            'done && '
            'SOCK=${SOCK:-/run/php/php8.5-fpm.sock} && '
            # Detect active web server and configure
            'if systemctl is-active nginx >/dev/null 2>&1; then '
            '  NGINX_USER=$(grep -oP "^user\\s+\\K\\S+" /etc/nginx/nginx.conf 2>/dev/null | tr -d ";" | head -1) && '
            '  NGINX_USER=${NGINX_USER:-www-data} && '
            '  mkdir -p /etc/nginx/conf.d && '
            '  printf "server {\\n  listen 8082;\\n  server_name _;\\n  root /usr/share/phpmyadmin;\\n  index index.php;\\n  location ~ \\\\.php$ {\\n    fastcgi_split_path_info ^(.+\\.php)(/.+)$;\\n    fastcgi_pass unix:$SOCK;\\n    fastcgi_index index.php;\\n    include fastcgi_params;\\n    fastcgi_param SCRIPT_FILENAME \\$document_root\\$fastcgi_script_name;\\n  }\\n}\\n" > /etc/nginx/conf.d/phpmyadmin.conf && '
            '  for v in 8.4 8.3 8.2 8.1 8.0 7.4 8.5; do '
            '    POOL=/etc/php/${v}/fpm/pool.d/www.conf; '
            '    [ -f "$POOL" ] || continue; '
            '    grep -q "^listen.owner" "$POOL" && sed -i "s|^listen.owner.*|listen.owner = $NGINX_USER|" "$POOL" || echo "listen.owner = $NGINX_USER" >> "$POOL"; '
            '    grep -q "^listen.group" "$POOL" && sed -i "s|^listen.group.*|listen.group = $NGINX_USER|" "$POOL" || echo "listen.group = $NGINX_USER" >> "$POOL"; '
            '    systemctl restart php${v}-fpm 2>/dev/null || true; '
            '  done && '
            '  nginx -t 2>/dev/null && systemctl reload nginx; '
            'elif systemctl is-active caddy >/dev/null 2>&1; then '
            '  printf "\n:8082 {\n  root * /usr/share/phpmyadmin\n  php_fastcgi unix/$SOCK\n  file_server\n}\n" >> /etc/caddy/Caddyfile && '
            '  systemctl reload caddy; '
            'elif systemctl is-active apache2 >/dev/null 2>&1; then '
            '  a2enmod proxy_fcgi setenvif 2>/dev/null; '
            '  cat > /etc/apache2/conf-available/phpmyadmin.conf << APACHEEOF\n'
            'Listen 8082\n'
            '<VirtualHost *:8082>\n'
            '  DocumentRoot /usr/share/phpmyadmin\n'
            '  <Directory /usr/share/phpmyadmin>\n'
            '    Options FollowSymLinks\n'
            '    DirectoryIndex index.php\n'
            '    Require all granted\n'
            '  </Directory>\n'
            '  <FilesMatch \.php$>\n'
            '    SetHandler "proxy:unix:$SOCK|fcgi://localhost"\n'
            '  </FilesMatch>\n'
            '</VirtualHost>\n'
            'APACHEEOF\n'
            '  a2enconf phpmyadmin && systemctl reload apache2; '
            'elif systemctl is-active lsws >/dev/null 2>&1; then '
            '  mkdir -p /usr/local/lsws/conf/vhosts/phpmyadmin && '
            '  echo "docRoot /usr/share/phpmyadmin" > /usr/local/lsws/conf/vhosts/phpmyadmin/vhconf.conf && '
            '  systemctl restart lsws; '
            'fi && '
            'echo "[VortexPanel] phpMyAdmin ready at http://YOUR-SERVER-IP:8082"'
        ),
        'uninstall':(
            'rm -rf /usr/share/phpmyadmin && '
            'rm -f /etc/nginx/conf.d/phpmyadmin.conf && '
            'systemctl reload nginx 2>/dev/null || true && '
            # Remove from Caddyfile
            'sed -i "/:8082/,/^}/d" /etc/caddy/Caddyfile 2>/dev/null && '
            'systemctl reload caddy 2>/dev/null || true && '
            'rm -f /etc/apache2/conf-available/phpmyadmin.conf && '
            'systemctl reload apache2 2>/dev/null || true'
        ),
        'manage':False,
    },
    # ── Security ─────────────────────────────────────────────────────────────
    {
        'id':'fail2ban', 'name':'Fail2ban', 'icon':'🛡', 'category':'Security',
        'desc':'Intrusion prevention & brute-force protection',
        'check':'which fail2ban-client 2>/dev/null',
        'versions':[
            {'label':'1.1.0 (Latest Stable)', 'value':'latest'},
        ],
        'install':'''apt-get install -y python3 python3-pip curl gzip && \
F2B_VER=$(curl -s https://api.github.com/repos/fail2ban/fail2ban/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+') && \
F2B_VER=${F2B_VER:-1.1.0} && \
curl -fsSL https://github.com/fail2ban/fail2ban/releases/download/${F2B_VER}/fail2ban_${F2B_VER#v}-1.upstream1_all.deb -o /tmp/fail2ban.deb 2>/dev/null && \
(dpkg -i /tmp/fail2ban.deb 2>/dev/null || apt-get install -y fail2ban) && \
systemctl enable fail2ban && systemctl start fail2ban''',
        'uninstall':'apt-get remove -y --purge fail2ban && apt-get autoremove -y',
        'service':'fail2ban', 'manage':True,
    },
    {
        'id':'clamav', 'name':'ClamAV', 'icon':'🦠', 'category':'Security',
        'desc':'Open source antivirus engine for mail gateways',
        'check':'which clamscan 2>/dev/null',
        'versions':[
            {'label':'1.4.2 (Latest Stable)', 'value':'latest'},
        ],
        'install':'''apt-get install -y curl && \
CLAM_VER=$(curl -s https://api.github.com/repos/Cisco-Talos/clamav/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+') && \
CLAM_VER=${CLAM_VER:-clamav-1.4.2} && \
CLAM_NUM=${CLAM_VER#clamav-} && \
curl -fsSL https://www.clamav.net/downloads/production/clamav-${CLAM_NUM}.linux.x86_64.deb -o /tmp/clamav.deb 2>/dev/null && \
(dpkg -i /tmp/clamav.deb 2>/dev/null || apt-get install -y clamav clamav-daemon) && \
apt-get install -f -y && \
systemctl enable clamav-freshclam && freshclam 2>/dev/null || true && systemctl start clamav-daemon''',
        'uninstall':'apt-get remove -y --purge clamav clamav-daemon clamav-freshclam && apt-get autoremove -y',
        'service':'clamav-daemon', 'manage':True,
    },
    # ── DNS ──────────────────────────────────────────────────────────────────
    {
        'id':'ddns', 'name':'DDNS Manager', 'icon':'🌍', 'category':'DNS',
        'desc':'Dynamic DNS — automatic IP update service',
        'check':'which ddclient 2>/dev/null',
        'versions':[
            {'label':'3.11.2 (Latest)', 'value':'latest'},
        ],
        'install':'apt-get install -y ddclient',
        'uninstall':'apt-get remove -y --purge ddclient && apt-get autoremove -y',
        'manage':False,
    },
    {
        'id':'bind9', 'name':'BIND9 DNS', 'icon':'🌐', 'category':'DNS',
        'desc':'Industry standard authoritative DNS server',
        'check':'which named 2>/dev/null',
        'versions':[
            {'label':'9.18 (ESV/LTS)', 'value':'9.18'},
            {'label':'9.20 (Latest)',  'value':'9.20'},
        ],
        'install':'apt-get install -y bind9 bind9utils bind9-doc && systemctl enable bind9 && systemctl start bind9',
        'uninstall':'apt-get remove -y --purge bind9 bind9utils && apt-get autoremove -y',
        'service':'bind9', 'manage':True,
    },
    # ── Runtimes ─────────────────────────────────────────────────────────────
    {
        'id':'nodejs', 'name':'Node.js', 'icon':'🟢', 'category':'Runtime',
        'desc':'JavaScript runtime built on Chrome V8 engine',
        'check':'which node 2>/dev/null || which nodejs 2>/dev/null',
        'versions':[
            {'label':'v22 LTS  (Jod)',     'value':'22'},
            {'label':'v24 LTS  (Krypton)', 'value':'24'},
            {'label':'v26 Current',        'value':'26'},
        ],
        'install_tpl':'curl -fsSL https://deb.nodesource.com/setup_{ver}.x | bash - && apt-get install -y nodejs',
        'install':'curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs',
        'uninstall':'apt-get remove -y --purge nodejs && apt-get autoremove -y',
        'manage':False,
    },
    {
        'id':'python', 'name':'Python Manager', 'icon':'🐍', 'category':'Runtime',
        'desc':'Python 3 runtime + pip + venv',
        'check':'which python3 2>/dev/null',
        'versions':[
            {'label':'3.10 (Security)', 'value':'3.10'},
            {'label':'3.11 (Security)', 'value':'3.11'},
            {'label':'3.12 (Active)',   'value':'3.12'},
            {'label':'3.13 (Latest)',   'value':'3.13'},
        ],
        'install_tpl':'''apt-get install -y software-properties-common && \
add-apt-repository -y ppa:deadsnakes/ppa && apt-get update -q && \
apt-get install -y python{ver} python{ver}-venv python{ver}-dev && \
curl -sS https://bootstrap.pypa.io/get-pip.py | python{ver} 2>/dev/null || true''',
        'install':'apt-get install -y python3 python3-pip python3-venv python3-dev',
        'uninstall_tpl':'''apt-get remove -y --purge python{ver} python{ver}-venv python{ver}-dev \
python{ver}-distutils python{ver}-lib2to3 2>/dev/null || true && \
apt-get autoremove -y 2>/dev/null || true && \
update-alternatives --remove python /usr/bin/python{ver} 2>/dev/null || true''',
        'uninstall':'''for ver in 3.10 3.11 3.12 3.13; do
  apt-get remove -y --purge python$ver python$ver-* 2>/dev/null || true
done
apt-get autoremove -y 2>/dev/null || true''',
        'manage':False,
    },
    # ── Containers ───────────────────────────────────────────────────────────
    {
        'id':'docker', 'name':'Docker', 'icon':'🐳', 'category':'Containers',
        'desc':'Container platform — build, ship, run anywhere',
        'check':'which docker 2>/dev/null',
        'versions':[
            {'label':'v27 CE (Stable)',  'value':'27'},
            {'label':'v28 CE (Stable)',  'value':'28'},
            {'label':'v29 CE (Latest)',  'value':'29'},
        ],
        'install':'curl -fsSL https://get.docker.com | sh && systemctl enable docker && systemctl start docker',
        'uninstall':'apt-get remove -y --purge docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin && apt-get autoremove -y',
        'service':'docker', 'manage':True,
    },
    # ── Dev ──────────────────────────────────────────────────────────────────
    {
        'id':'composer', 'name':'Composer', 'icon':'🎼', 'category':'Dev',
        'desc':'PHP dependency & package manager',
        'check':'which composer 2>/dev/null',
        'versions':[
            {'label':'2.8 (Latest Stable)', 'value':'2'},
        ],
        'install':'curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer',
        'uninstall':'rm -f /usr/local/bin/composer',
        'manage':False,
    },
    # ── Cache ────────────────────────────────────────────────────────────────
    {
        'id':'redis', 'name':'Redis', 'icon':'🔴', 'category':'Cache',
        'desc':'In-memory data store, cache & message broker',
        'check':'which redis-server 2>/dev/null',
        'versions':[
            {'label':'7.2.7 (Stable)', 'value':'7.2'},
            {'label':'8.0.2 (Latest)', 'value':'8.0'},
        ],
        'install_tpl':'''curl -fsSL https://packages.redis.io/gpg | gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg && \
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list && \
apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; \
apt-get install -y redis-server && systemctl enable redis-server && systemctl start redis-server''',
        'install':'''curl -fsSL https://packages.redis.io/gpg | gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg && \
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list && \
apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; \
apt-get install -y redis-server && systemctl enable redis-server && systemctl start redis-server''',
        'uninstall':'apt-get remove -y --purge redis-server redis-tools && apt-get autoremove -y',
        'service':'redis-server', 'manage':True,
    },
    # ── Server Tools ─────────────────────────────────────────────────────────
    {
        'id':'supervisor', 'name':'Supervisor', 'icon':'⚙', 'category':'Server',
        'desc':'Process control — keep programs running',
        'check':'which supervisord 2>/dev/null',
        'versions':[
            {'label':'4.3.0 (Latest Stable)', 'value':'latest'},
        ],
        'install':'apt-get install -y supervisor && systemctl enable supervisor && systemctl start supervisor',
        'uninstall':'apt-get remove -y --purge supervisor && apt-get autoremove -y',
        'service':'supervisor', 'manage':True,
    },
    # ── Webmail ───────────────────────────────────────────────────────────────
    {
        'id':'roundcube', 'name':'Roundcube', 'icon':'📨', 'category':'Mail',
        'desc':'Modern web-based IMAP email client',
        'check':'test -d /var/www/roundcube && echo found',
        'versions':[
            {'label':'1.6.16 (LTS)',    'value':'1.6.16'},
            {'label':'1.7.1  (Latest)', 'value':'1.7.1'},
        ],
        'install_tpl':'''apt-get install -y wget php php-mysql php-curl php-json php-mbstring \
php-intl php-imagick php-xml php-zip php-gd && \
mkdir -p /var/www/roundcube && \
wget -q https://github.com/roundcube/roundcubemail/releases/download/{ver}/roundcubemail-{ver}-complete.tar.gz \
  -O /tmp/roundcube.tar.gz && \
tar -xzf /tmp/roundcube.tar.gz -C /var/www/roundcube --strip-components=1 && \
cp /var/www/roundcube/config/config.inc.php.sample /var/www/roundcube/config/config.inc.php && \
chown -R www-data:www-data /var/www/roundcube/''',
        'install':'',
        'uninstall':'rm -rf /var/www/roundcube',
        'manage':False,
    },
    # ── WAF / Security ────────────────────────────────────────────────────────
    {
        'id':'modsecurity', 'name':'ModSecurity WAF', 'icon':'🔥', 'category':'Security',
        'desc':'OWASP Web Application Firewall for Nginx/Apache (v3)',
        'check':'dpkg -l libmodsecurity3 2>/dev/null | grep -c "^ii"',
        'versions':[
            {'label':'v3 + OWASP CRS (Recommended)', 'value':'3'},
            {'label':'v2 (Apache legacy)',            'value':'2'},
        ],
        'install_tpl':'''apt-get install -y libmodsecurity3 libmodsecurity-dev && \
apt-get install -y libnginx-mod-http-modsecurity 2>/dev/null || true && \
mkdir -p /etc/nginx/modsec && \
wget -q https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended \
  -O /etc/nginx/modsec/modsecurity.conf && \
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf && \
wget -q https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.0.0.tar.gz -O /tmp/crs.tar.gz && \
mkdir -p /etc/nginx/modsec/crs && \
tar -xzf /tmp/crs.tar.gz -C /etc/nginx/modsec/crs --strip-components=1 && \
cp /etc/nginx/modsec/crs/crs-setup.conf.example /etc/nginx/modsec/crs/crs-setup.conf && \
echo "Include /etc/nginx/modsec/modsecurity.conf" > /etc/nginx/modsec/main.conf && \
echo "Include /etc/nginx/modsec/crs/crs-setup.conf" >> /etc/nginx/modsec/main.conf && \
echo "Include /etc/nginx/modsec/crs/rules/*.conf"   >> /etc/nginx/modsec/main.conf && \
systemctl reload nginx 2>/dev/null || true''',
        'install':'apt-get install -y libmodsecurity3 libnginx-mod-http-modsecurity 2>/dev/null || true',
        'uninstall':'apt-get remove -y --purge libmodsecurity3 libnginx-mod-http-modsecurity && apt-get autoremove -y && rm -rf /etc/nginx/modsec',
        'manage':False,
    },
    # ── Load Balancer ─────────────────────────────────────────────────────────
    {
        'id':'nginx-lb', 'name':'Nginx Load Balancer', 'icon':'⚖', 'category':'Web Server',
        'desc':'Configure Nginx upstream load balancing (Round Robin, Least Conn, IP Hash)',
        'check':'test -f /etc/nginx/conf.d/loadbalancer.conf && echo found',
        'versions':[
            {'label':'Round Robin (Default)', 'value':'roundrobin'},
            {'label':'Least Connections',     'value':'leastconn'},
            {'label':'IP Hash (Sticky)',       'value':'iphash'},
        ],
        'install_tpl':'''# Create Nginx load balancer config with {ver} method
mkdir -p /etc/nginx/conf.d/
cat > /etc/nginx/conf.d/loadbalancer.conf << 'LBEOF'
# VortexPanel Load Balancer Configuration
# Method: {ver}
# Edit upstream servers below to match your backend servers

upstream vortex_backend {{
    # {ver} load balancing
    # Add/remove servers as needed
    server 127.0.0.1:8001 weight=1;
    server 127.0.0.1:8002 weight=1;
    server 127.0.0.1:8003 weight=1;

    # Health check - mark server down if it fails
    # server 127.0.0.1:8004 down;

    # Keepalive connections to upstream
    keepalive 32;
}}

# Uncomment to use Least Connections:
# upstream vortex_backend {{ least_conn; server ...; }}

# Uncomment to use IP Hash (sticky sessions):
# upstream vortex_backend {{ ip_hash; server ...; }}

server {{
    listen 80;
    server_name _;

    location / {{
        proxy_pass http://vortex_backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 10s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        proxy_next_upstream error timeout invalid_header http_500 http_502 http_503;
    }}
}}
LBEOF
nginx -t && systemctl reload nginx''',
        'install':'',
        'uninstall':'rm -f /etc/nginx/conf.d/loadbalancer.conf && systemctl reload nginx 2>/dev/null || true',
        'manage':False,
    },

    # ── CDN ───────────────────────────────────────────────────────────────────
    {
        'id':'cdn', 'name':'CDN Manager', 'icon':'⚡', 'category':'Network',
        'desc':'Connect Cloudflare, BunnyCDN, Akamai, CloudFront, KeyCDN, StackPath, Google CDN, Sucuri — HOT MODULE',
        'check':'echo found',  # Always available — built-in panel feature
        'versions':[
            {'label':'Built-in', 'value':'builtin'},
        ],
        'install':'mkdir -p /opt/vortexpanel && echo "{}" > /opt/vortexpanel/cdn_config.json',
        'uninstall':'rm -f /opt/vortexpanel/cdn_config.json',
        'manage':False,
    },
]

def _get_mod(mod_id):
    return next((m for m in MODULES if m['id'] == mod_id), None)

@modules_bp.route('/api/modules')
def list_modules():
    if not req(): return jsonify({'ok':False}), 401
    result = []
    for m in MODULES:
        installed   = is_installed(m['check'])
        svc_status  = ''
        installed_ver = ''
        if installed:
            svc = m.get('service','')
            if svc:
                r = subprocess.run(f'systemctl is-active {svc} 2>/dev/null',
                                   shell=True, capture_output=True, text=True)
                svc_status = r.stdout.strip()
            installed_ver = get_version(m['id'])
        result.append({
            'id': m['id'], 'name': m['name'], 'icon': m['icon'],
            'category': m['category'], 'desc': m['desc'],
            'installed': installed, 'svcStatus': svc_status,
            'installedVer': installed_ver,
            'versions': m.get('versions', []),
            'manage': m.get('manage', False),
        })
    return jsonify({'ok':True, 'modules':result})

@modules_bp.route('/api/modules/<mod_id>/install', methods=['POST'])
def install_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    mod = _get_mod(mod_id)
    if not mod: return jsonify({'ok':False, 'error':'Module not found'}), 404

    d   = request.get_json() or {}
    ver = d.get('version','')

    if mod.get('versions') and not ver:
        return jsonify({'ok':False, 'error':'Version required'}), 400

    tpl = mod.get('install_tpl', mod.get('install',''))
    cmd = tpl.replace('{ver}', ver) if ver and tpl else (mod.get('install', tpl) or tpl)
    if not cmd: return jsonify({'ok':False, 'error':'No install command defined'}), 400

    job_id = str(uuid.uuid4())[:8]
    _jobs[job_id] = {'status':'running', 'lines':[], 'done':False, 'success':False, 'installed':False}

    def run_job():
        _jobs[job_id]['lines'].append(f'[VortexPanel] Installing {mod["name"]} {ver}...')
        proc = subprocess.Popen(f'DEBIAN_FRONTEND=noninteractive {cmd} 2>&1',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:
            _jobs[job_id]['lines'].append(line.rstrip())
        proc.wait()
        installed     = is_installed(mod['check'])
        inst_ver      = get_version(mod['id']) if installed else ''
        _jobs[job_id].update({'installed':installed,'installedVer':inst_ver,'done':True,'success':installed,'status':'done'})
        _jobs[job_id]['lines'].append(
            f'[VortexPanel] {"✓ Installed successfully! Version: "+inst_ver if installed else "⚠ Installation may have failed — check output above."}'
        )

    threading.Thread(target=run_job, daemon=True).start()
    return jsonify({'ok':True, 'job_id':job_id, 'action':'install'})

@modules_bp.route('/api/modules/<mod_id>/uninstall', methods=['POST'])
def uninstall_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    mod = _get_mod(mod_id)
    if not mod: return jsonify({'ok':False, 'error':'Not found'}), 404

    d   = request.get_json() or {}
    ver = d.get('version','')

    # Support version-specific uninstall (PHP, Python)
    tpl = mod.get('uninstall_tpl','')
    if tpl and ver:
        cmd = tpl.replace('{ver}', ver)
    else:
        cmd = mod.get('uninstall','')

    if not cmd: return jsonify({'ok':False, 'error':'No uninstall command defined'}), 400

    job_id = str(uuid.uuid4())[:8]
    _jobs[job_id] = {'status':'running', 'lines':[], 'done':False, 'success':False, 'installed':True}

    def run_job():
        _jobs[job_id]['lines'].append(f'[VortexPanel] Removing {mod["name"]} {ver}...')
        proc = subprocess.Popen(f'DEBIAN_FRONTEND=noninteractive {cmd} 2>&1',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:
            _jobs[job_id]['lines'].append(line.rstrip())
        proc.wait()
        # For versioned modules (PHP, Python), check version-specific binary
        if ver and mod_id in ('php','python'):
            ver_binary = f'php{ver}' if mod_id=='php' else f'python{ver}'
            still_installed = bool(sh(f'which {ver_binary} 2>/dev/null'))
        else:
            still_installed = is_installed(mod['check'])
        removed = not still_installed
        # For PHP: overall 'installed' = any PHP still present
        if mod_id == 'php':
            any_php = is_installed(mod['check'])
            _jobs[job_id].update({'installed':any_php,'done':True,'success':removed,'status':'done'})
        else:
            _jobs[job_id].update({'installed':still_installed,'done':True,'success':removed,'status':'done'})
        _jobs[job_id]['lines'].append(
            f'[VortexPanel] {"✓ Removed successfully!" if removed else "⚠ May not be fully removed — check output above."}'
        )

    threading.Thread(target=run_job, daemon=True).start()
    return jsonify({'ok':True, 'job_id':job_id, 'action':'uninstall'})

@modules_bp.route('/api/modules/job/<job_id>')
def job_stream(job_id):
    def generate():
        sent = 0
        while True:
            job = _jobs.get(job_id)
            if not job:
                yield f'data: {json.dumps({"error":"Job not found"})}\n\n'; break
            while sent < len(job['lines']):
                yield f'data: {json.dumps({"line": job["lines"][sent]})}\n\n'
                sent += 1
            if job['done']:
                yield f'data: {json.dumps({"done":True,"success":job["success"],"installed":job["installed"],"installedVer":job.get("installedVer","")})}\n\n'
                break
            time.sleep(0.3)
    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

@modules_bp.route('/api/modules/<mod_id>/control', methods=['POST'])
def control_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    action = (request.get_json() or {}).get('action','status')
    mod = _get_mod(mod_id)
    if not mod: return jsonify({'ok':False}), 404
    svc = mod.get('service','')
    if svc and action in ('start','stop','restart','reload'):
        subprocess.run(f'systemctl {action} {svc} 2>&1', shell=True)
        time.sleep(0.8)
        status = subprocess.run(f'systemctl is-active {svc} 2>/dev/null',
                                shell=True, capture_output=True, text=True).stdout.strip()
        return jsonify({'ok':True, 'status':status})
    return jsonify({'ok':False, 'error':'No service defined'})


# ── App Settings Modal endpoints ─────────────────────────────────────────────

@modules_bp.route('/api/modules/<mod_id>/settings')
def get_module_settings(mod_id):
    if not req(): return jsonify({'ok': False}), 401
    import os, re as _re
    def sh(cmd, t=15):
        try: return subprocess.check_output(cmd,shell=True,text=True,stderr=subprocess.DEVNULL,timeout=t).strip()
        except: return ''

    if mod_id == 'nginx':
        status  = sh('systemctl is-active nginx') or 'inactive'
        version = sh('nginx -v 2>&1 | grep -oP "[0-9.]+"') or ''
        paths   = ['/etc/nginx/nginx.conf','/www/server/nginx/conf/nginx.conf']
        conf_path = next((p for p in paths if os.path.exists(p)), '/etc/nginx/nginx.conf')
        try:
            with open(conf_path) as f: conf_content = f.read()
        except: conf_content = ''
        log_path = next((p for p in ['/var/log/nginx/error.log','/www/wwwlogs/nginx_error.log'] if os.path.exists(p)), '')
        logs = sh('tail -100 ' + log_path) if log_path else 'No error log found'
        nginx_versions = [
            {'label':'1.30.2 (Stable)','value':'stable'},
            {'label':'1.31.1 (Mainline)','value':'mainline'},
        ]
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs,'log_path':log_path,
            'versions':nginx_versions,
            'optimization':{
                'worker_processes':    sh('grep -oP "worker_processes\\s+\\K\\S+" ' + conf_path + ' 2>/dev/null | head -1') or 'auto',
                'worker_connections':  sh('grep -oP "worker_connections\\s+\\K[0-9]+" ' + conf_path + ' 2>/dev/null | head -1') or '1024',
                'keepalive_timeout':   sh('grep -oP "keepalive_timeout\\s+\\K[0-9]+" ' + conf_path + ' 2>/dev/null | head -1') or '65',
                'client_max_body_size':sh('grep -oP "client_max_body_size\\s+\\K\\S+" ' + conf_path + ' 2>/dev/null | head -1') or '50m',
                'gzip':                sh('grep -oP "^\\s*gzip\\s+\\K\\S+" ' + conf_path + ' 2>/dev/null | head -1') or 'on',
            }})

    elif mod_id == 'apache2':
        status  = sh('systemctl is-active apache2') or 'inactive'
        version = sh("apache2 -v 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1") or ''
        paths   = ['/etc/apache2/apache2.conf','/etc/httpd/conf/httpd.conf']
        conf_path = next((p for p in paths if os.path.exists(p)), '/etc/apache2/apache2.conf')
        try:
            with open(conf_path) as f: conf_content = f.read()
        except: conf_content = ''
        logs = sh('tail -100 /var/log/apache2/error.log') or sh('journalctl -u apache2 -n 80') or 'No logs'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs})

    elif mod_id == 'openlitespeed':
        status   = sh('systemctl is-active lsws 2>/dev/null || systemctl is-active openlitespeed 2>/dev/null') or 'inactive'
        version  = sh("cat /usr/local/lsws/VERSION 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1") or ''
        conf_path = '/usr/local/lsws/conf/httpd_config.conf'
        try:
            with open(conf_path) as f: conf_content = f.read()
        except: conf_content = ''
        log_path = '/usr/local/lsws/logs/error.log'
        logs = sh(f'tail -100 {log_path}') if os.path.exists(log_path) else 'No logs'
        def lsget(key):
            return sh(f"grep -oP '{key}\s+\K\S+' {conf_path} 2>/dev/null | head -1").strip() or ''
        optimization = {
            'maxConnections':    lsget('maxConnections') or '10000',
            'maxSSLConnections': lsget('maxSSLConnections') or '10000',
            'connTimeout':       lsget('connTimeout') or '300',
            'maxKeepAliveReq':   lsget('maxKeepAliveReq') or '10000',
            'enableGzip':        lsget('enableGzip') or '1',
            'gzipCompressLevel': lsget('gzipCompressLevel') or '6',
        }
        versions = [
            {'label':'1.8.3','value':'1.8.3'},
            {'label':'1.8.4','value':'1.8.4'},
            {'label':'1.8.5 (Latest)','value':'1.8.5'},
        ]
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,
            'logs':logs,'log_path':log_path,
            'optimization':optimization,'versions':versions})

    elif mod_id == 'mysql':
        status  = sh('systemctl is-active mysql 2>/dev/null || systemctl is-active mysqld') or 'inactive'
        version = (sh("mysql --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'")+' ').split('\n')[0].strip() or ''
        paths   = ['/etc/mysql/mysql.conf.d/mysqld.cnf','/etc/mysql/my.cnf','/etc/my.cnf']
        conf_path = next((p for p in paths if os.path.exists(p)), '/etc/mysql/my.cnf')
        try:
            with open(conf_path) as f: conf_content = f.read()
        except: conf_content = ''
        log_path = '/var/log/mysql/error.log'
        logs     = sh('tail -100 ' + log_path) or sh('journalctl -u mysql -n 50') or 'No logs'
        slow_log = sh('tail -80 /var/log/mysql/mysql-slow.log 2>/dev/null') or 'Slow log not enabled'
        def mvar(var):
            return sh("mysql -e 'SHOW VARIABLES LIKE \"" + var + "\"' 2>/dev/null | awk 'NR==2{print $2}'") or ''
        def mstat(stat):
            return sh("mysql -e 'SHOW STATUS LIKE \"" + stat + "\"' 2>/dev/null | awk 'NR==2{print $2}'") or ''
        port    = mvar('port') or '3306'
        datadir = mvar('datadir') or '/var/lib/mysql'
        uptime  = mstat('Uptime') or '0'
        launch_time = sh("date -d '@$(( $(date +%s) - " + uptime + " ))' '+%Y-%m-%d %H:%M:%S' 2>/dev/null") if uptime.isdigit() else ''
        current_status = {
            'launch_time':       launch_time,
            'total_connections': mstat('Connections'),
            'send':              mstat('Bytes_sent'),
            'receive':           mstat('Bytes_received'),
            'query_per_sec':     mstat('Questions'),
            'threads_connected': mstat('Threads_connected'),
        }
        optimization = {
            'key_buffer_size':         mvar('key_buffer_size') or '8M',
            'tmp_table_size':          mvar('tmp_table_size') or '16M',
            'innodb_buffer_pool_size': mvar('innodb_buffer_pool_size') or '128M',
            'innodb_log_buffer_size':  mvar('innodb_log_buffer_size') or '8M',
            'sort_buffer_size':        mvar('sort_buffer_size') or '2M',
            'read_buffer_size':        mvar('read_buffer_size') or '128K',
            'thread_cache_size':       mvar('thread_cache_size') or '10',
            'max_connections':         mvar('max_connections') or '151',
            'table_open_cache':        mvar('table_open_cache') or '2000',
        }
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,
            'logs':logs,'log_path':log_path,'slow_log':slow_log,
            'port':port,'datadir':datadir,
            'current_status':current_status,'optimization':optimization})

    elif mod_id == 'mariadb':
        status  = sh('systemctl is-active mariadb') or 'inactive'
        version = sh("mariadb --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'") or \
                  sh("mysql --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'") or ''
        paths   = ['/etc/mysql/mariadb.conf.d/50-server.cnf','/etc/my.cnf','/etc/mysql/my.cnf']
        conf_path = next((p for p in paths if os.path.exists(p)), '/etc/mysql/my.cnf')
        try:
            with open(conf_path) as f: conf_content = f.read()
        except: conf_content = ''
        logs = sh('journalctl -u mariadb -n 80') or 'No logs'
        port = sh("mysql -e 'SHOW VARIABLES LIKE \"port\"' 2>/dev/null | awk 'NR==2{print $2}'") or '3306'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs,'port':port})

    elif mod_id == 'redis':
        status  = sh('systemctl is-active redis-server 2>/dev/null || systemctl is-active redis') or 'inactive'
        version = sh("redis-server --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'") or ''
        paths   = ['/etc/redis/redis.conf','/etc/redis.conf']
        conf_path = next((p for p in paths if os.path.exists(p)), '/etc/redis/redis.conf')
        try:
            with open(conf_path) as f: conf_content = f.read()
        except: conf_content = ''
        logs = sh('tail -100 /var/log/redis/redis-server.log 2>/dev/null') or \
               sh('journalctl -u redis -n 80') or 'No logs'
        info = sh('redis-cli INFO 2>/dev/null') or ''
        def rget(key):
            for line in info.split('\n'):
                if line.startswith(key + ':'): return line.split(':', 1)[1].strip()
            return ''
        def rcfg(key):
            r = sh('redis-cli CONFIG GET ' + key + ' 2>/dev/null')
            lines = r.split('\n')
            return lines[1] if len(lines) > 1 else ''
        current_status = {
            'uptime_in_days':             rget('uptime_in_days'),
            'tcp_port':                   rget('tcp_port'),
            'connected_clients':          rget('connected_clients'),
            'used_memory_human':          rget('used_memory_human'),
            'used_memory_rss_human':      rget('used_memory_rss_human'),
            'mem_fragmentation_ratio':    rget('mem_fragmentation_ratio'),
            'total_connections_received': rget('total_connections_received'),
            'total_commands_processed':   rget('total_commands_processed'),
            'keyspace_hits':              rget('keyspace_hits'),
            'keyspace_misses':            rget('keyspace_misses'),
        }
        optimization = {
            'bind':        rcfg('bind') or '127.0.0.1',
            'port':        rcfg('port') or '6379',
            'timeout':     rcfg('timeout') or '0',
            'maxclients':  rcfg('maxclients') or '10000',
            'databases':   rcfg('databases') or '16',
            'requirepass': rcfg('requirepass') or '',
            'maxmemory':   rcfg('maxmemory') or '0',
        }
        persistence = {
            'dir':         rcfg('dir') or '/var/lib/redis',
            'aof_enabled': rcfg('appendonly') or 'no',
            'appendfsync': rcfg('appendfsync') or 'everysec',
            'rdb_saves':   sh('redis-cli CONFIG GET save 2>/dev/null | tail -1') or '',
        }
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs,
            'current_status':current_status,'optimization':optimization,'persistence':persistence,
            'versions':[{'label':'Redis 7.2 (Stable)','value':'7.2'},{'label':'Redis 8.0 (Latest)','value':'8.0'}]})

    elif mod_id == 'php':
        php_versions = []
        for v in ['8.5','8.4','8.3','8.2','8.1','8.0','7.4','7.3','7.2']:
            if os.path.exists('/usr/bin/php' + v):
                php_versions.append({
                    'version': v,
                    'status':  sh('systemctl is-active php' + v + '-fpm') or 'inactive',
                    'ini_path':'/etc/php/' + v + '/fpm/php.ini',
                    'fpm_conf':'/etc/php/' + v + '/fpm/pool.d/www.conf',
                })
        sel = php_versions[0]['version'] if php_versions else '8.3'
        ini_path = '/etc/php/' + sel + '/fpm/php.ini'
        fpm_conf = '/etc/php/' + sel + '/fpm/pool.d/www.conf'
        try:
            with open(ini_path) as f: ini_content = f.read()
        except: ini_content = ''
        try:
            with open(fpm_conf) as f: fpm_content = f.read()
        except: fpm_content = ''
        logs = sh('tail -100 /var/log/php' + sel + '-fpm.log 2>/dev/null') or \
               sh('journalctl -u php' + sel + '-fpm -n 80') or 'No logs'
        def ini_get(key):
            return sh('grep -oP "^' + key + '\s*=\s*\K.*" ' + ini_path + ' 2>/dev/null | head -1').strip() or ''
        def fpm_get(key):
            return sh('grep -oP "^' + key + '\s*=\s*\K.*" ' + fpm_conf + ' 2>/dev/null | head -1').strip() or ''
        config = {
            'short_open_tag':      ini_get('short_open_tag') or 'On',
            'max_execution_time':  ini_get('max_execution_time') or '300',
            'memory_limit':        ini_get('memory_limit') or '128M',
            'post_max_size':       ini_get('post_max_size') or '50M',
            'upload_max_filesize': ini_get('upload_max_filesize') or '50M',
            'max_file_uploads':    ini_get('max_file_uploads') or '20',
            'display_errors':      ini_get('display_errors') or 'On',
            'date.timezone':       ini_get('date.timezone') or 'UTC',
            'max_input_time':      ini_get('max_input_time') or '60',
            'disable_functions':   ini_get('disable_functions') or '',
            'session.gc_maxlifetime': ini_get('session.gc_maxlifetime') or '1440',
        }
        fpm_profile = {
            'pm':                   fpm_get('pm') or 'dynamic',
            'pm.max_children':      fpm_get('pm.max_children') or '50',
            'pm.start_servers':     fpm_get('pm.start_servers') or '5',
            'pm.min_spare_servers': fpm_get('pm.min_spare_servers') or '5',
            'pm.max_spare_servers': fpm_get('pm.max_spare_servers') or '35',
            'listen':               fpm_get('listen') or '/run/php/php' + sel + '-fpm.sock',
            'request_slowlog_timeout': fpm_get('request_slowlog_timeout') or '0',
        }
        EXTS = [
            {'name':'fileinfo','type':'Universal','desc':'Get file MIME type and encoding'},
            {'name':'memcached','type':'Cache','desc':'Advanced distributed caching'},
            {'name':'redis','type':'Cache','desc':'Redis key-value store client'},
            {'name':'apcu','type':'Cache','desc':'PHP script bytecode cache'},
            {'name':'imagick','type':'Universal','desc':'ImageMagick graphics library'},
            {'name':'exif','type':'General','desc':'Read image EXIF information'},
            {'name':'intl','type':'Universal','desc':'Internationalization support'},
            {'name':'mbstring','type':'Universal','desc':'Multibyte string handling'},
            {'name':'zip','type':'Universal','desc':'ZIP file support'},
            {'name':'gd','type':'Universal','desc':'GD graphics library'},
            {'name':'curl','type':'Universal','desc':'cURL HTTP client'},
            {'name':'opcache','type':'Cache','desc':'PHP opcode cache'},
            {'name':'xdebug','type':'Debug','desc':'Debugger and profiler'},
            {'name':'sodium','type':'Security','desc':'Modern cryptography'},
            {'name':'xml','type':'Universal','desc':'XML parsing'},
        ]
        extensions = []
        for ext in EXTS:
            installed = bool(sh('php' + sel + ' -m 2>/dev/null | grep -ix "' + ext['name'] + '"'))
            extensions.append({**ext, 'installed': installed})
        return jsonify({'ok':True,
            'status':  sh('systemctl is-active php' + sel + '-fpm') or 'inactive',
            'version': sh('php' + sel + ' --version 2>/dev/null | head -1 | grep -oP "[0-9]+[.][0-9]+[.][0-9]+"') or sel,
            'sel_ver': sel, 'php_versions': php_versions,
            'ini_path': ini_path, 'ini_content': ini_content,
            'fpm_conf': fpm_conf, 'fpm_content': fpm_content,
            'config': config, 'fpm_profile': fpm_profile,
            'extensions': extensions, 'logs': logs,
            'phpinfo': {
                'version': sel,
                'install_path': sh('php' + sel + ' -r "echo PHP_PREFIX;" 2>/dev/null') or '/usr',
                'ini_path': ini_path,
                'loaded': sh('php' + sel + ' -m 2>/dev/null') or '',
            }})

    elif mod_id in ('pure-ftpd', 'pure_ftpd'):
        status  = sh('systemctl is-active pure-ftpd') or 'inactive'
        version = sh('pure-ftpd --version 2>/dev/null | head -1 | grep -oP "[0-9]+[.][0-9]+[.][0-9]+"') or ''
        paths   = ['/etc/pure-ftpd/pure-ftpd.conf','/etc/pure-ftpd.conf']
        conf_path = next((p for p in paths if os.path.exists(p)), '/etc/pure-ftpd/pure-ftpd.conf')
        try:
            with open(conf_path) as f: conf_content = f.read()
        except: conf_content = ''
        port = sh("grep -r '^Bind' /etc/pure-ftpd/conf/ 2>/dev/null | head -1 | awk '{print $2}'") or '21'
        users_raw = sh('pure-pw list 2>/dev/null') or ''
        users = []
        for line in users_raw.strip().split('\n'):
            if line.strip():
                parts = line.split()
                if parts:
                    users.append({'user': parts[0], 'home': parts[1] if len(parts) > 1 else '/www/wwwroot', 'status': 'active'})
        logs = sh('journalctl -u pure-ftpd -n 80') or sh('tail -50 /var/log/syslog 2>/dev/null | grep pure') or 'No logs'
        ftp_addr = sh("hostname -I 2>/dev/null | awk '{print $1}'") or 'YOUR-IP'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,
            'port':port,'users':users,'logs':logs,
            'ftp_addr':'ftp://' + ftp_addr + ':' + port,
            'versions':[{'label':'1.0.49 (Stable)','value':'1.0.49'},{'label':'1.0.52 (Latest)','value':'1.0.52'}]})

    elif mod_id == 'fail2ban':
        status  = sh('systemctl is-active fail2ban') or 'inactive'
        version = sh('fail2ban-client --version 2>/dev/null | grep -oP "[0-9]+[.][0-9]+[.][0-9]+"') or ''
        try:
            with open('/etc/fail2ban/ip.blacklist') as f: black_ips = f.read()
        except: black_ips = ''
        try:
            with open('/etc/fail2ban/ip.whitelist') as f: white_ips = f.read()
        except: white_ips = '127.0.0.1/8'
        jails_raw = sh('fail2ban-client status 2>/dev/null') or ''
        jail_line = _re.findall(r'Jail list:\s+(.+)', jails_raw)
        jails = []
        if jail_line:
            for jail in jail_line[0].replace(' ', '').split(','):
                if not jail: continue
                jail_status = sh('fail2ban-client status ' + jail + ' 2>/dev/null') or ''
                banned = _re.findall(r'Banned IP list:\s+(.+)', jail_status)
                banned_ips = banned[0].split() if banned else []
                currently  = _re.search(r'Currently banned:\s+(\d+)', jail_status)
                jails.append({'name': jail, 'banned_ips': banned_ips,
                              'currently': currently.group(1) if currently else '0'})
        logs = sh('tail -80 /var/log/fail2ban.log 2>/dev/null') or \
               sh('journalctl -u fail2ban -n 80') or 'No logs'
        return jsonify({'ok':True,'status':status,'version':version,
            'jails':jails,'black_ips':black_ips,'white_ips':white_ips,'logs':logs})

    elif mod_id == 'supervisor':
        status  = sh('systemctl is-active supervisor') or 'inactive'
        version = sh('supervisord --version 2>/dev/null') or ''
        conf_path = '/etc/supervisor/supervisord.conf'
        try:
            with open(conf_path) as f: conf_content = f.read()
        except: conf_content = ''
        logs = sh('tail -80 /var/log/supervisor/supervisord.log 2>/dev/null') or \
               sh('journalctl -u supervisor -n 80') or 'No logs'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs})

    elif mod_id == 'clamav':
        status  = sh('systemctl is-active clamav-daemon') or 'inactive'
        version = sh('clamscan --version 2>/dev/null | grep -oP "[0-9]+[.][0-9]+[.][0-9]+"') or ''
        logs    = sh('tail -80 /var/log/clamav/clamav.log 2>/dev/null') or \
                  sh('journalctl -u clamav-daemon -n 80') or 'No logs'
        return jsonify({'ok':True,'status':status,'version':version,'logs':logs})

    elif mod_id == 'postgresql':
        status  = sh('systemctl is-active postgresql') or 'inactive'
        version = sh('psql --version 2>/dev/null | grep -oP "[0-9]+[.][0-9]+"') or ''
        paths   = ['/etc/postgresql/16/main/postgresql.conf',
                   '/etc/postgresql/15/main/postgresql.conf',
                   '/etc/postgresql/14/main/postgresql.conf']
        conf_path = next((p for p in paths if os.path.exists(p)), paths[0])
        try:
            with open(conf_path) as f: conf_content = f.read()
        except: conf_content = ''
        logs = sh('journalctl -u postgresql -n 80') or 'No logs'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs})

    elif mod_id == 'mongodb':
        status  = sh('systemctl is-active mongod') or 'inactive'
        version = sh('mongod --version 2>/dev/null | grep -oP "[0-9]+[.][0-9]+[.][0-9]+"') or ''
        conf_path = '/etc/mongod.conf'
        try:
            with open(conf_path) as f: conf_content = f.read()
        except: conf_content = ''
        logs = sh('tail -80 /var/log/mongodb/mongod.log 2>/dev/null') or \
               sh('journalctl -u mongod -n 80') or 'No logs'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs})

    elif mod_id == 'phpmyadmin':
        pma_conf = '/etc/nginx/conf.d/phpmyadmin.conf'
        port = '8082'
        if os.path.exists(pma_conf):
            with open(pma_conf) as f: cc = f.read()
            m = _re.search(r'listen\s+(\d+)', cc)
            if m: port = m.group(1)
        php_versions = [v for v in ['8.5','8.4','8.3','8.2','8.1','8.0','7.4'] if os.path.exists('/usr/bin/php' + v)]
        current_php = ''
        if os.path.exists(pma_conf):
            with open(pma_conf) as f: cc = f.read()
            m = _re.search(r'php(\d+\.\d+)-fpm\.sock', cc)
            if m: current_php = m.group(1)
        return jsonify({'ok':True,'installed':os.path.isdir('/usr/share/phpmyadmin'),
            'port':port,'url':'http://YOUR-IP:' + port,
            'php_versions':php_versions,'current_php':current_php,'conf_path':pma_conf})

    elif mod_id == 'docker':
        status  = sh('systemctl is-active docker') or 'inactive'
        version = sh('docker version --format "{{.Server.Version}}" 2>/dev/null') or ''
        info    = sh('docker info 2>/dev/null | head -25') or ''
        return jsonify({'ok':True,'status':status,'version':version,'info':info})

    elif mod_id == 'caddy':
        status   = sh('systemctl is-active caddy') or 'inactive'
        version  = sh("caddy version 2>/dev/null | awk '{print $1}' | tr -d v") or ''
        conf_path = '/etc/caddy/Caddyfile'
        try:
            with open(conf_path) as f: conf_content = f.read()
        except: conf_content = ''
        log_path = '/var/log/caddy/caddy.log'
        logs = sh(f'tail -100 {log_path} 2>/dev/null') or sh('journalctl -u caddy -n 100 --no-pager') or 'No logs'
        # Parse global options from Caddyfile
        def cget(key):
            return sh(f"grep -oP '^\s*{key}\s+\K\S+' {conf_path} 2>/dev/null | head -1").strip() or ''
        global_opts = {
            'email':      cget('email') or '',
            'http_port':  cget('http_port') or '80',
            'https_port': cget('https_port') or '443',
            'admin':      cget('admin') or 'localhost:2019',
        }
        # TLS cert info
        tls_certs = sh("ls /var/lib/caddy/.local/share/certmagic/acme/acme-v02.api.letsencrypt.org/sites/ 2>/dev/null || ls /root/.local/share/caddy/certificates/ 2>/dev/null | head -20") or 'No certificates found'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs,'log_path':log_path,
            'global_opts':global_opts,'tls_certs':tls_certs})

    elif mod_id == 'nodejs':
        status  = sh('systemctl is-active nodejs 2>/dev/null') or 'inactive'
        version = sh('node --version 2>/dev/null | tr -d v') or ''
        npm_ver = sh('npm --version 2>/dev/null') or ''
        node_path = sh('which node 2>/dev/null') or ''
        npm_path  = sh('which npm 2>/dev/null') or ''
        info = f'Node.js {version}\nnpm {npm_ver}\nnode: {node_path}\nnpm: {npm_path}'
        return jsonify({'ok':True,'status':'active' if node_path else 'inactive',
            'version':version,'info':info})

    # Generic fallback
    mod = _get_mod(mod_id)
    if not mod: return jsonify({'ok':False,'error':'Module not found'}), 404
    svc    = mod.get('service', mod_id)
    status = sh('systemctl is-active ' + svc + ' 2>/dev/null') or 'inactive'
    version= sh(svc + ' --version 2>/dev/null | head -1') or ''
    return jsonify({'ok':True,'status':status,'version':version})



@modules_bp.route('/api/modules/<mod_id>/settings', methods=['POST'])
def save_module_settings(mod_id):
    """Save app-specific settings."""
    if not req(): return jsonify({'ok': False}), 401

    import os
    d = request.get_json() or {}
    action = d.get('action', 'save_config')
    ver = d.get('version', '')

    if action == 'get_ver_data' and ver:
        import os as _os
        ini_path = f'/etc/php/{ver}/fpm/php.ini'
        fpm_conf = f'/etc/php/{ver}/fpm/pool.d/www.conf'
        try:
            with open(ini_path) as f: ini_content = f.read()
        except: ini_content = ''
        try:
            with open(fpm_conf) as f: fpm_content = f.read()
        except: fpm_content = ''
        def ini_get(key):
            import re as _re
            m = _re.search(rf'^{re.escape(key)}\s*=\s*(.+)', ini_content, _re.MULTILINE)
            return m.group(1).strip() if m else ''
        def fpm_get(key):
            import re as _re
            m = _re.search(rf'^{re.escape(key)}\s*=\s*(.+)', fpm_content, _re.MULTILINE)
            return m.group(1).strip() if m else ''
        import subprocess as _sp
        def sh2(c):
            try: return _sp.check_output(c,shell=True,text=True,stderr=_sp.DEVNULL,timeout=10).strip()
            except: return ''
        raw = sh2(f'php{ver} -m 2>/dev/null')
        installed_exts = set(e.lower().strip() for e in raw.splitlines() if e.strip() and not e.startswith('['))
        EXTS = [
            {'name':'fileinfo','type':'Universal','desc':'Get file MIME type'},
            {'name':'redis','type':'Cache','desc':'Redis client'},
            {'name':'apcu','type':'Cache','desc':'PHP opcode cache'},
            {'name':'imagick','type':'Universal','desc':'ImageMagick'},
            {'name':'exif','type':'General','desc':'Read image EXIF'},
            {'name':'intl','type':'Universal','desc':'Internationalization'},
            {'name':'mbstring','type':'Universal','desc':'Multibyte strings'},
            {'name':'zip','type':'Universal','desc':'ZIP support'},
            {'name':'gd','type':'Universal','desc':'GD graphics'},
            {'name':'curl','type':'Universal','desc':'cURL HTTP client'},
            {'name':'opcache','type':'Cache','desc':'Opcode cache'},
            {'name':'xdebug','type':'Debug','desc':'Debugger'},
            {'name':'sodium','type':'Security','desc':'Cryptography'},
            {'name':'xml','type':'Universal','desc':'XML parsing'},
        ]
        extensions = [{**e, 'installed': e['name'] in installed_exts} for e in EXTS]
        config = {
            'short_open_tag':         ini_get('short_open_tag') or 'On',
            'max_execution_time':     ini_get('max_execution_time') or '300',
            'memory_limit':           ini_get('memory_limit') or '128M',
            'post_max_size':          ini_get('post_max_size') or '50M',
            'upload_max_filesize':    ini_get('upload_max_filesize') or '50M',
            'max_file_uploads':       ini_get('max_file_uploads') or '20',
            'display_errors':         ini_get('display_errors') or 'Off',
            'date.timezone':          ini_get('date.timezone') or 'UTC',
            'max_input_time':         ini_get('max_input_time') or '60',
            'disable_functions':      ini_get('disable_functions') or '',
            'session.gc_maxlifetime': ini_get('session.gc_maxlifetime') or '1440',
        }
        fpm_profile = {
            'pm':                   fpm_get('pm') or 'dynamic',
            'pm.max_children':      fpm_get('pm.max_children') or '50',
            'pm.start_servers':     fpm_get('pm.start_servers') or '5',
            'pm.min_spare_servers': fpm_get('pm.min_spare_servers') or '5',
            'pm.max_spare_servers': fpm_get('pm.max_spare_servers') or '35',
            'listen':               fpm_get('listen') or f'/run/php/php{ver}-fpm.sock',
            'request_slowlog_timeout': fpm_get('request_slowlog_timeout') or '0',
        }
        logs = sh2(f'tail -80 /var/log/php{ver}-fpm.log 2>/dev/null') or                sh2(f'journalctl -u php{ver}-fpm -n 50 --no-pager') or 'No logs'
        version_full = sh2(f"php{ver} --version 2>/dev/null | head -1 | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'") or ver
        status = sh2(f'systemctl is-active php{ver}-fpm 2>/dev/null') or 'inactive'
        return jsonify({'ok':True,'version':version_full,'status':status,'ini_path':ini_path,
            'ini_content':ini_content,'fpm_conf':fpm_conf,'fpm_content':fpm_content,
            'fpm_profile':fpm_profile,'config':config,'extensions':extensions,'logs':logs})

    def sh(cmd, t=30):
        try:
            return subprocess.check_output(cmd, shell=True, text=True,
                                           stderr=subprocess.STDOUT, timeout=t).strip()
        except subprocess.CalledProcessError as e:
            return e.output or ''
        except: return ''

    if action == 'save_fpm_content':
        conf_path = d.get('conf_path', '')
        fpm_content = d.get('content', '')
        version = d.get('version', '')
        if not conf_path or not fpm_content:
            return jsonify({'ok': False, 'error': 'Missing conf_path or content'})
        try:
            with open(conf_path, 'w') as f: f.write(fpm_content)
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)})
        sh(f'systemctl reload php{version}-fpm 2>/dev/null || systemctl reload php-fpm 2>/dev/null')
        return jsonify({'ok': True})

    if action == 'save_config':
        conf_path = d.get('conf_path', '')
        content   = d.get('content', '')
        if not conf_path or not content:
            return jsonify({'ok': False, 'error': 'Missing conf_path or content'})
        try:
            with open(conf_path, 'w') as f: f.write(content)
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)})
        # Test and reload
        if mod_id == 'nginx':
            test = sh('nginx -t 2>&1')
            if 'successful' not in test and 'ok' not in test.lower():
                return jsonify({'ok': False, 'error': 'Config test failed: ' + test})
            sh('systemctl reload nginx 2>&1')
        elif mod_id == 'apache2':
            test = sh('apache2ctl configtest 2>&1 || apachectl configtest 2>&1')
            if 'Syntax OK' not in test:
                return jsonify({'ok': False, 'error': 'Config test failed: ' + test})
            sh('systemctl reload apache2 2>&1')
        elif mod_id == 'caddy':
            test = sh('caddy validate --config ' + conf_path + ' 2>&1')
            if 'Valid' not in test and 'valid' not in test.lower() and test:
                return jsonify({'ok': False, 'error': 'Caddyfile invalid: ' + test[:200]})
            sh('systemctl reload caddy 2>/dev/null || caddy reload --config ' + conf_path + ' 2>/dev/null')
        elif mod_id == 'openlitespeed':
            sh('systemctl reload lsws 2>/dev/null || systemctl restart lsws 2>/dev/null')
        elif mod_id in ('mysql', 'mariadb'):
            sh(f'systemctl restart {mod_id} 2>&1')
        return jsonify({'ok': True, 'message': 'Configuration saved and service reloaded'})

    elif action == 'save_optimization':
        opts = d.get('optimization', {})
        if mod_id == 'apache2':
            conf = '/etc/apache2/apache2.conf'
            mpm_conf = sh('find /etc/apache2/mods-enabled/ -name "mpm_*.conf" 2>/dev/null | head -1')
            apache_keys = ['Timeout','KeepAlive','MaxKeepAliveRequests','KeepAliveTimeout']
            mpm_keys = ['StartServers','MinSpareThreads','MaxSpareThreads','ThreadsPerChild','MaxRequestWorkers']
            import re as _re
            if os.path.exists(conf):
                with open(conf) as f: c = f.read()
                for k in apache_keys:
                    if k in opts:
                        c = _re.sub(rf'^(\s*{k}\s+)\S+', rf'\g<1>{opts[k]}', c, flags=_re.MULTILINE)
                with open(conf,'w') as f: f.write(c)
            if mpm_conf and os.path.exists(mpm_conf):
                with open(mpm_conf) as f: c = f.read()
                for k in mpm_keys:
                    if k in opts:
                        c = _re.sub(rf'^(\s*{k}\s+)\S+', rf'\g<1>{opts[k]}', c, flags=_re.MULTILINE)
                with open(mpm_conf,'w') as f: f.write(c)
            sh('apache2ctl configtest 2>&1 && systemctl reload apache2 2>&1')
            return jsonify({'ok': True})
        if mod_id == 'openlitespeed':
            conf = '/usr/local/lsws/conf/httpd_config.conf'
            import re as _re
            if os.path.exists(conf):
                with open(conf) as f: c = f.read()
                for k,v in opts.items():
                    c = _re.sub(rf'({k}\s+)\S+', rf'\g<1>{v}', c)
                with open(conf,'w') as f: f.write(c)
            sh('systemctl reload lsws 2>/dev/null || kill -USR1 $(cat /tmp/lshttpd/lshttpd.pid 2>/dev/null) 2>/dev/null')
            return jsonify({'ok': True})
        if mod_id == 'nginx':

            conf = '/etc/nginx/nginx.conf'
            try:
                with open(conf) as f: content = f.read()
                import re as _re
                for key, val in opts.items():
                    content = _re.sub(rf'(\s+{key}\s+)\S+;', rf'\g<1>{val};', content)
                with open(conf, 'w') as f: f.write(content)
                sh('nginx -t && systemctl reload nginx')
                return jsonify({'ok': True})
            except Exception as e:
                return jsonify({'ok': False, 'error': str(e)})

    elif action == 'switch_version':
        ver = d.get('version', '')
        if mod_id == 'redis' and ver:
            # Stop redis, install specific version from redis.io, restart
            script = (
                'systemctl stop redis-server 2>/dev/null || systemctl stop redis 2>/dev/null; '
                'curl -fsSL https://packages.redis.io/gpg | gpg --batch --yes --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg && '
                'echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list && '
                'apt-get update -o APT::Update::Error-Mode=any 2>/dev/null && '
                'apt-get install -y --allow-downgrades redis-server=' + ver + '.* 2>/dev/null || '
                'apt-get install -y redis-server && '
                'systemctl start redis-server 2>/dev/null || systemctl start redis'
            )
            out = sh(script, t=120)
            new_ver = sh("redis-server --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'") or ''
            return jsonify({'ok': True, 'output': out, 'version': new_ver})
        elif mod_id in ('pure-ftpd', 'pure_ftpd') and ver:
            out = sh('apt-get install -y pure-ftpd=' + ver + ' 2>/dev/null || apt-get install -y pure-ftpd 2>&1', t=60)
            return jsonify({'ok': True, 'output': out})
        elif mod_id == 'nginx' and ver:
            # Switch nginx repo based on channel (stable/mainline)
            repo = 'http://nginx.org/packages/ubuntu' if ver == 'stable' else 'http://nginx.org/packages/mainline/ubuntu'
            script = (
                f'echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] {repo} $(lsb_release -cs) nginx" '
                '> /etc/apt/sources.list.d/nginx.list && '
                'apt-get update -o APT::Update::Error-Mode=any 2>/dev/null && '
                'apt-get install -y nginx && '
                'systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null'
            )
            out = sh(script, t=120)
            new_ver = sh("nginx -v 2>&1 | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'") or ''
            return jsonify({'ok': True, 'output': out, 'version': new_ver})
        elif mod_id == 'openlitespeed' and ver:
            script = (
                'systemctl stop lsws 2>/dev/null; '
                'wget -q https://repo.litespeed.sh -O ls_repo.sh && bash ls_repo.sh && '
                '(apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && '
                f'apt-get install -y --allow-downgrades openlitespeed={ver} 2>/dev/null || '
                'apt-get install -y openlitespeed && '
                'systemctl start lsws'
            )
            out = sh(script, t=120)
            new_ver = sh("cat /usr/local/lsws/VERSION 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'") or ''
            return jsonify({'ok': True, 'output': out, 'version': new_ver})
        return jsonify({'ok': False, 'error': 'Version switch not supported for ' + mod_id})

    elif action == 'save_global_opts':
        opts = d.get('opts', {})
        conf_path = d.get('conf_path', '/etc/caddy/Caddyfile')
        if not os.path.exists(conf_path):
            return jsonify({'ok': False, 'error': 'Caddyfile not found'})
        import re as _re
        with open(conf_path) as f: caddyfile = f.read()
        # Update or insert global block
        lines = ['{']
        for k, v in opts.items():
            if v: lines.append(f'\t{k} {v}')
        lines.append('}')
        global_block = '\n'.join(lines)
        if _re.search(r'^\s*\{[^}]*\}', caddyfile, _re.MULTILINE | _re.DOTALL):
            caddyfile = _re.sub(r'^\s*\{[^}]*\}', global_block, caddyfile, count=1, flags=_re.MULTILINE | _re.DOTALL)
        else:
            caddyfile = global_block + chr(10) + chr(10) + caddyfile
        with open(conf_path, 'w') as f: f.write(caddyfile)
        sh('systemctl reload caddy 2>/dev/null || caddy reload --config ' + conf_path + ' 2>/dev/null')
        return jsonify({'ok': True})

    elif action == 'export_certs':
        # Export Caddy certs to /etc/ssl/vortexpanel/ for portability
        cert_dirs = [
            '/var/lib/caddy/.local/share/certmagic/acme/acme-v02.api.letsencrypt.org/sites',
            '/root/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org',
            '/var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org',
        ]
        sh('mkdir -p /etc/ssl/vortexpanel')
        exported = []
        for base in cert_dirs:
            if not os.path.exists(base): continue
            domains = sh(f'ls {base} 2>/dev/null').split()
            for domain in domains:
                domain_dir = f'{base}/{domain}'
                dest = f'/etc/ssl/vortexpanel/{domain}'
                sh(f'mkdir -p {dest}')
                # Copy cert and key files
                for ext in ['.crt', '.key', '.pem']:
                    sh(f'cp {domain_dir}/*{ext} {dest}/ 2>/dev/null || true')
                exported.append(domain)
        if exported:
            return jsonify({'ok': True, 'exported': exported})
        return jsonify({'ok': False, 'error': 'No certificates found to export'})

    elif action == 'pma_set_port':
        port = d.get('port', '8082')
        conf = '/etc/nginx/conf.d/phpmyadmin.conf'
        if os.path.exists(conf):
            import re as _re
            with open(conf) as f: c = f.read()
            c = _re.sub(r'listen\s+\d+', f'listen {port}', c)
            with open(conf, 'w') as f: f.write(c)
            sh('nginx -t && systemctl reload nginx')
            return jsonify({'ok': True, 'port': port})
        return jsonify({'ok': False, 'error': 'phpMyAdmin nginx config not found'})

    elif action == 'pma_set_php':
        php_ver = d.get('php_version', '')
        conf    = '/etc/nginx/conf.d/phpmyadmin.conf'
        if os.path.exists(conf) and php_ver:
            import re as _re
            with open(conf) as f: c = f.read()
            c = _re.sub(r'php[\d.]+\-fpm\.sock', f'php{php_ver}-fpm.sock', c)
            with open(conf, 'w') as f: f.write(c)
            sh('nginx -t && systemctl reload nginx')
            return jsonify({'ok': True})
        return jsonify({'ok': False, 'error': 'Config not found or PHP version missing'})

    return jsonify({'ok': False, 'error': 'Unknown action'})
