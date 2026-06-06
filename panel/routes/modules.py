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
        'caddy':        "caddy version 2>/dev/null | grep -oP 'v[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'nginx':        "nginx -v 2>&1 | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'apache2':      "apache2 -v 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'openlitespeed':"cat /usr/local/lsws/VERSION 2>/dev/null || /usr/local/lsws/bin/lshttpd -v 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+'",
        'mysql':        "mysql --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'mariadb':      "mariadbd --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'mongodb':      "mongod --version 2>/dev/null | grep -oP 'v[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'postgresql':   "psql --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+' | head -1",
        'php':          "php -v 2>/dev/null | grep -oP 'PHP [0-9]+\\.[0-9]+\\.[0-9]+' | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+'",
        'redis':        "redis-server --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'nodejs':       "node --version 2>/dev/null | tr -d 'v'",
        'python':       "python3 --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+'",
        'docker':       "docker --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'git':          "git --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'composer':     "composer --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'fail2ban':     "fail2ban-client --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'pure-ftpd':    "pure-ftpd --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'clamav':       "clamscan --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'bind9':        "named -v 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'supervisor':   "supervisord --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+'",
        'redis':        "redis-server --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'opendkim':     "opendkim --version 2>&1 | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
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
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list && \
apt-get update -q && apt-get install -y nginx && systemctl enable --now nginx''',
        'install':'apt-get install -y nginx && systemctl enable --now nginx',
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
apt-get update -q && apt-get install -y openlitespeed={ver} 2>/dev/null || \
apt-get install -y openlitespeed && \
systemctl enable lsws && systemctl start lsws''',
        'install':'''wget -q https://repo.litespeed.sh -O ls_repo.sh && bash ls_repo.sh && \
apt-get update -q && apt-get install -y openlitespeed && \
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
apt-get update -q && apt-get install -y caddy && \
systemctl enable caddy && systemctl start caddy''',
        'install':'''apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl && \
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
  gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && \
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
  tee /etc/apt/sources.list.d/caddy-stable.list && \
chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg && \
chmod o+r /etc/apt/sources.list.d/caddy-stable.list && \
apt-get update -q && apt-get install -y caddy && \
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
apt-get update -q && apt-get install -y mongodb-org && systemctl enable mongod && systemctl start mongod''',
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
apt-get update -q && apt-get install -y postgresql-{ver} && systemctl enable postgresql && systemctl start postgresql''',
        'install':'apt-get install -y postgresql postgresql-contrib && systemctl enable postgresql && systemctl start postgresql',
        'uninstall':'apt-get remove -y --purge postgresql postgresql-* && apt-get autoremove -y && rm -rf /etc/postgresql /var/lib/postgresql',
        'service':'postgresql', 'manage':True,
    },
    # ── PHP ──────────────────────────────────────────────────────────────────
    {
        'id':'php', 'name':'PHP', 'icon':'🐘', 'category':'PHP',
        'desc':'PHP-FPM — multiple versions supported side by side',
        'check':'which php 2>/dev/null',
        'versions':[
            {'label':'7.4 (Legacy)',    'value':'7.4'},
            {'label':'8.1 (Security)',  'value':'8.1'},
            {'label':'8.2 (Active)',    'value':'8.2'},
            {'label':'8.3 (Active)',    'value':'8.3'},
            {'label':'8.4 (Latest)',    'value':'8.4'},
        ],
        'install_tpl':'''apt-get install -y software-properties-common && \
add-apt-repository -y ppa:ondrej/php && apt-get update -q && \
apt-get install -y php{ver} php{ver}-fpm php{ver}-common php{ver}-mysql php{ver}-xml \
php{ver}-curl php{ver}-gd php{ver}-mbstring php{ver}-zip php{ver}-bcmath php{ver}-intl \
php{ver}-soap php{ver}-cli php{ver}-readline && \
systemctl enable php{ver}-fpm && systemctl start php{ver}-fpm''',
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
            'DEBIAN_FRONTEND=noninteractive apt-get install -y '
            'php-mbstring php-zip php-gd php-json php-curl php-cli wget && '
            'wget -q https://files.phpmyadmin.net/phpMyAdmin/5.2.2/'
            'phpMyAdmin-5.2.2-all-languages.tar.gz -O /tmp/pma.tar.gz && '
            'mkdir -p /usr/share/phpmyadmin && '
            'tar -xzf /tmp/pma.tar.gz -C /usr/share/phpmyadmin --strip-components=1 && '
            'cp /usr/share/phpmyadmin/config.sample.inc.php /usr/share/phpmyadmin/config.inc.php && '
            'SOCK=$(ls /run/php/php8.*-fpm.sock 2>/dev/null | sort -r | head -1) && '
            'SOCK=${SOCK:-/run/php/php8.3-fpm.sock} && '
            'echo "server{listen 8082;server_name _;root /usr/share/phpmyadmin;index index.php;'
            'location ~ [.]php${include snippets/fastcgi-php.conf;fastcgi_pass $SOCK;include fastcgi_params;}}" '
            '> /etc/nginx/conf.d/phpmyadmin.conf && '
            'nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true && '
            'echo "[VortexPanel] phpMyAdmin ready at http://YOUR-SERVER-IP:8082"'
        ),
        'uninstall':'rm -rf /usr/share/phpmyadmin /etc/nginx/conf.d/phpmyadmin.conf && systemctl reload nginx 2>/dev/null || true',
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
        'install':'apt-get install -y fail2ban && systemctl enable fail2ban && systemctl start fail2ban',
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
        'install':'apt-get install -y clamav clamav-daemon && systemctl enable clamav-freshclam && freshclam 2>/dev/null || true && systemctl start clamav-daemon',
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
        'id':'git', 'name':'Git', 'icon':'📦', 'category':'Dev',
        'desc':'Distributed version control system',
        'check':'which git 2>/dev/null',
        'versions':[
            {'label':'2.48 (Latest Stable)', 'value':'latest'},
        ],
        'install':'apt-get install -y git',
        'uninstall':'apt-get remove -y git && apt-get autoremove -y',
        'manage':False,
    },
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
        'install':'apt-get install -y redis-server && systemctl enable redis-server && systemctl start redis-server',
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
        'check':'test -f /opt/vortexpanel/cdn_config.json && echo found',
        'versions':[
            {'label':'Latest (Built-in)', 'value':'latest'},
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
