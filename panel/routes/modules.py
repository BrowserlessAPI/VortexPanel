from flask import Blueprint, jsonify, request, session
import subprocess, os

modules_bp = Blueprint('modules', __name__)
def req(): return 'user' in session

def sh(c, t=180):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired: return 'Timed out'
    except Exception as e: return str(e)

def is_installed(check_cmd):
    try:
        r = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, timeout=5)
        out = r.stdout.strip()
        return r.returncode == 0 and out not in ('', '0', 'inactive', 'unknown')
    except: return False

MODULES = [
    # ── Web Servers ────────────────────────────────────────────────────────────
    {
        'id':'nginx', 'name':'Nginx', 'icon':'🌐', 'category':'Web Server',
        'desc':'High-performance web server (v1.26+)',
        'check':'which nginx 2>/dev/null',
        'install':'apt-get install -y nginx && systemctl enable nginx && systemctl start nginx',
        'uninstall':'apt-get remove -y nginx nginx-common && apt-get autoremove -y',
        'manage': True,
    },
    {
        'id':'apache2', 'name':'Apache2', 'icon':'🔴', 'category':'Web Server',
        'desc':'Apache HTTP Server (latest)',
        'check':'which apache2 2>/dev/null',
        'install':'apt-get install -y apache2 && systemctl enable apache2 && systemctl start apache2',
        'uninstall':'apt-get remove -y apache2 && apt-get autoremove -y',
        'manage': True,
    },
    {
        'id':'openlitespeed', 'name':'OpenLiteSpeed', 'icon':'⚡', 'category':'Web Server',
        'desc':'LiteSpeed open source web server',
        'check':'which lshttpd 2>/dev/null || test -f /usr/local/lsws/bin/lshttpd',
        'install':'''wget -q https://repo.litespeed.sh -O ls_repo.sh && bash ls_repo.sh && apt-get install -y openlitespeed && systemctl enable lsws && systemctl start lsws''',
        'uninstall':'apt-get remove -y openlitespeed && apt-get autoremove -y',
        'manage': True,
    },

    # ── Databases ─────────────────────────────────────────────────────────────
    {
        'id':'mysql', 'name':'MySQL', 'icon':'🐬', 'category':'Database',
        'desc':'MySQL 8.0+ database server',
        'check':'which mysqld 2>/dev/null || systemctl is-active mysql 2>/dev/null | grep -c active',
        'install':'apt-get install -y mysql-server && systemctl enable mysql && systemctl start mysql',
        'uninstall':'apt-get remove -y mysql-server mysql-common && apt-get autoremove -y',
        'versions':['MySQL 8.0','MariaDB 10.11','MariaDB 11.x'],
        'manage': True,
    },
    {
        'id':'mariadb', 'name':'MariaDB', 'icon':'🦭', 'category':'Database',
        'desc':'MariaDB database server (latest)',
        'check':'which mariadbd 2>/dev/null || which mysqld 2>/dev/null && mysqld --version 2>/dev/null | grep -i maria',
        'install':'apt-get install -y mariadb-server && systemctl enable mariadb && systemctl start mariadb',
        'uninstall':'apt-get remove -y mariadb-server mariadb-common && apt-get autoremove -y',
        'manage': True,
    },
    {
        'id':'mongodb', 'name':'MongoDB', 'icon':'🍃', 'category':'Database',
        'desc':'MongoDB document database (latest)',
        'check':'which mongod 2>/dev/null',
        'install':'''apt-get install -y gnupg curl && \
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor && \
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-7.0.list && \
apt-get update -q && apt-get install -y mongodb-org && \
systemctl enable mongod && systemctl start mongod''',
        'uninstall':'apt-get remove -y mongodb-org && apt-get autoremove -y',
        'manage': True,
    },
    {
        'id':'postgresql', 'name':'PostgreSQL Manager', 'icon':'🐘', 'category':'Database',
        'desc':'PostgreSQL relational database',
        'check':'which psql 2>/dev/null',
        'install':'apt-get install -y postgresql postgresql-contrib && systemctl enable postgresql && systemctl start postgresql',
        'uninstall':'apt-get remove -y postgresql postgresql-contrib && apt-get autoremove -y',
        'manage': True,
    },

    # ── PHP ───────────────────────────────────────────────────────────────────
    {
        'id':'php', 'name':'PHP', 'icon':'🐘', 'category':'PHP',
        'desc':'PHP runtime — select version to install',
        'check':'which php 2>/dev/null',
        'versions':['7.4','8.1','8.2','8.3','8.4','8.5'],
        'install_tpl':'''add-apt-repository -y ppa:ondrej/php 2>/dev/null || true && \
apt-get update -q && apt-get install -y php{ver} php{ver}-fpm php{ver}-common php{ver}-mysql \
php{ver}-xml php{ver}-curl php{ver}-gd php{ver}-mbstring php{ver}-zip php{ver}-bcmath \
php{ver}-intl php{ver}-soap && \
systemctl enable php{ver}-fpm && systemctl start php{ver}-fpm''',
        'manage': True,
    },

    # ── FTP ───────────────────────────────────────────────────────────────────
    {
        'id':'pure-ftpd', 'name':'Pure-FTPd', 'icon':'📂', 'category':'FTP',
        'desc':'Pure-FTPd server (latest)',
        'check':'which pure-ftpd 2>/dev/null',
        'install':'apt-get install -y pure-ftpd pure-ftpd-common && systemctl enable pure-ftpd && systemctl start pure-ftpd',
        'uninstall':'apt-get remove -y pure-ftpd && apt-get autoremove -y',
        'manage': True,
    },

    # ── Admin Tools ───────────────────────────────────────────────────────────
    {
        'id':'phpmyadmin', 'name':'phpMyAdmin', 'icon':'🗄', 'category':'Admin Tools',
        'desc':'phpMyAdmin web database manager (latest)',
        'check':'dpkg -l phpmyadmin 2>/dev/null | grep -c "^ii"',
        'install':'''apt-get install -y phpmyadmin php-mbstring php-zip php-gd php-json php-curl && \
phpenmod mbstring 2>/dev/null || true && \
systemctl reload apache2 2>/dev/null || systemctl reload nginx 2>/dev/null || true''',
        'uninstall':'apt-get remove -y phpmyadmin && apt-get autoremove -y',
        'manage': True,
    },

    # ── Security ─────────────────────────────────────────────────────────────
    {
        'id':'fail2ban', 'name':'Fail2ban Manager', 'icon':'🛡', 'category':'Security',
        'desc':'Brute-force protection & IP banning',
        'check':'which fail2ban-client 2>/dev/null',
        'install':'apt-get install -y fail2ban && systemctl enable fail2ban && systemctl start fail2ban',
        'uninstall':'apt-get remove -y fail2ban && apt-get autoremove -y',
        'manage': True,
    },
    {
        'id':'clamav', 'name':'ClamAV', 'icon':'🦠', 'category':'Security',
        'desc':'Open source antivirus engine',
        'check':'which clamscan 2>/dev/null',
        'install':'apt-get install -y clamav clamav-daemon && systemctl enable clamav-daemon && freshclam',
        'uninstall':'apt-get remove -y clamav clamav-daemon && apt-get autoremove -y',
        'manage': True,
    },
    {
        'id':'certbot', 'name':'Certbot (SSL)', 'icon':'🔒', 'category':'Security',
        'desc':'Let\'s Encrypt free SSL certificates',
        'check':'which certbot 2>/dev/null',
        'install':'apt-get install -y certbot python3-certbot-nginx',
        'uninstall':'apt-get remove -y certbot && apt-get autoremove -y',
        'manage': False,
    },

    # ── DNS ───────────────────────────────────────────────────────────────────
    {
        'id':'ddns', 'name':'DDNS Manager 1.0', 'icon':'🌍', 'category':'DNS',
        'desc':'Dynamic DNS manager for auto IP updates',
        'check':'which ddclient 2>/dev/null',
        'install':'apt-get install -y ddclient',
        'uninstall':'apt-get remove -y ddclient && apt-get autoremove -y',
        'manage': True,
    },
    {
        'id':'bind9', 'name':'BIND9 DNS', 'icon':'🌐', 'category':'DNS',
        'desc':'BIND9 authoritative DNS server',
        'check':'which named 2>/dev/null',
        'install':'apt-get install -y bind9 bind9utils bind9-doc && systemctl enable bind9 && systemctl start bind9',
        'uninstall':'apt-get remove -y bind9 && apt-get autoremove -y',
        'manage': True,
    },

    # ── Runtimes ──────────────────────────────────────────────────────────────
    {
        'id':'nodejs', 'name':'Node.js', 'icon':'🟢', 'category':'Runtime',
        'desc':'Node.js JavaScript runtime (v20 LTS)',
        'check':'which node 2>/dev/null || which nodejs 2>/dev/null',
        'install':'curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs',
        'uninstall':'apt-get remove -y nodejs && apt-get autoremove -y',
        'manage': False,
    },
    {
        'id':'python', 'name':'Python Manager', 'icon':'🐍', 'category':'Runtime',
        'desc':'Python 3 runtime + pip + venv',
        'check':'which python3 2>/dev/null',
        'install':'apt-get install -y python3 python3-pip python3-venv python3-dev',
        'uninstall':'apt-get remove -y python3 && apt-get autoremove -y',
        'manage': True,
    },

    # ── Tools ─────────────────────────────────────────────────────────────────
    {
        'id':'docker', 'name':'Docker', 'icon':'🐳', 'category':'Containers',
        'desc':'Docker container platform',
        'check':'which docker 2>/dev/null',
        'install':'curl -fsSL https://get.docker.com | sh && systemctl enable docker && systemctl start docker',
        'uninstall':'apt-get remove -y docker-ce docker-ce-cli && apt-get autoremove -y',
        'manage': True,
    },
    {
        'id':'git', 'name':'Git', 'icon':'📦', 'category':'Dev',
        'desc':'Version control system',
        'check':'which git 2>/dev/null',
        'install':'apt-get install -y git',
        'uninstall':'apt-get remove -y git',
        'manage': False,
    },
    {
        'id':'composer', 'name':'Composer', 'icon':'🎼', 'category':'Dev',
        'desc':'PHP dependency manager',
        'check':'which composer 2>/dev/null',
        'install':'curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer',
        'uninstall':'rm -f /usr/local/bin/composer',
        'manage': False,
    },
    {
        'id':'redis', 'name':'Redis', 'icon':'🔴', 'category':'Cache',
        'desc':'In-memory data store & cache',
        'check':'which redis-server 2>/dev/null',
        'install':'apt-get install -y redis-server && systemctl enable redis-server && systemctl start redis-server',
        'uninstall':'apt-get remove -y redis-server && apt-get autoremove -y',
        'manage': True,
    },
    {
        'id':'supervisor', 'name':'Supervisor', 'icon':'⚙', 'category':'Server',
        'desc':'Process control system',
        'check':'which supervisord 2>/dev/null',
        'install':'apt-get install -y supervisor && systemctl enable supervisor && systemctl start supervisor',
        'uninstall':'apt-get remove -y supervisor && apt-get autoremove -y',
        'manage': True,
    },
    {
        'id':'opendkim', 'name':'OpenDKIM', 'icon':'✍', 'category':'Mail',
        'desc':'DKIM email signing & verification',
        'check':'which opendkim 2>/dev/null',
        'install':'apt-get install -y opendkim opendkim-tools',
        'uninstall':'apt-get remove -y opendkim && apt-get autoremove -y',
        'manage': False,
    },
]

@modules_bp.route('/api/modules')
def list_modules():
    if not req(): return jsonify({'ok':False}), 401
    result = []
    for m in MODULES:
        installed = is_installed(m['check'])
        entry = {
            'id':       m['id'],
            'name':     m['name'],
            'icon':     m['icon'],
            'category': m['category'],
            'desc':     m['desc'],
            'installed': installed,
            'versions': m.get('versions', []),
            'manage':   m.get('manage', False),
        }
        result.append(entry)
    return jsonify({'ok':True, 'modules':result})

@modules_bp.route('/api/modules/<mod_id>/install', methods=['POST'])
def install_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    d   = request.get_json() or {}
    ver = d.get('version','')  # For PHP version selection

    mod = next((m for m in MODULES if m['id']==mod_id), None)
    if not mod: return jsonify({'ok':False,'error':'Module not found'}), 404

    # PHP uses version template
    if mod_id == 'php' and ver:
        cmd = mod['install_tpl'].replace('{ver}', ver)
    else:
        cmd = mod.get('install','')

    if not cmd: return jsonify({'ok':False,'error':'No install command'}), 400

    out = sh(f'DEBIAN_FRONTEND=noninteractive {cmd} 2>&1', t=300)
    installed = is_installed(mod['check'])
    return jsonify({'ok':True, 'installed':installed, 'output':out[-800:]})

@modules_bp.route('/api/modules/<mod_id>/uninstall', methods=['POST'])
def uninstall_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    mod = next((m for m in MODULES if m['id']==mod_id), None)
    if not mod: return jsonify({'ok':False,'error':'Not found'}), 404
    cmd = mod.get('uninstall','')
    if cmd: sh(f'DEBIAN_FRONTEND=noninteractive {cmd} 2>&1', t=120)
    return jsonify({'ok':True, 'installed':is_installed(mod['check'])})

@modules_bp.route('/api/modules/<mod_id>/status')
def module_status(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    svc_map = {'nginx':'nginx','apache2':'apache2','mysql':'mysql','mariadb':'mariadb',
               'mongodb':'mongod','postgresql':'postgresql','redis':'redis-server',
               'docker':'docker','fail2ban':'fail2ban','supervisor':'supervisor',
               'pure-ftpd':'pure-ftpd','openlitespeed':'lsws'}
    svc = svc_map.get(mod_id)
    if svc:
        status = subprocess.run(f'systemctl is-active {svc} 2>/dev/null',
                                shell=True, capture_output=True, text=True).stdout.strip()
        return jsonify({'ok':True, 'status':status or 'inactive'})
    return jsonify({'ok':True, 'status':'unknown'})

@modules_bp.route('/api/modules/<mod_id>/control', methods=['POST'])
def control_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    action = (request.get_json() or {}).get('action','status')
    svc_map = {'nginx':'nginx','apache2':'apache2','mysql':'mysql','mariadb':'mariadb',
               'mongodb':'mongod','postgresql':'postgresql','redis':'redis-server',
               'docker':'docker','fail2ban':'fail2ban','supervisor':'supervisor',
               'pure-ftpd':'pure-ftpd','openlitespeed':'lsws'}
    svc = svc_map.get(mod_id)
    if svc and action in ('start','stop','restart','reload'):
        sh(f'systemctl {action} {svc} 2>&1')
    return jsonify({'ok':True})
