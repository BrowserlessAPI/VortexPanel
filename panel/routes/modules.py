from flask import Blueprint, jsonify, request, session, Response
import subprocess, os, threading, time, json, uuid

modules_bp = Blueprint('modules', __name__)
def req(): return 'user' in session

# Job store for progress tracking
_jobs = {}

def sh(c, t=300):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired: return 'Timed out after 5 minutes'
    except Exception as e: return str(e)

def is_installed(check_cmd):
    """Strict install check — no false positives"""
    try:
        r = subprocess.run(check_cmd, shell=True, capture_output=True, text=True, timeout=5)
        out = r.stdout.strip()
        # Never count 'inactive','unknown','0','' as installed
        if out in ('', '0', 'inactive', 'unknown', 'failed', 'activating'):
            return False
        return r.returncode == 0
    except: return False

MODULES = [
    # ── Web Servers ─────────────────────────────────────────────────────────
    {
        'id':'nginx', 'name':'Nginx', 'icon':'🌐', 'category':'Web Server',
        'desc':'High-performance web server',
        'check':'which nginx 2>/dev/null && nginx -v 2>&1 | grep -o "nginx/[0-9.]*"',
        'versions':['1.26','1.28','1.30 (latest)'],
        'install_tpl':'apt-get install -y nginx && systemctl enable nginx && systemctl start nginx',
        'install':'apt-get install -y nginx && systemctl enable nginx && systemctl start nginx',
        'uninstall':'apt-get remove -y nginx nginx-common && apt-get autoremove -y',
        'service':'nginx', 'manage':True,
    },
    {
        'id':'apache2', 'name':'Apache2', 'icon':'🔴', 'category':'Web Server',
        'desc':'Apache HTTP Server (latest stable)',
        'check':'which apache2 2>/dev/null',
        'install':'apt-get install -y apache2 && systemctl enable apache2 && systemctl start apache2',
        'uninstall':'apt-get remove -y apache2 apache2-utils && apt-get autoremove -y',
        'service':'apache2', 'manage':True,
    },
    {
        'id':'openlitespeed', 'name':'OpenLiteSpeed', 'icon':'⚡', 'category':'Web Server',
        'desc':'LiteSpeed open source web server (latest)',
        'check':'test -f /usr/local/lsws/bin/lshttpd && echo found',
        'install':'''wget -q https://repo.litespeed.sh -O ls_repo.sh && bash ls_repo.sh && \
apt-get install -y openlitespeed && systemctl enable lsws && systemctl start lsws''',
        'uninstall':'/usr/local/lsws/admin/misc/uninstall.sh 2>/dev/null || apt-get remove -y openlitespeed',
        'service':'lsws', 'manage':True,
    },
    # ── Databases ────────────────────────────────────────────────────────────
    {
        'id':'mysql', 'name':'MySQL', 'icon':'🐬', 'category':'Database',
        'desc':'MySQL 8.0 database server',
        'check':'dpkg -l mysql-server 2>/dev/null | grep -c "^ii"',
        'install':'apt-get install -y mysql-server && systemctl enable mysql && systemctl start mysql',
        'uninstall':'apt-get remove -y mysql-server mysql-client mysql-common && apt-get autoremove -y && apt-get purge -y mysql-server',
        'service':'mysql', 'manage':True,
    },
    {
        'id':'mariadb', 'name':'MariaDB', 'icon':'🦭', 'category':'Database',
        'desc':'MariaDB database server (latest)',
        'check':'dpkg -l mariadb-server 2>/dev/null | grep -c "^ii"',
        'install':'apt-get install -y mariadb-server && systemctl enable mariadb && systemctl start mariadb',
        'uninstall':'apt-get remove -y mariadb-server mariadb-common && apt-get autoremove -y',
        'service':'mariadb', 'manage':True,
    },
    {
        'id':'mongodb', 'name':'MongoDB', 'icon':'🍃', 'category':'Database',
        'desc':'MongoDB document database (latest)',
        'check':'which mongod 2>/dev/null',
        'install':'''apt-get install -y gnupg curl && \
curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor 2>/dev/null && \
echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-7.0.list && \
apt-get update -q && apt-get install -y mongodb-org && systemctl enable mongod && systemctl start mongod''',
        'uninstall':'apt-get remove -y mongodb-org && apt-get autoremove -y',
        'service':'mongod', 'manage':True,
    },
    {
        'id':'postgresql', 'name':'PostgreSQL Manager', 'icon':'🐘', 'category':'Database',
        'desc':'PostgreSQL relational database (latest)',
        'check':'which psql 2>/dev/null',
        'install':'apt-get install -y postgresql postgresql-contrib && systemctl enable postgresql && systemctl start postgresql',
        'uninstall':'apt-get remove -y postgresql postgresql-contrib && apt-get autoremove -y',
        'service':'postgresql', 'manage':True,
    },
    # ── PHP ──────────────────────────────────────────────────────────────────
    {
        'id':'php', 'name':'PHP', 'icon':'🐘', 'category':'PHP',
        'desc':'PHP-FPM — select version (7.4 → 8.5)',
        'check':'which php 2>/dev/null',
        'versions':['7.4','8.1','8.2','8.3','8.4','8.5'],
        'install_tpl':'''add-apt-repository -y ppa:ondrej/php 2>/dev/null | tail -1 && apt-get update -q && \
apt-get install -y php{ver} php{ver}-fpm php{ver}-common php{ver}-mysql php{ver}-xml \
php{ver}-curl php{ver}-gd php{ver}-mbstring php{ver}-zip php{ver}-bcmath php{ver}-intl \
php{ver}-soap php{ver}-cli && \
systemctl enable php{ver}-fpm && systemctl start php{ver}-fpm''',
        'install':'',
        'uninstall':'',
        'manage':False,
    },
    # ── FTP ──────────────────────────────────────────────────────────────────
    {
        'id':'pure-ftpd', 'name':'Pure-FTPd', 'icon':'📂', 'category':'FTP',
        'desc':'Pure-FTPd server (latest)',
        'check':'which pure-ftpd 2>/dev/null',
        'install':'apt-get install -y pure-ftpd pure-ftpd-common && systemctl enable pure-ftpd && systemctl start pure-ftpd',
        'uninstall':'apt-get remove -y pure-ftpd && apt-get autoremove -y',
        'service':'pure-ftpd', 'manage':True,
    },
    # ── Admin Tools ──────────────────────────────────────────────────────────
    {
        'id':'phpmyadmin', 'name':'phpMyAdmin', 'icon':'🗄', 'category':'Admin Tools',
        'desc':'phpMyAdmin web database manager (latest)',
        'check':'test -d /usr/share/phpmyadmin && echo found',
        'install':'''apt-get install -y phpmyadmin php-mbstring php-zip php-gd php-json php-curl 2>/dev/null || \
(wget -q https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-all-languages.tar.gz -O /tmp/pma.tar.gz && \
mkdir -p /usr/share/phpmyadmin && tar -xzf /tmp/pma.tar.gz -C /usr/share/phpmyadmin --strip-components=1)''',
        'uninstall':'apt-get remove -y phpmyadmin && rm -rf /usr/share/phpmyadmin',
        'manage':False,
    },
    # ── Security ─────────────────────────────────────────────────────────────
    {
        'id':'fail2ban', 'name':'Fail2ban Manager', 'icon':'🛡', 'category':'Security',
        'desc':'Brute-force protection & IP banning',
        'check':'which fail2ban-client 2>/dev/null',
        'install':'apt-get install -y fail2ban && systemctl enable fail2ban && systemctl start fail2ban',
        'uninstall':'apt-get remove -y fail2ban && apt-get autoremove -y',
        'service':'fail2ban', 'manage':True,
    },
    {
        'id':'clamav', 'name':'ClamAV', 'icon':'🦠', 'category':'Security',
        'desc':'Open source antivirus engine',
        'check':'which clamscan 2>/dev/null',
        'install':'apt-get install -y clamav clamav-daemon && systemctl enable clamav-freshclam && freshclam 2>/dev/null || true',
        'uninstall':'apt-get remove -y clamav clamav-daemon && apt-get autoremove -y',
        'service':'clamav-daemon', 'manage':True,
    },
    # ── DNS ──────────────────────────────────────────────────────────────────
    {
        'id':'ddns', 'name':'DDNS Manager', 'icon':'🌍', 'category':'DNS',
        'desc':'Dynamic DNS — auto IP update service',
        'check':'which ddclient 2>/dev/null',
        'install':'apt-get install -y ddclient',
        'uninstall':'apt-get remove -y ddclient && apt-get autoremove -y',
        'manage':False,
    },
    {
        'id':'bind9', 'name':'BIND9 DNS', 'icon':'🌐', 'category':'DNS',
        'desc':'Authoritative DNS name server',
        'check':'which named 2>/dev/null',
        'install':'apt-get install -y bind9 bind9utils && systemctl enable bind9 && systemctl start bind9',
        'uninstall':'apt-get remove -y bind9 && apt-get autoremove -y',
        'service':'bind9', 'manage':True,
    },
    # ── Runtimes ─────────────────────────────────────────────────────────────
    {
        'id':'nodejs', 'name':'Node.js', 'icon':'🟢', 'category':'Runtime',
        'desc':'Node.js v20 LTS + npm',
        'check':'which node 2>/dev/null || which nodejs 2>/dev/null',
        'install':'curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs',
        'uninstall':'apt-get remove -y nodejs && apt-get autoremove -y',
        'manage':False,
    },
    {
        'id':'python', 'name':'Python Manager', 'icon':'🐍', 'category':'Runtime',
        'desc':'Python 3 + pip + venv',
        'check':'which python3 2>/dev/null',
        'install':'apt-get install -y python3 python3-pip python3-venv python3-dev',
        'uninstall':'apt-get remove -y python3-pip python3-venv && apt-get autoremove -y',
        'manage':False,
    },
    # ── Containers ───────────────────────────────────────────────────────────
    {
        'id':'docker', 'name':'Docker', 'icon':'🐳', 'category':'Containers',
        'desc':'Docker container platform (latest)',
        'check':'which docker 2>/dev/null',
        'install':'curl -fsSL https://get.docker.com | sh && systemctl enable docker && systemctl start docker',
        'uninstall':'apt-get remove -y docker-ce docker-ce-cli containerd.io && apt-get autoremove -y',
        'service':'docker', 'manage':True,
    },
    # ── Dev ──────────────────────────────────────────────────────────────────
    {
        'id':'git', 'name':'Git', 'icon':'📦', 'category':'Dev',
        'desc':'Version control system',
        'check':'which git 2>/dev/null',
        'install':'apt-get install -y git',
        'uninstall':'apt-get remove -y git',
        'manage':False,
    },
    {
        'id':'composer', 'name':'Composer', 'icon':'🎼', 'category':'Dev',
        'desc':'PHP dependency manager',
        'check':'which composer 2>/dev/null',
        'install':'curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer',
        'uninstall':'rm -f /usr/local/bin/composer',
        'manage':False,
    },
    # ── Cache ────────────────────────────────────────────────────────────────
    {
        'id':'redis', 'name':'Redis', 'icon':'🔴', 'category':'Cache',
        'desc':'In-memory data store & cache',
        'check':'which redis-server 2>/dev/null',
        'install':'apt-get install -y redis-server && systemctl enable redis-server && systemctl start redis-server',
        'uninstall':'apt-get remove -y redis-server && apt-get autoremove -y',
        'service':'redis-server', 'manage':True,
    },
    # ── Server ───────────────────────────────────────────────────────────────
    {
        'id':'supervisor', 'name':'Supervisor', 'icon':'⚙', 'category':'Server',
        'desc':'Process control & monitoring',
        'check':'which supervisord 2>/dev/null',
        'install':'apt-get install -y supervisor && systemctl enable supervisor && systemctl start supervisor',
        'uninstall':'apt-get remove -y supervisor && apt-get autoremove -y',
        'service':'supervisor', 'manage':True,
    },
    # ── Mail ─────────────────────────────────────────────────────────────────
    {
        'id':'opendkim', 'name':'OpenDKIM', 'icon':'✍', 'category':'Mail',
        'desc':'DKIM email signing & verification',
        'check':'which opendkim 2>/dev/null',
        'install':'apt-get install -y opendkim opendkim-tools',
        'uninstall':'apt-get remove -y opendkim && apt-get autoremove -y',
        'manage':False,
    },
]

def _get_mod(mod_id):
    return next((m for m in MODULES if m['id']==mod_id), None)

@modules_bp.route('/api/modules')
def list_modules():
    if not req(): return jsonify({'ok':False}), 401
    result = []
    for m in MODULES:
        installed = is_installed(m['check'])
        svc = m.get('service','')
        svc_status = ''
        if installed and svc:
            r = subprocess.run(f'systemctl is-active {svc} 2>/dev/null',
                               shell=True, capture_output=True, text=True)
            svc_status = r.stdout.strip()
        result.append({
            'id':m['id'], 'name':m['name'], 'icon':m['icon'],
            'category':m['category'], 'desc':m['desc'],
            'installed':installed, 'svcStatus':svc_status,
            'versions':m.get('versions',[]),
            'manage':m.get('manage',False),
            'hasVersions': bool(m.get('versions')),
        })
    return jsonify({'ok':True, 'modules':result})

@modules_bp.route('/api/modules/<mod_id>/install', methods=['POST'])
def install_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    mod = _get_mod(mod_id)
    if not mod: return jsonify({'ok':False,'error':'Module not found'}), 404

    d   = request.get_json() or {}
    ver = d.get('version','')
    job_id = str(uuid.uuid4())[:8]

    # Get install command
    if mod_id == 'php' and ver:
        cmd = mod.get('install_tpl','').replace('{ver}', ver)
    elif mod.get('versions') and not ver:
        return jsonify({'ok':False,'error':'Version required'}), 400
    else:
        cmd = mod.get('install_tpl', mod.get('install',''))
        if ver and '{ver}' in cmd:
            cmd = cmd.replace('{ver}', ver)

    if not cmd: return jsonify({'ok':False,'error':'No install command defined'}), 400

    _jobs[job_id] = {'status':'running','lines':[],'done':False,'installed':False}

    def run_job():
        _jobs[job_id]['lines'].append(f'[VortexPanel] Starting installation of {mod["name"]}...')
        proc = subprocess.Popen(
            f'DEBIAN_FRONTEND=noninteractive {cmd} 2>&1',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        for line in proc.stdout:
            _jobs[job_id]['lines'].append(line.rstrip())
        proc.wait()
        installed = is_installed(mod['check'])
        _jobs[job_id]['installed'] = installed
        _jobs[job_id]['done'] = True
        _jobs[job_id]['status'] = 'done'
        _jobs[job_id]['lines'].append(
            f'[VortexPanel] {"✓ Installation complete!" if installed else "⚠ Installation finished — verify above for errors."}'
        )

    threading.Thread(target=run_job, daemon=True).start()
    return jsonify({'ok':True, 'job_id':job_id})

@modules_bp.route('/api/modules/job/<job_id>')
def job_stream(job_id):
    """SSE stream for install progress"""
    def generate():
        sent = 0
        while True:
            job = _jobs.get(job_id)
            if not job:
                yield f'data: {json.dumps({"error":"Job not found"})}\n\n'
                break
            lines = job['lines']
            while sent < len(lines):
                yield f'data: {json.dumps({"line": lines[sent]})}\n\n'
                sent += 1
            if job['done']:
                yield f'data: {json.dumps({"done":True,"installed":job["installed"]})}\n\n'
                break
            time.sleep(0.3)
    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

@modules_bp.route('/api/modules/<mod_id>/uninstall', methods=['POST'])
def uninstall_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    mod = _get_mod(mod_id)
    if not mod: return jsonify({'ok':False,'error':'Not found'}), 404

    job_id = str(uuid.uuid4())[:8]
    cmd = mod.get('uninstall','')
    if not cmd: return jsonify({'ok':False,'error':'No uninstall command'}), 400

    _jobs[job_id] = {'status':'running','lines':[],'done':False,'installed':True}

    def run_job():
        _jobs[job_id]['lines'].append(f'[VortexPanel] Removing {mod["name"]}...')
        proc = subprocess.Popen(
            f'DEBIAN_FRONTEND=noninteractive {cmd} 2>&1',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1
        )
        for line in proc.stdout:
            _jobs[job_id]['lines'].append(line.rstrip())
        proc.wait()
        installed = is_installed(mod['check'])
        _jobs[job_id]['installed'] = installed
        _jobs[job_id]['done'] = True
        _jobs[job_id]['status'] = 'done'
        _jobs[job_id]['lines'].append(
            f'[VortexPanel] {"✓ Removed successfully!" if not installed else "⚠ May not be fully removed."}'
        )

    threading.Thread(target=run_job, daemon=True).start()
    return jsonify({'ok':True, 'job_id':job_id})

@modules_bp.route('/api/modules/<mod_id>/control', methods=['POST'])
def control_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    action = (request.get_json() or {}).get('action','status')
    mod = _get_mod(mod_id)
    if not mod: return jsonify({'ok':False}), 404
    svc = mod.get('service','')
    if svc and action in ('start','stop','restart','reload'):
        r = subprocess.run(f'systemctl {action} {svc} 2>&1',
                           shell=True, capture_output=True, text=True)
        time.sleep(0.5)
        status = subprocess.run(f'systemctl is-active {svc} 2>/dev/null',
                                shell=True, capture_output=True, text=True).stdout.strip()
        return jsonify({'ok':True, 'status':status})
    return jsonify({'ok':False,'error':'No service defined'})
