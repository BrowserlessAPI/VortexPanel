from flask import Blueprint, jsonify, request, session, Response
import subprocess, os, threading, time, json, uuid, re, shutil
try:
    from panel.routes.os_utils import get_os, pkg_install, pkg_update, nginx_install_script, php_install_script, mariadb_install_script, postgresql_install_script, redis_install_script, mongodb_install_script, docker_install_script, nodejs_install_script, panel_cache
except ImportError:
    from os_utils import get_os, pkg_install, pkg_update, nginx_install_script, php_install_script, mariadb_install_script, postgresql_install_script, redis_install_script, mongodb_install_script, docker_install_script, nodejs_install_script, panel_cache

modules_bp = Blueprint('modules', __name__)

def os_cmd(apt_cmd):
    """Translate apt-get commands to the current OS package manager"""
    _os = get_os()
    if _os['family'] == 'debian':
        return apt_cmd
    # RHEL/Fedora/AlmaLinux/Rocky
    cmd = apt_cmd
    cmd = cmd.replace('DEBIAN_FRONTEND=noninteractive ', '')
    cmd = cmd.replace('apt-get install -y', 'dnf install -y')
    cmd = cmd.replace('apt-get update -qq', 'dnf check-update -q; true')
    cmd = cmd.replace('apt-get update -q', 'dnf check-update -q; true')
    cmd = cmd.replace('apt-get update', 'dnf check-update; true')
    # Strip dpkg-specific options that don't apply to dnf
    import re as _re
    cmd = _re.sub(r"-o Dpkg::Options::='[^']*'\s*", '', cmd)
    cmd = _re.sub(r'-o Dpkg::Options::="[^"]*"\s*', '', cmd)
    cmd = _re.sub(r'-o Dpkg::Options::=\S+\s*', '', cmd)
    cmd = cmd.replace('apt-get remove -y --purge', 'dnf remove -y')
    cmd = cmd.replace('apt-get remove -y', 'dnf remove -y')
    cmd = cmd.replace('apt-get autoremove -y', 'dnf autoremove -y')
    cmd = cmd.replace('add-apt-repository -y', 'true #')
    cmd = cmd.replace('add-apt-repository', 'true #')
    cmd = cmd.replace('apt-get -y install', 'dnf install -y')
    # Package name differences
    cmd = cmd.replace('software-properties-common', 'dnf-plugins-core')
    cmd = cmd.replace('python3-pip', 'python3-pip')
    cmd = cmd.replace('apache2', 'httpd')
    cmd = cmd.replace('apache2-utils', 'httpd-tools')
    return cmd

def translate_install_cmd(cmd):
    """Translate install command for current OS"""
    _os = get_os()
    if _os['family'] == 'debian':
        return cmd
    return os_cmd(cmd)

def req(): return 'user' in session

# --- Job store: JSONL append-only files shared across all gunicorn workers ----
# Each job = one .jsonl file where every line is a complete JSON object.
# Appending one JSON line is atomic for small writes — no read-modify-write,
# no corruption, no locks needed between workers.
# Format per line:
#   {"line": "apt-get output..."}          — progress output line
#   {"done": true, "success": true/false,  — final status (last line)
#    "installed": true, "installedVer": "x.y.z"}
_JOBS_DIR = '/tmp/vortex_jobs'
os.makedirs(_JOBS_DIR, exist_ok=True)

def _job_path(job_id):
    return os.path.join(_JOBS_DIR, f'{job_id}.jsonl')

def _job_create(job_id, **_):
    """Create empty job file so SSE stream knows it exists."""
    open(_job_path(job_id), 'w').close()

def _job_append_line(job_id, line):
    """Append one output line. Atomic for small writes."""
    try:
        with open(_job_path(job_id), 'a') as f:
            f.write(json.dumps({'line': line}) + '\n')
    except Exception as e:
        pass  # non-fatal; best-effort streaming

def _job_finish(job_id, success, installed, inst_ver=''):
    """Append final status line to job file."""
    try:
        with open(_job_path(job_id), 'a') as f:
            f.write(json.dumps({
                'done': True, 'success': success,
                'installed': installed, 'installedVer': inst_ver,
            }) + '\n')
    except Exception:
        pass

def _job_get(job_id):
    """Read all lines from JSONL job file. Returns dict with lines[], done, etc."""
    path = _job_path(job_id)
    if not os.path.exists(path):
        return None
    lines = []
    done = False
    success = False
    installed = True
    inst_ver = ''
    try:
        with open(path) as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if 'line' in obj:
                    lines.append(obj['line'])
                elif obj.get('done'):
                    done = True
                    success = obj.get('success', False)
                    installed = obj.get('installed', True)
                    inst_ver = obj.get('installedVer', '')
    except Exception:
        pass
    return {'lines': lines, 'done': done, 'success': success,
            'installed': installed, 'installedVer': inst_ver}

# Shim so existing _jobs[job_id] reads still work (used nowhere new, but safe)
class _JobsShim:
    def get(self, job_id, default=None): return _job_get(job_id) or default
_jobs = _JobsShim()

def sh(c, t=10):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return (r.stdout + r.stderr).strip()
    except: return ''

def get_version(mod_id, ver=None):
    cmds = {
        'nginx':        "nginx -v 2>&1 | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'apache2':      "apache2 -v 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1 || httpd -v 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'openlitespeed':"cat /usr/local/lsws/VERSION 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1 || /usr/local/lsws/bin/lshttpd -v 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'caddy':        "caddy version 2>/dev/null | awk '{print $1}' | tr -d v",
        'mysql':        "mysqld --version 2>/dev/null | grep -iv mariadb | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'mariadb':      "mysqld --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1 || mariadbd --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'mongodb':      "mongod --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'redis':        "redis-server --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'nodejs':       "node --version 2>/dev/null | tr -d 'v'",
        # PHP and PostgreSQL both support multiple versions installed side by
        # side. A fixed priority list here (checking 8.5 before 7.4, or just
        # trusting whatever `psql`/`php` resolves to via update-alternatives)
        # is exactly what caused a real, confirmed bug: installing PHP 7.4
        # on a system that already had 8.5 reported back "Version: 8.5.8" --
        # the 7.4 that was ACTUALLY just installed was never even checked.
        # When the caller knows which version was just requested, check that
        # one specifically; only fall back to the priority list when it
        # isn't known (e.g. refreshing the general module list).
        'php':          (f"php{ver} --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1" if ver else
                          "for v in 8.5 8.4 8.3 8.2 8.1 8.0 7.4; do if which php$v >/dev/null 2>&1; then php$v --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1; break; fi; done"),
        'postgresql':   (f"psql --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+' | head -1" if not ver else
                          f"(psql -V 2>/dev/null | grep -q '{ver}' && psql --version | grep -oP '[0-9]+\\.[0-9]+' | head -1) || (which psql{ver} >/dev/null 2>&1 && echo {ver}) || (test -d /usr/lib/postgresql/{ver} && echo {ver})"),
        'python':       "python3 --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+'",
        'docker':       "docker --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'composer':     "composer --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'fail2ban':     "fail2ban-client --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'pure-ftpd':    "pure-ftpd --help 2>&1 | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'clamav':       "clamscan --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'bind9':        "named -v 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1",
        'supervisor':   "supervisord --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+'",
        'phpmyadmin':   "grep -oP '\"version\": \"\\K[0-9]+[.][0-9]+[.][0-9]+' /usr/share/phpmyadmin/composer.json 2>/dev/null | head -1",
        'roundcube':    "grep -oP '\"version\": \"\\K[0-9]+[.][0-9]+[.][0-9]+' /var/www/roundcube/composer.json 2>/dev/null | head -1",
        'modsecurity':  "modsec_rules_check --version 2>/dev/null | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1 || dpkg -l libmodsecurity3t64 2>/dev/null | grep '^ii' | awk '{print $3}'",
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
    # --- Web Servers -----------------------------------------------------------
    {
        'id':'nginx', 'name':'Nginx', 'icon':'/static/icons/nginx.svg', 'category':'Web Server',
        'desc':'High-performance HTTP & reverse proxy server',
        'check':'which nginx 2>/dev/null',
        'versions':[
            {'label':'1.30.4 (Stable — security)',   'value':'stable'},
            {'label':'1.31.3 (Mainline — security)', 'value':'mainline'},
        ],
        'install_tpl':'''OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian) && \
if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then \
  apt-get install -y curl gnupg2 ca-certificates lsb-release && \
  rm -f /usr/share/keyrings/nginx-archive-keyring.gpg && \
  curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --batch --yes --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg && \
  REPO="http://nginx.org/packages/{ver}/ubuntu" && \
  [ "{ver}" = "stable" ] && REPO="http://nginx.org/packages/ubuntu" || true && \
  echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] $REPO $(lsb_release -cs) nginx" | tee /etc/apt/sources.list.d/nginx.list && \
  apt-get update -o APT::Update::Error-Mode=any 2>/dev/null && \
  apt-get install -y nginx && systemctl enable --now nginx; \
elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then \
  RHEL_VER=$(rpm -E %rhel 2>/dev/null || echo 9) && \
  REPO_PATH="rhel/$RHEL_VER" && \
  [ "{ver}" = "mainline" ] && REPO_PATH="mainline/rhel/$RHEL_VER" || true && \
  printf "[nginx]\nname=nginx repo\nbaseurl=http://nginx.org/packages/%s/\\$basearch/\ngpgcheck=1\nenabled=1\ngpgkey=https://nginx.org/keys/nginx_signing.key\nmodule_hotfixes=true\n" "$REPO_PATH" > /etc/yum.repos.d/nginx.repo && \
  (dnf install -y nginx 2>/dev/null || yum install -y nginx) && \
  systemctl enable --now nginx; \
fi''',
        'install':'(apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y nginx && systemctl enable --now nginx',
        'uninstall':'systemctl stop nginx 2>/dev/null; systemctl disable nginx 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=\'--force-confdef\' -o Dpkg::Options::=\'--force-confold\' nginx nginx-common nginx-full nginx-core 2>/dev/null; dnf remove -y nginx 2>/dev/null; yum remove -y nginx 2>/dev/null; apt-get autoremove -y 2>/dev/null; rm -rf /etc/nginx /usr/share/keyrings/nginx-archive-keyring.gpg /etc/apt/sources.list.d/nginx.list /etc/apt/sources.list.d/nginx-mainline.list /etc/yum.repos.d/nginx.repo 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'service':'nginx', 'manage':True,
    },
    {
        'id':'apache2', 'name':'Apache2', 'icon':'/static/icons/apache.svg', 'category':'Web Server',
        'desc':'Apache HTTP Server — widely-used web server',
        'check':'which apache2 2>/dev/null || which httpd 2>/dev/null',
        'versions':[
            {'label':'2.4.68 (Latest Stable)', 'value':'2.4.68'},
            {'label':'2.4.67 (Stable)',         'value':'2.4.67'},
        ],
        'install_tpl':(
            'export DEBIAN_FRONTEND=noninteractive && '
            # Same failure class already confirmed for ondrej/php: this PPA
            # may not have a release for a very new Ubuntu codename yet, and
            # add-apt-repository writes it to disk regardless of whether the
            # following apt-get update ever succeeds -- silently poisoning
            # every future apt-get update on the system, unrelated installs
            # included, unless cleaned up here on failure.
            'add-apt-repository -y ppa:ondrej/apache2 2>/dev/null; '
            'if ! apt-get update -qq 2>/tmp/vp_apache_repo_err.log; then '
            '  echo "[VortexPanel] ondrej/apache2 has no release for {codename} yet -- removing it, using stock Ubuntu apache2 instead"; '
            '  add-apt-repository --remove -y ppa:ondrej/apache2 2>/dev/null; '
            '  rm -f /etc/apt/sources.list.d/ondrej-ubuntu-apache2-*.list /etc/apt/sources.list.d/ondrej-ubuntu-apache2-*.sources 2>/dev/null; '
            '  apt-get update -qq; '
            'fi && '
            'apt-get install -y apache2={ver}.* 2>/dev/null || apt-get install -y apache2 && '
            'systemctl enable apache2 && systemctl start apache2'
        ),
        'install':'export DEBIAN_FRONTEND=noninteractive && apt-get install -y apache2 && systemctl enable apache2 && systemctl start apache2',
        'uninstall':'systemctl stop apache2 2>/dev/null; systemctl disable apache2 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold apache2 apache2-utils apache2-bin && apt-get autoremove -y',
        'service':'apache2', 'manage':True,
    },
    {
        'id':'openlitespeed', 'name':'OpenLiteSpeed', 'icon':'/static/icons/litespeed.svg', 'category':'Web Server',
        'desc':'LiteSpeed open source web server',
        'check':'test -f /usr/local/lsws/bin/lshttpd && echo found',
        'versions':[
            {'label':'1.9.x (Latest - Apr 2026)', 'value':'1.9'},
            {'label':'1.8.5 (Stable - Jan 2026)', 'value':'1.8.5'},
            {'label':'1.8.4 (Stable)',               'value':'1.8.4'},
        ],
        'install_tpl':'''OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian) && \
if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then \
  wget -q https://repo.litespeed.sh -O ls_repo.sh && bash ls_repo.sh; \
  if ! apt-get update -o APT::Update::Error-Mode=any 2>/tmp/vp_ols_err.log; then \
    if grep -q litespeedtech.com /tmp/vp_ols_err.log 2>/dev/null; then \
      echo "[VortexPanel] litespeedtech.com has no build for $(lsb_release -cs) yet -- retrying with the previous stable codename (bullseye), a confirmed working substitution for this exact situation"; \
      for f in /etc/apt/sources.list.d/*.list; do \
        [ -f "$f" ] && grep -qi litespeedtech "$f" && sed -i "s/$(lsb_release -cs)/bullseye/g" "$f"; \
      done; \
    fi; \
    apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; \
  fi; \
  apt-get install -y openlitespeed={ver} 2>/dev/null || apt-get install -y openlitespeed; \
  systemctl enable lsws && systemctl start lsws; \
  LSPHP_VER="lsphp83" && \
  apt-get install -y $LSPHP_VER $LSPHP_VER-common 2>&1 && \
  for ext in mysql curl opcache imagick intl mbstring xml zip gd soap; do \
    apt-get install -y $LSPHP_VER-$ext 2>/dev/null || true; \
  done; \
elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky|cloudlinux"; then \
  RHEL_VER=$(rpm -E %rhel 2>/dev/null || echo 9) && \
  (dnf install -y epel-release 2>/dev/null || yum install -y epel-release 2>/dev/null; true) && \
  (dnf install -y https://rpms.remirepo.net/enterprise/remi-release-${RHEL_VER}.rpm 2>/dev/null || true) && \
  (rpm -Uvh --force http://rpms.litespeedtech.com/centos/litespeed-repo-1.3-1.el${RHEL_VER}.noarch.rpm 2>/dev/null || true) && \
  (dnf install -y openlitespeed 2>/dev/null || yum install -y openlitespeed 2>/dev/null) && \
  systemctl enable lsws && systemctl start lsws; \
  LSPHP_VER="lsphp83" && \
  (dnf install -y $LSPHP_VER $LSPHP_VER-common 2>/dev/null || yum install -y $LSPHP_VER $LSPHP_VER-common 2>/dev/null); \
  for ext in mysqlnd curl opcache imagick intl mbstring xml zip gd soap process bcmath pdo mcrypt; do \
    (dnf install -y $LSPHP_VER-$ext 2>/dev/null || yum install -y $LSPHP_VER-$ext 2>/dev/null || true); \
  done; \
fi; \
mkdir -p /var/log/openlitespeed && chown nobody:nogroup /var/log/openlitespeed 2>/dev/null; true''',
        'install':'''wget -q https://repo.litespeed.sh -O ls_repo.sh && bash ls_repo.sh && \
(apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y openlitespeed && \
systemctl enable lsws && systemctl start lsws && \
LSPHP_VER="lsphp83" && \
apt-get install -y $LSPHP_VER $LSPHP_VER-common 2>&1 && \
for ext in mysql curl opcache imagick intl mbstring xml zip gd soap; do \
  apt-get install -y $LSPHP_VER-$ext 2>/dev/null || true; \
done; \
mkdir -p /var/log/openlitespeed && chown nobody:nogroup /var/log/openlitespeed 2>/dev/null; true''',
        'uninstall':(
            'systemctl stop lsws 2>/dev/null; systemctl disable lsws 2>/dev/null; '
            '/usr/local/lsws/admin/misc/uninstall.sh 2>/dev/null; '
            "apt-get remove -y -o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold' openlitespeed 2>/dev/null; "
            'rm -rf /usr/local/lsws; '
            # LiteSpeed's own ls_repo.sh (downloaded from repo.litespeed.sh)
            # writes the actual apt source file under a name that isn't
            # documented/verifiable from here -- same leftover-repo class of
            # bug just found and fixed for MariaDB (a stale repo definition
            # surviving uninstall and interfering with later unrelated
            # installs). Matching by content instead of guessing a filename:
            'grep -l -i litespeed /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null | xargs -r rm -f; '
            'find /etc/apt/sources.list.d/ -iname "*litespeed*" -delete 2>/dev/null; '
            'rm -f /usr/share/keyrings/*litespeed*.gpg /etc/apt/trusted.gpg.d/*litespeed*.gpg 2>/dev/null; '
            'apt-get update -qq 2>/dev/null; true'
        ),
        'service':'lsws', 'manage':True,
    },
    # --- Databases -------------------------------------------------------------
    {
        'id':'caddy', 'name':'Caddy', 'icon':'/static/icons/caddy.svg', 'category':'Web Server',
        'desc':'Auto-HTTPS web server — HTTP/3, zero-config TLS via Lets Encrypt',
        'check':'which caddy 2>/dev/null',
        'versions':[
            {'label':'v2.11.4 (Latest — security)', 'value':'2.11.4'},
            {'label':'v2.11.3 (Stable — security)', 'value':'2.11.3'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl && '
                # FIX: previous version piped the curl'd GPG key into "rm -f" (which ignores
                # stdin and discards it) instead of into "gpg --dearmor" — producing an empty/
                # invalid keyring file. Corrected: remove old file first, then pipe curl -> gpg.
            '  rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg && '
            '  curl -fsSL \'https://dl.cloudsmith.io/public/caddy/stable/gpg.key\' | gpg --batch --no-tty --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && '
            '  curl -fsSL \'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt\' | tee /etc/apt/sources.list.d/caddy-stable.list && '
            '  chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg && '
            '  chmod o+r /etc/apt/sources.list.d/caddy-stable.list && '
            '  (apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y caddy && '
            '  systemctl enable caddy && systemctl start caddy; '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
                # Caddy's officially documented Fedora/EL method — COPR repo.
            '  (dnf install -y dnf-plugins-core 2>/dev/null || yum install -y dnf-plugins-core 2>/dev/null || true) && '
            '  (dnf copr enable -y @caddy/caddy 2>/dev/null || yum copr enable -y @caddy/caddy 2>/dev/null || true) && '
            '  (dnf install -y caddy 2>/dev/null || yum install -y caddy 2>/dev/null) && '
            '  systemctl enable caddy && systemctl start caddy; '
            'fi'
        ),
        'install':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl && '
            '  rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg && '
            '  curl -fsSL \'https://dl.cloudsmith.io/public/caddy/stable/gpg.key\' | gpg --batch --no-tty --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && '
            '  curl -fsSL \'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt\' | tee /etc/apt/sources.list.d/caddy-stable.list && '
            '  chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg && '
            '  chmod o+r /etc/apt/sources.list.d/caddy-stable.list && '
            '  (apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && apt-get install -y caddy && '
            '  systemctl enable caddy && systemctl start caddy; '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
            '  (dnf install -y dnf-plugins-core 2>/dev/null || yum install -y dnf-plugins-core 2>/dev/null || true) && '
            '  (dnf copr enable -y @caddy/caddy 2>/dev/null || yum copr enable -y @caddy/caddy 2>/dev/null || true) && '
            '  (dnf install -y caddy 2>/dev/null || yum install -y caddy 2>/dev/null) && '
            '  systemctl enable caddy && systemctl start caddy; '
            'fi'
        ),
        'uninstall':'systemctl stop caddy 2>/dev/null; systemctl disable caddy 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold caddy 2>/dev/null; dnf remove -y caddy 2>/dev/null; yum remove -y caddy 2>/dev/null; apt-get autoremove -y 2>/dev/null; rm -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list 2>/dev/null; apt-get update -qq 2>/dev/null; true && rm -rf /etc/caddy',
        'service':'caddy', 'manage':True,
    },
    {
        'id':'mysql', 'name':'MySQL', 'icon':'/static/icons/mysql.svg', 'category':'Database',
        'desc':'The world\'s most popular open source database',
        'check':'systemctl is-active mysql 2>/dev/null | grep -q active && ! systemctl is-active mariadb 2>/dev/null | grep -q active && echo found || (mysqld --version 2>/dev/null | grep -i mysql | grep -iv mariadb | grep -c mysql)',
        'versions':[
            {'label':'Innovation (rolling — currently 26.7.0, latest quarterly release)', 'value':'innovation'},
            {'label':'9.7.2 (LTS)',           'value':'9.7'},
            {'label':'8.4.11 (LTS)',          'value':'8.4'},
            {'label':'8.0.46 (EOL since Apr 2026 — no security patches, not recommended)', 'value':'8.0'},
        ],
        'install_tpl':(
            # Hard guard, independent of the higher-level conflict check:
            # MySQL and MariaDB share the same package namespace
            # (mysql-common, mysql-client) and cannot coexist. Confirmed via
            # a real failure: installing mysql-server while MariaDB was
            # already active caused mysql-server's postinst script to fail
            # with "configure-symlinks: No such file or directory" (it
            # expects Ubuntu's own mysql-common, but MariaDB'"'"'s mysql-common
            # package was already providing that path instead) -- dpkg
            # returned an error, yet a stray mysqld binary from the
            # otherwise-successful mysql-server-core package made the old
            # "is it installed" check falsely report success. Refusing to
            # even attempt this is far safer than relying on dpkg to fail
            # loudly enough afterward.
            # IMPORTANT: this checks whether MariaDB *packages* are
            # present (dpkg -l), not whether the mariadb *service* is
            # currently active -- confirmed via a second real failure
            # that checking only systemctl is-active let this exact
            # conflict through a second time, because MariaDB's packages
            # (and its conflicting mysql-common) were still installed
            # even though the service happened not to be running at
            # that moment. The package-level conflict exists regardless
            # of whether the service is running.
            'if dpkg -l mariadb-server 2>/dev/null | grep -q "^ii" || dpkg -l mysql-common 2>/dev/null | grep "^ii" | grep -qi maria; then '
            '  echo "[VortexPanel] MariaDB is already installed on this server (its packages own mysql-common/mysql-client). MySQL and MariaDB cannot coexist -- uninstall MariaDB first (App Store -> MariaDB -> Uninstall) if you want MySQL instead."; '
            '  exit 1; '
            'fi; '
            # Third layer of the same defense: even with MariaDB genuinely
            # uninstalled, its apt REPOSITORY DEFINITION can persist on a
            # server that had MariaDB installed before this uninstall fix
            # existed -- confirmed live: a leftover mariadb.sources file
            # supplied a conflicting mysql-common during MySQL's dependency
            # resolution even though mariadb-server itself was already gone,
            # producing the exact same postinst crash through a different
            # path. Removing any stale MariaDB repo file before touching
            # apt at all closes that regardless of whether it happened via
            # the uninstall bug or by any other means.
            'rm -f /etc/apt/sources.list.d/mariadb.list /etc/apt/sources.list.d/mariadb.sources; '
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  export DEBIAN_FRONTEND=noninteractive && '
            '  apt-get install -y wget lsb-release gnupg debconf-utils && '
            '  wget -q https://dev.mysql.com/get/mysql-apt-config_0.8.39-1_all.deb -O /tmp/mysql-apt.deb && '
            # mysql-apt-config presents server-track selection as a debconf
            # question (mysql-apt-config/select-server) -- without an answer
            # preseeded, it silently defaults to whichever track it
            # considers primary (confirmed real: requesting 9.7 installed
            # 8.4 instead, with zero indication anything was wrong). MySQL
            # publishes two tracks: mysql-8.0 / mysql-8.4-lts (LTS) for 8.x,
            # and mysql-innovation for the rolling 9.x releases -- there is
            # no per-point-release component like "mysql-9.7" specifically.
            # UNCERTAIN: I have not been able to directly confirm the exact
            # track name for 9.x releases against a real system (never seen
            # "mysql-innovation" appear in an actual log, only inferred from
            # general MySQL release-model knowledge) -- and a separate,
            # also-unverified source suggests 9.7 may now be marketed as its
            # own LTS track rather than Innovation. Rather than commit to
            # either guess, the debconf preseed below uses this as a
            # starting attempt only; the real selection happens afterward by
            # scanning what mysql-apt-config actually generated.
            '  MYSQL_TRACK_GUESS="mysql-8.4-lts"; '
            '  case "{ver}" in 8.0*) MYSQL_TRACK_GUESS="mysql-8.0";; 8.4*) MYSQL_TRACK_GUESS="mysql-8.4-lts";; 9.7*) MYSQL_TRACK_GUESS="mysql-9.7-lts";; innovation) MYSQL_TRACK_GUESS="mysql-innovation";; esac; '
            '  echo "[VortexPanel] debconf preseed attempt: mysql-apt-config/select-server = $MYSQL_TRACK_GUESS"; '
            '  echo "mysql-apt-config mysql-apt-config/select-server select $MYSQL_TRACK_GUESS" | debconf-set-selections; '
            '  DEBIAN_FRONTEND=noninteractive dpkg -i /tmp/mysql-apt.deb && '
            # Self-discovering correction, independent of both the debconf
            # answer and my track-name guesses above: mysql-apt-config
            # writes every ACTUAL track name it knows about into the repo
            # file (commenting out all but the selected one), so scan for
            # what is really there instead of assuming. Priority 1: a track
            # whose name literally contains the requested version string
            # (e.g. would correctly find "mysql-9.7-lts" if that turns out
            # to be real, without me having had to know that in advance).
            # Priority 2: fall back to the LTS/Innovation heuristic only if
            # no exact version match exists.
            '  for f in /etc/apt/sources.list.d/mysql.list /etc/apt/sources.list.d/mysql.sources; do '
            '    if [ ! -f "$f" ]; then echo "[VortexPanel] $f does not exist -- skipping"; continue; fi; '
            '    echo "[VortexPanel] found $f, discovering tracks..."; '
            '    ALL_TRACKS=$(grep -oP "\\s\\Kmysql-[a-zA-Z0-9.-]+$" "$f" | grep -vE "^mysql-(apt-config|tools|common|client|server)$" | sort -u); '
            '    echo "[VortexPanel] discovered tracks: $ALL_TRACKS"; '
            '    MYSQL_TRACK=""; '
            '    for T in $ALL_TRACKS; do case "$T" in *"{ver}"*) MYSQL_TRACK="$T"; break;; esac; done; '
            '    if [ -z "$MYSQL_TRACK" ]; then '
            '      case "{ver}" in '
            '        8.0*) for T in $ALL_TRACKS; do case "$T" in mysql-8.0*) MYSQL_TRACK="$T"; break;; esac; done ;; '
            '        8.4*) for T in $ALL_TRACKS; do case "$T" in mysql-8.4*) MYSQL_TRACK="$T"; break;; esac; done ;; '
            '        9.7*) for T in $ALL_TRACKS; do case "$T" in mysql-9.7*|mysql-9*-lts) MYSQL_TRACK="$T"; break;; esac; done ;; '
            '        innovation) for T in $ALL_TRACKS; do case "$T" in mysql-innovation|mysql-9*) MYSQL_TRACK="$T"; break;; esac; done ;; '
            '      esac; '
            '    fi; '
            '    echo "[VortexPanel] selected track for {ver}: ${MYSQL_TRACK:-<none found>}"; '
            '    if [ -z "$MYSQL_TRACK" ]; then echo "[VortexPanel] no matching track -- leaving $f untouched"; continue; fi; '
            '    sed -i "/\\b${MYSQL_TRACK}\\b/s/^#\\s*//" "$f"; '
            '    for OTHER in $ALL_TRACKS; do '
            '      [ "$OTHER" = "$MYSQL_TRACK" ] && continue; '
            '      sed -i "/\\b${OTHER}\\b/{/^#/!s/^/# /}" "$f"; '
            '    done; '
            '  done; '
            '  echo "[VortexPanel] active (uncommented) lines after track selection:"; '
            '  for f in /etc/apt/sources.list.d/mysql.list /etc/apt/sources.list.d/mysql.sources; do '
            '    [ -f "$f" ] && grep "^deb" "$f"; '
            '  done; '
            # Confirmed via a real failure: every codename attempt (questing,
            # plucky, oracular, noble, jammy) failed with the SAME
            # "EXPKEYSIG B7B3B788A8D3785C" error -- not a missing Release
            # file, an EXPIRED signing key bundled in the old, pinned
            # mysql-apt-config_0.8.39-1 package. Re-fetching that exact key
            # ID from a keyserver gets whatever current version MySQL has
            # published (keyservers reflect renewed expiry dates the stale
            # bundled copy doesn'"'"'t have) -- this is the standard remediation
            # for EXPKEYSIG, not a signature-verification bypass.
            #
            # IMPORTANT: writing the refreshed key to a NEW file in
            # /etc/apt/trusted.gpg.d/ was NOT enough -- confirmed via a real
            # failure on a FRESH Ubuntu 24.04 install (the correct native
            # codename, no fallback even needed) that the exact same
            # EXPKEYSIG error still occurred. mysql-apt-config'"'"'s generated
            # sources file has its own explicit Signed-By= pointing at a
            # specific bundled keyring file, which overrides the global
            # trusted keyring for that repo entirely -- adding a second key
            # elsewhere does nothing if apt never looks there. Discovering
            # whatever path is actually referenced and overwriting THAT
            # exact file, in addition to the trusted.gpg.d fallback for the
            # case where no explicit Signed-By is used at all.
            '  MYSQL_KEYRING_PATH=""; '
            '  for f in /etc/apt/sources.list.d/mysql.list /etc/apt/sources.list.d/mysql.sources; do '
            '    [ -f "$f" ] && MYSQL_KEYRING_PATH=$(grep -oP "(?:signed-by=|Signed-By:\\s*)\\K[^]\\s]+" "$f" 2>/dev/null | head -1) && [ -n "$MYSQL_KEYRING_PATH" ] && break; '
            '  done; '
            '  (gpg --no-default-keyring --keyring /tmp/mysql-refresh.gpg --keyserver keyserver.ubuntu.com --recv-keys B7B3B788A8D3785C 2>/dev/null && '
            '   gpg --no-default-keyring --keyring /tmp/mysql-refresh.gpg --export B7B3B788A8D3785C > /etc/apt/trusted.gpg.d/mysql-refreshed.gpg 2>/dev/null && '
            '   if [ -n "$MYSQL_KEYRING_PATH" ]; then mkdir -p "$(dirname "$MYSQL_KEYRING_PATH")"; gpg --no-default-keyring --keyring /tmp/mysql-refresh.gpg --export B7B3B788A8D3785C > "$MYSQL_KEYRING_PATH" 2>/dev/null; fi) || true; '
            # mysql-apt-config is a pinned package (0.8.39-1, confirmed
            # current as of the user's own check against dev.mysql.com --
            # was previously hardcoded to the much older 0.8.33-1, which may
            # explain why selecting a 9.x track never worked no matter how
            # it was preseeded: a config tool built before 9.x existed would
            # never have had that option to select in the first place) that
            # writes /etc/apt/sources.list.d/mysql.list based on whatever
            # codename it detects -- confirmed via a real failure log:
            # repo.mysql.com genuinely has no release for a brand-new Ubuntu
            # codename yet (404 Not Found), and this stale file was left
            # behind, poisoning every unrelated apt-get update afterward
            # (it broke a completely separate PHP install in the same way
            # already seen for ondrej/php, mariadb, postgresql, etc).
            '  if ! apt-get update -q 2>/tmp/vp_mysql_repo_err.log; then '
            # repo.mysql.com has no build for the running codename yet.
            # Confirmed directly from repo.mysql.com's real directory listing
            # (not a guess): questing, plucky, oracular, noble, jammy all
            # genuinely exist there, with questing (25.10) the most recently
            # updated -- matching what MySQL's own download page shows for
            # both 8.4 and 9.7. Probing newest-first and using the first one
            # whose Release file actually resolves.
            '    RUNNING_CODENAME=$(lsb_release -sc); '
            '    MYSQL_OK=0; '
            '    for CN in questing plucky oracular noble jammy; do '
            '      for f in /etc/apt/sources.list.d/mysql.list /etc/apt/sources.list.d/mysql.sources; do '
            '        [ -f "$f" ] && sed -i "s/${RUNNING_CODENAME}/${CN}/g; s/\\b\\(questing\\|plucky\\|oracular\\|noble\\|jammy\\)\\b/${CN}/g" "$f"; '
            '      done; '
            '      if apt-get update -q 2>/tmp/vp_mysql_${CN}_err.log; then '
            '        echo "[VortexPanel] repo.mysql.com has no build for ${RUNNING_CODENAME} yet -- using its ${CN} build instead (closest available match)"; '
            '        MYSQL_OK=1; break; '
            '      fi; '
            '    done; '
            '    if [ "$MYSQL_OK" != "1" ]; then '
            '      echo "[VortexPanel] repo.mysql.com has no usable build for any recent Ubuntu codename -- removing the broken repo entry, falling back to distro-packaged mysql-server (may not match the exact version requested)"; '
            '      rm -f /etc/apt/sources.list.d/mysql.list /etc/apt/sources.list.d/mysql.sources; '
            '      apt-get update -q; '
            '    fi; '
            '  fi && '
            '  if [ "{ver}" = "innovation" ]; then '
            # No version-suffixed package exists for Innovation at all --
            # confirmed by the real "Unable to locate package
            # mysql-server-9.x" failure this produced under the old value.
            # Whatever "mysql-server" resolves to IS the current quarterly
            # Innovation release; there is nothing more specific to ask for.
            '    apt-get install -y mysql-server; '
            '  else '
            '    apt-get install -y mysql-server-{ver} 2>/dev/null || apt-get install -y mysql-server; '
            '  fi && '
            '  systemctl enable --now mysql; '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
                # RHEL 8+ ships MySQL directly in the built-in AppStream module stream —
                # no external repo or GPG key needed at all, the safest possible path.
                # Module streams only offer a couple of minor versions (not every {ver}
                # choice maps 1:1) so we pick the closest available stream.
                #
                # IMPORTANT, confirmed just from reading the module-stream mechanism
                # itself (not from a live RHEL-family log -- unlike the Debian/Ubuntu
                # path in this same install_tpl, this branch has NOT been validated
                # against a real system yet): RHEL'"'"'s built-in AppStream module never
                # publishes a 9.x stream at all, so a 9.x request used to silently fall
                # through to the 8.4 case= condition below and install 8.4 instead --
                # same "wrong version installed with no indication" bug already found
                # and fixed on the Debian/Ubuntu side. 9.x now skips the module-stream
                # attempt entirely and goes straight to Oracle'"'"'s own community repo,
                # since that'"'"'s the only place a 9.x release actually exists for
                # RHEL-family systems.
            '  MYSQL_STREAM=""; '
            '  case "{ver}" in 8.0*) MYSQL_STREAM="8.0";; 8.4*) MYSQL_STREAM="8.4";; esac; '
            '  MYSQL_MODULE_OK=1; '
            '  if [ -n "$MYSQL_STREAM" ]; then '
            '    (dnf module reset -y mysql 2>/dev/null; dnf module enable -y mysql:$MYSQL_STREAM 2>/dev/null; '
            '     dnf install -y mysql-server 2>/dev/null) || MYSQL_MODULE_OK=0; '
            '  else '
            '    MYSQL_MODULE_OK=0; '
            '  fi; '
            '  if [ "$MYSQL_MODULE_OK" != "1" ]; then '
                # Oracle's official community-release config RPM, confirmed directly
                # against dev.mysql.com/downloads/repo/yum/ (not a guess this time) --
                # every EL major version and Fedora release has its own distinct
                # filename and build suffix, which the previous single hardcoded
                # "el7-11" filename never accounted for.
            '    EL_MAJOR=$(rpm -E %{rhel} 2>/dev/null); '
            '    FEDORA_MAJOR=$(rpm -E %{fedora} 2>/dev/null); '
            '    MYSQL_YUM_CONF=""; '
            '    if [ -n "$FEDORA_MAJOR" ] && [ "$FEDORA_MAJOR" != "%{fedora}" ]; then '
            '      case "$FEDORA_MAJOR" in '
            '        43) MYSQL_YUM_CONF="mysql84-community-release-fc43-2.noarch.rpm";; '
            '        42) MYSQL_YUM_CONF="mysql84-community-release-fc42-4.noarch.rpm";; '
            '      esac; '
            '    elif [ -n "$EL_MAJOR" ] && [ "$EL_MAJOR" != "%{rhel}" ]; then '
            '      case "$EL_MAJOR" in '
            '        10) MYSQL_YUM_CONF="mysql84-community-release-el10-3.noarch.rpm";; '
            '        9)  MYSQL_YUM_CONF="mysql84-community-release-el9-4.noarch.rpm";; '
            '        8)  MYSQL_YUM_CONF="mysql84-community-release-el8-3.noarch.rpm";; '
            '        7)  MYSQL_YUM_CONF="mysql84-community-release-el7-4.noarch.rpm";; '
            '        6)  MYSQL_YUM_CONF="mysql80-community-release-el6-11.noarch.rpm";; '
            '      esac; '
            '    fi; '
            '    if [ -z "$MYSQL_YUM_CONF" ]; then '
            '      echo "[VortexPanel] Could not determine the correct MySQL community-release package for this specific EL/Fedora version -- falling back to the EL9 build as a best-effort guess"; '
            '      MYSQL_YUM_CONF="mysql84-community-release-el9-4.noarch.rpm"; '
            '    fi; '
            '    (dnf install -y "https://dev.mysql.com/get/${MYSQL_YUM_CONF}" 2>/dev/null || '
            '     yum install -y "https://dev.mysql.com/get/${MYSQL_YUM_CONF}" 2>/dev/null); '
                # This config RPM sets up multiple sub-repos (one per MySQL major
                # version/track, similar to how mysql-apt-config works on
                # Debian/Ubuntu) and enables one by default -- self-discover and
                # select the repo matching the requested version instead of
                # assuming which one is on by default, same philosophy as the
                # apt-side fix, since the exact default and sub-repo IDs are NOT
                # independently confirmed here.
            '    for rf in /etc/yum.repos.d/mysql-community.repo /etc/yum.repos.d/mysql-community-source.repo; do '
            '      [ -f "$rf" ] || continue; '
            '      ALL_REPOIDS=$(grep -oE "^\\[[a-zA-Z0-9_-]+\\]" "$rf" | tr -d "[]"); '
            '      TARGET_REPO=""; '
            '      for R in $ALL_REPOIDS; do case "$R" in *"{ver}"*) TARGET_REPO="$R"; break;; esac; done; '
            '      if [ -z "$TARGET_REPO" ]; then '
            '        case "{ver}" in '
            '          8.0*) for R in $ALL_REPOIDS; do case "$R" in *80*) TARGET_REPO="$R"; break;; esac; done ;; '
            '          8.4*) for R in $ALL_REPOIDS; do case "$R" in *84*) TARGET_REPO="$R"; break;; esac; done ;; '
            '          9.7*) for R in $ALL_REPOIDS; do case "$R" in *97*|*9.7*) TARGET_REPO="$R"; break;; esac; done ;; '
            '          innovation) for R in $ALL_REPOIDS; do case "$R" in *innovation*) TARGET_REPO="$R"; break;; esac; done ;; '
            '        esac; '
            '      fi; '
            '      [ -n "$TARGET_REPO" ] && (dnf config-manager --set-enabled "$TARGET_REPO" 2>/dev/null || yum-config-manager --enable "$TARGET_REPO" 2>/dev/null); '
            '      for R in $ALL_REPOIDS; do '
            '        [ "$R" = "$TARGET_REPO" ] && continue; '
            '        case "$R" in *community*) (dnf config-manager --set-disabled "$R" 2>/dev/null || yum-config-manager --disable "$R" 2>/dev/null);; esac; '
            '      done; '
            '    done; '
            '    yum install -y mysql-community-server 2>/dev/null || dnf install -y mysql-community-server 2>/dev/null; '
            '  fi && '
            '  systemctl enable --now mysqld 2>/dev/null || systemctl enable --now mysql 2>/dev/null; '
            'fi'
        ),
        'uninstall':'systemctl stop mysql mysqld 2>/dev/null; systemctl disable mysql mysqld 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold mysql-server mysql-client mysql-common mysql-server-core-* mysql-client-core-* 2>/dev/null; apt-get autoremove -y 2>/dev/null; dnf remove -y mysql-server mysql-community-server 2>/dev/null; yum remove -y mysql-server mysql-community-server 2>/dev/null; rm -rf /etc/mysql /var/lib/mysql',
        'service':'mysql', 'manage':True,
    },
    {
        'id':'mariadb', 'name':'MariaDB', 'icon':'/static/icons/mariadb.svg', 'category':'Database',
        'desc':'Community-developed MySQL fork by MariaDB Foundation',
        'check':'systemctl is-active mariadb 2>/dev/null | grep -q "^active" && echo found || (which mariadbd 2>/dev/null && mariadbd --version 2>/dev/null | grep -c MariaDB)',
        'versions':[
            {'label':'12.3.2 (Latest Stable)', 'value':'12.3'},
            {'label':'11.8.8',                 'value':'11.8'},
            {'label':'11.4.5 (LTS)',           'value':'11.4'},
            {'label':'10.11.11 (LTS)',         'value':'10.11'},
        ],
        'install_tpl':'''curl -fLsS https://downloads.mariadb.com/MariaDB/mariadb_repo_setup -o /tmp/mariadb_repo.sh && \
bash /tmp/mariadb_repo.sh --mariadb-server-version="mariadb-{ver}" --skip-maxscale; \
for f in /etc/apt/sources.list.d/*.sources; do [ -f "$f" ] || continue; if grep -qi maxscale "$f"; then awk -v RS="" -v ORS="\n\n" \'tolower($0) !~ /maxscale/\' "$f" > "$f.tmp" && mv "$f.tmp" "$f"; fi; done; \
for f in /etc/apt/sources.list.d/*.list; do [ -f "$f" ] || continue; if grep -qi maxscale "$f"; then sed -i \'/[Mm]ax[Ss]cale/d\' "$f"; fi; done; \
apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server && \
systemctl enable --now mariadb''',
        'install':'DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server && systemctl enable mariadb && systemctl start mariadb',
        'uninstall':'systemctl stop mariadb 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold mariadb-server mariadb-client mariadb-common mysql-common && apt-get autoremove -y && rm -rf /etc/mysql /var/lib/mysql /etc/apt/sources.list.d/mariadb.list /etc/apt/sources.list.d/mariadb.sources /etc/apt/keyrings/mariadb-keyring.pgp /usr/share/keyrings/mariadb-keyring*.gpg 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'service':'mariadb', 'manage':True,
    },
    {
        'id':'mongodb', 'name':'MongoDB', 'icon':'/static/icons/mongodb.svg', 'category':'Database',
        'desc':'Document-oriented NoSQL database',
        'check':'which mongod 2>/dev/null',
        'versions':[
            {'label':'7.0 (LTS)',    'value':'7.0'},
            {'label':'8.0 (Latest)', 'value':'8.0'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  export DEBIAN_FRONTEND=noninteractive && '
            '  apt-get install -y gnupg curl && '
            '  rm -f /usr/share/keyrings/mongodb-server-{ver}.gpg /etc/apt/sources.list.d/mongodb-org-{ver}.list && '
            '  curl -fsSL https://www.mongodb.org/static/pgp/server-{ver}.asc -o /tmp/mongo.key && '
            '  gpg --batch --no-tty --dearmor -o /usr/share/keyrings/mongodb-server-{ver}.gpg /tmp/mongo.key && '
            '  rm -f /tmp/mongo.key && '
            '  echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-{ver}.gpg ] '
            'https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/{ver} multiverse" '
            '  > /etc/apt/sources.list.d/mongodb-org-{ver}.list && '
            # MongoDB has no fallback in Ubuntu'"'"'s own archive at all (it'"'"'s
            # never distro-packaged), so unlike Redis there'"'"'s nothing to fall
            # back to if repo.mongodb.org has no release for this codename yet
            # -- but the broken repo file must still be cleaned up, or it
            # poisons every unrelated apt-get update run afterward.
            '  if ! apt-get update -qq 2>/tmp/vp_mongo_repo_err.log; then '
            '    echo "[VortexPanel] repo.mongodb.org has no release for $(lsb_release -cs) yet -- removing the broken repo entry so it does not block other installs"; '
            '    rm -f /etc/apt/sources.list.d/mongodb-org-{ver}.list; '
            '    apt-get update -qq; '
            '    exit 1; '
            '  fi && '
            '  apt-get install -y mongodb-org && '
            '  systemctl enable mongod && systemctl start mongod; '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
                # Official MongoDB-documented RHEL .repo format (repo.mongodb.org/yum/redhat)
            '  RHEL_VER=$(rpm -E %rhel 2>/dev/null || echo 9) && '
            '  printf "[mongodb-org-{ver}]\\nname=MongoDB Repository\\nbaseurl=https://repo.mongodb.org/yum/redhat/%s/mongodb-org/{ver}/\\$basearch/\\ngpgcheck=1\\nenabled=1\\ngpgkey=https://www.mongodb.org/static/pgp/server-{ver}.asc\\n" "$RHEL_VER" > /etc/yum.repos.d/mongodb-org-{ver}.repo && '
            '  (dnf install -y mongodb-org 2>/dev/null || yum install -y mongodb-org) && '
            '  systemctl enable mongod && systemctl start mongod; '
            'fi'
        ),
        'install':'',  # always uses install_tpl
        'uninstall':'systemctl stop mongod 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold mongodb-org mongodb-org-* 2>/dev/null; dnf remove -y mongodb-org 2>/dev/null; yum remove -y mongodb-org 2>/dev/null; apt-get autoremove -y 2>/dev/null; rm -rf /var/lib/mongodb /var/log/mongodb /usr/share/keyrings/mongodb-server-*.gpg /etc/apt/sources.list.d/mongodb-org-*.list /etc/yum.repos.d/mongodb-org-*.repo 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'service':'mongod', 'manage':True,
    },
    {
        'id':'postgresql', 'name':'PostgreSQL', 'icon':'/static/icons/postgresql.svg', 'category':'Database',
        'desc':'Advanced open source relational database',
        'check':'which psql 2>/dev/null',
        'versions':[
            {'label':'15 (Stable)', 'value':'15'},
            {'label':'16 (Stable)', 'value':'16'},
            {'label':'17 (Latest)', 'value':'17'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  export DEBIAN_FRONTEND=noninteractive && '
            '  apt-get install -y gnupg2 curl lsb-release && '
            '  rm -f /usr/share/keyrings/postgresql.gpg /etc/apt/sources.list.d/pgdg.list && '
            '  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /tmp/pg.asc && '
            '  gpg --batch --no-tty --dearmor -o /usr/share/keyrings/postgresql.gpg /tmp/pg.asc && '
            '  rm -f /tmp/pg.asc && '
            '  PG_CODENAME=$(lsb_release -cs) && '
            '  echo "deb [signed-by=/usr/share/keyrings/postgresql.gpg] '
            'http://apt.postgresql.org/pub/repos/apt ${PG_CODENAME}-pgdg main" '
            '  > /etc/apt/sources.list.d/pgdg.list && '
            # Same failure class already confirmed elsewhere: PGDG is a much
            # more actively-maintained project than the PPAs above, but a
            # brand-new Ubuntu codename can still lag behind by days/weeks
            # before PGDG publishes for it. Leaving a broken pgdg.list in
            # place would poison every future apt-get update on the system.
            '  if ! apt-get update -qq 2>/tmp/vp_pg_repo_err.log; then '
            '    echo "[VortexPanel] apt.postgresql.org has no release for ${PG_CODENAME} yet -- removing pgdg.list so it does not block other installs"; '
            '    rm -f /etc/apt/sources.list.d/pgdg.list; '
            '    apt-get update -qq; '
            '    exit 1; '
            '  fi && '
            '  apt-get install -y postgresql-{ver} postgresql-contrib && '
            '  systemctl enable postgresql && systemctl start postgresql; '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
                # Official PostgreSQL-documented RHEL method — pgdg-redhat-repo RPM.
                # RHEL/AlmaLinux/Rocky ship an OLDER "postgresql" AppStream module by
                # default which conflicts with PGDG's own versioned packages, so it
                # must be disabled first (this is PostgreSQL's own documented step).
            '  RHEL_VER=$(rpm -E %rhel 2>/dev/null || echo 9) && '
            '  ARCH=$(uname -m) && '
            '  (dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-${RHEL_VER}-${ARCH}/pgdg-redhat-repo-latest.noarch.rpm 2>/dev/null || '
            '   yum install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-${RHEL_VER}-${ARCH}/pgdg-redhat-repo-latest.noarch.rpm 2>/dev/null) && '
            '  dnf -qy module disable postgresql 2>/dev/null; '
            '  (dnf install -y postgresql{ver}-server postgresql{ver}-contrib 2>/dev/null || '
            '   yum install -y postgresql{ver}-server postgresql{ver}-contrib 2>/dev/null) && '
            '  /usr/pgsql-{ver}/bin/postgresql-{ver}-setup initdb 2>/dev/null && '
            '  systemctl enable postgresql-{ver} && systemctl start postgresql-{ver}; '
            'fi'
        ),
        'install':'apt-get install -y postgresql postgresql-contrib && systemctl enable postgresql && systemctl start postgresql',
        'uninstall':'systemctl stop postgresql postgresql-* 2>/dev/null; systemctl disable postgresql postgresql-* 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold postgresql postgresql-* 2>/dev/null; dnf remove -y postgresql-server postgresql-contrib "postgresql*-server" "postgresql*-contrib" 2>/dev/null; yum remove -y postgresql-server postgresql-contrib 2>/dev/null; apt-get autoremove -y 2>/dev/null; rm -rf /etc/postgresql /var/lib/postgresql /var/lib/pgsql /usr/share/keyrings/postgresql.gpg /etc/apt/sources.list.d/pgdg.list /etc/yum.repos.d/pgdg-redhat-repo.repo 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'service':'postgresql', 'manage':True,
    },
    # --- PHP -------------------------------------------------------------------
    {
        'id':'php', 'name':'PHP', 'icon':'/static/icons/php.svg', 'category':'PHP',
        'desc':'PHP-FPM — multiple versions supported side by side',
        'check':'which php8.5 php8.4 php8.3 php8.2 php8.1 php8.0 2>/dev/null | head -1',
        'versions':[
            {'label':'8.5 (Latest — active)',        'value':'8.5'},
            {'label':'8.4 (Active)',                 'value':'8.4'},
            {'label':'8.3 (Security only)',          'value':'8.3'},
            {'label':'8.2 (Security only — EOL Dec 2026)', 'value':'8.2'},
            {'label':'8.1 (EOL — unpatched)',        'value':'8.1'},
            {'label':'7.4 (EOL — unpatched)',        'value':'7.4'},
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
apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold php{ver} php{ver}-fpm php{ver}-common php{ver}-mysql \
php{ver}-xml php{ver}-curl php{ver}-gd php{ver}-mbstring php{ver}-zip php{ver}-bcmath \
php{ver}-intl php{ver}-soap php{ver}-cli php{ver}-readline php{ver}-* 2>/dev/null || true && \
apt-get autoremove -y 2>/dev/null || true''',
        'uninstall':'''for ver in 7.4 8.1 8.2 8.3 8.4; do
  systemctl stop php$ver-fpm 2>/dev/null || true
  apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold php$ver php$ver-* 2>/dev/null || true
done
apt-get autoremove -y 2>/dev/null || true''',
        'manage':False,
    },
    # --- FTP -------------------------------------------------------------------
    {
        'id':'pure-ftpd', 'name':'Pure-FTPd', 'icon':'/static/icons/filezilla.svg', 'category':'FTP',
        'desc':'Simple, fast and secure FTP server',
        'check':'which pure-ftpd 2>/dev/null',
        'versions':[
            {'label':'1.0.52 (Latest Stable)', 'value':'latest'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  apt-get install -y pure-ftpd pure-ftpd-common; '
            'else '
            # Confirmed via multiple current EPEL/RHEL package sources:
            # pure-ftpd-common does not exist as a separate RPM package on
            # RHEL-family - it's just pure-ftpd there. dnf fails the ENTIRE
            # install command if any one listed package doesn't exist, so
            # this previously failed outright on every RHEL-family system.
            '  (dnf install -y epel-release 2>/dev/null || yum install -y epel-release 2>/dev/null; true) && '
            '  (dnf install -y pure-ftpd 2>/dev/null || yum install -y pure-ftpd 2>/dev/null); '
            'fi && '
            'systemctl enable pure-ftpd && systemctl start pure-ftpd'
        ),
        'uninstall':'systemctl stop pure-ftpd 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold pure-ftpd pure-ftpd-common && apt-get autoremove -y',
        'service':'pure-ftpd', 'manage':True,
    },
    # --- Admin Tools -----------------------------------------------------------
    {
        'id':'phpmyadmin', 'name':'phpMyAdmin', 'icon':'/static/icons/phpmyadmin.svg', 'category':'Admin Tools',
        'desc':'Web-based MySQL/MariaDB admin — auto-configured at port 8082',
        'check':'test -f /usr/share/phpmyadmin/config.inc.php && echo found',
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
            '  <FilesMatch \\.php$>\n'
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
            '(command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active" && ufw allow 8082/tcp comment "phpMyAdmin" || true) && '
            '(command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --permanent --add-port=8082/tcp && firewall-cmd --reload || true) && '
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
            'systemctl reload apache2 2>/dev/null || true && '
            '(command -v ufw >/dev/null 2>&1 && ufw delete allow 8082/tcp 2>/dev/null || true) && '
            '(command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --permanent --remove-port=8082/tcp && firewall-cmd --reload || true)'
        ),
        'manage':False,
    },
    # --- Security --------------------------------------------------------------
    {
        'id':'fail2ban', 'name':'Fail2ban', 'icon':'/static/icons/fail2ban.svg', 'category':'Security',
        'desc':'Intrusion prevention & brute-force protection',
        'check':'which fail2ban-client 2>/dev/null',
        'versions':[
            {'label':'1.1.0 (Latest Stable)', 'value':'latest'},
        ],
        'install':r'''OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian) && \
if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then \
  apt-get install -y python3 python3-pip curl gzip && \
  F2B_VER=$(curl -fsSL https://api.github.com/repos/fail2ban/fail2ban/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+') && \
  F2B_VER=${F2B_VER:-1.1.0} && \
  curl -fsSL https://github.com/fail2ban/fail2ban/releases/download/${F2B_VER}/fail2ban_${F2B_VER#v}-1.upstream1_all.deb -o /tmp/fail2ban.deb 2>/dev/null && \
  dpkg -i /tmp/fail2ban.deb 2>/dev/null; \
  if [ ! -f /lib/systemd/system/fail2ban.service ] && [ ! -f /usr/lib/systemd/system/fail2ban.service ]; then \
    echo "[VortexPanel] Upstream package did not provide a systemd unit -- falling back to the distro package"; \
    apt-get install -y fail2ban; \
  fi && \
  systemctl enable fail2ban && systemctl start fail2ban; \
elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then \
  echo "[VortexPanel] fail2ban is not in the default RHEL-family repos -- enabling EPEL first" && \
  (dnf install -y epel-release 2>/dev/null || yum install -y epel-release 2>/dev/null; true) && \
  (dnf install -y fail2ban fail2ban-firewalld 2>/dev/null || yum install -y fail2ban fail2ban-firewalld 2>/dev/null || dnf install -y fail2ban 2>/dev/null || yum install -y fail2ban) && \
  systemctl enable --now fail2ban; \
fi''',
        'uninstall':(
            'systemctl stop fail2ban 2>/dev/null; '
            'apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold fail2ban 2>/dev/null; '
            'apt-get autoremove -y 2>/dev/null; '
            'dnf remove -y fail2ban fail2ban-firewalld 2>/dev/null; yum remove -y fail2ban fail2ban-firewalld 2>/dev/null; true'
        ),
        'service':'fail2ban', 'manage':True,
    },
    {
        'id':'clamav', 'name':'ClamAV', 'icon':'/static/icons/clamav.svg', 'category':'Security',
        'desc':'Open source antivirus engine for mail gateways',
        'check':'which clamscan 2>/dev/null',
        'versions':[
            {'label':'Distro-provided (Ubuntu security-maintained)', 'value':'latest'},
        ],
        'install':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  export DEBIAN_FRONTEND=noninteractive && '
            '  apt-get install -y clamav clamav-daemon clamav-freshclam && '
            '  systemctl enable clamav-freshclam 2>/dev/null; systemctl enable clamav-daemon 2>/dev/null; '
            '  (freshclam 2>&1 || true) && '
            '  systemctl start clamav-freshclam 2>/dev/null; systemctl start clamav-daemon 2>/dev/null; '
            'else '
            # Confirmed via multiple current sources: RHEL-family package
            # names genuinely differ, not just a Debian-vs-RHEL prefix -
            # clamav-daemon and clamav-freshclam do not exist as RPM
            # packages at all. The correct names are clamd and
            # clamav-update, and the service unit is clamd@scan (a systemd
            # template unit), not clamav-daemon.
            '  (dnf install -y epel-release 2>/dev/null || yum install -y epel-release 2>/dev/null; true) && '
            '  (dnf install -y clamav clamd clamav-update 2>/dev/null || yum install -y clamav clamd clamav-update 2>/dev/null) && '
            '  (freshclam 2>&1 || true) && '
            '  systemctl enable clamd@scan 2>/dev/null; systemctl start clamd@scan 2>/dev/null; '
            'fi; true'
        ),
        'uninstall':'systemctl stop clamav-daemon clamav-freshclam 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold clamav clamav-daemon clamav-freshclam && apt-get autoremove -y',
        'service':'clamav-daemon', 'manage':True,
    },
    # --- DNS -------------------------------------------------------------------
    {
        'id':'ddns', 'name':'DDNS Manager', 'icon':'/static/icons/cloudflare.svg', 'category':'DNS',
        'desc':'Dynamic DNS — automatic IP update service via ddclient (Cloudflare, DynDNS and more)',
        'check':'which ddclient 2>/dev/null',
        'versions':[
            {'label':'Latest (apt)', 'value':'latest'},
        ],
        'install':'apt-get install -y ddclient',
        'uninstall':'apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold ddclient && apt-get autoremove -y',
        'manage':False,
    },
        {
        'id':'bind9', 'name':'BIND9 DNS', 'icon':'/static/icons/isc.svg', 'category':'DNS',
        'desc':'Industry standard authoritative DNS server',
        'check':'which named 2>/dev/null',
        'versions':[
            {'label':'9.18.x (ESV/LTS - Ubuntu repo)', 'value':'9.18'},
            {'label':'9.20.x (Stable - ISC official)',  'value':'9.20'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian) && '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  apt-get install -y software-properties-common && '
            '  if [ "{ver}" = "9.20" ]; then '
                 # Same failure class already confirmed for ondrej/php and
                 # ondrej/apache2: isc/bind may have no release for a very new
                 # Ubuntu codename, and add-apt-repository writes it regardless,
                 # poisoning every future apt-get update if left behind.
            '    add-apt-repository -y ppa:isc/bind && '
            '    if ! apt-get update -q 2>/tmp/vp_bind_repo_err.log; then '
            '      echo "[VortexPanel] isc/bind has no release for {codename} yet -- removing it, using stock Ubuntu bind9 (9.18) instead"; '
            '      add-apt-repository --remove -y ppa:isc/bind 2>/dev/null; '
            '      rm -f /etc/apt/sources.list.d/isc-ubuntu-bind-*.list /etc/apt/sources.list.d/isc-ubuntu-bind-*.sources 2>/dev/null; '
            '      apt-get update -q; '
            '    fi; '
            '    apt-get install -y bind9 bind9utils bind9-doc; '
            '  else '
            '    apt-get update -q && apt-get install -y bind9 bind9utils bind9-doc; '
            '  fi && '
            '  mkdir -p /etc/bind/zones && '
            '  (systemctl enable named 2>/dev/null || systemctl enable bind9 2>/dev/null) && '
            '  (systemctl start named 2>/dev/null || systemctl start bind9 2>/dev/null); '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
                 # Package names are 'bind'+'bind-utils' on RHEL-family, NOT
                 # 'bind9' -- confirmed against multiple current, official
                 # RHEL/AlmaLinux/Rocky documentation sources. No verified
                 # ISC-official repo exists for RHEL-family the way it does
                 # for Ubuntu, so this always installs whatever version the
                 # distro's own default repo provides, regardless of {ver} --
                 # honest about that rather than inventing an unverified repo URL.
            '  echo "[VortexPanel] Installing BIND from the distro default repo on RHEL-family (no verified ISC-official RHEL repo for a specific version)"; '
            '  (dnf install -y bind bind-utils 2>/dev/null || yum install -y bind bind-utils) && '
            '  mkdir -p /var/named && '
            '  systemctl enable --now named; '
            'fi'
        ),
        'install':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  apt-get install -y bind9 bind9utils bind9-doc && mkdir -p /etc/bind/zones && systemctl enable bind9 && systemctl start bind9; '
            'else '
            '  (dnf install -y bind bind-utils 2>/dev/null || yum install -y bind bind-utils) && mkdir -p /var/named && systemctl enable --now named; '
            'fi'
        ),
        'uninstall':(
            'systemctl stop named 2>/dev/null; systemctl stop bind9 2>/dev/null; '
            'apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold bind9 bind9utils bind9-doc 2>/dev/null; '
            'dnf remove -y bind bind-utils 2>/dev/null; yum remove -y bind bind-utils 2>/dev/null; '
            'apt-get autoremove -y 2>/dev/null; rm -rf /etc/bind/zones /var/named/*.local 2>/dev/null'
        ),
        'service':'named', 'manage':True,
    },
    # --- Runtimes --------------------------------------------------------------
    {
        'id':'nodejs', 'name':'Node.js', 'icon':'/static/icons/nodejs.svg', 'category':'Runtime',
        'desc':'JavaScript runtime built on Chrome V8 engine',
        'check':'which node 2>/dev/null || which nodejs 2>/dev/null',
        'versions':[
            {'label':'v24 LTS — Active (Krypton)', 'value':'24'},
            {'label':'v22 LTS — Maintenance (Jod)', 'value':'22'},
            {'label':'v26 Current (non-LTS)',       'value':'26'},
        ],
        'install_tpl':'''mkdir -p /etc/apt/keyrings && \\
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --batch --yes --dearmor -o /etc/apt/keyrings/nodesource.gpg && \\
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_{ver}.x nodistro main" > /etc/apt/sources.list.d/nodesource.list && \\
apt-get update -o APT::Update::Error-Mode=any && \\
DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs''',
        'install':'''mkdir -p /etc/apt/keyrings && \\
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --batch --yes --dearmor -o /etc/apt/keyrings/nodesource.gpg && \\
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_24.x nodistro main" > /etc/apt/sources.list.d/nodesource.list && \\
apt-get update -o APT::Update::Error-Mode=any && \\
DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs''',
        'uninstall':'apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold nodejs && apt-get autoremove -y && rm -f /etc/apt/sources.list.d/nodesource.list /usr/share/keyrings/nodesource.gpg /usr/share/keyrings/nodesource-repo.gpg /etc/apt/keyrings/nodesource.gpg 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'manage':False,
    },
    {
        'id':'python', 'name':'Python Manager', 'icon':'/static/icons/python.svg', 'category':'Runtime',
        'desc':'Python 3 runtime + pip + venv',
        'check':'which python3 2>/dev/null',
        'versions':[
            {'label':'3.10 (Security)', 'value':'3.10'},
            {'label':'3.11 (Security)', 'value':'3.11'},
            {'label':'3.12 (Active)',   'value':'3.12'},
            {'label':'3.13 (Latest)',   'value':'3.13'},
        ],
        'install_tpl':'''apt-get install -y software-properties-common && \
add-apt-repository -y ppa:deadsnakes/ppa && \
if ! apt-get update -q 2>/tmp/vp_python_repo_err.log; then \
  echo "[VortexPanel] deadsnakes/ppa has no release for {codename} yet -- this specific Python version cannot be installed via PPA on this OS release. Removing the broken repo entry so it does not block other installs."; \
  add-apt-repository --remove -y ppa:deadsnakes/ppa 2>/dev/null; \
  rm -f /etc/apt/sources.list.d/deadsnakes-ubuntu-ppa-*.list /etc/apt/sources.list.d/deadsnakes-ubuntu-ppa-*.sources 2>/dev/null; \
  apt-get update -q; \
  exit 1; \
fi && \
apt-get install -y python{ver} python{ver}-venv python{ver}-dev && \
curl -sS https://bootstrap.pypa.io/get-pip.py | python{ver} 2>/dev/null || true''',
        'install':'apt-get install -y python3 python3-pip python3-venv python3-dev',
        'uninstall_tpl':'''apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold python{ver} python{ver}-venv python{ver}-dev \
python{ver}-distutils python{ver}-lib2to3 2>/dev/null || true && \
apt-get autoremove -y 2>/dev/null || true && \
update-alternatives --remove python /usr/bin/python{ver} 2>/dev/null || true''',
        'uninstall':'''for ver in 3.10 3.11 3.12 3.13; do
  apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold python$ver python$ver-* 2>/dev/null || true
done
apt-get autoremove -y 2>/dev/null || true''',
        'manage':False,
    },
    # --- Containers ------------------------------------------------------------
    {
        'id':'docker', 'name':'Docker', 'icon':'/static/icons/docker.svg', 'category':'Containers',
        'desc':'Container platform — build, ship, run anywhere',
        'check':'which docker 2>/dev/null',
        'versions':[
            {'label':'v27 CE (Stable)',  'value':'27'},
            {'label':'v28 CE (Stable)',  'value':'28'},
            {'label':'v29 CE (Latest)',  'value':'29'},
        ],
        'install':'curl -fsSL https://get.docker.com | sh && systemctl enable docker && systemctl start docker',
        'uninstall':'systemctl stop docker 2>/dev/null; systemctl disable docker 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin && apt-get autoremove -y && rm -f /usr/share/keyrings/docker-archive-keyring.gpg /etc/apt/sources.list.d/docker.list 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'service':'docker', 'manage':True,
    },
    # --- Dev -------------------------------------------------------------------
    {
        'id':'composer', 'name':'Composer', 'icon':'/static/icons/composer.svg', 'category':'Dev',
        'desc':'PHP dependency & package manager',
        'check':'which composer 2>/dev/null',
        'versions':[
            {'label':'2.8 (Latest Stable)', 'value':'2'},
        ],
        'install_tpl':(
            'curl -fsSL https://getcomposer.org/installer -o /tmp/composer-setup.php && '
            'php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer && '
            'rm /tmp/composer-setup.php && '
            'chmod +x /usr/local/bin/composer'
        ),
        'install':(
            'curl -fsSL https://getcomposer.org/installer -o /tmp/composer-setup.php && '
            'php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer && '
            'rm /tmp/composer-setup.php && '
            'chmod +x /usr/local/bin/composer'
        ),
        'uninstall':'rm -f /usr/local/bin/composer',
        'uninstall':'rm -f /usr/local/bin/composer',
        'manage':False,
    },
    # --- Cache -----------------------------------------------------------------
    {
        'id':'redis', 'name':'Redis', 'icon':'/static/icons/redis.svg', 'category':'Cache',
        'desc':'In-memory data store, cache & message broker',
        'check':'which redis-server 2>/dev/null',
        'versions':[
            {'label':'7.2.7 (Stable)', 'value':'7.2'},
            {'label':'8.0.2 (Latest)', 'value':'8.0'},
        ],
        'install_tpl':'''rm -f /usr/share/keyrings/redis-archive-keyring.gpg && curl -fsSL https://packages.redis.io/gpg | gpg --batch --no-tty --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg && \
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list && \
if ! apt-get update -o APT::Update::Error-Mode=any 2>/tmp/vp_redis_repo_err.log; then \
  echo "[VortexPanel] packages.redis.io has no release for $(lsb_release -cs) yet -- removing it, using distro-packaged redis-server instead"; \
  rm -f /etc/apt/sources.list.d/redis.list; \
  apt-get update -qq; \
fi; \
apt-get install -y redis-server && systemctl enable redis-server && systemctl start redis-server''',
        'install':'''rm -f /usr/share/keyrings/redis-archive-keyring.gpg && curl -fsSL https://packages.redis.io/gpg | gpg --batch --no-tty --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg && \
echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list && \
apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; \
apt-get install -y redis-server && systemctl enable redis-server && systemctl start redis-server''',
        'uninstall':'systemctl stop redis-server 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold redis-server redis-tools && apt-get autoremove -y && rm -f /usr/share/keyrings/redis-archive-keyring.gpg /etc/apt/sources.list.d/redis.list 2>/dev/null; apt-get update -qq 2>/dev/null; true',
        'service':'redis-server', 'manage':True,
    },
    # --- Server Tools ----------------------------------------------------------
    {
        'id':'supervisor', 'name':'Supervisor', 'icon':'/static/icons/supervisor.svg', 'category':'Server',
        'desc':'Process control — keep programs running',
        'check':'which supervisord 2>/dev/null',
        'versions':[
            {'label':'4.3.0 (Latest Stable)', 'value':'latest'},
        ],
        'install_tpl':(
            'export DEBIAN_FRONTEND=noninteractive && '
            + ('apt-get install -y supervisor' if __import__("subprocess").run("which apt-get",shell=True,capture_output=True).returncode==0 else 'dnf install -y supervisor') +
            ' && systemctl enable supervisord 2>/dev/null || systemctl enable supervisor && '
            'systemctl start supervisord 2>/dev/null || systemctl start supervisor'
        ),
        'install':'DEBIAN_FRONTEND=noninteractive apt-get install -y supervisor && systemctl enable supervisor && systemctl start supervisor',
        'uninstall':'systemctl stop supervisor 2>/dev/null; apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold supervisor && apt-get autoremove -y',
        'service':'supervisor', 'manage':True,
    },
    {
        'id':'memcached', 'name':'Memcached', 'icon':'/static/icons/memcached.svg', 'category':'Cache',
        'desc':'Memcached is a high performance distributed memory object caching system',
        # memcached is packaged natively in every mainstream distro's default repos —
        # no custom keyring/repo dance needed, unlike Redis/nginx/etc.
        'check':'which memcached 2>/dev/null',
        'versions':[
            {'label':'Latest (distro-packaged)', 'value':'latest'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  apt-get install -y memcached libmemcached-tools && '
            '  systemctl enable memcached && systemctl start memcached; '
            'elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
            '  (dnf install -y memcached libmemcached 2>/dev/null || yum install -y memcached libmemcached 2>/dev/null) && '
            '  systemctl enable memcached && systemctl start memcached; '
            'fi'
        ),
        'install':'apt-get install -y memcached libmemcached-tools && systemctl enable memcached && systemctl start memcached',
        'uninstall':'systemctl stop memcached 2>/dev/null; systemctl disable memcached 2>/dev/null; apt-get remove -y --purge memcached libmemcached-tools 2>/dev/null; dnf remove -y memcached libmemcached 2>/dev/null; yum remove -y memcached libmemcached 2>/dev/null; apt-get autoremove -y 2>/dev/null; rm -f /etc/memcached.conf /etc/sysconfig/memcached',
        'service':'memcached', 'manage':True,
    },
    {
        'id':'ffmpeg', 'name':'ffmpeg manager', 'icon':'/static/icons/ffmpeg.svg', 'category':'Tools',
        'desc':'Supports installation and management of versions 7.1, 8.1, and nightly master. It is an open source computer program used to record, convert and stream audio and video.',
        # ffmpeg is a CLI tool, not a background service — no 'service' key, no start/stop.
        # Multiple major versions install SIDE BY SIDE (not one-at-a-time like PHP/Node),
        # each to its own directory with its own command alias (ffmpeg3/4/5/6), matching
        # aaPanel's ffmpeg manager UX exactly. Managed via dedicated /api/modules/ffmpeg/versions/*
        # endpoints rather than the generic single install/uninstall pattern.
        'check':'find /www/server/ffmpeg -mindepth 3 -maxdepth 3 -type f -name ffmpeg -path "*/bin/ffmpeg" 2>/dev/null | grep -q . && echo found',
        'versions':[],  # version list is dynamic — served by /api/modules/ffmpeg/versions
        'install_tpl':'',   # installs happen per-version, see dedicated endpoints
        'install':'',
        'uninstall':'',     # uninstalls happen per-version, see dedicated endpoints
        'manage':True,
    },
    # --- Webmail ----------------------------------------------------------------
    {
        'id':'roundcube', 'name':'Roundcube', 'icon':'/static/icons/roundcube.svg', 'category':'Mail',
        'desc':'Modern web-based IMAP email client',
        'check':'test -d /var/www/roundcube && echo found',
        'versions':[
            {'label':'1.6.16 (LTS)',    'value':'1.6.16'},
            {'label':'1.7.1  (Latest)', 'value':'1.7.1'},
        ],
        'install_tpl':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '  apt-get install -y wget php php-mysql php-curl php-json php-mbstring '
            '  php-intl php-imagick php-xml php-zip php-gd; '
            '  WEB_USER=www-data; '
            'else '
            # Confirmed via multiple current sources (including the widely-used
            # geerlingguy.php-mysql Ansible role's own distro-specific default):
            # RHEL-family uses php-mysqlnd, not php-mysql - that package does
            # not exist there at all, and dnf fails the ENTIRE install command
            # if any one listed package is unknown, unlike a partial failure.
            '  (dnf install -y epel-release 2>/dev/null || yum install -y epel-release 2>/dev/null; true); '
            '  (dnf install -y wget php php-mysqlnd php-curl php-json php-mbstring '
            '  php-intl php-imagick php-xml php-zip php-gd 2>/dev/null || '
            '  yum install -y wget php php-mysqlnd php-curl php-json php-mbstring '
            '  php-intl php-imagick php-xml php-zip php-gd 2>/dev/null); '
            # www-data does not exist as a user on RHEL-family at all - the
            # actual web server user there is apache (or nginx, if that's
            # what's installed) - confirmed the same way get_webserver_user()
            # already resolves this elsewhere in this codebase.
            '  WEB_USER=apache; '
            '  id nginx >/dev/null 2>&1 && systemctl is-active nginx >/dev/null 2>&1 && WEB_USER=nginx; '
            'fi && '
            'mkdir -p /var/www/roundcube && '
            'wget -q https://github.com/roundcube/roundcubemail/releases/download/{ver}/roundcubemail-{ver}-complete.tar.gz '
            '  -O /tmp/roundcube.tar.gz && '
            'tar -xzf /tmp/roundcube.tar.gz -C /var/www/roundcube --strip-components=1 && '
            'cp /var/www/roundcube/config/config.inc.php.sample /var/www/roundcube/config/config.inc.php && '
            'chown -R $WEB_USER:$WEB_USER /var/www/roundcube/'
        ),
        'install':'',
        'uninstall':'rm -rf /var/www/roundcube',
        'manage':True,
    },
    # --- WAF / Security ---------------------------------------------------------
    {
        'id':'modsecurity', 'name':'ModSecurity WAF', 'icon':'/static/icons/modsecurity.svg', 'category':'Security',
        'desc':'OWASP CRS v4 Web Application Firewall — Nginx/Apache, all distros (Debian/Ubuntu/RHEL/Fedora/AlmaLinux/Rocky)',
        # "Installed" requires the CORE engine to be usable (library + modsecurity.conf) —
        # NOT the CRS ruleset, which is a separate, retriable download step (see install_tpl
        # below). Previously this only checked the library .so file, so a server where the
        # library installed but the LATER modsecurity.conf/CRS download steps failed (e.g.
        # GitHub API rate-limit, network hiccup) would show "Installed" in the App Store
        # while every actual WAF control (Engine Mode toggle, Paranoia level) failed with
        # "not installed" / "CRS setup.conf not found" — a real, confirmed bug.
        # "Installed" requires the library, the config, AND the nginx connector
        # module to actually be loadable by nginx — not just present on disk.
        # Checking only the library+config (as before) is exactly the false-green
        # pattern already fixed once for the CRS chain; the connector needs the
        # same treatment now that it's a from-source build rather than an apt
        # package that either installs cleanly or is simply absent.
        'check':(
            '('
            '(test -f /usr/lib/x86_64-linux-gnu/libmodsecurity.so.3 || '
            'test -f /usr/lib64/libmodsecurity.so.3 || '
            'test -f /usr/lib/aarch64-linux-gnu/libmodsecurity.so.3 || '
            'which modsec_rules_check 2>/dev/null 1>&2) && '
            'test -f /etc/nginx/modsec/modsecurity.conf && '
            '(find /usr/lib/nginx/modules /usr/lib64/nginx/modules -name "ngx_http_modsecurity_module.so" 2>/dev/null | grep -q .) && '
            'grep -q "modsecurity_rules_file" /etc/nginx/nginx.conf 2>/dev/null'
            ') || ('
            'dpkg -l libapache2-mod-security2 2>/dev/null | grep -q "^ii" && '
            'test -f /etc/modsecurity/modsecurity.conf && '
            '(a2query -m security2 2>/dev/null | grep -q enabled || grep -rq "security2" /etc/apache2/mods-enabled/ 2>/dev/null)'
            ') && echo found'
        ),
        'versions':[
            {'label':'v3 + OWASP CRS v4 (Recommended)', 'value':'3'},
            {'label':'v2 + OWASP CRS v4 (Apache legacy)', 'value':'2'},
        ],
        'install_tpl':(
    'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); echo "[VortexPanel] Installing ModSecurity engine..."; WAF_VER="{ver}"; if [ "$WAF_VER" = "2" ]; then apt-get install -y libapache2-mod-security2 2>&1   || echo "[WARN] libapache2-mod-security2 install reported errors"; a2enmod security2 >/dev/null 2>&1 || true; mkdir -p /etc/modsecurity; if [ -f /etc/modsecurity/modsecurity.conf-recommended ]; then   cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf;   sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/" /etc/modsecurity/modsecurity.conf;   sed -i "s#SecUnicodeMapFile unicode.mapping#SecUnicodeMapFile /etc/modsecurity/unicode.mapping#" /etc/modsecurity/modsecurity.conf;   echo "[VortexPanel] OK Core engine config written (Apache)"; else   echo "[ERROR] modsecurity.conf-recommended not found - writing fallback";   printf "SecRuleEngine On\\nSecRequestBodyAccess On\\nSecAuditEngine RelevantOnly\\nSecAuditLog /var/log/modsec_audit.log\\n" > /etc/modsecurity/modsecurity.conf; fi; if [ -f /usr/share/modsecurity-crs/owasp-crs.load ]; then   mv /usr/share/modsecurity-crs/owasp-crs.load /usr/share/modsecurity-crs/owasp-crs.load.disabled-by-vortexpanel 2>/dev/null; fi; echo "[VortexPanel] Downloading OWASP CRS ruleset..."; mkdir -p /etc/modsecurity/crs && CRS_OK=0; for attempt in 1 2 3; do   CRS_TAG=$(curl -s --max-time 10 https://api.github.com/repos/coreruleset/coreruleset/releases/latest     | python3 -c "import json,sys; print(json.load(sys.stdin)[\'tag_name\'])" 2>/dev/null);   CRS_TAG=${CRS_TAG:-v4.0.0};   wget -q --timeout=15 "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_TAG}.tar.gz" -O /tmp/crs.tar.gz     && tar -xzf /tmp/crs.tar.gz -C /etc/modsecurity/crs --strip-components=1 2>/dev/null     && rm -f /tmp/crs.tar.gz && CRS_OK=1 && break;   echo "[VortexPanel] CRS download attempt $attempt failed, retrying..."; sleep 3; done; if [ "$CRS_OK" = "1" ] && [ -f /etc/modsecurity/crs/crs-setup.conf.example ]; then   cp /etc/modsecurity/crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf;   printf "Include /etc/modsecurity/crs/crs-setup.conf\\nInclude /etc/modsecurity/crs/rules/*.conf\\n" > /etc/modsecurity/main.conf;   echo "[VortexPanel] OK OWASP CRS $CRS_TAG installed"; else   printf "" > /etc/modsecurity/main.conf;   echo "[WARN] Could not download CRS after 3 attempts."; fi; echo "0 3 * * 0 root /bin/bash -c \\"CRS_TAG=\\$(curl -s --max-time 10 https://api.github.com/repos/coreruleset/coreruleset/releases/latest | python3 -c \\"import json,sys; print(json.load(sys.stdin)[chr(39)+chr(116)+chr(97)+chr(103)+chr(95)+chr(110)+chr(97)+chr(109)+chr(101)+chr(39)])\\" 2>/dev/null) && wget -q --timeout=15 https://github.com/coreruleset/coreruleset/archive/refs/tags/\\${CRS_TAG}.tar.gz -O /tmp/crs.tar.gz && tar -xzf /tmp/crs.tar.gz -C /etc/modsecurity/crs --strip-components=1 && rm -f /tmp/crs.tar.gz && apache2ctl configtest && systemctl reload apache2\\"" > /etc/cron.d/vortex-crs-update-apache && chmod 644 /etc/cron.d/vortex-crs-update-apache; if apache2ctl configtest 2>&1; then   systemctl reload apache2 2>/dev/null || service apache2 reload 2>/dev/null;   echo "[VortexPanel] OK apache2 config test passed"; else   echo "[ERROR] apache2 configtest failed - disabling security2 module";   a2dismod security2 >/dev/null 2>&1;   (apache2ctl configtest 2>&1 && (systemctl reload apache2 2>/dev/null || service apache2 reload 2>/dev/null) && echo "[VortexPanel] OK security2 disabled, apache2 back up")     || echo "[ERROR] apache2 still failing even with security2 disabled"; fi; else CONNECTOR_OK=0; MODULES_PATH=/usr/lib/nginx/modules; if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then   apt-get update -qq && apt-get install -y libmodsecurity-dev build-essential git     zlib1g-dev libssl-dev 2>&1     || echo "[WARN] libmodsecurity/build-tooling install reported errors";   apt-get install -y libpcre2-dev 2>&1 || apt-get install -y libpcre3-dev 2>&1     || echo "[WARN] Neither libpcre2-dev nor libpcre3-dev available on this system — proceeding anyway, nginx\'s own ./configure will report clearly if it actually needs one";   NGINX_VER=$(nginx -v 2>&1 | grep -oP \'nginx/\\K[0-9.]+\');   DETECTED_MP=$(nginx -V 2>&1 | grep -oP -- \'--modules-path=\\K[^ ]+\');   [ -n "$DETECTED_MP" ] && MODULES_PATH="$DETECTED_MP";   if [ -n "$NGINX_VER" ]; then     BUILD_DIR=$(mktemp -d) && cd "$BUILD_DIR" &&     echo "[VortexPanel] Compiling nginx-ModSecurity connector for nginx $NGINX_VER...";     if wget -q "https://nginx.org/download/nginx-${NGINX_VER}.tar.gz" -O nginx.tar.gz         && tar -xzf nginx.tar.gz         && git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity-nginx.git         && cd "nginx-${NGINX_VER}"         && ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx              > /tmp/modsec-connector-configure.log 2>&1         && make modules > /tmp/modsec-connector-make.log 2>&1         && mkdir -p "$MODULES_PATH"         && cp objs/ngx_http_modsecurity_module.so "$MODULES_PATH/"; then       CONNECTOR_OK=1;       echo "[VortexPanel] ✓ Connector compiled for nginx $NGINX_VER — WAF can actually load in nginx";     else       echo "[ERROR] Connector build failed against nginx $NGINX_VER — see /tmp/modsec-connector-configure.log and /tmp/modsec-connector-make.log on this server. nginx.conf will NOT be modified, so nginx stays working; the engine/CRS below still get prepared but the WAF will not actually be active until this is resolved.";     fi;     cd / && rm -rf "$BUILD_DIR";   else     echo "[ERROR] Could not detect installed nginx version via "nginx -v" — skipping connector build. nginx.conf will NOT be modified.";   fi; elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then   dnf install -y epel-release 2>/dev/null || true;   (dnf install -y gcc make automake autoconf libtool pcre2-devel openssl-devel zlib-devel git 2>&1 || echo "[WARN] build-tooling install reported errors"); NGINX_VER=$(nginx -v 2>&1 | grep -oP \'nginx/\\K[0-9.]+\'); DETECTED_MP=$(nginx -V 2>&1 | grep -oP -- \'--modules-path=\\K[^ ]+\'); [ -n "$DETECTED_MP" ] && MODULES_PATH="$DETECTED_MP"; if [ -n "$NGINX_VER" ]; then   BUILD_DIR=$(mktemp -d) && cd "$BUILD_DIR" &&   echo "[VortexPanel] Compiling nginx-ModSecurity connector for nginx $NGINX_VER (RHEL-family)...";   if wget -q "https://nginx.org/download/nginx-${NGINX_VER}.tar.gz" -O nginx.tar.gz       && tar -xzf nginx.tar.gz       && git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity-nginx.git       && cd "nginx-${NGINX_VER}"       && ./configure --with-compat --add-dynamic-module=../ModSecurity-nginx            > /tmp/modsec-connector-configure.log 2>&1       && make modules > /tmp/modsec-connector-make.log 2>&1       && mkdir -p "$MODULES_PATH"       && cp objs/ngx_http_modsecurity_module.so "$MODULES_PATH/"; then     CONNECTOR_OK=1;     echo "[VortexPanel] ✓ Connector compiled for nginx $NGINX_VER (RHEL-family) — WAF can actually load in nginx";   else     echo "[ERROR] Connector build failed against nginx $NGINX_VER on RHEL-family — see /tmp/modsec-connector-configure.log and /tmp/modsec-connector-make.log on this server.";   fi;   cd / && rm -rf "$BUILD_DIR"; else   echo "[ERROR] Could not detect installed nginx version via nginx -v on RHEL-family — skipping connector build."; fi;   dnf install -y mod_security mod_security_crs 2>&1 || echo "[WARN] mod_security package install reported errors"; fi; echo "[VortexPanel] Writing core engine config..."; mkdir -p /etc/nginx/modsec && CONF_OK=0; for attempt in 1 2 3; do   wget -q https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended     -O /etc/nginx/modsec/modsecurity.conf && CONF_OK=1 && break;   echo "[VortexPanel] modsecurity.conf download attempt $attempt failed, retrying..."; sleep 2; done; if [ "$CONF_OK" = "1" ]; then   sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/" /etc/nginx/modsec/modsecurity.conf;   sed -i "s/SecAuditLogParts ABIJDEFHZ/SecAuditLogParts ABCEFHJKZ/" /etc/nginx/modsec/modsecurity.conf;   wget -q https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping     -O /etc/nginx/modsec/unicode.mapping &&     sed -i "s#SecUnicodeMapFile unicode.mapping#SecUnicodeMapFile /etc/nginx/modsec/unicode.mapping#" /etc/nginx/modsec/modsecurity.conf     || echo "[WARN] Could not download unicode.mapping — nginx -t will fail until this is retried from the WAF page";   echo "[VortexPanel] ✓ Core engine config written — Engine Mode toggle will work"; else   echo "[ERROR] Could not download modsecurity.conf after 3 attempts — writing a minimal fallback config so the engine is still usable";   printf "SecRuleEngine On\\nSecRequestBodyAccess On\\nSecAuditEngine RelevantOnly\\nSecAuditLog /var/log/modsec_audit.log\\n" > /etc/nginx/modsec/modsecurity.conf; fi; echo "[VortexPanel] Downloading OWASP CRS ruleset..."; mkdir -p /etc/nginx/modsec/crs && CRS_OK=0; for attempt in 1 2 3; do   CRS_TAG=$(curl -s --max-time 10 https://api.github.com/repos/coreruleset/coreruleset/releases/latest     | python3 -c "import json,sys; print(json.load(sys.stdin)[\'tag_name\'])" 2>/dev/null);   CRS_TAG=${CRS_TAG:-v4.0.0};   wget -q --timeout=15 "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_TAG}.tar.gz" -O /tmp/crs.tar.gz     && tar -xzf /tmp/crs.tar.gz -C /etc/nginx/modsec/crs --strip-components=1 2>/dev/null     && rm -f /tmp/crs.tar.gz && CRS_OK=1 && break;   echo "[VortexPanel] CRS download attempt $attempt failed, retrying..."; sleep 3; done; if [ "$CRS_OK" = "1" ] && [ -f /etc/nginx/modsec/crs/crs-setup.conf.example ]; then   cp /etc/nginx/modsec/crs/crs-setup.conf.example /etc/nginx/modsec/crs/crs-setup.conf;   echo "[VortexPanel] ✓ OWASP CRS $CRS_TAG installed — Paranoia level control will work"; else   echo "[WARN] Could not download OWASP CRS ruleset after 3 attempts. The core engine (Engine Mode toggle) is still usable, but no attack-pattern rules are loaded yet and Paranoia level will show unavailable until you retry from the WAF page (Repair CRS button)."; fi; if [ "$CRS_OK" = "1" ]; then   printf "Include /etc/nginx/modsec/modsecurity.conf\\nInclude /etc/nginx/modsec/crs/crs-setup.conf\\nInclude /etc/nginx/modsec/crs/rules/*.conf\\n" > /etc/nginx/modsec/main.conf; else   printf "Include /etc/nginx/modsec/modsecurity.conf\\n" > /etc/nginx/modsec/main.conf; fi; cp /etc/nginx/nginx.conf /tmp/nginx.conf.pre-modsecurity 2>/dev/null; if [ "$CONNECTOR_OK" = "1" ]; then   grep -q "ngx_http_modsecurity_module.so" /etc/nginx/nginx.conf 2>/dev/null ||     sed -i "1i load_module ${MODULES_PATH}/ngx_http_modsecurity_module.so;" /etc/nginx/nginx.conf;   grep -q "modsecurity_rules_file" /etc/nginx/nginx.conf 2>/dev/null ||     sed -i "/^http {/a\\    modsecurity on;\\n    modsecurity_rules_file /etc/nginx/modsec/main.conf;"     /etc/nginx/nginx.conf 2>/dev/null || true; else   echo "[VortexPanel] Skipping nginx.conf changes — connector module isn\'t present. nginx stays working; WAF stays inactive until the connector build succeeds."; fi; echo "0 3 * * 0 root /bin/bash -c \\"CRS_TAG=\\$(curl -s --max-time 10 https://api.github.com/repos/coreruleset/coreruleset/releases/latest | python3 -c \\"import json,sys; print(json.load(sys.stdin)[chr(39)+chr(116)+chr(97)+chr(103)+chr(95)+chr(110)+chr(97)+chr(109)+chr(101)+chr(39)])\\" 2>/dev/null) && wget -q --timeout=15 https://github.com/coreruleset/coreruleset/archive/refs/tags/\\${CRS_TAG}.tar.gz -O /tmp/crs.tar.gz && tar -xzf /tmp/crs.tar.gz -C /etc/nginx/modsec/crs --strip-components=1 && rm -f /tmp/crs.tar.gz && nginx -t && systemctl reload nginx\\"" > /etc/cron.d/vortex-crs-update && chmod 644 /etc/cron.d/vortex-crs-update; if nginx -t 2>&1; then   systemctl reload nginx 2>/dev/null;   echo "[VortexPanel] ✓ nginx config test passed — WAF is actually serving traffic"; else   echo "[ERROR] nginx -t failed after this install — restoring nginx.conf to its pre-install state so the server keeps working. WAF is NOT active; fix the underlying issue and reinstall.";   if [ -f /tmp/nginx.conf.pre-modsecurity ]; then     cp /tmp/nginx.conf.pre-modsecurity /etc/nginx/nginx.conf;     nginx -t 2>&1 && systemctl reload nginx 2>/dev/null && echo "[VortexPanel] ✓ nginx.conf restored, server is back up"       || echo "[ERROR] Restore also failed nginx -t — nginx.conf may have been broken before this install ran too. Manual check required.";   fi; fi; echo "[VortexPanel] ModSecurity install finished. Connector: $([ \\"$CONNECTOR_OK\\" = \\"1\\" ] && echo compiled-and-enabled || echo FAILED — WAF NOT active, see /tmp/modsec-connector-*.log). Engine: $([ \\"$CONF_OK\\" = \\"1\\" ] && echo ready || echo fallback-config). CRS ruleset: $([ \\"$CRS_OK\\" = \\"1\\" ] && echo loaded || echo MISSING — use Repair CRS on the WAF page)."; fi; '
        ),
        'uninstall':(
            'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian); '
            'if [ -f /etc/modsecurity/modsecurity.conf ]; then '
                # Apache path -- detected by the actual config file present,
                # not by re-asking which version was originally selected,
                # since that value isn't available at uninstall time and
                # the wrong assumption is exactly what caused this bug:
                # previously uninstall always ran the nginx removal
                # regardless of what was genuinely installed.
            '  if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '    apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold libapache2-mod-security2 modsecurity-crs 2>/dev/null || true; '
            '    apt-get autoremove -y 2>/dev/null || true; '
            '  elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
            '    dnf remove -y mod_security mod_security_crs 2>/dev/null || true; '
            '  fi; '
            '  a2dismod security2 >/dev/null 2>&1 || true; '
            '  rm -rf /etc/modsecurity /etc/cron.d/vortex-crs-update-apache; '
            '  if [ -f /usr/share/modsecurity-crs/owasp-crs.load.disabled-by-vortexpanel ]; then '
            '    mv /usr/share/modsecurity-crs/owasp-crs.load.disabled-by-vortexpanel /usr/share/modsecurity-crs/owasp-crs.load 2>/dev/null || true; '
            '  fi; '
            '  apache2ctl configtest 2>&1 && (systemctl reload apache2 2>/dev/null || service apache2 reload 2>/dev/null) || true; '
            'else '
                # nginx path -- unchanged, already correct for this case.
            '  if echo "$OS_FAMILY" | grep -qiE "debian|ubuntu"; then '
            '    apt-get remove -y --purge -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold libmodsecurity-dev libmodsecurity3t64 libnginx-mod-http-modsecurity 2>/dev/null || true; '
            '    apt-get autoremove -y 2>/dev/null || true; '
            '  elif echo "$OS_FAMILY" | grep -qiE "rhel|fedora|centos|almalinux|rocky"; then '
            '    dnf remove -y mod_security nginx-mod-modsecurity 2>/dev/null || true; '
            '  fi; '
            '  find /usr/lib/nginx/modules /usr/lib64/nginx/modules -name "ngx_http_modsecurity_module.so" -delete 2>/dev/null; '
            '  rm -rf /etc/nginx/modsec /etc/cron.d/vortex-crs-update; '
            '  sed -i "/modsecurity/d" /etc/nginx/nginx.conf 2>/dev/null || true; '
            '  nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true; '
            'fi'
        ),
        'manage':False,
    },
    # --- Load Balancer ----------------------------------------------------------
    {
        'id':'nginx-lb', 'name':'Nginx Load Balancer', 'icon':'/static/icons/nginx.svg', 'category':'Web Server',
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

    # --- CDN --------------------------------------------------------------------
    {
        'id':'cdn', 'name':'CDN Manager', 'icon':'/static/icons/cloudflare.svg', 'category':'Network',
        'desc':'Connect Cloudflare, BunnyCDN, Akamai, CloudFront, KeyCDN, StackPath, Google CDN, Sucuri',
        'check':'echo found',
        'builtin':True,
        'versions':[{'label':'Built-in', 'value':'builtin'}],
        'install':'mkdir -p /opt/vortexpanel && echo "{}" > /opt/vortexpanel/cdn_config.json',
        'uninstall':'rm -f /opt/vortexpanel/cdn_config.json',
        'manage':False,
    },
]

def _get_mod(mod_id):
    return next((m for m in MODULES if m['id'] == mod_id), None)


# --- Conflict groups — only one from each group can be installed ---------------
CONFLICT_GROUPS = {
    'webserver': ['nginx', 'apache2', 'openlitespeed', 'caddy'],
    'database':  ['mysql', 'mariadb', 'mongodb', 'postgresql'],
}

def get_conflict(mod_id):
    """Return (group, installed_member) if a conflicting app is installed"""
    for group, members in CONFLICT_GROUPS.items():
        if mod_id not in members:
            continue
        for member in members:
            if member == mod_id:
                continue
            mod = _get_mod(member)
            if mod and is_installed(mod['check']):
                return group, member
    return None, None

@modules_bp.route('/api/modules')
def list_modules():
    if not req(): return jsonify({'ok':False}), 401
    cached = panel_cache.get('modules_list')
    if cached: return jsonify(cached)
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
            'builtin': m.get('builtin', False),
            'conflict_group': next((g for g,ms in CONFLICT_GROUPS.items() if m['id'] in ms), None),
        })
    response = {'ok':True, 'modules':result}
    panel_cache.set('modules_list', response, ttl=30)
    return jsonify(response)

@modules_bp.route('/api/modules/<mod_id>/install', methods=['POST'])
def install_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    mod = _get_mod(mod_id)
    if not mod: return jsonify({'ok':False, 'error':'Module not found'}), 404

    # FFmpeg is a multi-version manager — it has no single install command.
    # Tell the frontend to open the Settings/Versions modal instead.
    if mod_id == 'ffmpeg':
        return jsonify({'ok': False, 'open_settings': True,
                        'error': 'ffmpeg manager uses per-version installation — open Settings to choose a version.'}), 400

    d   = request.get_json() or {}
    ver = d.get('version','')

    if mod.get('versions') and not ver:
        return jsonify({'ok':False, 'error':'Version required'}), 400
    # Check for conflicts
    conflict_group, conflict_mod = get_conflict(mod_id)
    if conflict_group and conflict_mod:
        conflict_name = next((m['name'] for m in MODULES if m['id']==conflict_mod), conflict_mod)
        return jsonify({'ok':False, 'error':'Cannot install: '+conflict_name+' is already installed. Please uninstall it first before installing a different '+conflict_group+'.', 'conflict':conflict_mod, 'conflict_group':conflict_group}), 409

    # OS-aware install command selection
    _os = get_os()
    _os_key = 'install_' + _os['family']  # e.g. install_rhel, install_fedora
    # Priority: OS-specific > install_tpl > install
    if _os['family'] != 'debian' and mod.get(_os_key):
        tpl = mod[_os_key]
    elif _os['family'] != 'debian' and mod.get('install_rhel') and _os['family'] == 'rhel':
        tpl = mod['install_rhel']
    else:
        tpl = mod.get('install_tpl', mod.get('install',''))
    cmd = tpl.replace('{ver}', ver).replace('{codename}', _os.get('codename','noble')) if tpl else ''
    if not cmd: cmd = mod.get('install','')
    if mod_id == 'nginx': cmd = nginx_install_script(ver or 'stable')
    elif mod_id == 'mariadb': cmd = mariadb_install_script(ver or '11.7')
    elif mod_id == 'postgresql': cmd = postgresql_install_script(ver or '17')
    elif mod_id == 'redis': cmd = redis_install_script()
    elif mod_id == 'mongodb': cmd = mongodb_install_script(ver or '8.0')
    elif mod_id == 'roundcube':
        rc_dir = '/var/www/roundcube'
        rc_conf = rc_dir + '/config/config.inc.php'
        nginx_conf = '/etc/nginx/conf.d/roundcube.conf'
        # Read config values
        def rc_get(key):
            cmd = "grep -oP \"'" + key + "'\\] = '\\K[^']+\" " + rc_conf + " 2>/dev/null | head -1"
            return sh(cmd).strip().lstrip("'") or ''
        imap_host  = rc_get('imap_host') or 'localhost'
        smtp_host  = rc_get('smtp_host') or 'localhost'
        smtp_port  = rc_get('smtp_port') or '587'
        skin       = rc_get('skin') or 'elastic'
        db_dsn     = rc_get('db_dsnw') or ''
        # Nginx port
        port = '8083'
        if os.path.exists(nginx_conf):
            with open(nginx_conf) as f: cc = f.read()
            m = _re.search(r'listen\s+(\d+)', cc)
            if m: port = m.group(1)
        # PHP version in use
        current_php = ''
        if os.path.exists(nginx_conf):
            with open(nginx_conf) as f: cc = f.read()
            m = _re.search(r'php(\d+\.\d+)-fpm\.sock', cc)
            if m: current_php = m.group(1)
        php_versions = [v for v in ['8.5','8.4','8.3','8.2','8.1','8.0','7.4'] if os.path.exists(f'/run/php/php{v}-fpm.sock')]
        # Available skins
        skins = []
        try: skins = [d for d in os.listdir(rc_dir+'/skins') if os.path.isdir(rc_dir+'/skins/'+d)]
        except: pass
        # Logs
        logs = sh(f'tail -80 {rc_dir}/logs/errors.log 2>/dev/null') or                sh(f'tail -80 {rc_dir}/logs/errors 2>/dev/null') or 'No logs found'
        # Conf content
        try:
            with open(rc_conf) as f: conf_content = f.read()
        except: conf_content = '# Config file not found'
        return jsonify({'ok':True,
            'port':port, 'url': 'http://YOUR-IP:'+port,
            'imap_host':imap_host, 'smtp_host':smtp_host, 'smtp_port':smtp_port,
            'skin':skin, 'db_dsn':db_dsn,
            'current_php':current_php, 'php_versions':php_versions,
            'skins':skins, 'conf_path':rc_conf, 'conf_content':conf_content,
            'logs':logs, 'rc_dir':rc_dir})
    elif mod_id == 'docker': cmd = docker_install_script()
    elif mod_id == 'nodejs': cmd = nodejs_install_script(ver or '22')
    elif mod_id == 'php': cmd = php_install_script(ver or '8.3')
    if not cmd: return jsonify({'ok':False, 'error':'No install command defined'}), 400

    job_id = str(uuid.uuid4())[:8]
    _job_create(job_id, initial_installed=False)

    def run_job():
        _job_append_line(job_id, f'[VortexPanel] Installing {mod["name"]} {ver}...')
        _final_cmd = translate_install_cmd(cmd)
        # Make apt-get wait out lock contention instead of failing
        # instantly -- confirmed via direct testing that apt's own
        # -o DPkg::Lock::Timeout does NOT cover /var/lib/apt/lists/lock
        # (only the separate dpkg-level locks), so a genuinely concurrent
        # apt-get (e.g. the Security Updates check, or two installs
        # started close together) fails every install instantly with
        # "Could not get lock" instead of just waiting a few seconds.
        # A real wrapper SCRIPT on PATH, not a shell function -- the
        # first attempt at this used a function named apt-get, which
        # dash (the actual shell subprocess.Popen(shell=True) invokes,
        # not bash) rejects outright with "Bad function name" since
        # dash doesn't allow hyphens in function names. Caught by
        # testing under dash specifically before shipping it.
        _wrap_dir = '/tmp/vp_apt_wrap'
        os.makedirs(_wrap_dir, exist_ok=True)
        with open(os.path.join(_wrap_dir, 'apt-get'), 'w') as _f:
            _f.write(
                '#!/bin/sh\n'
                'max=90; w=0\n'
                'while true; do\n'
                '    out=$("$APT_GET_REAL" "$@" 2>&1); rc=$?\n'
                '    if [ $rc -eq 0 ]; then echo "$out"; exit 0; fi\n'
                '    if echo "$out" | grep -q "Could not get lock\\|Unable to lock"; then\n'
                '        if [ $w -ge $max ]; then echo "$out"; echo "[VortexPanel] Timed out waiting for another apt process to finish"; exit $rc; fi\n'
                '        echo "[VortexPanel] apt is busy with another process, waiting... (${w}s/${max}s)"\n'
                '        sleep 3; w=$((w+3))\n'
                '    else\n'
                '        echo "$out"; exit $rc\n'
                '    fi\n'
                'done\n'
            )
        os.chmod(os.path.join(_wrap_dir, 'apt-get'), 0o755)
        _final_cmd = f'export APT_GET_REAL=/usr/bin/apt-get; export PATH={_wrap_dir}:$PATH; ' + _final_cmd

        env = os.environ.copy()
        env['DEBIAN_FRONTEND'] = 'noninteractive'
        env['APT_LISTCHANGES_FRONTEND'] = 'none'
        env['UCF_FORCE_CONFFOLD'] = '1'

        proc = subprocess.Popen(_final_cmd,
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, env=env)

        import time as _time
        start = _time.time()
        MAX_SECONDS = 600  # 10 min max for install
        for line in proc.stdout:
            _job_append_line(job_id, line.rstrip())
            if _time.time() - start > MAX_SECONDS:
                proc.kill()
                _job_append_line(job_id, '[VortexPanel] ⚠ Timed out after 10 minutes. Process killed.')
                break
        proc.wait()

        proc_ok       = (proc.returncode == 0)
        check_ok      = is_installed(mod['check'])
        installed     = proc_ok and check_ok
        if check_ok and not proc_ok:
            _job_append_line(job_id, '[VortexPanel] The install command itself reported an error (see output above) even though something matching the check command was found on the system — treating this as failed rather than silently reporting success.')
        inst_ver      = get_version(mod['id'], ver) if installed else ''
        _job_append_line(job_id,
            f'[VortexPanel] {"✓ Installed successfully! Version: "+inst_ver if installed else "⚠ Installation may have failed — check output above."}'
        )
        _job_finish(job_id, success=installed, installed=installed, inst_ver=inst_ver)
        panel_cache.invalidate('modules_list')

    threading.Thread(target=run_job, daemon=True).start()
    return jsonify({'ok':True, 'job_id':job_id, 'action':'install'})

@modules_bp.route('/api/modules/<mod_id>/uninstall', methods=['POST'])
def uninstall_module(mod_id):
    if not req(): return jsonify({'ok':False}), 401
    mod = _get_mod(mod_id)
    if not mod: return jsonify({'ok':False, 'error':'Not found'}), 404

    # FFmpeg is a multi-version manager — redirect to Settings to manage individual versions
    if mod_id == 'ffmpeg':
        return jsonify({'ok': False, 'open_settings': True,
                        'error': 'Use the ffmpeg manager Settings to uninstall individual versions.'}), 400

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
    _job_create(job_id, initial_installed=True)

    def run_job():
        _job_append_line(job_id, f'[VortexPanel] Removing {mod["name"]} {ver}...')

        # Stop the service first to prevent dpkg from hanging on restart triggers
        svc = mod.get('service', mod_id)
        if svc:
            _job_append_line(job_id, f'[VortexPanel] Stopping {svc} service...')
            subprocess.run(f'systemctl stop {svc} 2>/dev/null || true', shell=True, timeout=15)

        env = os.environ.copy()
        env['DEBIAN_FRONTEND'] = 'noninteractive'
        env['APT_LISTCHANGES_FRONTEND'] = 'none'
        env['UCF_FORCE_CONFFOLD'] = '1'

        proc = subprocess.Popen(cmd,
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, env=env)

        import time as _time
        start = _time.time()
        MAX_SECONDS = 300  # 5 min max for uninstall
        for line in proc.stdout:
            _job_append_line(job_id, line.rstrip())
            if _time.time() - start > MAX_SECONDS:
                proc.kill()
                _job_append_line(job_id, '[VortexPanel] ⚠ Timed out after 5 minutes. Process killed.')
                break
        proc.wait()

        if ver and mod_id in ('php','python'):
            ver_binary = f'php{ver}' if mod_id=='php' else f'python{ver}'
            still_installed = bool(sh(f'which {ver_binary} 2>/dev/null'))
        else:
            still_installed = is_installed(mod['check'])
        removed = not still_installed
        if mod_id == 'php':
            any_php = is_installed(mod['check'])
            _job_finish(job_id, success=removed, installed=any_php)
        else:
            _job_finish(job_id, success=removed, installed=still_installed)
        _job_append_line(job_id,
            f'[VortexPanel] {"✓ Removed successfully!" if removed else "⚠ May not be fully removed — check output above."}'
        )
        panel_cache.invalidate('modules_list')

    threading.Thread(target=run_job, daemon=True).start()
    return jsonify({'ok':True, 'job_id':job_id, 'action':'uninstall'})

@modules_bp.route('/api/modules/job/<job_id>')
def job_stream(job_id):
    def generate():
        path = _job_path(job_id)
        # Wait up to 5s for the job file to appear (handles race between
        # POST creating the job and the EventSource connecting)
        for _ in range(50):
            if os.path.exists(path):
                break
            time.sleep(0.1)
        else:
            yield f'data: {json.dumps({"error": "Job not found"})}\n\n'
            return

        sent = 0  # number of JSONL lines already sent to client
        for _ in range(1200):  # max 6 minutes (1200 × 0.3s)
            try:
                with open(path) as f:
                    all_lines = f.readlines()
            except Exception:
                time.sleep(0.3)
                continue

            # Stream any new lines since last poll
            for raw in all_lines[sent:]:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    sent += 1
                    continue
                if 'line' in obj:
                    yield f'data: {json.dumps({"line": obj["line"]})}\n\n'
                elif obj.get('done'):
                    yield f'data: {json.dumps({"done": True, "success": obj.get("success", False), "installed": obj.get("installed", True), "installedVer": obj.get("installedVer", "")})}\n\n'
                    try:
                        os.remove(path)
                    except Exception:
                        pass
                    return
                sent += 1

            time.sleep(0.3)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})

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


# --- FFMPEG MANAGER -----------------------------------------------------------------
# Source: BtbN/FFmpeg-Builds on GitHub — officially listed on https://www.ffmpeg.org/download.html#build-linux
# Provides GPL static builds for both x86_64 (linux64) and aarch64 (linuxarm64).
#
# URL scheme (VERIFIED LIVE from GitHub expanded_assets on 2026-07-03):
#   https://github.com/BtbN/FFmpeg-Builds/releases/download/latest/<filename>
#
# Static build filenames (no "shared" suffix = statically linked, no dependencies):
#   ffmpeg-n8.1-latest-linux64-gpl-8.1.tar.xz       x86_64 v8.1 stable
#   ffmpeg-n8.1-latest-linuxarm64-gpl-8.1.tar.xz    arm64  v8.1 stable
#   ffmpeg-n7.1-latest-linux64-gpl-7.1.tar.xz       x86_64 v7.1 stable
#   ffmpeg-n7.1-latest-linuxarm64-gpl-7.1.tar.xz    arm64  v7.1 stable
#   ffmpeg-master-latest-linux64-gpl.tar.xz          x86_64 latest nightly (master)
#   ffmpeg-master-latest-linuxarm64-gpl.tar.xz       arm64  latest nightly (master)
#
# Archive internal structure (verified from build.sh + linux-install-static.sh):
#   ffmpeg-n7.1.X-linux64-gpl-7.1/
#     bin/ffmpeg       <- the binary we care about
#     bin/ffprobe
#     bin/ffplay
#     doc/, man/, presets/
#
# Multiple versions install SIDE BY SIDE to /www/server/ffmpeg/ffmpeg-{ver}/
# Each accessible via a command alias: ffmpeg7, ffmpeg8, ffmpegmaster
# Matching aaPanel's ffmpeg manager UX exactly.

FFMPEG_BASE_DIR = '/www/server/ffmpeg'
FFMPEG_BASE_URL = 'https://github.com/BtbN/FFmpeg-Builds/releases/download/latest'

# Version map — "display" is what the user sees, "branch" is the BtbN branch name
# "ver_suffix" is the version number appended at the end of the filename for stable releases
FFMPEG_VERSIONS = [
    {'version': '8.1',    'label': 'ffmpeg-8.1 (Latest Stable)', 'branch': 'n8.1',   'suffix': '8.1',  'alias': 'ffmpeg8'},
    {'version': '7.1',    'label': 'ffmpeg-7.1 (Previous Stable)','branch': 'n7.1',   'suffix': '7.1',  'alias': 'ffmpeg7'},
    {'version': 'master', 'label': 'ffmpeg-master (Nightly)',       'branch': 'master', 'suffix': None,   'alias': 'ffmpegmaster'},
]

def _ffmpeg_arch():
    """Map uname -m to BtbN's Linux target name.
    linux64 = x86_64, linuxarm64 = aarch64 (arm64).
    Verified from BtbN README: targets are linux64 / linuxarm64."""
    m = subprocess.run('uname -m', shell=True, capture_output=True, text=True).stdout.strip()
    return {'x86_64': 'linux64', 'aarch64': 'linuxarm64', 'arm64': 'linuxarm64'}.get(m, 'linux64')

def _ffmpeg_dir(version):
    return os.path.join(FFMPEG_BASE_DIR, f'ffmpeg-{version}')

def _ffmpeg_url(v):
    """Build the exact BtbN download URL for a given version + current arch.
    Pattern verified live from GitHub expanded_assets 2026-07-03."""
    arch = _ffmpeg_arch()
    branch = v['branch']
    suffix = v['suffix']
    if suffix:
        # Stable release: ffmpeg-n7.1-latest-linux64-gpl-7.1.tar.xz
        fname = f'ffmpeg-{branch}-latest-{arch}-gpl-{suffix}.tar.xz'
    else:
        # Master nightly: ffmpeg-master-latest-linux64-gpl.tar.xz
        fname = f'ffmpeg-{branch}-latest-{arch}-gpl.tar.xz'
    return f'{FFMPEG_BASE_URL}/{fname}', fname

@modules_bp.route('/api/modules/ffmpeg/versions')
def ffmpeg_list_versions():
    if not req(): return jsonify({'ok': False}), 401
    out = []
    for v in FFMPEG_VERSIONS:
        d = _ffmpeg_dir(v['version'])
        binary = os.path.join(d, 'bin', 'ffmpeg')
        url, fname = _ffmpeg_url(v)
        out.append({
            'version': v['version'],
            'label':   v['label'],
            'installed': os.path.isfile(binary),
            'path':     d,
            'binary':   binary,
            'command':  v['alias'],
            'url':      url,
        })
    return jsonify({'ok': True, 'versions': out})

@modules_bp.route('/api/modules/ffmpeg/versions/<version>/detail')
def ffmpeg_version_detail(version):
    if not req(): return jsonify({'ok': False}), 401
    v = next((x for x in FFMPEG_VERSIONS if x['version'] == version), None)
    if not v: return jsonify({'ok': False, 'error': 'Unknown version'})
    d = _ffmpeg_dir(version)
    binary = os.path.join(d, 'bin', 'ffmpeg')
    if not os.path.isfile(binary):
        return jsonify({'ok': False, 'error': 'Not installed'})
    # Get exact installed version string from the binary
    ver_out = subprocess.run(f'"{binary}" -version', shell=True,
                              capture_output=True, text=True, timeout=5)
    ver_str = ver_out.stdout.splitlines()[0] if ver_out.stdout else ''
    return jsonify({'ok': True, 'path': d, 'full_command': binary,
                    'command': v['alias'], 'version_string': ver_str})

@modules_bp.route('/api/modules/ffmpeg/versions/<version>/install', methods=['POST'])
def ffmpeg_install_version(version):
    if not req(): return jsonify({'ok': False}), 401
    v = next((x for x in FFMPEG_VERSIONS if x['version'] == version), None)
    if not v: return jsonify({'ok': False, 'error': 'Unknown version'})

    dest_dir = _ffmpeg_dir(version)
    binary = os.path.join(dest_dir, 'bin', 'ffmpeg')
    if os.path.isfile(binary):
        return jsonify({'ok': False, 'error': f'ffmpeg {version} is already installed'})

    url, fname = _ffmpeg_url(v)
    arch = _ffmpeg_arch()
    tmp_archive = f'/tmp/{fname}'
    job_id = str(uuid.uuid4())[:8]
    _job_create(job_id)

    def run_job():
        try:
            _job_append_line(job_id, f'[VortexPanel] FFmpeg {version} — {arch} build')
            _job_append_line(job_id, f'[VortexPanel] Source: BtbN/FFmpeg-Builds (listed on ffmpeg.org/download.html#build-linux)')
            _job_append_line(job_id, f'[VortexPanel] Downloading: {url}')

            # Download with progress visible in the job terminal
            dl = subprocess.run(
                f'curl -fL --progress-bar --max-time 180 "{url}" -o "{tmp_archive}"',
                shell=True, capture_output=True, text=True, executable='/bin/bash'
            )
            if dl.returncode != 0 or not os.path.isfile(tmp_archive):
                _job_append_line(job_id, f'[ERROR] Download failed: {dl.stderr.strip() or dl.stdout.strip()}')
                _job_finish(job_id, False, False)
                return

            file_size = os.path.getsize(tmp_archive)
            _job_append_line(job_id, f'[VortexPanel] Downloaded {round(file_size/1024/1024, 1)} MB — extracting...')

            os.makedirs(dest_dir, exist_ok=True)

            # BtbN archives have ONE top-level directory (e.g. ffmpeg-n7.1.7-linux64-gpl-7.1/)
            # containing bin/, doc/, man/, presets/ — strip it with --strip-components=1
            ext = subprocess.run(
                f'tar -xJf "{tmp_archive}" -C "{dest_dir}" --strip-components=1',
                shell=True, capture_output=True, text=True, timeout=120
            )
            subprocess.run(f'rm -f "{tmp_archive}"', shell=True)

            if ext.returncode != 0:
                _job_append_line(job_id, f'[ERROR] Extract failed: {ext.stderr.strip()}')
                shutil.rmtree(dest_dir, ignore_errors=True)
                _job_append_line(job_id, '[VortexPanel] Cleaned up partial install directory')
                _job_finish(job_id, False, False)
                return

            if not os.path.isfile(binary):
                _job_append_line(job_id, '[ERROR] ffmpeg binary not found after extraction — archive structure may have changed')
                shutil.rmtree(dest_dir, ignore_errors=True)
                _job_append_line(job_id, '[VortexPanel] Cleaned up partial install directory')
                _job_finish(job_id, False, False)
                return

            # Make all binaries executable
            subprocess.run(f'chmod +x "{dest_dir}/bin/"*', shell=True)

            # Verify the binary executes correctly before declaring success
            verify = subprocess.run(f'"{binary}" -version',
                                     shell=True, capture_output=True, text=True, timeout=10)
            if verify.returncode != 0:
                _job_append_line(job_id, f'[ERROR] Binary failed to execute: {verify.stderr.strip()[:300]}')
                shutil.rmtree(dest_dir, ignore_errors=True)
                _job_append_line(job_id, '[VortexPanel] Cleaned up partial install directory')
                _job_finish(job_id, False, False)
                return

            # Create command alias so user can type e.g. "ffmpeg8" anywhere
            alias_path = f'/usr/local/bin/{v["alias"]}'
            subprocess.run(f'ln -sf "{binary}" "{alias_path}"', shell=True)

            # Also symlink ffprobe and ffplay with version suffix if present
            for tool in ('ffprobe', 'ffplay'):
                tool_bin = os.path.join(dest_dir, 'bin', tool)
                if os.path.isfile(tool_bin):
                    subprocess.run(f'ln -sf "{tool_bin}" "/usr/local/bin/{tool}{v["alias"][6:]}"', shell=True)

            ver_line = verify.stdout.splitlines()[0] if verify.stdout else ''
            _job_append_line(job_id, f'[VortexPanel] ✓ Verified: {ver_line}')
            _job_append_line(job_id, f'[VortexPanel] ✓ Installed to {dest_dir}/bin/ffmpeg')
            _job_append_line(job_id, f'[VortexPanel] ✓ Command alias: {v["alias"]} -> {binary}')
            _job_finish(job_id, True, True, version)

        except Exception as e:
            _job_append_line(job_id, f'[ERROR] Unexpected error: {str(e)}')
            _job_finish(job_id, False, False)
            subprocess.run(f'rm -f "{tmp_archive}"', shell=True)

    threading.Thread(target=run_job, daemon=True).start()
    return jsonify({'ok': True, 'job_id': job_id})

@modules_bp.route('/api/modules/ffmpeg/versions/<version>/uninstall', methods=['POST'])
def ffmpeg_uninstall_version(version):
    if not req(): return jsonify({'ok': False}), 401
    v = next((x for x in FFMPEG_VERSIONS if x['version'] == version), None)
    if not v: return jsonify({'ok': False, 'error': 'Unknown version'})
    d = _ffmpeg_dir(version)
    binary = os.path.join(d, 'bin', 'ffmpeg')
    if not os.path.isdir(d):
        return jsonify({'ok': False, 'error': f'ffmpeg {version} is not installed'})
    subprocess.run(f'rm -rf "{d}"', shell=True)
    alias_path = f'/usr/local/bin/{v["alias"]}'
    subprocess.run(f'rm -f "{alias_path}"', shell=True)
    # Remove ffprobe/ffplay aliases too
    for tool in ('probe', 'play'):
        subprocess.run(f'rm -f "/usr/local/bin/ff{tool}{v["alias"][6:]}"', shell=True)
    return jsonify({'ok': True})

@modules_bp.route('/api/modules/ffmpeg/reset', methods=['POST'])
def ffmpeg_reset():
    """Full removal — deletes every installed version, every command alias, and the
    base directory itself. This is the only genuine 'uninstall ffmpeg manager
    completely' action: since ffmpeg has no single install/uninstall command
    (each version is managed independently), this exists specifically to recover
    from stuck states — e.g. a leftover empty directory from a previously
    interrupted install that made the App Store list falsely show 'installed'
    with nothing actually usable underneath."""
    if not req(): return jsonify({'ok': False}), 401
    removed = []
    for v in FFMPEG_VERSIONS:
        d = _ffmpeg_dir(v['version'])
        if os.path.isdir(d):
            removed.append(v['version'])
        shutil.rmtree(d, ignore_errors=True)
        subprocess.run(f'rm -f "/usr/local/bin/{v["alias"]}"', shell=True)
        for tool in ('probe', 'play'):
            subprocess.run(f'rm -f "/usr/local/bin/ff{tool}{v["alias"][6:]}"', shell=True)
    # Remove the base directory entirely (covers stale/empty dirs from any
    # interrupted install, even ones that don't match a known version)
    shutil.rmtree(FFMPEG_BASE_DIR, ignore_errors=True)
    return jsonify({'ok': True, 'removed_versions': removed})

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
            {'label':'1.30.4 (Stable — security)','value':'stable'},
            {'label':'1.31.3 (Mainline — security)','value':'mainline'},
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
            return sh(rf"grep -oP '{key}\s+\K\S+' {conf_path} 2>/dev/null | head -1").strip() or ''
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
            'current_status':current_status,'optimization':optimization, 'versions': [{'label': '9.3 (Latest)', 'value': '9.3'}, {'label': '8.4 (LTS)', 'value': '8.4'}, {'label': '8.0 (LTS)', 'value': '8.0'}]})

    elif mod_id == 'mariadb':
        status  = sh('systemctl is-active mariadb') or 'inactive'
        version = sh("mariadb --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'") or \
                  sh("mysql --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'") or ''
        paths   = ['/etc/mysql/mariadb.conf.d/50-server.cnf','/etc/my.cnf','/etc/mysql/my.cnf']
        conf_path = next((p for p in paths if os.path.exists(p)), '/etc/mysql/my.cnf')
        try:
            with open(conf_path) as f: conf_content = f.read()
        except: conf_content = ''
        logs     = sh('journalctl -u mariadb -n 80') or 'No logs'
        log_path = '/var/log/mysql/error.log'
        port     = sh(r"mysql -e 'SHOW VARIABLES LIKE \"port\"' 2>/dev/null | awk 'NR==2{print $2}'") or '3306'
        datadir  = sh(r"mysql -e 'SHOW VARIABLES LIKE \"datadir\"' 2>/dev/null | awk 'NR==2{print $2}'") or '/var/lib/mysql'
        def mvar(v): return sh(f"mysql -e 'SHOW VARIABLES LIKE \"{v}\"' 2>/dev/null | awk 'NR==2{{print $2}}'") or ''
        def mstat(v): return sh(f"mysql -e 'SHOW STATUS LIKE \"{v}\"' 2>/dev/null | awk 'NR==2{{print $2}}'") or ''
        current_status = {
            'uptime':            mstat('Uptime'),
            'queries':           mstat('Queries'),
            'slow_queries':      mstat('Slow_queries'),
            'threads_connected': mstat('Threads_connected'),
            'connections':       mstat('Connections'),
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
        slow_log_path = mvar('slow_query_log_file') or '/var/log/mysql/mariadb-slow.log'
        slow_log = sh(f'tail -100 {slow_log_path} 2>/dev/null') or 'Slow query log is empty or not enabled.'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,
            'logs':logs,'log_path':log_path,
            'port':port,'datadir':datadir,
            'current_status':current_status,'optimization':optimization,'slow_log':slow_log,
            'versions':[{'label':'12.3 (Latest)','value':'12.3'},{'label':'11.8','value':'11.8'},{'label':'11.7','value':'11.7'},{'label':'11.4 (LTS)','value':'11.4'},{'label':'10.11 (LTS)','value':'10.11'},{'label':'10.6 (LTS)','value':'10.6'}]})

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

    elif mod_id == 'memcached':
        status  = sh('systemctl is-active memcached 2>/dev/null') or 'inactive'
        version = sh("memcached -h 2>/dev/null | head -1 | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'") or ''
        conf_paths = ['/etc/memcached.conf', '/etc/sysconfig/memcached']
        conf_path = next((p for p in conf_paths if os.path.exists(p)), '/etc/memcached.conf')
        try:
            with open(conf_path) as f: conf_content = f.read()
        except Exception: conf_content = ''

        def mcfg(key, default=''):
            # memcached.conf uses "-X value" flag-style lines (Debian) OR KEY="value" (RHEL sysconfig)
            m = _re.search(rf'^-{key}\s+(\S+)', conf_content, _re.MULTILINE)
            if m: return m.group(1)
            m = _re.search(rf'^{key.upper()}="?([^"\n]*)"?', conf_content, _re.MULTILINE)
            return m.group(1) if m else default

        bind_ip = mcfg('l', '127.0.0.1')
        port    = mcfg('p', '11211')
        cache_mb  = mcfg('m', '64')
        maxconn = mcfg('c', '1024')

        # Live stats via memcached's own text protocol ("stats" command) — same technique
        # aaPanel uses. No extra client library needed, just a raw TCP round-trip.
        def memcached_stats():
            import socket
            try:
                with socket.create_connection((bind_ip or '127.0.0.1', int(port or 11211)), timeout=2) as s:
                    s.sendall(b'stats\r\n')
                    data = b''
                    s.settimeout(2)
                    while b'END\r\n' not in data:
                        chunk = s.recv(4096)
                        if not chunk: break
                        data += chunk
                    return data.decode(errors='ignore')
            except Exception:
                return ''

        raw_stats = memcached_stats()
        def sget(key):
            m = _re.search(rf'STAT {key} (\S+)', raw_stats)
            return m.group(1) if m else '0'

        def fmt_bytes(n):
            try: n = float(n)
            except (TypeError, ValueError): return '0.00 B'
            for unit in ['B','KB','MB','GB']:
                if n < 1024: return f'{n:.2f} {unit}'
                n /= 1024
            return f'{n:.2f} TB'

        cmd_get    = int(sget('cmd_get') or 0)
        get_hits   = int(sget('get_hits') or 0)
        hit_rate   = round(get_hits / cmd_get, 2) if cmd_get else 0

        current_status = {
            'bind': bind_ip or '127.0.0.1', 'port': port or '11211',
            'maxconn': maxconn or '1024', 'cachesize': cache_mb or '64',
            'curr_connections': sget('curr_connections'),
            'cmd_get': sget('cmd_get'), 'get_hits': sget('get_hits'), 'get_misses': sget('get_misses'),
            'bytes_read':    fmt_bytes(sget('bytes_read')),
            'bytes_written': fmt_bytes(sget('bytes_written')),
            'bytes':         fmt_bytes(sget('bytes')),
            'curr_items': sget('curr_items'), 'evictions': sget('evictions'),
            'hit_rate': hit_rate,
        }
        optimization = {
            'bind': bind_ip or '127.0.0.1', 'port': port or '11211',
            'cachesize': cache_mb or '64', 'maxconn': maxconn or '1024',
        }
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,
            'current_status':current_status,'optimization':optimization,
            'versions':[{'label':f'Memcached {version}' if version else 'Memcached (installed)','value':'latest'}]})

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
            return sh('grep -oP "^' + key + r'\s*=\s*\K.*" ' + ini_path + ' 2>/dev/null | head -1').strip() or ''
        def fpm_get(key):
            return sh('grep -oP "^' + key + r'\s*=\s*\K.*" ' + fpm_conf + ' 2>/dev/null | head -1').strip() or ''
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
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs, 'versions': [{'label': '17 (Latest)', 'value': '17'}, {'label': '16 (Stable)', 'value': '16'}, {'label': '15 (Stable)', 'value': '15'}]})

    elif mod_id == 'mongodb':
        status  = sh('systemctl is-active mongod') or 'inactive'
        version = sh('mongod --version 2>/dev/null | grep -oP "[0-9]+[.][0-9]+[.][0-9]+" | head -1') or ''
        conf_path = '/etc/mongod.conf'
        try:
            with open(conf_path) as f: conf_content = f.read()
        except: conf_content = ''
        logs = sh('tail -80 /var/log/mongodb/mongod.log 2>/dev/null') or \
               sh('journalctl -u mongod -n 80') or 'No logs'
        return jsonify({'ok':True,'status':status,'version':version,
            'conf_path':conf_path,'conf_content':conf_content,'logs':logs, 'versions': [{'label': '8.0 (Latest)', 'value': '8.0'}, {'label': '7.0 (Stable)', 'value': '7.0'}, {'label': '6.0 (LTS)', 'value': '6.0'}]})

    elif mod_id == 'phpmyadmin':
        pma_conf = '/etc/nginx/conf.d/phpmyadmin.conf'
        port = '8082'
        if os.path.exists(pma_conf):
            with open(pma_conf) as f: cc = f.read()
            m = _re.search(r'listen\s+(\d+)', cc)
            if m: port = m.group(1)
        php_versions = [v for v in ['8.5','8.4','8.3','8.2','8.1','8.0','7.4'] if os.path.exists(f'/run/php/php{v}-fpm.sock')]
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
            return sh(rf"grep -oP '^\s*{key}\s+\K\S+' {conf_path} 2>/dev/null | head -1").strip() or ''
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
            'version':version,'info':info, 'versions': [
                {'label': 'v24 LTS — Active (Krypton)', 'value': '24'},
                {'label': 'v22 LTS — Maintenance (Jod)', 'value': '22'},
                {'label': 'v26 Current (non-LTS)',       'value': '26'},
            ]})

    elif mod_id == 'bind9':
        status  = sh('systemctl is-active named 2>/dev/null || systemctl is-active bind9 2>/dev/null') or 'inactive'
        version = sh("named -v 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1") or ''
        zones_dir = '/etc/bind/zones'
        named_conf = '/etc/bind/named.conf'
        named_conf_local = '/etc/bind/named.conf.local'
        os.makedirs(zones_dir, exist_ok=True)
        # Read zones from named.conf.local
        zones = []
        import re as _re
        for conf_file in [named_conf_local, named_conf]:
            if os.path.exists(conf_file):
                with open(conf_file) as f: raw = f.read()
                for m in _re.finditer(r'zone\s+"([^"]+)"\s*\{[^}]*file\s+"([^"]+)"', raw, _re.DOTALL):
                    domain, zone_file = m.group(1), m.group(2)
                    if domain not in [z['domain'] for z in zones]:
                        zones.append({'domain': domain, 'file': zone_file,
                            'records': int(sh(f'grep -c "IN" {zone_file} 2>/dev/null') or 0)})
        # Read zone files from zones dir
        if os.path.isdir(zones_dir):
            for f_name in os.listdir(zones_dir):
                if f_name.startswith('db.'):
                    domain = f_name[3:]
                    if domain not in [z['domain'] for z in zones]:
                        zones.append({'domain': domain, 'file': f'{zones_dir}/{f_name}',
                            'records': int(sh(f'grep -c "IN" {zones_dir}/{f_name} 2>/dev/null') or 0)})
        try:
            with open(named_conf) as f: conf_content = f.read()
        except: conf_content = ''
        logs = sh('journalctl -u named -n 80 --no-pager 2>/dev/null') or                sh('journalctl -u bind9 -n 80 --no-pager 2>/dev/null') or 'No logs'
        return jsonify({'ok':True, 'status':status, 'version':version,
            'zones': zones, 'conf_path': named_conf, 'conf_content': conf_content,
            'logs': logs, 'zones_dir': zones_dir, 'versions': [{'label': '9.20.x (Stable - ISC)', 'value': '9.20'}, {'label': '9.18.x (ESV/LTS - Ubuntu)', 'value': '9.18'}]})

    elif mod_id == 'ddns':
        import json as _json
        cfg_file = '/opt/vortexpanel/ddns_config.json'
        cfg = {}
        if os.path.exists(cfg_file):
            try:
                with open(cfg_file) as f: cfg = _json.load(f)
            except: pass
        log = ''
        log_file = '/opt/vortexpanel/ddns.log'
        if os.path.exists(log_file):
            log = sh(f'tail -100 {log_file}') or ''
        # Get current public IP
        ip = sh("curl -s --max-time 5 https://api.ipify.org 2>/dev/null || curl -s --max-time 5 https://ifconfig.me/ip 2>/dev/null") or 'Unknown'
        return jsonify({'ok':True, 'status':'active' if cfg.get('enabled') else 'inactive',
            'version':'', 'domains': cfg.get('domains',[]),
            'enabled': cfg.get('enabled', False),
            'current_ip': ip, 'interval': cfg.get('interval', 300),
            'log': log})

    elif mod_id == 'modsecurity':
        # ModSecurity has no standalone systemd service — it's a shared
        # module loaded into whichever webserver is active (see the App
        # Store install_tpl). Reusing security.py's real detection layer
        # here rather than duplicating nginx-only logic a second time --
        # that duplication is exactly what caused this same tab to show
        # "nginx service: inactive" on a genuinely working Apache install.
        from panel.routes.security import _modsec_installed, _connector_present, _modsec_conf, _modsec_target
        installed = _modsec_installed()
        connector = _connector_present()
        target = _modsec_target()
        engine_state = 'not installed'
        conf = _modsec_conf()
        if os.path.exists(conf):
            try:
                content = open(conf).read()
                m = _re.search(r'^SecRuleEngine\s+(\S+)', content, _re.MULTILINE)
                engine_state = m.group(1) if m else 'unknown'
            except Exception:
                engine_state = 'unknown'
        if target == 'apache':
            webserver_name = 'apache2'
            webserver_status = sh('systemctl is-active apache2 2>/dev/null') or 'inactive'
        else:
            webserver_name = 'nginx'
            webserver_status = sh('systemctl is-active nginx 2>/dev/null') or 'inactive'
        return jsonify({'ok':True,
            'modsec_installed': installed,
            'connector_loaded': connector,
            'engine_state': engine_state,
            'webserver_name': webserver_name,
            'webserver_status': webserver_status,
            'nginx_status': webserver_status})


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
    mod = _get_mod(mod_id)  # needed by switch_version closure

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
        elif mod_id == 'bind9':
            sh('rndc reload 2>/dev/null || systemctl reload named 2>/dev/null || systemctl reload bind9 2>/dev/null')
        elif mod_id == 'caddy':
            test = sh('caddy validate --config ' + conf_path + ' 2>&1')
            if 'Valid' not in test and 'valid' not in test.lower() and test:
                return jsonify({'ok': False, 'error': 'Caddyfile invalid: ' + test[:200]})
            sh('systemctl reload caddy 2>/dev/null || caddy reload --config ' + conf_path + ' 2>/dev/null')
        elif mod_id == 'openlitespeed':
            sh('systemctl reload lsws 2>/dev/null || systemctl restart lsws 2>/dev/null')
        elif mod_id in ('mysql', 'mariadb'):
            sh(f'systemctl restart {mod_id} 2>&1')
        elif mod_id == 'memcached':
            sh('systemctl restart memcached 2>&1')
        return jsonify({'ok': True, 'message': 'Configuration saved and service reloaded'})

    elif action == 'save_optimization':
        opts = d.get('optimization', {})
        if mod_id == 'memcached':
            conf_paths = ['/etc/memcached.conf', '/etc/sysconfig/memcached']
            conf_path = next((p for p in conf_paths if os.path.exists(p)), '/etc/memcached.conf')
            try:
                with open(conf_path) as f: c = f.read()
            except Exception:
                c = ''
            import re as _re2
            flag_map = {'bind': 'l', 'port': 'p', 'cachesize': 'm', 'maxconn': 'c'}
            for opt_key, flag in flag_map.items():
                if opt_key not in opts: continue
                val = opts[opt_key]
                pattern = rf'^-{flag}\s+\S+'
                replacement = f'-{flag} {val}'
                if _re2.search(pattern, c, _re2.MULTILINE):
                    c = _re2.sub(pattern, replacement, c, flags=_re2.MULTILINE)
                else:
                    c += f'\n{replacement}\n'
            try:
                with open(conf_path, 'w') as f: f.write(c)
            except Exception as e:
                return jsonify({'ok': False, 'error': str(e)})
            sh('systemctl restart memcached 2>&1')
            return jsonify({'ok': True})
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

        if mod_id in ('mysql', 'mariadb'):
            # Determine cnf path
            if mod_id == 'mariadb':
                cnf_paths = ['/etc/mysql/mariadb.conf.d/50-server.cnf', '/etc/my.cnf', '/etc/mysql/my.cnf']
            else:
                cnf_paths = ['/etc/mysql/mysql.conf.d/mysqld.cnf', '/etc/my.cnf', '/etc/mysql/my.cnf']
            cnf = next((p for p in cnf_paths if os.path.exists(p)), cnf_paths[-1])
            import re as _re
            try:
                with open(cnf) as f: c = f.read()
                for key, val in opts.items():
                    if not val: continue
                    # Update if exists, else append under [mysqld]
                    if _re.search(rf'^\s*{key}\s*=', c, flags=_re.MULTILINE):
                        c = _re.sub(rf'^(\s*{key}\s*=\s*)\S+', rf'\g<1>{val}', c, flags=_re.MULTILINE)
                    else:
                        c = _re.sub(r'(\[mysqld\])', rf'\1\n{key} = {val}', c, count=1)
                with open(cnf, 'w') as f: f.write(c)
                sh(f'systemctl restart {mod_id} 2>&1')
                return jsonify({'ok': True, 'message': 'Optimization saved and MariaDB restarted.'})
            except Exception as e:
                return jsonify({'ok': False, 'error': str(e)})

    elif action == 'switch_version':
        ver = d.get('version', '')
        if not ver:
            return jsonify({'ok': False, 'error': 'No version specified'}), 400

        # Build the switch script per module
        script = None
        ver_check_cmd = None  # command to get new version string after switch

        if mod_id == 'redis':
            script = (
                'systemctl stop redis-server 2>/dev/null || systemctl stop redis 2>/dev/null && '
                'curl -fsSL https://packages.redis.io/gpg | gpg --batch --yes --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg && '
                'echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/redis.list && '
                'apt-get update -o APT::Update::Error-Mode=any 2>/dev/null && '
                f'apt-get install -y --allow-downgrades redis-server={ver}.* 2>/dev/null || apt-get install -y redis-server && '
                'systemctl start redis-server 2>/dev/null || systemctl start redis'
            )
            ver_check_cmd = "redis-server --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'"

        elif mod_id in ('pure-ftpd', 'pure_ftpd'):
            script = f'apt-get install -y pure-ftpd={ver} 2>/dev/null || apt-get install -y pure-ftpd'
            ver_check_cmd = "pure-ftpd --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1"

        elif mod_id == 'mariadb':
            script = (
                'export DEBIAN_FRONTEND=noninteractive && '
                'systemctl stop mariadb 2>/dev/null && '
                f'curl -fsSL --max-time 30 https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | bash -s -- --mariadb-server-version={ver} --skip-maxscale; '
                'for f in /etc/apt/sources.list.d/*.sources; do [ -f "$f" ] || continue; if grep -qi maxscale "$f"; then awk -v RS="" -v ORS="\\n\\n" \'tolower($0) !~ /maxscale/\' "$f" > "$f.tmp" && mv "$f.tmp" "$f"; fi; done; '
                'for f in /etc/apt/sources.list.d/*.list; do [ -f "$f" ] || continue; if grep -qi maxscale "$f"; then sed -i \'/[Mm]ax[Ss]cale/d\' "$f"; fi; done; '
                # Same self-healing already added to the main install_tpl:
                # verify the repo genuinely resolves before relying on it,
                # rather than leaving a broken entry to poison every other
                # apt-get update afterward if this specific version/codename
                # combination has no build yet.
                'if ! apt-get update -qq -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 2>/tmp/vp_mariadb_switch_err.log; then '
                '  echo "[VortexPanel] MariaDB repo has no usable build for this version/distro combination -- removing the broken repo entry"; '
                '  rm -f /etc/apt/sources.list.d/mariadb.list /etc/apt/sources.list.d/mariadb.sources /etc/apt/keyrings/mariadb-keyring.pgp; '
                '  apt-get update -qq 2>/dev/null; '
                '  exit 1; '
                'fi && '
                'apt-get install -y --allow-downgrades --allow-change-held-packages '
                '-o Dpkg::Options::="--force-confnew" mariadb-server && '
                'systemctl start mariadb && systemctl enable mariadb'
            )
            ver_check_cmd = "mariadb --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1"

        elif mod_id == 'mysql':
            script = (
                'export DEBIAN_FRONTEND=noninteractive && '
                f'apt-get install -y --allow-downgrades mysql-server={ver}* 2>/dev/null || '
                'apt-get install -y mysql-server && '
                'systemctl restart mysql'
            )
            ver_check_cmd = "mysql --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1"

        elif mod_id == 'postgresql':
            script = (
                'export DEBIAN_FRONTEND=noninteractive && '
                'rm -f /usr/share/keyrings/postgresql.gpg /etc/apt/sources.list.d/pgdg.list && '
                'curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /tmp/pg.asc && '
                'gpg --batch --no-tty --dearmor -o /usr/share/keyrings/postgresql.gpg /tmp/pg.asc && '
                f'echo "deb [signed-by=/usr/share/keyrings/postgresql.gpg] http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list && '
                'apt-get update -qq -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 && '
                f'apt-get install -y postgresql-{ver} && '
                'systemctl restart postgresql'
            )
            ver_check_cmd = "psql --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+' | head -1"

        elif mod_id == 'mongodb':
            script = (
                'export DEBIAN_FRONTEND=noninteractive && '
                'systemctl stop mongod 2>/dev/null && '
                f'rm -f /usr/share/keyrings/mongodb-server-*.gpg /etc/apt/sources.list.d/mongodb*.list && '
                f'curl -fsSL https://www.mongodb.org/static/pgp/server-{ver}.asc -o /tmp/mongo.asc && '
                f'gpg --batch --no-tty --dearmor -o /usr/share/keyrings/mongodb-server-{ver}.gpg /tmp/mongo.asc && '
                f'echo "deb [signed-by=/usr/share/keyrings/mongodb-server-{ver}.gpg] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/{ver} multiverse" > /etc/apt/sources.list.d/mongodb-org-{ver}.list && '
                'apt-get update -qq -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 && '
                'apt-get install -y mongodb-org && '
                'systemctl start mongod'
            )
            ver_check_cmd = "mongod --version 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1"

        elif mod_id == 'apache2':
            script = (
                'export DEBIAN_FRONTEND=noninteractive && '
                'OS_FAMILY=$(. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE" || echo debian) && '
                # Same PPA-on-Debian bug already fixed in the main install_tpl
                # and the earlier switch_version instance - ppa:ondrej/apache2
                # is Launchpad/Ubuntu-only, skip it entirely on Debian.
                + ('if echo "$OS_FAMILY" | grep -qiE "^debian"; then '
                   '  apt-get install -y apache2; '
                   'else '
                   '  add-apt-repository -y ppa:ondrej/apache2 2>/dev/null; '
                   '  apt-get update -qq -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 && '
                   f'  (apt-get install -y --allow-downgrades apache2={ver}-* 2>/dev/null || apt-get install -y apache2); '
                   'fi && ') +
                'systemctl restart apache2'
            )
            ver_check_cmd = "apache2 -v 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1"

        elif mod_id == 'nodejs':
            script = (
                'export DEBIAN_FRONTEND=noninteractive && '
                # Remove old nodesource repo so the new one takes precedence
                'rm -f /etc/apt/sources.list.d/nodesource.list '
                '/etc/apt/sources.list.d/nodejs.list '
                '/usr/share/keyrings/nodesource.gpg '
                '/usr/share/keyrings/nodesource-repo.gpg '
                '/etc/apt/keyrings/nodesource.gpg && '
                'mkdir -p /etc/apt/keyrings && '
                # Same fix as elsewhere: setup_XX.x scripts are officially
                # deprecated per NodeSource's own GitHub. Using their current
                # distro-agnostic 'nodistro' method instead.
                f'curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --batch --yes --dearmor -o /etc/apt/keyrings/nodesource.gpg && '
                f'echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_{ver}.x nodistro main" > /etc/apt/sources.list.d/nodesource.list && '
                'apt-get update -qq && '
                'apt-get install -y --allow-downgrades nodejs'
            )
            ver_check_cmd = f"node --version 2>/dev/null | tr -d 'v'"

        elif mod_id == 'bind9':
            script = (
                'export DEBIAN_FRONTEND=noninteractive && '
                + ('add-apt-repository -y ppa:isc/bind && apt-get update -qq && ' if ver == '9.20' else 'apt-get update -qq && ') +
                'apt-get install -y bind9 bind9utils && '
                '(systemctl restart named 2>/dev/null || systemctl restart bind9 2>/dev/null)'
            )
            ver_check_cmd = "named -v 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+' | head -1"

        elif mod_id == 'nginx':
            repo = 'http://nginx.org/packages/ubuntu' if ver == 'stable' else 'http://nginx.org/packages/mainline/ubuntu'
            script = (
                f'echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] {repo} $(lsb_release -cs) nginx" '
                '> /etc/apt/sources.list.d/nginx.list && '
                'apt-get update -o APT::Update::Error-Mode=any 2>/dev/null && '
                'apt-get install -y nginx && '
                'systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null'
            )
            ver_check_cmd = "nginx -v 2>&1 | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'"

        elif mod_id == 'openlitespeed':
            script = (
                'systemctl stop lsws 2>/dev/null && '
                'wget -q https://repo.litespeed.sh -O ls_repo.sh && bash ls_repo.sh && '
                '(apt-get update -o APT::Update::Error-Mode=any 2>/dev/null; true) && '
                f'apt-get install -y --allow-downgrades openlitespeed={ver} 2>/dev/null || apt-get install -y openlitespeed && '
                'systemctl start lsws'
            )
            ver_check_cmd = "cat /usr/local/lsws/VERSION 2>/dev/null | grep -oP '[0-9]+[.][0-9]+[.][0-9]+'"

        if not script:
            return jsonify({'ok': False, 'error': f'Version switch not supported for {mod_id}'}), 400

        # Run as a streaming job — same system as install/uninstall
        job_id = str(uuid.uuid4())[:8]
        _job_create(job_id, initial_installed=True)

        def run_switch():
            mod_name = mod['name'] if mod else mod_id
            _job_append_line(job_id, f'[VortexPanel] Switching {mod_name} to version {ver}...')
            env = os.environ.copy()
            env['DEBIAN_FRONTEND'] = 'noninteractive'
            # Prevent apt-get from hanging indefinitely on slow/unreachable mirrors
            env['APT_LISTCHANGES_FRONTEND'] = 'none'
            proc = subprocess.Popen(
                script,
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, env=env
            )
            # Max 8 minutes — kills hanging apt-get update etc.
            MAX_SECONDS = 480
            import time as _time
            start = _time.time()
            for line in proc.stdout:
                _job_append_line(job_id, line.rstrip())
                if _time.time() - start > MAX_SECONDS:
                    proc.kill()
                    _job_append_line(job_id, '[VortexPanel] ⚠ Timed out after 8 minutes. Operation killed.')
                    break
            proc.wait()
            success = proc.returncode == 0
            new_ver = sh(ver_check_cmd) if ver_check_cmd else ver
            _job_append_line(job_id,
                f'[VortexPanel] {"✓ Switched to " + new_ver + " successfully!" if success else "⚠ Switch failed — check output above."}'
            )
            _job_finish(job_id, success=success, installed=True, inst_ver=new_ver)
            panel_cache.invalidate('modules_list')

        threading.Thread(target=run_switch, daemon=True).start()
        return jsonify({'ok': True, 'job_id': job_id, 'action': 'switch_version'})

    elif action == 'setup_private_dns':
        networks = d.get('networks', '127.0.0.1;')
        conf_local = '/etc/bind/named.conf.options'
        acl_lines = chr(10).join(['        '+n.strip()+';' for n in networks.replace(chr(10),';').split(';') if n.strip()])
        options_conf = 'options {' + chr(10)
        options_conf += '    directory "/var/cache/bind";' + chr(10)
        options_conf += '    recursion yes;' + chr(10)
        options_conf += '    allow-query {' + chr(10)
        options_conf += acl_lines + chr(10)
        options_conf += '    };' + chr(10)
        options_conf += '    allow-recursion {' + chr(10)
        options_conf += acl_lines + chr(10)
        options_conf += '    };' + chr(10)
        options_conf += '    dnssec-validation auto;' + chr(10)
        options_conf += '    listen-on { any; };' + chr(10)
        options_conf += '};' + chr(10)
        try:
            with open(conf_local, 'w') as f: f.write(options_conf)
            sh('rndc reload 2>/dev/null || systemctl reload named 2>/dev/null || systemctl reload bind9 2>/dev/null')
            return jsonify({'ok': True})
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)})

    elif action == 'set_forwarders':
        fwds = d.get('forwarders', '8.8.8.8; 1.1.1.1;')
        conf_local = '/etc/bind/named.conf.options'
        fwd_lines = chr(10).join(['        '+f.strip()+';' for f in fwds.replace(chr(10),';').split(';') if f.strip()])
        try:
            import re as _re
            if os.path.exists(conf_local):
                with open(conf_local) as f: c = f.read()
                if 'forwarders' in c:
                    c = _re.sub(r'forwarders\s*\{[^}]*\}', 'forwarders {' + chr(10) + fwd_lines + chr(10) + '    }', c)
                else:
                    c = c.replace('dnssec-validation auto;', 'forwarders {' + chr(10) + fwd_lines + chr(10) + '    };' + chr(10) + '    dnssec-validation auto;')
                with open(conf_local,'w') as f: f.write(c)
            sh('rndc reload 2>/dev/null || systemctl reload named 2>/dev/null || systemctl reload bind9 2>/dev/null')
            return jsonify({'ok': True})
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)})

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
        nginx_conf  = '/etc/nginx/conf.d/phpmyadmin.conf'
        apache_conf = '/etc/apache2/conf-available/phpmyadmin.conf'
        caddyfile   = '/etc/caddy/Caddyfile'

        def _update_firewall(old_port, new_port):
            if old_port and old_port != new_port:
                sh(f'ufw status 2>/dev/null | grep -q "Status: active" && ufw delete allow {old_port}/tcp 2>/dev/null; '
                   f'firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --permanent --remove-port={old_port}/tcp 2>/dev/null && firewall-cmd --reload 2>/dev/null; true')
            sh(f'ufw status 2>/dev/null | grep -q "Status: active" && ufw allow {new_port}/tcp comment "phpMyAdmin" 2>/dev/null; '
               f'firewall-cmd --state >/dev/null 2>&1 && firewall-cmd --permanent --add-port={new_port}/tcp 2>/dev/null && firewall-cmd --reload 2>/dev/null; true')

        if os.path.exists(nginx_conf):
            with open(nginx_conf) as f: c = f.read()
            m = re.search(r'listen\s+(\d+)', c)
            old_port = m.group(1) if m else None
            c = re.sub(r'listen\s+\d+', f'listen {port}', c)
            with open(nginx_conf, 'w') as f: f.write(c)
            sh('nginx -t && systemctl reload nginx')
            _update_firewall(old_port, port)
            return jsonify({'ok': True, 'port': port})

        if os.path.exists(apache_conf):
            with open(apache_conf) as f: c = f.read()
            m = re.search(r'Listen\s+(\d+)', c)
            old_port = m.group(1) if m else None
            c = re.sub(r'Listen\s+\d+', f'Listen {port}', c)
            c = re.sub(r'<VirtualHost \*:\d+>', f'<VirtualHost *:{port}>', c)
            with open(apache_conf, 'w') as f: f.write(c)
            sh('apache2ctl configtest && systemctl reload apache2')
            _update_firewall(old_port, port)
            return jsonify({'ok': True, 'port': port})

        if os.path.exists(caddyfile):
            with open(caddyfile) as f: c = f.read()
            m = re.search(r':(\d+)\s*\{\s*root \* /usr/share/phpmyadmin', c)
            old_port = m.group(1) if m else None
            if old_port:
                c = c.replace(f':{old_port} {{\n  root * /usr/share/phpmyadmin', f':{port} {{\n  root * /usr/share/phpmyadmin')
                with open(caddyfile, 'w') as f: f.write(c)
                sh('systemctl reload caddy')
                _update_firewall(old_port, port)
                return jsonify({'ok': True, 'port': port})

        return jsonify({'ok': False, 'error': 'phpMyAdmin config not found for any supported web server (nginx, Apache, Caddy)'})

    elif action == 'pma_set_php':
        php_ver = d.get('php_version', '')
        if not php_ver:
            return jsonify({'ok': False, 'error': 'PHP version missing'})

        # Mirror the install script's own webserver detection - it correctly
        # writes to a different location depending on which webserver is
        # active (nginx: conf.d file, Apache: conf-available file, Caddy:
        # a block inside Caddyfile). This action was hardcoded to nginx's
        # path only, so anyone running Apache or Caddy got "Config not
        # found" on every attempt - confirmed from a real report matching
        # this exact error message.
        nginx_conf   = '/etc/nginx/conf.d/phpmyadmin.conf'
        apache_conf  = '/etc/apache2/conf-available/phpmyadmin.conf'
        caddyfile    = '/etc/caddy/Caddyfile'

        if os.path.exists(nginx_conf):
            with open(nginx_conf) as f: c = f.read()
            c = re.sub(r'php[\d.]+\-fpm\.sock', f'php{php_ver}-fpm.sock', c)
            with open(nginx_conf, 'w') as f: f.write(c)
            sh('nginx -t && systemctl reload nginx')
            return jsonify({'ok': True})

        if os.path.exists(apache_conf):
            with open(apache_conf) as f: c = f.read()
            # Apache's block uses SetHandler "proxy:unix:$SOCK|fcgi://localhost"
            # with the socket path already expanded at install time, not a
            # literal PHP-version pattern - match the actual socket path form.
            c = re.sub(r'unix:/run/php/php[\d.]+-fpm\.sock', f'unix:/run/php/php{php_ver}-fpm.sock', c)
            with open(apache_conf, 'w') as f: f.write(c)
            sh('apache2ctl configtest && systemctl reload apache2')
            return jsonify({'ok': True})

        if os.path.exists(caddyfile):
            with open(caddyfile) as f: c = f.read()
            if ':8082' in c:
                c = re.sub(r'(:8082\s*\{[^}]*?php_fastcgi unix/)/run/php/php[\d.]+-fpm\.sock', 
                           rf'\g<1>/run/php/php{php_ver}-fpm.sock', c, flags=re.DOTALL)
                with open(caddyfile, 'w') as f: f.write(c)
                sh('systemctl reload caddy')
                return jsonify({'ok': True})

        return jsonify({'ok': False, 'error': 'phpMyAdmin config not found for any supported web server (nginx, Apache, Caddy)'})

    elif action == 'set_php':
        # Used by Roundcube's PHP Version tab to switch which PHP-FPM
        # socket serves it via nginx.
        php_ver = d.get('version', '')
        conf    = '/etc/nginx/conf.d/roundcube.conf'
        if os.path.exists(conf) and php_ver:
            import re as _re
            with open(conf) as f: c = f.read()
            c = _re.sub(r'php[\d.]+\-fpm\.sock', f'php{php_ver}-fpm.sock', c)
            with open(conf, 'w') as f: f.write(c)
            sh('nginx -t && systemctl reload nginx')
            return jsonify({'ok': True})
        return jsonify({'ok': False, 'error': 'Roundcube nginx config not found or PHP version missing'})

    return jsonify({'ok': False, 'error': 'Unknown action'})
