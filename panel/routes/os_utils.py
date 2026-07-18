"""
OS detection and package management utilities for VortexPanel.
Supports: Ubuntu, Debian, Fedora, RHEL, AlmaLinux, Rocky Linux
"""
import subprocess, os, re

def sh(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except: return ''

def detect_os():
    """Detect OS family, name, version, codename"""
    info = {'family':'debian','name':'ubuntu','version':'24.04','codename':'noble','pkg':'apt','id':'ubuntu'}
    try:
        with open('/etc/os-release') as f:
            for line in f:
                line = line.strip().strip('"')
                if line.startswith('ID='):
                    info['id'] = line[3:].lower().strip('"')
                elif line.startswith('VERSION_ID='):
                    info['version'] = line[11:].strip('"')
                elif line.startswith('VERSION_CODENAME='):
                    info['codename'] = line[17:].strip('"')
                elif line.startswith('NAME='):
                    info['name'] = line[5:].lower().strip('"')
    except: pass

    os_id = info['id']
    if os_id in ('ubuntu','debian','linuxmint','pop'):
        info['family'] = 'debian'
        info['pkg']    = 'apt'
        # Get codename if missing
        if not info.get('codename'):
            info['codename'] = sh('lsb_release -cs 2>/dev/null') or 'noble'
    elif os_id in ('fedora',):
        info['family'] = 'fedora'
        info['pkg']    = 'dnf'
    elif os_id in ('rhel','centos','almalinux','rocky','ol'):
        info['family'] = 'rhel'
        info['pkg']    = 'dnf' if _dnf_available() else 'yum'
    return info

def _dnf_available():
    return bool(sh('which dnf 2>/dev/null'))

_OS = None
def get_os():
    global _OS
    if _OS is None:
        _OS = detect_os()
    return _OS

def pkg_install(packages, extra_flags=''):
    """Return install command for current OS"""
    os_info = get_os()
    pkg = os_info['pkg']
    if pkg == 'apt':
        return f'DEBIAN_FRONTEND=noninteractive apt-get install -y {extra_flags} {packages}'
    elif pkg in ('dnf','yum'):
        return f'{pkg} install -y {extra_flags} {packages}'
    return f'apt-get install -y {packages}'

import time as _time

class _TTLCache:
    """Simple in-process TTL cache for expensive read-only endpoints."""
    def __init__(self):
        self._store = {}
    def get(self, key):
        item = self._store.get(key)
        if item and (_time.monotonic() - item['ts']) < item['ttl']:
            return item['val']
        return None
    def set(self, key, val, ttl=30):
        self._store[key] = {'val': val, 'ts': _time.monotonic(), 'ttl': ttl}
    def invalidate(self, key):
        self._store.pop(key, None)

panel_cache = _TTLCache()


def pkg_update():
    """Return update command for current OS"""
    os_info = get_os()
    pkg = os_info['pkg']
    if pkg == 'apt':
        return 'apt-get update -qq'
    elif pkg in ('dnf','yum'):
        return f'{pkg} check-update -q; true'
    return 'apt-get update -qq'

def pkg_remove(packages):
    """Return remove command for current OS"""
    os_info = get_os()
    pkg = os_info['pkg']
    if pkg == 'apt':
        return f'DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge {packages} && apt-get autoremove -y'
    elif pkg in ('dnf','yum'):
        return f'{pkg} remove -y {packages}'
    return f'apt-get remove -y --purge {packages}'

def add_repo_key(url, keyring_path):
    """Download and add GPG key, works on all distros"""
    return (
        f'curl -fsSL {url} -o /tmp/repo.key && '
        f'gpg --batch --no-tty --dearmor -o {keyring_path} /tmp/repo.key && '
        f'rm -f /tmp/repo.key'
    )

def nginx_install_script(channel='stable'):
    """Nginx official install script for all distros.
    Also:
    - Opens UDP 443 in firewall (required for HTTP/3 QUIC)
    - Adds stream {} block to nginx.conf (required for TCP load balancing)
    """
    os_info = get_os()
    stream_setup = (
        # Only add stream block if nginx.conf exists AND stream block is not already present.
        # Use printf (not echo -e) — echo -e prints "-e" literally in dash/sh on Ubuntu.
        'if [ -f /etc/nginx/nginx.conf ] && ! grep -q "^stream" /etc/nginx/nginx.conf; then '
        'printf "\\nstream {\\n    include /etc/nginx/stream.d/*.conf;\\n}\\n" >> /etc/nginx/nginx.conf; '
        'fi; '
        'mkdir -p /etc/nginx/stream.d; '
        # Open UDP 443 for HTTP/3 QUIC — idempotent
        '(ufw status 2>/dev/null | grep -q "Status: active" && ufw allow 443/udp 2>/dev/null); '
        '(firewall-cmd --state 2>/dev/null | grep -q running && '
        'firewall-cmd --add-port=443/udp --permanent 2>/dev/null && '
        'firewall-cmd --reload 2>/dev/null); '
        'true'
    )
    if os_info['family'] == 'debian':
        repo = 'http://nginx.org/packages/ubuntu' if channel == 'stable' else 'http://nginx.org/packages/mainline/ubuntu'
        return (
            f'rm -f /usr/share/keyrings/nginx-archive-keyring.gpg && curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --batch --no-tty --yes --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg && '
            f'echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] {repo} {os_info["codename"]} nginx" > /etc/apt/sources.list.d/nginx.list && '
            f'{pkg_update()} && '
            f'{pkg_install("nginx")} && '
            f'systemctl enable nginx && nginx -t && systemctl start nginx && '
            f'{stream_setup}'
        )
    elif os_info['family'] in ('rhel', 'fedora'):
        return (
            f'cat > /etc/yum.repos.d/nginx.repo << EOF\n'
            f'[nginx-{channel}]\n'
            f'name=nginx {channel} repo\n'
            f'baseurl=http://nginx.org/packages/{"" if channel=="stable" else "mainline/"}rhel/$releasever/$basearch/\n'
            f'gpgcheck=1\n'
            f'enabled=1\n'
            f'gpgkey=https://nginx.org/keys/nginx_signing.key\n'
            f'EOF\n'
            f'{pkg_install("nginx")} && '
            f'systemctl enable nginx && nginx -t && systemctl start nginx && '
            f'{stream_setup}'
        )
    return (
        f'{pkg_install("nginx")} && systemctl enable nginx && nginx -t && systemctl start nginx && '
        f'{stream_setup}'
    )

def php_install_script(ver):
    """PHP install script for all distros"""
    os_info = get_os()
    # After installing PHP-FPM, align the pool's listen.owner/listen.group
    # with nginx's actual worker user. Package defaults (www-data on
    # Debian/Ubuntu, apache/nginx on RHEL) may not match what nginx is
    # actually configured to run as - a mismatch causes nginx to fail
    # connecting to the FPM socket with "(13: Permission denied)", i.e.
    # every website on this PHP version returns 502 Bad Gateway.
    fix_pool_owner = (
        'NGINX_USER=$(grep -oP "^user\\s+\\K\\S+" /etc/nginx/nginx.conf 2>/dev/null | tr -d ";" | head -1); '
        'NGINX_USER=${NGINX_USER:-www-data}; '
        f'for POOL in /etc/php/{ver}/fpm/pool.d/www.conf /etc/php-fpm.d/www.conf; do '
        '  [ -f "$POOL" ] || continue; '
        '  grep -q "^listen.owner" "$POOL" && sed -i "s|^listen.owner.*|listen.owner = $NGINX_USER|" "$POOL" || echo "listen.owner = $NGINX_USER" >> "$POOL"; '
        '  grep -q "^listen.group" "$POOL" && sed -i "s|^listen.group.*|listen.group = $NGINX_USER|" "$POOL" || echo "listen.group = $NGINX_USER" >> "$POOL"; '
        'done'
    )
    if os_info['family'] == 'debian':
        codename = os_info['codename']
        # THIS is the function that actually runs for the Install button
        # (modules.py's /install route overrides install_tpl with this for
        # mod_id=='php' unconditionally) -- the install_tpl fallback logic
        # for ondrej/php never executed in practice. Same self-healing
        # pattern as the mariadb/postgresql/redis fixes: ondrej/php has no
        # release for a very new Ubuntu codename yet (confirmed: its own
        # apt output names packages.sury.org as the canonical replacement
        # for Ubuntu Resolute specifically), and add-apt-repository writes
        # the broken PPA to disk regardless of what happens next, poisoning
        # every future apt-get update system-wide unless cleaned up.
        php_repo_setup = (
            'add-apt-repository -y ppa:ondrej/php && '
            f'if ! {pkg_update()} 2>/tmp/vp_php_repo_err.log; then '
            f'  echo "[VortexPanel] ondrej/php has no release for {codename} yet -- removing it and trying packages.sury.org"; '
            '  add-apt-repository --remove -y ppa:ondrej/php 2>/dev/null; '
            '  rm -f /etc/apt/sources.list.d/ondrej-ubuntu-php-*.list /etc/apt/sources.list.d/ondrej-ubuntu-php-*.sources 2>/dev/null; '
            '  apt-get install -y ca-certificates apt-transport-https gnupg2 && '
            '  curl -sSLo /usr/share/keyrings/deb.sury.org-php.gpg https://packages.sury.org/php/apt.gpg && '
            f'  echo "deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ {codename} main" > /etc/apt/sources.list.d/php-sury.list && '
            f'  if ! {pkg_update()} 2>/tmp/vp_php_sury_err.log; then '
            f'    echo "[VortexPanel] packages.sury.org has no release for {codename} yet either -- falling back to noble (24.04) packages"; '
            '    echo "deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ noble main" > /etc/apt/sources.list.d/php-sury.list && '
            f'    {pkg_update()}; '
            '  fi; '
            'fi'
        )
        return (
            f'{php_repo_setup} && '
            f'{pkg_install(f"php{ver} php{ver}-fpm php{ver}-common php{ver}-mysql php{ver}-xml php{ver}-curl php{ver}-mbstring php{ver}-zip php{ver}-gd php{ver}-bcmath php{ver}-intl php{ver}-soap php{ver}-redis")} && '
            f'systemctl enable php{ver}-fpm && systemctl start php{ver}-fpm && '
            f'{fix_pool_owner} && systemctl restart php{ver}-fpm'
        )
    elif os_info['family'] in ('rhel','fedora'):
        return (
            f'dnf install -y https://rpms.remirepo.net/enterprise/remi-release-$(rpm -E %rhel).rpm 2>/dev/null; '
            f'dnf module reset php -y 2>/dev/null; '
            f'dnf module enable php:remi-{ver} -y 2>/dev/null; '
            f'{pkg_install(f"php php-fpm php-common php-mysql php-xml php-curl php-mbstring php-zip php-gd php-bcmath php-intl php-soap")} && '
            f'systemctl enable php-fpm && systemctl start php-fpm && '
            f'{fix_pool_owner} && systemctl restart php-fpm'
        )
    return f'{pkg_install(f"php{ver}-fpm")} && systemctl enable php{ver}-fpm'

def mariadb_install_script(ver='11.7'):
    """MariaDB install script for all distros.

    THIS IS THE FUNCTION THAT ACTUALLY RUNS for the App Store Install button
    (modules.py's /install route overrides install_tpl with this for
    mod_id=='mariadb' unconditionally) -- confirmed by tracing the real
    execution path after --skip-maxscale + repo-file cleanup fixes to
    install_tpl had zero effect across multiple attempts.

    Root cause, confirmed against real repeated failures on Ubuntu 26.04
    (resolute): the official mariadb_repo_setup script's own internal
    "Adding trusted package signing keys" step runs its OWN apt-get update
    BEFORE returning control to us, and it does so with the MaxScale repo
    already written regardless of --skip-maxscale (that flag apparently
    only affects whether MaxScale *packages* get installed later, not
    whether its repo file gets written or referenced during this internal
    step) -- so the script fails and exits before we ever get a chance to
    clean anything up.

    Fix: stop trusting the vendor script's internal behavior entirely for
    Debian/Ubuntu. Hand-write only the mariadb-server repository directly,
    using the exact URL structure and codename substitution CONFIRMED
    working from real logs (dlm.mariadb.com/repo/mariadb-server/{ver}/...
    successfully returned a Release file for "resolute" every single time
    this was attempted -- only the separate MaxScale repo ever failed).
    MaxScale is never referenced anywhere in this path, so there is nothing
    for it to break.
    """
    os_info = get_os()
    if os_info['family'] == 'debian':
        codename = os_info['codename']
        return (
            'mkdir -p /etc/apt/keyrings && '
            'rm -f /etc/apt/sources.list.d/mariadb.sources /etc/apt/sources.list.d/mariadb.list && '
            # Fetch MariaDB's package signing key. Two independent methods
            # attempted in sequence -- if the direct HTTPS key download is
            # ever unavailable/changed, fall back to the keyserver method
            # using MariaDB's long-standing published key ID, so a single
            # broken URL cannot silently leave packages unverifiable.
            '(curl -fsSL https://mariadb.org/mariadb_release_signing_key.asc -o /tmp/mariadb.key 2>/dev/null && '
            ' gpg --batch --no-tty --dearmor -o /etc/apt/keyrings/mariadb-keyring.pgp /tmp/mariadb.key 2>/dev/null) || '
            'gpg --no-default-keyring --keyring /etc/apt/keyrings/mariadb-keyring.pgp '
            '--keyserver keyserver.ubuntu.com --recv-keys 0xF1656F24C74CD1D8 2>/dev/null; '
            'rm -f /tmp/mariadb.key; '
            f'printf "Types: deb\nURIs: https://dlm.mariadb.com/repo/mariadb-server/{ver}/repo/ubuntu\nSuites: %s\nComponents: main main/debug\nSigned-By: /etc/apt/keyrings/mariadb-keyring.pgp\n" "{codename}" '
            '> /etc/apt/sources.list.d/mariadb.sources && '
            f'{pkg_update()} && '
            f'{pkg_install("mariadb-server mariadb-client")} && '
            f'systemctl enable mariadb && systemctl start mariadb'
        )
    elif os_info['family'] in ('rhel', 'fedora'):
        return (
            f'curl -fsSL https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | '
            f'bash -s -- --mariadb-server-version=mariadb-{ver} --skip-maxscale; '
            f'{pkg_update()} && '
            f'{pkg_install("MariaDB-server MariaDB-client")} && '
            f'systemctl enable mariadb && systemctl start mariadb'
        )
    return (
        f'curl -fsSL https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | '
        f'bash -s -- --mariadb-server-version=mariadb-{ver} --skip-maxscale; '
        f'{pkg_update()} && '
        f'{pkg_install("mariadb-server mariadb-client")} && '
        f'systemctl enable mariadb && systemctl start mariadb'
    )

def postgresql_install_script(ver='17'):
    """PostgreSQL official install script for all distros"""
    os_info = get_os()
    if os_info['family'] == 'debian':
        return (
            f'rm -f /usr/share/keyrings/postgresql.gpg /etc/apt/sources.list.d/pgdg.list && '
            f'curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /tmp/pg.asc && '
            f'gpg --batch --no-tty --dearmor -o /usr/share/keyrings/postgresql.gpg /tmp/pg.asc && '
            f'echo "deb [signed-by=/usr/share/keyrings/postgresql.gpg] http://apt.postgresql.org/pub/repos/apt {os_info["codename"]}-pgdg main" > /etc/apt/sources.list.d/pgdg.list && '
            # A brand-new Ubuntu codename can lag behind PGDG's own release
            # cadence by days/weeks. Leaving a broken pgdg.list in place
            # would poison every future apt-get update on the system, the
            # same failure class already confirmed for mariadb/php/apache2.
            f'(if ! {pkg_update()} 2>/tmp/vp_pg_repo_err.log; then '
            f'  echo "[VortexPanel] apt.postgresql.org has no release for {os_info["codename"]} yet -- removing pgdg.list so it does not block other installs"; '
            f'  rm -f /etc/apt/sources.list.d/pgdg.list; {pkg_update()}; exit 1; fi) && '
            # postgresql-contrib (unversioned) depends on the "postgresql"
            # metapackage, which PGDG always points at its newest published
            # major version -- confirmed via a real log: requesting version
            # 15 silently ALSO installed and activated version 18 as the
            # default cluster, because contrib's dependency chain pulled it
            # in regardless of {ver}. postgresql-contrib-{ver} is the
            # versioned equivalent and carries no such side effect.
            f'{pkg_install(f"postgresql-{ver} postgresql-contrib-{ver}")} && '
            f'systemctl enable postgresql && systemctl start postgresql'
        )
    elif os_info['family'] in ('rhel','fedora'):
        major = ver.split('.')[0]
        return (
            f'PGARCH=$(uname -m) && '
            f'dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-$(rpm -E %rhel)-${{PGARCH}}/pgdg-redhat-repo-latest.noarch.rpm 2>/dev/null; '
            f'dnf -qy module disable postgresql 2>/dev/null; '
            f'{pkg_install(f"postgresql{major}-server postgresql{major}-contrib")} && '
            f'/usr/pgsql-{major}/bin/postgresql-{major}-setup initdb 2>/dev/null; '
            f'systemctl enable postgresql-{major} && systemctl start postgresql-{major}'
        )
    return f'{pkg_install(f"postgresql-{ver}")} && systemctl enable postgresql'

def redis_install_script():
    """Redis official install script for all distros"""
    os_info = get_os()
    if os_info['family'] == 'debian':
        return (
            f'rm -f /usr/share/keyrings/redis-archive-keyring.gpg && '
            f'curl -fsSL https://packages.redis.io/gpg | gpg --batch --no-tty --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg && '
            f'echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb {os_info["codename"]} main" > /etc/apt/sources.list.d/redis.list && '
            f'(if ! {pkg_update()} 2>/tmp/vp_redis_repo_err.log; then '
            f'  echo "[VortexPanel] packages.redis.io has no release for {os_info["codename"]} yet -- removing it, using distro-packaged redis-server instead"; '
            f'  rm -f /etc/apt/sources.list.d/redis.list; {pkg_update()}; fi) && '
            f'{pkg_install("redis-server")} && '
            f'systemctl enable redis-server && systemctl start redis-server'
        )
    elif os_info['family'] in ('rhel','fedora'):
        return (
            f'dnf install -y https://rpms.remirepo.net/enterprise/remi-release-$(rpm -E %rhel).rpm 2>/dev/null; '
            f'{pkg_install("redis")} && '
            f'systemctl enable redis && systemctl start redis'
        )
    return f'{pkg_install("redis-server")} && systemctl enable redis-server'

def mongodb_install_script(ver='8.0'):
    """MongoDB official install script for all distros"""
    os_info = get_os()
    if os_info['family'] == 'debian':
        codename = os_info['codename']
        return (
            f'rm -f /usr/share/keyrings/mongodb-server-{ver}.gpg /etc/apt/sources.list.d/mongodb-org-{ver}.list && '
            f'curl -fsSL https://www.mongodb.org/static/pgp/server-{ver}.asc -o /tmp/mongo.asc && '
            f'gpg --batch --no-tty --dearmor -o /usr/share/keyrings/mongodb-server-{ver}.gpg /tmp/mongo.asc && '
            f'echo "deb [signed-by=/usr/share/keyrings/mongodb-server-{ver}.gpg arch=amd64,arm64] https://repo.mongodb.org/apt/ubuntu {codename}/mongodb-org/{ver} multiverse" > /etc/apt/sources.list.d/mongodb-org-{ver}.list && '
            # If repo.mongodb.org has no release for this exact codename yet,
            # try noble (24.04) -- confirmed directly from MongoDB's own
            # build source (buildscripts/package_test.py in mongodb/mongo on
            # GitHub): "ubuntu2404" is the newest Ubuntu target anywhere in
            # their packaging test matrix, nothing for 24.10/25.04/25.10
            # exists yet. Not a guess this time.
            f'(if ! {pkg_update()} 2>/tmp/vp_mongo_repo_err.log; then '
            f'  echo "[VortexPanel] repo.mongodb.org has no release for {codename} yet -- trying noble (24.04) packages instead"; '
            f'  echo "deb [signed-by=/usr/share/keyrings/mongodb-server-{ver}.gpg arch=amd64,arm64] https://repo.mongodb.org/apt/ubuntu noble/mongodb-org/{ver} multiverse" > /etc/apt/sources.list.d/mongodb-org-{ver}.list; '
            f'  if ! {pkg_update()} 2>/tmp/vp_mongo_noble_err.log; then '
            f'    echo "[VortexPanel] repo.mongodb.org has no release for noble either -- removing the broken repo entry so it does not block other installs"; '
            f'    rm -f /etc/apt/sources.list.d/mongodb-org-{ver}.list; {pkg_update()}; exit 1; '
            f'  fi; '
            f'fi) && '
            f'{pkg_install("mongodb-org")} && '
            f'systemctl enable mongod && systemctl start mongod'
        )
    elif os_info['family'] in ('rhel','fedora'):
        return (
            f'MGARCH=$(uname -m) && '
            f'cat > /etc/yum.repos.d/mongodb-org-{ver}.repo << EOF\n'
            f'[mongodb-org-{ver}]\nname=MongoDB Repository\n'
            f'baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/{ver}/${{MGARCH}}/\n'
            f'gpgcheck=1\nenabled=1\n'
            f'gpgkey=https://pgp.mongodb.com/server-{ver}.asc\nEOF\n'
            f'{pkg_install("mongodb-org")} && '
            f'systemctl enable mongod && systemctl start mongod'
        )
    return f'{pkg_install("mongodb-org")} && systemctl enable mongod'

def docker_install_script():
    """Docker CE official install script for all distros"""
    os_info = get_os()
    if os_info['family'] == 'debian':
        os_name = 'ubuntu' if 'ubuntu' in os_info['name'] else 'debian'
        codename = os_info['codename']
        return (
            f'rm -f /usr/share/keyrings/docker-archive-keyring.gpg && '
            f'curl -fsSL https://download.docker.com/linux/{os_name}/gpg | gpg --batch --no-tty --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && '
            f'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/{os_name} {codename} stable" > /etc/apt/sources.list.d/docker.list && '
            # Docker is generally fast to support new Ubuntu releases, but
            # applying the same defensive pattern as everywhere else on this
            # server for consistency: never leave a broken repo entry behind
            # to poison unrelated future installs.
            f'(if ! {pkg_update()} 2>/tmp/vp_docker_repo_err.log; then '
            f'  echo "[VortexPanel] download.docker.com has no release for {codename} yet -- removing it and falling back to get.docker.com'"'"'s own installer"; '
            '  rm -f /etc/apt/sources.list.d/docker.list; '
            f'  curl -fsSL https://get.docker.com | sh; '
            f'  {pkg_update()}; '
            'fi) && '
            f'{pkg_install("docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin")} 2>/dev/null; '
            'systemctl enable docker && systemctl start docker'
        )
    elif os_info['family'] in ('rhel','fedora'):
        return (
            f'dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo 2>/dev/null; '
            f'{pkg_install("docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin")} && '
            f'systemctl enable docker && systemctl start docker'
        )
    return 'curl -fsSL https://get.docker.com | sh && systemctl enable docker && systemctl start docker'

def nodejs_install_script(ver='24'):
    """Node.js official install script for all distros"""
    return (
        f'rm -f /etc/apt/sources.list.d/nodesource.list /usr/share/keyrings/nodesource.gpg /usr/share/keyrings/nodesource-repo.gpg 2>/dev/null; '
        f'curl -fsSL https://deb.nodesource.com/setup_{ver}.x | bash - 2>/dev/null || '
        f'curl -fsSL https://rpm.nodesource.com/setup_{ver}.x | bash - 2>/dev/null; '
        f'{pkg_install("nodejs")}'
    )

def get_webserver_user():
    """Return web server user for current OS"""
    os_info = get_os()
    if os_info['family'] == 'debian':
        return 'www-data'
    return 'nginx'

# os_utils loaded
