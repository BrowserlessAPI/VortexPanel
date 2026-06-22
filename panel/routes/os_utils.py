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
        # Add stream block if missing — needed for TCP LB
        'grep -q "^stream" /etc/nginx/nginx.conf 2>/dev/null || '
        'echo -e "\\nstream {\\n    include /etc/nginx/stream.d/*.conf;\\n}" >> /etc/nginx/nginx.conf; '
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
            f'curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --batch --no-tty --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg && '
            f'echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] {repo} {os_info["codename"]} nginx" > /etc/apt/sources.list.d/nginx.list && '
            f'{pkg_update()} && '
            f'{pkg_install("nginx")} && '
            f'systemctl enable nginx && systemctl start nginx && '
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
            f'systemctl enable nginx && systemctl start nginx && '
            f'{stream_setup}'
        )
    return (
        f'{pkg_install("nginx")} && systemctl enable nginx && systemctl start nginx && '
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
        return (
            f'add-apt-repository -y ppa:ondrej/php 2>/dev/null; '
            f'{pkg_update()} && '
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
    """MariaDB official install script for all distros"""
    return (
        f'curl -fsSL https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | '
        f'bash -s -- --mariadb-server-version=mariadb-{ver} && '
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
            f'{pkg_update()} && '
            f'{pkg_install(f"postgresql-{ver} postgresql-contrib")} && '
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
            f'{pkg_update()} && {pkg_install("redis-server")} && '
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
            f'{pkg_update()} && {pkg_install("mongodb-org")} && '
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
        return (
            f'rm -f /usr/share/keyrings/docker-archive-keyring.gpg && '
            f'curl -fsSL https://download.docker.com/linux/{os_name}/gpg | gpg --batch --no-tty --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg && '
            f'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/{os_name} {os_info["codename"]} stable" > /etc/apt/sources.list.d/docker.list && '
            f'{pkg_update()} && {pkg_install("docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin")} && '
            f'systemctl enable docker && systemctl start docker'
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
