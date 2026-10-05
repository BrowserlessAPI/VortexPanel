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

_DEBIAN_CODENAMES = {'10': 'buster', '11': 'bullseye', '12': 'bookworm', '13': 'trixie', '14': 'forky'}


def detect_os(os_release='/etc/os-release'):
    """Detect OS family, name, version, codename"""
    info = {'family':'debian','name':'ubuntu','version':'24.04','codename':'noble','pkg':'apt','id':'ubuntu'}
    raw = {}
    try:
        with open(os_release) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, _, v = line.partition('=')
                raw[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    if raw.get('ID'):         info['id'] = raw['ID'].lower()
    if raw.get('ID_LIKE'):    info['id_like'] = raw['ID_LIKE'].lower()
    if raw.get('VERSION_ID'): info['version'] = raw['VERSION_ID']
    if raw.get('NAME'):       info['name'] = raw['NAME'].lower()
    # Only trust a codename the OS actually reported -- never keep this
    # function's own Ubuntu-shaped default ('noble') on Debian.
    info['codename'] = raw.get('VERSION_CODENAME', '')

    os_id = info['id']
    id_like = info.get('id_like', '')
    if os_id in ('ubuntu','debian','linuxmint','pop') or 'debian' in id_like or 'ubuntu' in id_like:
        # Debian/Ubuntu and their derivatives (Mint, Pop!_OS, Raspbian, ...).
        # 'base' says which upstream repo layout (debian vs ubuntu) applies,
        # and the codename is the UPSTREAM one, since third-party repos
        # (nginx.org, sury, PGDG, docker) only publish upstream codenames.
        info['family'] = 'debian'
        info['pkg']    = 'apt'
        is_ubuntu = os_id == 'ubuntu' or 'ubuntu' in id_like
        info['base'] = 'ubuntu' if is_ubuntu else 'debian'
        cn = ''
        if is_ubuntu:
            cn = raw.get('UBUNTU_CODENAME', '') or (info['codename'] if os_id == 'ubuntu' else '')
        else:
            cn = raw.get('DEBIAN_CODENAME', '') or (info['codename'] if os_id == 'debian' else '')
        if not cn and os_id in ('ubuntu', 'debian'):
            m = re.search(r'\(([a-z]+)', raw.get('VERSION', '').lower())
            cn = m.group(1) if m else ''
        if not cn and os_id in ('ubuntu', 'debian'):
            cn = sh('lsb_release -cs 2>/dev/null')
        if not cn and not is_ubuntu:
            try:
                major = open('/etc/debian_version').read().strip().split('.')[0]
                cn = _DEBIAN_CODENAMES.get(major, '')
            except Exception:
                cn = ''
        info['codename'] = cn or ('noble' if is_ubuntu else 'bookworm')
    elif os_id in ('fedora',):
        info['family'] = 'fedora'
        info['pkg']    = 'dnf'
    elif os_id in ('rhel','centos','almalinux','rocky','ol','cloudlinux') or \
            'fedora' in id_like or 'rhel' in id_like or 'centos' in id_like:
        # Confirmed real-world case: CloudLinux reports ID="cloudlinux" with
        # ID_LIKE="rhel fedora centos". The ID_LIKE match also covers Amazon
        # Linux, EuroLinux, Navy Linux and any future RHEL rebuild.
        info['family'] = 'rhel'
        info['pkg']    = 'dnf' if _dnf_available() else 'yum'
    else:
        # Unknown ID / ID_LIKE (or no /etc/os-release at all): go by the
        # package manager that actually exists instead of silently assuming
        # Ubuntu and running apt-get on a dnf system.
        if sh('command -v apt-get 2>/dev/null'):
            info['family'], info['pkg'] = 'debian', 'apt'
            info['base'] = 'debian'
            info['codename'] = info['codename'] or 'bookworm'
        elif _dnf_available() or sh('command -v yum 2>/dev/null'):
            info['family'] = 'rhel'
            info['pkg']    = 'dnf' if _dnf_available() else 'yum'
        elif sh('command -v zypper 2>/dev/null'):
            info['family'], info['pkg'] = 'suse', 'zypper'
    return info


def _deb_base(os_info):
    """'debian' or 'ubuntu' -- which upstream repo layout to use."""
    b = os_info.get('base')
    if b in ('debian', 'ubuntu'):
        return b
    return 'debian' if os_info.get('id') == 'debian' else 'ubuntu'

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
    elif pkg == 'zypper':
        return f'zypper --non-interactive install {extra_flags} {packages}'
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
        # Grouped: 'dnf check-update; true && X' made X run even when the
        # command before the update failed, and `if ! <update>` never failed.
        # check-update exits 100 when updates are available -- not an error.
        return f'{{ {pkg} check-update -q || true; }}'
    elif pkg == 'zypper':
        return 'zypper --non-interactive refresh'
    return 'apt-get update -qq'

def pkg_remove(packages):
    """Return remove command for current OS"""
    os_info = get_os()
    pkg = os_info['pkg']
    if pkg == 'apt':
        return f'DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge {packages} && apt-get autoremove -y'
    elif pkg in ('dnf','yum'):
        return f'{pkg} remove -y {packages}'
    elif pkg == 'zypper':
        return f'zypper --non-interactive remove {packages}'
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
        # Grouped in ( ... ) so its trailing "true" cannot mask a failed
        # install earlier in the && chain (it used to make every nginx
        # install exit 0, even when nothing was installed).
        '( '
        # Only add stream block if nginx.conf exists AND stream block is not already present.
        # Use printf (not echo -e) — echo -e prints "-e" literally in dash/sh on Ubuntu.
        'mkdir -p /etc/nginx/stream.d; '
        'if [ -f /etc/nginx/nginx.conf ] && ! grep -q "^stream" /etc/nginx/nginx.conf; then '
        'cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.vp-prestream; '
        'printf "\\nstream {\\n    include /etc/nginx/stream.d/*.conf;\\n}\\n" >> /etc/nginx/nginx.conf; '
        # A build without the stream module (distro nginx without
        # libnginx-mod-stream / nginx-mod-stream) rejects the block and would
        # fail every later reload -- revert instead of leaving nginx broken.
        'nginx -t >/dev/null 2>&1 || { echo "[VortexPanel] this nginx build has no stream module -- stream{} block not added"; '
        'cp /etc/nginx/nginx.conf.vp-prestream /etc/nginx/nginx.conf; }; '
        'rm -f /etc/nginx/nginx.conf.vp-prestream; '
        'fi; '
        # Open UDP 443 for HTTP/3 QUIC — idempotent
        '(ufw status 2>/dev/null | grep -q "Status: active" && ufw allow 443/udp 2>/dev/null); '
        '(firewall-cmd --state 2>/dev/null | grep -q running && '
        'firewall-cmd --add-port=443/udp --permanent 2>/dev/null && '
        'firewall-cmd --reload 2>/dev/null); '
        'true )'
    )
    if os_info['family'] == 'debian':
        # Same bug as mariadb_install_script: family='debian' groups genuine
        # Debian and Ubuntu together, but nginx.org has a genuinely separate
        # path for each - confirmed via nginx.org's own documentation. This
        # hardcoded /ubuntu regardless, which is very likely the actual root
        # cause behind issue #20's "ubuntu bookworm Release file not found"
        # error, since this function overrides modules.py's install_tpl for
        # the real Install button click.
        distro_path = _deb_base(os_info)
        cn = os_info["codename"]
        repo = f'http://nginx.org/packages/{distro_path}' if channel == 'stable' else f'http://nginx.org/packages/mainline/{distro_path}'
        return (
            f'rm -f /usr/share/keyrings/nginx-archive-keyring.gpg && curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --batch --no-tty --yes --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg && '
            f'echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] {repo} {cn} nginx" > /etc/apt/sources.list.d/nginx.list && '
            # nginx.org lags new codenames: never leave a broken nginx.list
            # behind (it poisons every later apt-get update) -- fall back to
            # the distro nginx package instead.
            f'(if ! {pkg_update()} 2>/tmp/vp_nginx_repo_err.log; then '
            f'  echo "[VortexPanel] nginx.org has no release for {cn} yet -- removing it, using the distro nginx package instead"; '
            f'  rm -f /etc/apt/sources.list.d/nginx.list; {pkg_update()}; '
            'fi) && '
            f'{pkg_install("nginx")} && '
            f'systemctl enable nginx && nginx -t && systemctl start nginx && '
            f'{stream_setup}'
        )
    elif os_info['family'] == 'fedora':
        # nginx.org publishes no Fedora packages (rhel/$releasever would be
        # rhel/40 -> 404). Use Fedora's own nginx; its stream module is a
        # separate dynamic-module package, required by the stream{} block below.
        return (
            f'{pkg_install("nginx nginx-mod-stream")} && '
            f'systemctl enable nginx && nginx -t && systemctl start nginx && '
            f'{stream_setup} && {selinux_web_booleans_cmd()}'
        )
    elif os_info['family'] == 'rhel':
        return (
            f'cat > /etc/yum.repos.d/nginx.repo << EOF\n'
            f'[nginx-{channel}]\n'
            f'name=nginx {channel} repo\n'
            f'baseurl=http://nginx.org/packages/{"" if channel=="stable" else "mainline/"}rhel/\\$releasever/\\$basearch/\n'
            f'gpgcheck=1\n'
            f'enabled=1\n'
            f'gpgkey=https://nginx.org/keys/nginx_signing.key\n'
            # Without this, EL8/EL9 modular filtering hides nginx.org's
            # packages behind the AppStream nginx module (installs 1.14/1.20).
            f'module_hotfixes=true\n'
            f'EOF\n'
            f'{pkg_install("nginx")} && '
            f'systemctl enable nginx && nginx -t && systemctl start nginx && '
            f'{stream_setup} && {selinux_web_booleans_cmd()}'
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
        # pattern as the mariadb/postgresql/redis fixes.
        is_debian = _deb_base(os_info) == 'debian'
        if is_debian:
            # ppa: syntax is a Launchpad/Ubuntu-specific mechanism with no
            # Debian equivalent - going straight to the known-working
            # packages.sury.org path rather than attempting a PPA that is
            # guaranteed to fail (or may not even be recognized) on Debian.
            php_repo_setup = (
                'apt-get install -y ca-certificates apt-transport-https gnupg2 && '
                'curl -sSLo /usr/share/keyrings/deb.sury.org-php.gpg https://packages.sury.org/php/apt.gpg && '
                f'echo "deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ {codename} main" > /etc/apt/sources.list.d/php-sury.list && '
                f'if ! {pkg_update()} 2>/tmp/vp_php_sury_err.log; then '
                f'  echo "[VortexPanel] packages.sury.org has no release for {codename} yet -- falling back to bookworm packages"; '
                '  echo "deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ bookworm main" > /etc/apt/sources.list.d/php-sury.list && '
                f'  {pkg_update()}; '
                'fi'
            )
        else:
            # ondrej/php has no release for a very new Ubuntu codename yet
            # (confirmed: its own apt output names packages.sury.org as the
            # canonical replacement for Ubuntu Resolute specifically), and
            # add-apt-repository writes the broken PPA to disk regardless of
            # what happens next, poisoning every future apt-get update
            # system-wide unless cleaned up.
            php_repo_setup = (
                '(command -v add-apt-repository >/dev/null 2>&1 || apt-get install -y software-properties-common); '
                # Fall back to packages.sury.org when the PPA cannot be added
                # at all (Launchpad unreachable) as well as when it has no
                # release for this codename -- previously only the second case
                # was handled and an unreachable Launchpad ended the install.
                f'if add-apt-repository -y ppa:ondrej/php && {pkg_update()} 2>/tmp/vp_php_repo_err.log; then :; else '
                f'  echo "[VortexPanel] ondrej/php is unavailable (unreachable, or no release for {codename}) -- removing it and trying packages.sury.org"; '
                '  add-apt-repository --remove -y ppa:ondrej/php 2>/dev/null; '
                '  rm -f /etc/apt/sources.list.d/ondrej-ubuntu-php-*.list /etc/apt/sources.list.d/ondrej-ubuntu-php-*.sources 2>/dev/null; '
                '  apt-get install -y ca-certificates apt-transport-https gnupg2 && '
                '  curl -fsSLo /usr/share/keyrings/deb.sury.org-php.gpg https://packages.sury.org/php/apt.gpg && '
                f'  echo "deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ {codename} main" > /etc/apt/sources.list.d/php-sury.list && '
                f'  if ! {pkg_update()} 2>/tmp/vp_php_sury_err.log; then '
                f'    echo "[VortexPanel] packages.sury.org has no release for {codename} yet either -- falling back to noble (24.04) packages"; '
                '    echo "deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ noble main" > /etc/apt/sources.list.d/php-sury.list && '
                f'    {pkg_update()}; '
                '  fi; '
                '  if [ ! -s /usr/share/keyrings/deb.sury.org-php.gpg ]; then '
                f'    echo "[VortexPanel] packages.sury.org could not be reached either -- PHP {ver} cannot be installed right now."; '
                '    rm -f /etc/apt/sources.list.d/php-sury.list /usr/share/keyrings/deb.sury.org-php.gpg; '
                f'    {pkg_update()}; false; '
                '  fi; '
                'fi'
            )
        return (
            f'{php_repo_setup} && '
            f'{pkg_install(f"php{ver} php{ver}-fpm php{ver}-common php{ver}-mysql php{ver}-xml php{ver}-curl php{ver}-mbstring php{ver}-zip php{ver}-gd php{ver}-bcmath php{ver}-intl php{ver}-soap php{ver}-redis")} && '
            f'systemctl enable php{ver}-fpm && systemctl start php{ver}-fpm && '
            f'( {fix_pool_owner} ) && systemctl restart php{ver}-fpm'
        )
    elif os_info['family'] in ('rhel','fedora'):
        # Two layouts (both understood by php.php_layout()):
        #  - module stream: the ONE system PHP (/usr/bin/php, php-fpm unit,
        #    /run/php-fpm/www.sock). Used only when no other system PHP is
        #    installed AND the php:remi-X stream really got enabled.
        #  - Remi SCL: phpXY-php-fpm side by side (/opt/remi/phpXY, unit
        #    phpXY-php-fpm). Used on EL10 / Fedora 41+ (no module streams --
        #    'dnf module enable' failed silently there and the distro PHP of
        #    some other version was installed), and when a different system
        #    PHP version already exists (a stream switch would replace it).
        vn = ver.replace('.', '')
        # Optional extensions go in one at a time: dnf aborts the whole
        # transaction when one listed name does not exist in the repo.
        exts = 'fpm cli common mysqlnd xml mbstring gd intl opcache'
        opt_exts = 'bcmath soap pecl-zip'
        mod_pkgs = 'php ' + ' '.join('php-' + e for e in exts.split())
        scl_pkgs = ' '.join(f'php{vn}-php-' + e for e in exts.split())
        mod_opt = ' '.join('php-' + e for e in opt_exts.split())
        scl_opt = ' '.join(f'php{vn}-php-' + e for e in opt_exts.split())
        opt_loop = ('  for P in {}; do dnf install -y "$P" >/dev/null 2>&1 || '
                    'echo "[VortexPanel] Note: optional package $P is not available -- skipped"; done\n')
        epel = (ensure_epel_cmd() + '; ') if os_info['family'] == 'rhel' else ''
        php_ver_q = '-r \'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;\' 2>/dev/null'
        return (
            epel +
            f'REMI_RPM=$(if [ -n "$(rpm -E %{{?fedora}} 2>/dev/null)" ]; then echo https://rpms.remirepo.net/fedora/remi-release-$(rpm -E %{{?fedora}}).rpm; else r=$(rpm -E %{{?rhel}} 2>/dev/null); echo https://rpms.remirepo.net/enterprise/remi-release-${{r:-9}}.rpm; fi)\n'
            'rpm -q remi-release >/dev/null 2>&1 || dnf install -y "$REMI_RPM" || '
            f'{{ echo "[VortexPanel] The Remi repository ($REMI_RPM) could not be installed -- PHP {ver} cannot be installed."; exit 1; }}\n'
            f'SYS=$(/usr/bin/php {php_ver_q})\n'
            'MODE=scl\n'
            f'if [ -z "$SYS" ] || [ "$SYS" = "{ver}" ]; then\n'
            f'  if dnf module reset php -y >/dev/null 2>&1 && dnf module enable php:remi-{ver} -y >/dev/null 2>&1 && '
            f'dnf module list --enabled php 2>/dev/null | grep -q "remi-{ver}"; then MODE=module; fi\n'
            'fi\n'
            'if [ "$MODE" = module ]; then\n'
            f'  echo "[VortexPanel] Installing PHP {ver} as the system PHP (Remi module stream php:remi-{ver})"\n'
            f'  dnf install -y {mod_pkgs} || exit 1\n'
            + opt_loop.format(mod_opt) +
            f'  GOT=$(/usr/bin/php {php_ver_q})\n'
            f'  if [ "$GOT" != "{ver}" ]; then\n'
            f'    echo "[VortexPanel] The module stream installed PHP ${{GOT:-unknown}}, not {ver} -- installing PHP {ver} side by side from the Remi SCL packages instead"\n'
            '    MODE=scl\n'
            '  else\n'
            '    SVC=php-fpm; POOL=/etc/php-fpm.d/www.conf; LIBDIR=/var/lib/php\n'
            '  fi\n'
            'fi\n'
            'if [ "$MODE" = scl ]; then\n'
            f'  if [ -n "$SYS" ]; then echo "[VortexPanel] PHP $SYS is the system PHP -- installing PHP {ver} side by side (Remi package php{vn}-php-fpm)"; '
            f'else echo "[VortexPanel] Installing PHP {ver} as the Remi package php{vn}-php-fpm (this OS has no usable php:remi-{ver} module stream)"; fi\n'
            f'  dnf install -y {scl_pkgs} || exit 1\n'
            + opt_loop.format(scl_opt) +
            f'  SVC=php{vn}-php-fpm; POOL=/etc/opt/remi/php{vn}/php-fpm.d/www.conf; LIBDIR=/var/opt/remi/php{vn}/lib/php\n'
            'fi\n'
            # nginx's worker user: the pool socket must be connectable by it
            # (RHEL pools also carry listen.acl_users), and the pool should run
            # as the user the panel gives site files to (get_webserver_user():
            # nginx). Distro pools run as apache, so WordPress could not write
            # its uploads/plugins in nginx-owned sites. Only when nginx is
            # installed -- with Apache alone the apache pool user is right, and
            # the old fallback 'www-data' does not exist here (php-fpm then
            # refused to start).
            'NGINX_USER=$(grep -oP "^\\s*user\\s+\\K[^;\\s]+" /etc/nginx/nginx.conf 2>/dev/null | head -1)\n'
            'if [ -f "$POOL" ] && [ -n "$NGINX_USER" ] && id "$NGINX_USER" >/dev/null 2>&1; then\n'
            '  for K in listen.owner listen.group user group; do\n'
            '    if grep -qE "^\\s*$K\\s*=" "$POOL"; then sed -i -E "s|^\\s*$K\\s*=.*|$K = $NGINX_USER|" "$POOL"; else echo "$K = $NGINX_USER" >> "$POOL"; fi\n'
            '  done\n'
            '  for D in session opcache wsdlcache; do [ -d "$LIBDIR/$D" ] && chgrp -R "$NGINX_USER" "$LIBDIR/$D"; done\n'
            'fi\n'
            'systemctl enable "$SVC" && systemctl restart "$SVC"'
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
        # detect_os() groups genuine Debian (id='debian') into the same
        # family='debian' bucket as Ubuntu (family is 'debian' for both) -
        # confirmed this was hardcoding /ubuntu in the URI regardless, for
        # the function that actually runs on the real Install button click.
        # This is very likely the true root cause behind issue #20's "ubuntu
        # bookworm Release file not found" error, since install_tpl-level
        # fixes elsewhere never touch this separate, overriding path.
        deb_path = _deb_base(os_info)
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
            f'printf "Types: deb\\nURIs: https://dlm.mariadb.com/repo/mariadb-server/{ver}/repo/{deb_path}\\nSuites: %s\\nComponents: main main/debug\\nSigned-By: /etc/apt/keyrings/mariadb-keyring.pgp\\n" "{codename}" '
            '> /etc/apt/sources.list.d/mariadb.sources && '
            f'{pkg_update()} && '
            f'{pkg_install("mariadb-server mariadb-client")} && '
            f'systemctl enable mariadb && systemctl start mariadb'
        )
    elif os_info['family'] == 'fedora':
        # mariadb_repo_setup does not support Fedora and MariaDB-server does
        # not exist there; Fedora ships a current MariaDB itself.
        return (
            f'{pkg_install("mariadb-server mariadb")} && '
            f'systemctl enable mariadb && systemctl start mariadb'
        )
    elif os_info['family'] == 'rhel':
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
            'PGARCH=$(uname -m) && '
            + (
                # PGDG has separate Fedora repos (F-<ver>); EL-9 RPMs on Fedora
                # pull incompatible dependencies.
                'dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/F-$(rpm -E %{fedora})-${PGARCH}/pgdg-fedora-repo-latest.noarch.rpm 2>/dev/null; '
                if os_info['family'] == 'fedora' else
                'dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-$(r=$(rpm -E %{?rhel} 2>/dev/null); echo ${r:-9})-${PGARCH}/pgdg-redhat-repo-latest.noarch.rpm 2>/dev/null; '
            ) +
            'dnf -qy module disable postgresql 2>/dev/null; '
            f'{pkg_install(f"postgresql{major}-server postgresql{major}-contrib")} && '
            f'/usr/pgsql-{major}/bin/postgresql-{major}-setup initdb 2>/dev/null; '
            f'systemctl enable postgresql-{major} && systemctl start postgresql-{major}'
        )
    return f'{pkg_install(f"postgresql-{ver}")} && systemctl enable postgresql'

def redis_install_script():
    """Redis official install script for all distros"""
    os_info = get_os()
    if os_info['family'] == 'debian':
        cn = os_info["codename"]
        # Two independent failure points, both must fall back to the distro
        # redis-server: (1) packages.redis.io unreachable (the key download
        # fails -- previously this aborted the whole install, the fallback
        # only covered (2)); (2) the repo has no release for this codename.
        return (
            'rm -f /usr/share/keyrings/redis-archive-keyring.gpg /etc/apt/sources.list.d/redis.list; '
            'if curl -fsSL --connect-timeout 20 --max-time 60 https://packages.redis.io/gpg -o /tmp/vp_redis.gpg '
            '&& gpg --batch --no-tty --yes --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg /tmp/vp_redis.gpg; then '
            f'  echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] https://packages.redis.io/deb {cn} main" > /etc/apt/sources.list.d/redis.list; '
            f'  if ! {pkg_update()} 2>/tmp/vp_redis_repo_err.log; then '
            f'    echo "[VortexPanel] packages.redis.io has no release for {cn} yet -- removing it, using distro-packaged redis-server instead"; '
            f'    rm -f /etc/apt/sources.list.d/redis.list /usr/share/keyrings/redis-archive-keyring.gpg; {pkg_update()}; '
            '  fi; '
            'else '
            '  echo "[VortexPanel] packages.redis.io could not be reached -- using the distro-packaged redis-server instead"; '
            f'  rm -f /usr/share/keyrings/redis-archive-keyring.gpg; {pkg_update()}; '
            'fi; '
            'rm -f /tmp/vp_redis.gpg; '
            f'{pkg_install("redis-server")} && '
            f'systemctl enable redis-server && systemctl restart redis-server'
        )
    elif os_info['family'] in ('rhel','fedora'):
        # remi-release for EL depends on epel-release.
        return (
            (ensure_epel_cmd() + '; ' if os_info['family'] == 'rhel' else '') +
            f'REMI_RPM=$(if [ -n "$(rpm -E %{{?fedora}} 2>/dev/null)" ]; then echo https://rpms.remirepo.net/fedora/remi-release-$(rpm -E %{{?fedora}}).rpm; else r=$(rpm -E %{{?rhel}} 2>/dev/null); echo https://rpms.remirepo.net/enterprise/remi-release-${{r:-9}}.rpm; fi); dnf install -y "$REMI_RPM" 2>/dev/null; '
            f'{pkg_install("redis")} && '
            f'systemctl enable redis && systemctl start redis'
        )
    return f'{pkg_install("redis-server")} && systemctl enable redis-server'

def mongodb_install_script(ver='8.0'):
    """MongoDB official install script for all distros"""
    os_info = get_os()
    if os_info['family'] == 'debian':
        codename = os_info['codename']
        # Same bug as nginx/mariadb: family='debian' groups genuine Debian
        # and Ubuntu together, but MongoDB's own docs confirm a genuinely
        # different path (/apt/debian vs /apt/ubuntu) AND component keyword
        # (main vs multiverse) is required - not just a codename difference.
        # Falling back to Ubuntu's noble codename on a genuine Debian system
        # would still install Ubuntu-built packages with different
        # dependency ABI expectations than Debian actually has.
        is_debian = _deb_base(os_info) == 'debian'
        deb_path = 'debian' if is_debian else 'ubuntu'
        component = 'main' if is_debian else 'multiverse'
        fallback_codename = 'bookworm' if is_debian else 'noble'
        return (
            f'rm -f /usr/share/keyrings/mongodb-server-{ver}.gpg /etc/apt/sources.list.d/mongodb-org-{ver}.list && '
            f'curl -fsSL https://www.mongodb.org/static/pgp/server-{ver}.asc -o /tmp/mongo.asc && '
            f'gpg --batch --no-tty --dearmor -o /usr/share/keyrings/mongodb-server-{ver}.gpg /tmp/mongo.asc && '
            f'echo "deb [signed-by=/usr/share/keyrings/mongodb-server-{ver}.gpg arch=amd64,arm64] https://repo.mongodb.org/apt/{deb_path} {codename}/mongodb-org/{ver} {component}" > /etc/apt/sources.list.d/mongodb-org-{ver}.list && '
            # If repo.mongodb.org has no release for this exact codename yet,
            # fall back to the previous stable release for the SAME distro
            # family (bookworm for Debian, noble for Ubuntu) rather than
            # ever crossing between them.
            f'(if ! {pkg_update()} 2>/tmp/vp_mongo_repo_err.log; then '
            f'  echo "[VortexPanel] repo.mongodb.org has no release for {codename} yet -- trying {fallback_codename} packages instead"; '
            f'  echo "deb [signed-by=/usr/share/keyrings/mongodb-server-{ver}.gpg arch=amd64,arm64] https://repo.mongodb.org/apt/{deb_path} {fallback_codename}/mongodb-org/{ver} {component}" > /etc/apt/sources.list.d/mongodb-org-{ver}.list; '
            f'  if ! {pkg_update()} 2>/tmp/vp_mongo_fallback_err.log; then '
            f'    echo "[VortexPanel] repo.mongodb.org has no release for {fallback_codename} either -- removing the broken repo entry so it does not block other installs"; '
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
            # repo.mongodb.org has no Fedora tree: Fedora uses the EL9 build.
            + (f'baseurl=https://repo.mongodb.org/yum/redhat/9/mongodb-org/{ver}/${{MGARCH}}/\n'
               if os_info['family'] == 'fedora' else
               f'baseurl=https://repo.mongodb.org/yum/redhat/\\$releasever/mongodb-org/{ver}/${{MGARCH}}/\n') +
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
        os_name = _deb_base(os_info)
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
            # No 2>/dev/null / ';' here: a failed install must show apt's
            # error and fail the job instead of a confusing systemctl error.
            f'{pkg_install("docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin")} && '
            'systemctl enable docker && systemctl start docker'
        )
    elif os_info['family'] in ('rhel','fedora'):
        repo_os = 'fedora' if os_info['family'] == 'fedora' else 'rhel'
        pkgs = 'docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin'
        return (
            # Fetch the .repo file directly: 'dnf config-manager --add-repo'
            # needs dnf-plugins-core (absent on minimal installs) and is
            # 'addrepo --from-repofile=' on dnf5 (Fedora 41+). Fedora also
            # needs the fedora tree, not rhel.
            f'curl -fsSL https://download.docker.com/linux/{repo_os}/docker-ce.repo -o /etc/yum.repos.d/docker-ce.repo && '
            # containerd.io conflicts with runc/podman-docker shipped on EL;
            # retry with --allowerasing so the install does not just fail.
            f'( {pkg_install(pkgs)} || {{ echo "[VortexPanel] Conflicting container packages (podman/runc/buildah) found -- replacing them with Docker CE"; {pkg_install(pkgs, "--allowerasing")}; }} ) && '
            f'systemctl enable docker && systemctl start docker'
        )
    return 'curl -fsSL https://get.docker.com | sh && systemctl enable docker && systemctl start docker'

def nodejs_install_script(ver='24'):
    """Node.js official install script for all distros.

    Debian-family uses NodeSource's current method (a distro-agnostic
    'nodistro' codename with a direct source file) rather than the old
    setup_XX.x scripts - confirmed via NodeSource's own GitHub that those
    scripts are explicitly no longer supported, and via multiple real bug
    reports (including a 404 specifically on Debian Bookworm) that the
    deprecated approach genuinely fails. 'nodistro' also sidesteps the
    Debian-vs-Ubuntu codename problem entirely, since there is no longer a
    per-codename repo at all. RHEL-family keeps the rpm.nodesource.com
    setup script, which was not confirmed deprecated on that side.
    """
    os_info = get_os()
    if os_info['family'] == 'debian':
        return (
            'rm -f /etc/apt/sources.list.d/nodesource.list /usr/share/keyrings/nodesource.gpg '
            '/usr/share/keyrings/nodesource-repo.gpg /etc/apt/keyrings/nodesource.gpg 2>/dev/null; '
            'mkdir -p /etc/apt/keyrings && '
            f'curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --batch --yes --dearmor -o /etc/apt/keyrings/nodesource.gpg && '
            f'echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_{ver}.x nodistro main" > /etc/apt/sources.list.d/nodesource.list && '
            f'{pkg_update()} && '
            f'{pkg_install("nodejs")}'
        )
    return (
        f'curl -fsSL https://rpm.nodesource.com/setup_{ver}.x | bash - 2>/dev/null; '
        f'{pkg_install("nodejs")}'
    )

def get_webserver_user():
    """Return web server user for current OS"""
    import pwd
    os_info = get_os()
    candidates = ('www-data', 'nginx', 'apache') if os_info['family'] == 'debian' else ('nginx', 'apache', 'www-data')
    for u in candidates:
        try:
            pwd.getpwnam(u)
            return u
        except KeyError:
            continue
    # Neither nginx nor httpd installed yet on RHEL (no 'nginx'/'apache'
    # account): returning a non-existent user makes systemd units fail with
    # "Failed to determine user credentials".
    return 'www-data' if os_info['family'] == 'debian' else 'nobody'

# os_utils loaded


# --- Shared web root -------------------------------------------------------------
WEBROOT = '/www/wwwroot'


def get_webroot():
    """The one place new sites are created: /www/wwwroot (created if missing).
    Never /var/www/html or /usr/share/nginx/html -- those are the docroot of
    the distro's default site (Apache 000-default, nginx.org default.conf),
    where a new site's files, including wp-config.php, would also be served,
    unparsed, as http://<server-ip>/<domain>/wp-config.php."""
    try:
        os.makedirs(WEBROOT, exist_ok=True)
        if not _WEBROOT_LABELLED[0]:
            # Once per process: restorecon -R over every site on every call
            # would make listing sites slow on big servers.
            _WEBROOT_LABELLED[0] = True
            selinux_label_path(WEBROOT)
    except Exception:
        pass
    return WEBROOT


_WEBROOT_LABELLED = [False]


# --- SELinux (RHEL family, Fedora) -----------------------------------------------
def selinux_enabled():
    """True when SELinux is Enforcing or Permissive."""
    try:
        out = subprocess.run(['getenforce'], capture_output=True, text=True, timeout=10).stdout.strip()
        return out in ('Enforcing', 'Permissive')
    except Exception:
        return False


_SELINUX_TOOLS_TRIED = [False]


def _selinux_tools():
    """semanage lives in policycoreutils-python-utils, missing on minimal images."""
    import shutil
    if shutil.which('semanage') or _SELINUX_TOOLS_TRIED[0]:
        return bool(shutil.which('semanage'))
    _SELINUX_TOOLS_TRIED[0] = True
    subprocess.run('dnf install -y policycoreutils-python-utils >/dev/null 2>&1 || '
                   'yum install -y policycoreutils-python-utils >/dev/null 2>&1', shell=True, timeout=600)
    return bool(shutil.which('semanage'))


def selinux_label_path(path, writable=True):
    """Give a web directory a persistent httpd context. No-op without SELinux."""
    if not path or not selinux_enabled():
        return
    ctx = 'httpd_sys_rw_content_t' if writable else 'httpd_sys_content_t'
    path = os.path.realpath(path).rstrip('/') or '/'
    if path in ('/', '/etc', '/usr', '/var', '/root', '/home', '/opt'):
        return
    if _selinux_tools():
        subprocess.run(['semanage', 'fcontext', '-a', '-t', ctx, path + '(/.*)?'],
                       capture_output=True, timeout=120)
        subprocess.run(['semanage', 'fcontext', '-m', '-t', ctx, path + '(/.*)?'],
                       capture_output=True, timeout=120)
        subprocess.run(['restorecon', '-R', path], capture_output=True, timeout=600)
    else:
        subprocess.run(['chcon', '-R', '-t', ctx, path], capture_output=True, timeout=600)


def selinux_allow_port(port, proto='tcp'):
    """Let web servers listen on a non-standard port (e.g. 8082 phpMyAdmin,
    8083 Roundcube). Without it nginx/httpd fail to bind after a reboot."""
    if not selinux_enabled():
        return
    try:
        port = int(port)
    except (TypeError, ValueError):
        return
    if port in (80, 443, 81, 8008, 8009, 8443, 488, 9000):   # already http_port_t in the default policy
        return
    if _selinux_tools():
        r = subprocess.run(['semanage', 'port', '-a', '-t', 'http_port_t', '-p', proto, str(port)],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            subprocess.run(['semanage', 'port', '-m', '-t', 'http_port_t', '-p', proto, str(port)],
                           capture_output=True, timeout=120)


def selinux_web_booleans(proxy=True, db=True, mail=False, ftp=False):
    """Booleans web stacks need on SELinux: reverse proxies to local ports
    (Node/Go/Docker apps, proxy rules, load balancer), PHP talking to remote
    DBs/APIs, PHP mail(), FTP writing into site directories."""
    if not selinux_enabled():
        return
    bools = []
    if proxy: bools.append('httpd_can_network_connect=1')
    if db: bools.append('httpd_can_network_connect_db=1')
    if mail: bools.append('httpd_can_sendmail=1')
    if ftp: bools.append('ftpd_full_access=1')
    if bools:
        subprocess.run(['setsebool', '-P'] + bools, capture_output=True, timeout=300)


# --- EPEL ---------------------------------------------------------------------------
def ensure_epel_cmd():
    """Shell snippet that enables EPEL on any RHEL-family distro: the
    epel-release package exists only on Alma/Rocky/CentOS/CloudLinux; Oracle
    Linux has oracle-epel-release-elN; RHEL itself needs the upstream RPM plus
    the CodeReady Builder repo. Always exits 0 (callers check what they install)."""
    # Fedora has no EPEL (its own repos carry those packages); without this
    # guard the fallback below installed the EL9 epel-release on Fedora.
    return (
        '( [ -n "$(rpm -E %{?fedora} 2>/dev/null)" ] || rpm -q epel-release >/dev/null 2>&1 || '
        '  dnf install -y epel-release >/dev/null 2>&1 || '
        '  { V=$(rpm -E %{?rhel} 2>/dev/null); V=${V:-9}; '
        '    if grep -qi "oracle" /etc/os-release 2>/dev/null; then dnf install -y oracle-epel-release-el$V; '
        '    else dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-$V.noarch.rpm && '
        '      (subscription-manager repos --enable codeready-builder-for-rhel-$V-$(arch)-rpms 2>/dev/null || '
        '       dnf config-manager --set-enabled crb 2>/dev/null || true); fi; } ; true )'
    )


# --- certbot renewal -------------------------------------------------------------
def certbot_enable_renewal():
    """Debian/Ubuntu packages enable certbot.timer automatically; EPEL ships
    certbot-renew.timer DISABLED, so certificates silently expired after 90
    days on the RHEL family. Idempotent."""
    subprocess.run('systemctl enable --now certbot-renew.timer >/dev/null 2>&1 || '
                   'systemctl enable --now certbot.timer >/dev/null 2>&1 || true',
                   shell=True, timeout=60)


# --- Shell-snippet forms of the SELinux helpers --------------------------------------
# For App Store install scripts (they run as one shell job, after the packages
# they need exist). All are no-ops without SELinux and always exit 0.
_SEL_ON = ('command -v getenforce >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null)" != Disabled ]')
_SEL_TOOLS = ('{ command -v semanage >/dev/null 2>&1 || dnf install -y policycoreutils-python-utils >/dev/null 2>&1 || '
              'yum install -y policycoreutils-python-utils >/dev/null 2>&1; }')


def selinux_web_booleans_cmd(proxy=True, db=True, mail=False, ftp=False):
    """Shell form of selinux_web_booleans()."""
    bools = []
    if proxy: bools.append('httpd_can_network_connect=1')
    if db: bools.append('httpd_can_network_connect_db=1')
    if mail: bools.append('httpd_can_sendmail=1')
    if ftp: bools.append('ftpd_full_access=1')
    if not bools:
        return 'true'
    return (f'( if {_SEL_ON}; then setsebool -P {" ".join(bools)} >/dev/null 2>&1 || '
            f'echo "[VortexPanel] Warning: could not set the SELinux booleans {" ".join(bools)}"; fi; true )')


def selinux_port_cmd(port, proto='tcp'):
    """Shell form of selinux_allow_port(): label a non-standard web port
    http_port_t so nginx/httpd can bind it (they fail to start otherwise)."""
    port = int(port)
    return (f'( if {_SEL_ON}; then {_SEL_TOOLS}; '
            f'semanage port -a -t http_port_t -p {proto} {port} >/dev/null 2>&1 || '
            f'semanage port -m -t http_port_t -p {proto} {port} >/dev/null 2>&1 || '
            f'semanage port -l 2>/dev/null | grep -E "^http_port_t .*[ ,]{port}(,|$)" >/dev/null || '
            f'echo "[VortexPanel] Warning: SELinux port {port}/{proto} could not be allowed for the web server '
            f'(run: semanage port -a -t http_port_t -p {proto} {port})"; fi; true )')


def selinux_label_cmd(path, writable=True):
    """Shell form of selinux_label_path() for a fixed, trusted path."""
    if not re.match(r'^/[A-Za-z0-9._/-]+$', path or ''):
        return 'true'
    ctx = 'httpd_sys_rw_content_t' if writable else 'httpd_sys_content_t'
    path = path.rstrip('/')
    return (f'( if {_SEL_ON}; then {_SEL_TOOLS}; '
            f'semanage fcontext -a -t {ctx} "{path}(/.*)?" >/dev/null 2>&1 || '
            f'semanage fcontext -m -t {ctx} "{path}(/.*)?" >/dev/null 2>&1; '
            f'restorecon -R "{path}" >/dev/null 2>&1 || chcon -R -t {ctx} "{path}" >/dev/null 2>&1; fi; true )')
