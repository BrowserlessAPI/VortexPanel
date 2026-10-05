from flask import Blueprint, jsonify, request, session
import subprocess, re, os, time
try:
    from panel.routes.os_utils import get_os, pkg_install, pkg_update, pkg_remove
except ImportError:
    try:
        from os_utils import get_os, pkg_install, pkg_update, pkg_remove
    except ImportError:
        def get_os(): return {'family':'debian','pkg':'apt','id':'ubuntu','codename':'noble'}
        def pkg_install(p, f=''): return f'DEBIAN_FRONTEND=noninteractive apt-get install -y {f} {p}'
        def pkg_update(): return 'apt-get update -qq'
        def pkg_remove(p): return f'apt-get remove -y --purge {p} && apt-get autoremove -y'


php_bp = Blueprint('php', __name__)
def req(): return 'user' in session
def sh(c, t=15):
    try: return subprocess.check_output(c, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=t).strip()
    except: return ''

def _run(args, t=30, inp=None, env=None):
    """Run an argument list (no shell). Returns (returncode, combined output)."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=t, input=inp, env=env)
        return r.returncode, ((r.stdout or '') + (r.stderr or '')).strip()
    except subprocess.TimeoutExpired:
        return 124, f'{args[0]} did not finish within {t}s'
    except Exception as e:
        return 127, str(e)

PHP_EXTENSIONS = [
    {'name':'fileinfo',   'type':'Universal',  'desc':'Get file MIME, encoding, etc.'},
    {'name':'curl',       'type':'Universal',  'desc':'HTTP requests via libcurl'},
    {'name':'gd',         'type':'Universal',  'desc':'Image creation & manipulation'},
    {'name':'imagick',    'type':'Universal',  'desc':'ImageMagick high-performance graphics'},
    {'name':'intl',       'type':'Universal',  'desc':'Internationalization support'},
    {'name':'mbstring',   'type':'Universal',  'desc':'Multibyte string functions'},
    {'name':'xml',        'type':'Universal',  'desc':'XML parsing support'},
    {'name':'xsl',        'type':'Universal',  'desc':'XSL parsing extensions'},
    {'name':'zip',        'type':'Universal',  'desc':'ZIP file handling'},
    {'name':'bcmath',     'type':'Universal',  'desc':'Arbitrary precision math'},
    {'name':'exif',       'type':'General',    'desc':'Read picture EXIF information'},
    {'name':'opcache',    'type':'Buffer',     'desc':'Opcode caching for performance'},
    {'name':'apcu',       'type':'Buffer',     'desc':'Script buffer / user cache'},
    {'name':'redis',      'type':'Cache',      'desc':'Key-value database / cache'},
    {'name':'memcached',  'type':'Buffer',     'desc':'More advanced memcache features'},
    {'name':'mysqli',     'type':'Database',   'desc':'MySQL improved extension'},
    {'name':'pdo',        'type':'Database',   'desc':'PHP Data Objects'},
    {'name':'pdo_mysql',  'type':'Database',   'desc':'PDO MySQL driver'},
    {'name':'pdo_pgsql',  'type':'Database',   'desc':'PDO PostgreSQL driver'},
    {'name':'pgsql',      'type':'Database',   'desc':'PostgreSQL support'},
    {'name':'mongodb',    'type':'Database',   'desc':'MongoDB driver'},
    {'name':'soap',       'type':'Universal',  'desc':'SOAP web services'},
    {'name':'sqlite3',    'type':'Database',   'desc':'SQLite3 support'},
    {'name':'imap',       'type':'Mail',       'desc':'IMAP/POP3/NNTP mail'},
    {'name':'ldap',       'type':'Universal',  'desc':'LDAP directory access'},
    {'name':'sockets',    'type':'Universal',  'desc':'Low-level socket functions'},
    {'name':'pcntl',      'type':'Universal',  'desc':'Process control functions'},
    {'name':'posix',      'type':'Universal',  'desc':'POSIX functions'},
    {'name':'tokenizer',  'type':'Universal',  'desc':'PHP tokenizer'},
    {'name':'simplexml',  'type':'Universal',  'desc':'Simple XML manipulation'},
    {'name':'sodium',     'type':'Security',   'desc':'Modern cryptography'},
    {'name':'xdebug',     'type':'Debug',      'desc':'Debugger and profiler'},
]

# --- PHP layout per distro ---------------------------------------------------------
# Debian/Ubuntu (ondrej/sury): /etc/php/X.Y/{fpm,cli}/php.ini, pool.d/www.conf,
#   unit phpX.Y-fpm, binary /usr/bin/phpX.Y, packages phpX.Y-<ext>.
# RHEL Remi SCL (side-by-side): /etc/opt/remi/phpXY/php.ini, php-fpm.d/www.conf,
#   unit phpXY-php-fpm, binary /opt/remi/phpXY/root/usr/bin/php, packages phpXY-php-<ext>.
# RHEL module stream (what the App Store installs there): /etc/php.ini,
#   /etc/php-fpm.d/www.conf, unit php-fpm, binary /usr/bin/php, packages php-<ext>.
PHP_VERSIONS = ['8.5', '8.4', '8.3', '8.2', '8.1', '8.0', '7.4', '7.3', '7.2']

def valid_php_ver(v):
    return isinstance(v, str) and v in PHP_VERSIONS

def _system_php_ver():
    if not os.path.exists('/usr/bin/php'):
        return ''
    rc, out = _run(['/usr/bin/php', '-n', '-r', 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;'], t=10)
    out = out.strip().splitlines()[-1] if rc == 0 and out.strip() else ''
    return out if re.match(r'^\d+\.\d+$', out) else ''

def php_layout(ver, _sys=None):
    """Paths/units for one installed PHP version, or None when it is not installed."""
    if not valid_php_ver(ver):
        return None
    vn = ver.replace('.', '')
    if os.path.exists(f'/usr/bin/php{ver}') or os.path.exists(f'/usr/sbin/php-fpm{ver}'):
        fpm_ini, cli_ini = f'/etc/php/{ver}/fpm/php.ini', f'/etc/php/{ver}/cli/php.ini'
        if not os.path.exists(fpm_ini) and os.path.exists(cli_ini):
            fpm_ini, cli_ini = cli_ini, ''   # CLI-only install (no php-fpm package)
        return {'flavor': 'debian', 'ver': ver,
                'bin': f'/usr/bin/php{ver}', 'fpm_bin': f'/usr/sbin/php-fpm{ver}',
                'ini': fpm_ini, 'ini_cli': cli_ini,
                'pool': f'/etc/php/{ver}/fpm/pool.d/www.conf', 'pool_dir': f'/etc/php/{ver}/fpm/pool.d',
                'svc': f'php{ver}-fpm', 'sock': f'/run/php/php{ver}-fpm.sock',
                'log': f'/var/log/php{ver}-fpm.log', 'pkg_prefix': f'php{ver}-'}
    root = f'/opt/remi/php{vn}/root'
    if os.path.exists(root + '/usr/bin/php') or os.path.exists(root + '/usr/sbin/php-fpm'):
        return {'flavor': 'remi', 'ver': ver,
                'bin': root + '/usr/bin/php', 'fpm_bin': root + '/usr/sbin/php-fpm',
                'ini': f'/etc/opt/remi/php{vn}/php.ini', 'ini_cli': '',
                'pool': f'/etc/opt/remi/php{vn}/php-fpm.d/www.conf', 'pool_dir': f'/etc/opt/remi/php{vn}/php-fpm.d',
                'svc': f'php{vn}-php-fpm', 'sock': f'/var/opt/remi/php{vn}/run/php-fpm/www.sock',
                'log': f'/var/opt/remi/php{vn}/log/php-fpm/error.log', 'pkg_prefix': f'php{vn}-php-'}
    sysver = _sys if _sys is not None else _system_php_ver()
    if sysver == ver and (os.path.exists('/etc/php.ini') or os.path.exists('/etc/php-fpm.conf')):
        return {'flavor': 'rhel', 'ver': ver,
                'bin': '/usr/bin/php', 'fpm_bin': '/usr/sbin/php-fpm',
                'ini': '/etc/php.ini', 'ini_cli': '',
                'pool': '/etc/php-fpm.d/www.conf', 'pool_dir': '/etc/php-fpm.d',
                'svc': 'php-fpm', 'sock': '/run/php-fpm/www.sock',
                'log': '/var/log/php-fpm/error.log', 'pkg_prefix': 'php-'}
    return None

def installed_php_layouts():
    sysver = _system_php_ver()
    out = []
    for v in PHP_VERSIONS:
        lay = php_layout(v, sysver)
        if lay:
            out.append(lay)
    return out

def php_layout_for_path(path):
    """The installed PHP version that owns this ini/pool file (or None)."""
    if not path:
        return None
    real = os.path.realpath(path)
    for lay in installed_php_layouts():
        for k in ('ini', 'ini_cli', 'pool'):
            if lay.get(k) and os.path.realpath(lay[k]) == real:
                return lay
        if lay.get('pool_dir') and os.path.dirname(real) == os.path.realpath(lay['pool_dir']) and real.endswith('.conf'):
            return lay
    return None

def php_loaded_modules(lay):
    """Extensions the FPM SAPI loads (falls back to the CLI binary)."""
    raw = ''
    for b in (lay.get('fpm_bin'), lay.get('bin')):
        if b and os.path.exists(b):
            rc, raw = _run([b, '-m'], t=20)
            if rc == 0 and raw:
                break
    mods = set(e.lower().strip() for e in raw.splitlines() if e.strip() and not e.startswith('['))
    if 'zend opcache' in mods:
        mods.add('opcache')
    return mods

def php_svc_status(lay):
    try:
        out = subprocess.run(['systemctl', 'is-active', lay['svc']], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        out = ''
    return out.strip().splitlines()[0] if out.strip() else 'inactive'

def php_fpm_test(lay):
    """php-fpm -t for this version. Returns (ok, output)."""
    b = lay.get('fpm_bin')
    if not b or not os.path.exists(b):
        return True, ''
    rc, out = _run([b, '-t'], t=30)
    return rc == 0, out

def php_ini_test(lay, ini_path):
    """PHP still starts with this php.ini and reports no ini syntax error."""
    b = lay.get('bin') if lay.get('bin') and os.path.exists(lay['bin']) else lay.get('fpm_bin')
    if not b or not os.path.exists(b):
        return True, ''
    rc, out = _run([b, '-c', ini_path, '-r', 'echo "ok";'], t=20)
    if rc != 0 or 'syntax error' in out.lower() or 'parse error' in out.lower():
        return False, out
    return True, out

def php_reload(lay):
    """Reload this version's FPM if it runs. Returns (ok, message)."""
    st = php_svc_status(lay)
    if st != 'active':
        return True, f'{lay["svc"]} is not running -- the change applies when it starts.'
    rc, out = _run(['systemctl', 'reload', lay['svc']], t=60)
    if rc != 0:
        rc, out = _run(['systemctl', 'restart', lay['svc']], t=90)
    time.sleep(1)
    if php_svc_status(lay) != 'active':
        return False, f'{lay["svc"]} did not come back after the change: {out}'
    return True, ''

def php_apply_file(lay, path, new_content, test='fpm'):
    """Write a PHP config file, test it, reload FPM; restore the previous
    file when the test or the reload fails. Returns (ok, message)."""
    try:
        with open(path) as f:
            old = f.read()
    except FileNotFoundError:
        old = None
    with open(path, 'w') as f:
        f.write(new_content)
    if test == 'ini':
        ok, out = php_ini_test(lay, path)
    else:
        ok, out = True, ''
    if ok:
        ok, out2 = php_fpm_test(lay)
        out = out2 if not ok else out
    if not ok:
        _restore(path, old)
        return False, 'Configuration test failed, the previous file was restored: ' + out[-800:]
    ok, msg = php_reload(lay)
    if not ok:
        _restore(path, old)
        php_reload(lay)
        return False, msg + ' The previous file was restored.'
    return True, msg

def _restore(path, old):
    try:
        if old is None:
            os.remove(path)
        else:
            with open(path, 'w') as f:
                f.write(old)
    except Exception:
        pass

_INI_KEY_RE = re.compile(r'^[A-Za-z0-9_.]{1,64}$')

def php_ini_set(content, key, val):
    """Set key = val in php.ini text (replaces an active or commented line)."""
    pat = re.compile(rf'^[ \t]*;?[ \t]*{re.escape(key)}[ \t]*=.*$', re.MULTILINE)
    line = f'{key} = {val}'
    m_active = re.search(rf'^[ \t]*{re.escape(key)}[ \t]*=.*$', content, re.MULTILINE)
    if m_active:
        return content[:m_active.start()] + line + content[m_active.end():]
    m = pat.search(content)
    if m:
        return content[:m.start()] + line + content[m.end():]
    return content.rstrip('\n') + f'\n{line}\n'

def php_save_ini_values(lay, cfg):
    """Set php.ini keys for one version (FPM ini, and the CLI ini on Debian),
    test, reload FPM; restore on failure. Returns (ok, message)."""
    if not isinstance(cfg, dict) or not cfg:
        return False, 'No settings given.'
    for key, val in cfg.items():
        sval = '' if val is None else str(val)
        if not _INI_KEY_RE.match(str(key)) or '\n' in sval or '\r' in sval or len(sval) > 4096:
            return False, f'Invalid setting: {key}'
    msgs, done = [], 0
    for ini_path in (lay['ini'], lay.get('ini_cli')):
        if not ini_path or not os.path.exists(ini_path): continue
        with open(ini_path) as f: content = f.read()
        for key, val in cfg.items():
            content = php_ini_set(content, str(key), '' if val is None else str(val))
        ok, msg = php_apply_file(lay, ini_path, content, test='ini')
        if not ok:
            return False, msg
        done += 1
        if msg and msg not in msgs: msgs.append(msg)
    if not done:
        return False, f'php.ini for PHP {lay["ver"]} was not found ({lay["ini"]}).'
    return True, ' '.join(msgs)

# Extension -> package suffix. None = compiled in / not packaged separately.
_EXT_PKG_DEB = {
    'mysqli': 'mysql', 'pdo_mysql': 'mysql', 'mysqlnd': 'mysql', 'pdo_pgsql': 'pgsql',
    'pdo_sqlite': 'sqlite3', 'simplexml': 'xml', 'xsl': 'xml', 'dom': 'xml',
    'xmlreader': 'xml', 'xmlwriter': 'xml',
    'fileinfo': 'common', 'exif': 'common', 'sockets': 'common', 'tokenizer': 'common',
    'posix': 'common', 'pdo': 'common', 'sodium': 'common', 'ffi': 'common', 'ctype': 'common',
    'calendar': 'common', 'ftp': 'common', 'gettext': 'common', 'iconv': 'common', 'phar': 'common',
    'shmop': 'common', 'sysvmsg': 'common', 'sysvsem': 'common', 'sysvshm': 'common',
    'pcntl': None,
}
_EXT_PKG_RPM = {
    'mysqli': 'mysqlnd', 'pdo_mysql': 'mysqlnd', 'mysql': 'mysqlnd', 'pdo_pgsql': 'pgsql',
    'sqlite3': 'pdo', 'pdo_sqlite': 'pdo', 'simplexml': 'xml', 'xsl': 'xml', 'dom': 'xml',
    'xmlreader': 'xml', 'xmlwriter': 'xml',
    'fileinfo': 'common', 'exif': 'common', 'sockets': 'common', 'tokenizer': 'common',
    'ctype': 'common', 'calendar': 'common', 'ftp': 'common', 'gettext': 'common', 'iconv': 'common',
    'phar': 'common', 'curl': 'common', 'posix': 'process', 'pcntl': 'process', 'sysvmsg': 'process',
    'sysvsem': 'process', 'sysvshm': 'process', 'shmop': 'process',
}
_SHARED_PKGS = {'common', 'cli', 'xml', 'process', 'pdo', 'mysql', 'mysqlnd'}
_EXT_RE = re.compile(r'^[a-z0-9_]{2,32}$')

def _ext_pkg(lay, ext):
    table = _EXT_PKG_DEB if lay['flavor'] == 'debian' else _EXT_PKG_RPM
    if ext in table:
        suf = table[ext]
    else:
        suf = ext
    return (lay['pkg_prefix'] + suf, suf) if suf else (None, None)

def _pkg_env():
    env = os.environ.copy()
    env['DEBIAN_FRONTEND'] = 'noninteractive'
    env['NEEDRESTART_MODE'] = 'a'
    return env

def php_install_ext(ver, ext):
    """Install/enable one extension for one PHP version. Returns (ok, message)."""
    lay = php_layout(ver)
    if not lay:
        return False, f'PHP {ver} is not installed.'
    ext = (ext or '').lower().strip()
    if not _EXT_RE.match(ext):
        return False, 'Invalid extension name.'
    if ext in php_loaded_modules(lay):
        return True, f'{ext} is already enabled for PHP {ver}.'
    pkg, suf = _ext_pkg(lay, ext)
    if not pkg:
        return False, f'{ext} is built into the PHP CLI binary and cannot be added to PHP-FPM as a package.'
    if lay['flavor'] == 'debian':
        rc, out = _run(['apt-get', 'install', '-y', '-o', 'DPkg::Lock::Timeout=120', pkg], t=600, env=_pkg_env())
        if rc == 0 and suf in _SHARED_PKGS and shutil_which('phpenmod'):
            _run(['phpenmod', '-v', ver, ext], t=30)
    else:
        mgr = 'dnf' if shutil_which('dnf') else 'yum'
        rc, out = _run([mgr, 'install', '-y', pkg], t=600)
    if rc != 0:
        return False, f'Installing {pkg} failed: ' + out[-600:]
    php_reload(lay)
    if ext in php_loaded_modules(lay):
        return True, f'{ext} installed for PHP {ver}.'
    return False, f'{pkg} was installed but PHP {ver} does not load {ext}. Output: ' + out[-400:]

def php_uninstall_ext(ver, ext):
    lay = php_layout(ver)
    if not lay:
        return False, f'PHP {ver} is not installed.'
    ext = (ext or '').lower().strip()
    if not _EXT_RE.match(ext):
        return False, 'Invalid extension name.'
    if ext not in php_loaded_modules(lay):
        return True, f'{ext} is not enabled for PHP {ver}.'
    pkg, suf = _ext_pkg(lay, ext)
    if not pkg or suf in _SHARED_PKGS:
        if lay['flavor'] == 'debian' and pkg and shutil_which('phpdismod'):
            _run(['phpdismod', '-v', ver, ext], t=30)
            php_reload(lay)
            if ext not in php_loaded_modules(lay):
                return True, f'{ext} disabled for PHP {ver} (it is part of {pkg}, which stays installed).'
        return False, f'{ext} is part of a core PHP package ({pkg or "built in"}) and cannot be removed on its own.'
    if lay['flavor'] == 'debian':
        # Refuse when apt would also remove other packages that depend on it.
        rc, sim = _run(['apt-get', '-s', 'remove', pkg], t=60, env=_pkg_env())
        others = [l.split()[1] for l in sim.splitlines() if l.startswith('Remv ') and len(l.split()) > 1 and l.split()[1] != pkg]
        if others:
            return False, f'Removing {pkg} would also remove: {", ".join(others[:10])}. Not removed.'
        rc, out = _run(['apt-get', 'remove', '-y', '-o', 'DPkg::Lock::Timeout=120', pkg], t=300, env=_pkg_env())
    else:
        mgr = 'dnf' if shutil_which('dnf') else 'yum'
        rc, out = _run([mgr, 'remove', '-y', '--noautoremove', pkg] if mgr == 'dnf' else [mgr, 'remove', '-y', pkg], t=300)
    if rc != 0:
        return False, f'Removing {pkg} failed: ' + out[-600:]
    php_reload(lay)
    if ext in php_loaded_modules(lay):
        return False, f'{pkg} was removed but PHP {ver} still loads {ext}.'
    return True, f'{ext} removed from PHP {ver}.'

def shutil_which(name):
    import shutil
    return shutil.which(name)

def get_php_versions():
    versions = []
    for lay in installed_php_layouts():
        v = lay['ver']
        rc, en = _run(['systemctl', 'is-enabled', lay['svc']], t=10)
        versions.append({
            'version': v, 'binary': lay['bin'],
            'fpm': lay['svc'], 'status': php_svc_status(lay),
            'enabled': en.strip() == 'enabled', 'ini_path': lay['ini'],
        })
    return versions

def _lay_or_404(version):
    lay = php_layout(version)
    if not lay:
        return None, (jsonify({'ok': False, 'error': f'PHP {version} is not installed'}), 404)
    return lay, None

@php_bp.route('/api/php/versions')
def versions():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'versions': get_php_versions()})

@php_bp.route('/api/php/installed')
def installed_versions():
    if not req(): return jsonify({'ok':False}), 401
    versions = [v['ver'] for v in installed_php_layouts()]
    return jsonify({'ok':True, 'versions': versions})

@php_bp.route('/api/php/<version>/extensions')
def extensions(version):
    if not req(): return jsonify({'ok':False}), 401
    lay, err = _lay_or_404(version)
    if err: return err
    installed = php_loaded_modules(lay)
    result = []
    for ext in PHP_EXTENSIONS:
        name = ext['name']
        is_inst = (name in installed or name.replace('_','') in installed)
        result.append({**ext, 'installed': is_inst})
    return jsonify({'ok':True, 'extensions': result})

@php_bp.route('/api/php/<version>/extensions/<ext>/install', methods=['POST'])
def install_ext(version, ext):
    if not req(): return jsonify({'ok':False}), 401
    ok, msg = php_install_ext(version, ext)
    return jsonify({'ok': ok, 'installed': ok, 'message': msg, 'error': '' if ok else msg})

@php_bp.route('/api/php/<version>/extensions/<ext>/uninstall', methods=['POST'])
def uninstall_ext(version, ext):
    if not req(): return jsonify({'ok':False}), 401
    ok, msg = php_uninstall_ext(version, ext)
    return jsonify({'ok': ok, 'message': msg, 'error': '' if ok else msg})

@php_bp.route('/api/php/<version>/ini')
def get_ini(version):
    if not req(): return jsonify({'ok':False}), 401
    lay, err = _lay_or_404(version)
    if err: return err
    for p in (lay['ini'], lay.get('ini_cli')):
        if p and os.path.exists(p):
            with open(p) as f: return jsonify({'ok':True, 'content':f.read(), 'path':p})
    return jsonify({'ok':False, 'error':'php.ini not found'}), 404

@php_bp.route('/api/php/<version>/ini', methods=['PUT'])
def save_ini(version):
    if not req(): return jsonify({'ok':False}), 401
    lay, err = _lay_or_404(version)
    if err: return err
    d = request.get_json() or {}
    path    = d.get('path','') or lay['ini']
    content = d.get('content','')
    if path not in (lay['ini'], lay.get('ini_cli')) or not os.path.exists(path):
        return jsonify({'ok':False, 'error':'Not a php.ini of PHP ' + version}), 400
    if not content.strip():
        return jsonify({'ok':False, 'error':'Refusing to save an empty php.ini'}), 400
    ok, msg = php_apply_file(lay, path, content, test='ini')
    return jsonify({'ok':ok, 'message':msg, 'error':'' if ok else msg}), (200 if ok else 400)

@php_bp.route('/api/php/<version>/config')
def get_config(version):
    """Get key php.ini values for the config panel"""
    if not req(): return jsonify({'ok':False}), 401
    lay, err = _lay_or_404(version)
    if err: return err
    keys = ['upload_max_filesize','post_max_size','max_execution_time',
            'max_input_time','memory_limit','display_errors',
            'error_reporting','date.timezone','session.gc_maxlifetime',
            'disable_functions']
    code = 'foreach ($argv as $i => $k) { if ($i) echo $k, "=", ini_get($k), "\\n"; }'
    args = [lay['bin'], '-c', lay['ini'], '-r', code, '--'] + keys if os.path.exists(lay['ini']) else [lay['bin'], '-r', code, '--'] + keys
    rc, out = _run(args, t=20)
    result = {k: '' for k in keys}
    for line in out.splitlines():
        k, sep, v = line.partition('=')
        if sep and k in result:
            result[k] = v
    return jsonify({'ok':True, 'config':result})

@php_bp.route('/api/php/<version>/config', methods=['PUT'])
def save_config(version):
    if not req(): return jsonify({'ok':False}), 401
    lay, err = _lay_or_404(version)
    if err: return err
    d = request.get_json() or {}
    cfg = d.get('config', {})
    if not isinstance(cfg, dict) or not cfg:
        return jsonify({'ok':False, 'error':'No settings given'}), 400
    ok, msg = php_save_ini_values(lay, cfg)
    if not ok:
        return jsonify({'ok':False, 'error':msg}), 400
    return jsonify({'ok':True, 'message':msg})

@php_bp.route('/api/php/<version>/fpm', methods=['POST'])
def control_fpm(version):
    if not req(): return jsonify({'ok':False}), 401
    action = (request.get_json() or {}).get('action','status')
    if action not in ('start','stop','restart','reload','enable','disable'):
        return jsonify({'ok':False,'error':'Invalid action'}), 400
    lay, err = _lay_or_404(version)
    if err: return err
    used_svc = lay['svc']
    rc, out_msg = _run(['systemctl', action, used_svc], t=60)
    time.sleep(1)
    status  = php_svc_status(lay)
    rc2, en = _run(['systemctl', 'is-enabled', used_svc], t=10)
    enabled = en.strip() == 'enabled'
    if action in ('enable', 'disable'):
        success = rc == 0
    else:
        success = (action == 'stop') or (status == 'active')
    return jsonify({
        'ok':      True,
        'success': success,
        'status':  status,
        'enabled': enabled,
        'service': used_svc,
        'output':  out_msg[:300] if not success else '',
    })

@php_bp.route('/api/php/<version>/fpmprofile')
def fpm_profile(version):
    if not req(): return jsonify({'ok':False}), 401
    lay, err = _lay_or_404(version)
    if err: return err
    pool_conf = lay['pool']
    keys = ['pm','pm.max_children','pm.start_servers','pm.min_spare_servers',
            'pm.max_spare_servers','pm.max_requests','request_terminate_timeout']
    result = {}
    if os.path.exists(pool_conf):
        with open(pool_conf) as f: content = f.read()
        for k in keys:
            m = re.search(rf'^{re.escape(k)}\s*=\s*(.+)', content, re.MULTILINE)
            result[k] = m.group(1).strip() if m else ''
        return jsonify({'ok':True, 'config':result, 'path':pool_conf})
    return jsonify({'ok':False, 'error':'FPM pool config not found'})

@php_bp.route('/api/php/<version>/logs')
def php_logs(version):
    if not req(): return jsonify({'ok':False}), 401
    lay, err = _lay_or_404(version)
    if err: return err
    for p in (lay['log'], '/var/log/php-fpm.log', f'/var/log/php/{version}/error.log'):
        if os.path.exists(p):
            rc, content = _run(['tail', '-n', '100', p], t=10)
            return jsonify({'ok':True, 'content':content, 'path':p})
    rc, content = _run(['journalctl', '-u', lay['svc'], '-n', '100', '--no-pager'], t=15)
    if content:
        return jsonify({'ok':True, 'content':content, 'path':'journalctl -u ' + lay['svc']})
    return jsonify({'ok':False, 'error':'Log file not found'})

@php_bp.route('/api/php/<version>/phpinfo')
def phpinfo(version):
    if not req(): return jsonify({'ok':False}), 401
    lay, err = _lay_or_404(version)
    if err: return err
    rc, info = _run([lay['bin'], '-i'], t=20)
    return jsonify({'ok':True, 'content':'\n'.join(info.splitlines()[:100])})
