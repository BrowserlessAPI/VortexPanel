from flask import Blueprint, jsonify, request, session
import subprocess, re, os
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
]

def get_php_versions():
    versions = []
    for v in ['8.5','8.4','8.3','8.2','8.1','8.0','7.4','7.3','7.2']:
        binary = sh(f'which php{v} 2>/dev/null')
        if binary:
            fpm_svc  = f'php{v}-fpm'
            status   = sh(f'systemctl is-active {fpm_svc} 2>/dev/null') or 'inactive'
            enabled  = sh(f'systemctl is-enabled {fpm_svc} 2>/dev/null') == 'enabled'
            ini_path = sh(f'php{v} --ini 2>/dev/null | grep "Loaded Config" | cut -d: -f2').strip()
            if not ini_path:
                ini_path = f'/etc/php/{v}/fpm/php.ini'
            versions.append({
                'version': v, 'binary': binary,
                'fpm': fpm_svc, 'status': status,
                'enabled': enabled, 'ini_path': ini_path,
            })
    # Fallback: default php
    if not versions:
        ver_out = sh('php -v 2>/dev/null | head -1')
        m = re.search(r'PHP (\d+\.\d+)', ver_out)
        if m:
            v = m.group(1)
            versions.append({
                'version': v, 'binary': sh('which php'),
                'fpm': 'php-fpm', 'status': sh('systemctl is-active php-fpm 2>/dev/null') or 'inactive',
                'enabled': False, 'ini_path': sh('php --ini 2>/dev/null | grep "Loaded Config" | cut -d: -f2').strip(),
            })
    return versions

def get_installed_extensions(version):
    raw = sh(f'php{version} -m 2>/dev/null || php -m 2>/dev/null')
    return set(e.lower().strip() for e in raw.split('\n') if e.strip() and not e.startswith('['))

@php_bp.route('/api/php/versions')
def versions():
    if not req(): return jsonify({'ok':False}), 401
    return jsonify({'ok':True, 'versions': get_php_versions()})

@php_bp.route('/api/php/installed')
def installed_versions():
    if not req(): return jsonify({'ok':False}), 401
    versions = [v['version'] for v in get_php_versions()]
    return jsonify({'ok':True, 'versions': versions})

@php_bp.route('/api/php/<version>/extensions')
def extensions(version):
    if not req(): return jsonify({'ok':False}), 401
    installed = get_installed_extensions(version)
    result = []
    for ext in PHP_EXTENSIONS:
        name = ext['name']
        is_inst = (name in installed or
                   name.replace('_','') in installed or
                   'php_'+name in installed)
        result.append({**ext, 'installed': is_inst})
    return jsonify({'ok':True, 'extensions': result})

@php_bp.route('/api/php/<version>/extensions/<ext>/install', methods=['POST'])
def install_ext(version, ext):
    if not req(): return jsonify({'ok':False}), 401
    # Try apt first, then pecl
    pkg = f'php{version}-{ext}'
    out = sh(f'apt-get install -y {pkg} 2>&1', t=120)
    if 'Unable to locate' in out or 'has no installation candidate' in out:
        out = sh(f'pecl install {ext} 2>&1', t=120)
    installed = ext in get_installed_extensions(version)
    sh(f'systemctl reload php{version}-fpm 2>/dev/null || true')
    return jsonify({'ok':True, 'installed':installed, 'output':out[:500]})

@php_bp.route('/api/php/<version>/extensions/<ext>/uninstall', methods=['POST'])
def uninstall_ext(version, ext):
    if not req(): return jsonify({'ok':False}), 401
    out = sh(f'apt-get remove -y php{version}-{ext} 2>&1', t=60)
    sh(f'systemctl reload php{version}-fpm 2>/dev/null || true')
    return jsonify({'ok':True, 'output':out[:300]})

@php_bp.route('/api/php/<version>/ini')
def get_ini(version):
    if not req(): return jsonify({'ok':False}), 401
    paths = [
        f'/etc/php/{version}/fpm/php.ini',
        f'/etc/php/{version}/cli/php.ini',
        f'/usr/local/etc/php/{version}/php.ini',
    ]
    for p in paths:
        if os.path.exists(p):
            with open(p) as f: return jsonify({'ok':True, 'content':f.read(), 'path':p})
    return jsonify({'ok':False, 'error':'php.ini not found'}), 404

@php_bp.route('/api/php/<version>/ini', methods=['PUT'])
def save_ini(version):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    path    = d.get('path','')
    content = d.get('content','')
    if not os.path.exists(path):
        return jsonify({'ok':False, 'error':'File not found'}), 404
    with open(path,'w') as f: f.write(content)
    sh(f'systemctl reload php{version}-fpm 2>/dev/null || true')
    return jsonify({'ok':True})

@php_bp.route('/api/php/<version>/config')
def get_config(version):
    """Get key php.ini values for the config panel"""
    if not req(): return jsonify({'ok':False}), 401
    keys = ['upload_max_filesize','post_max_size','max_execution_time',
            'max_input_time','memory_limit','display_errors',
            'error_reporting','date.timezone','session.gc_maxlifetime',
            'disable_functions']
    result = {}
    for k in keys:
        val = sh(f'php{version} -r "echo ini_get(\'{k}\');" 2>/dev/null')
        result[k] = val
    return jsonify({'ok':True, 'config':result})

@php_bp.route('/api/php/<version>/config', methods=['PUT'])
def save_config(version):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    cfg = d.get('config', {})
    ini_paths = [f'/etc/php/{version}/fpm/php.ini', f'/etc/php/{version}/cli/php.ini']
    for ini_path in ini_paths:
        if not os.path.exists(ini_path): continue
        with open(ini_path) as f: content = f.read()
        for key, val in cfg.items():
            # Replace existing or append
            pattern = re.compile(rf'^;?\s*{re.escape(key)}\s*=.*', re.MULTILINE)
            new_line = f'{key} = {val}'
            if pattern.search(content):
                content = pattern.sub(new_line, content)
            else:
                content += f'\n{new_line}\n'
        with open(ini_path,'w') as f: f.write(content)
    sh(f'systemctl reload php{version}-fpm 2>/dev/null || true')
    return jsonify({'ok':True})

@php_bp.route('/api/php/<version>/fpm', methods=['POST'])
def control_fpm(version):
    if not req(): return jsonify({'ok':False}), 401
    action = (request.get_json() or {}).get('action','status')
    if action not in ('start','stop','restart','reload','enable','disable'):
        return jsonify({'ok':False,'error':'Invalid action'}), 400

    # Try both possible service names
    svc_names = [f'php{version}-fpm', f'php-fpm{version}', 'php-fpm']
    used_svc  = None
    out_msg   = ''

    for svc in svc_names:
        # Check if this service exists first
        exists_out = sh(f'systemctl list-unit-files {svc}.service 2>/dev/null | grep {svc}')
        if not exists_out:
            continue
        used_svc = svc
        out_msg  = sh(f'systemctl {action} {svc} 2>&1', t=15)
        break

    if not used_svc:
        return jsonify({'ok':False, 'error':f'PHP {version} FPM service not found. Is php{version}-fpm installed?'})

    # Give systemd a moment to update state
    import time
    time.sleep(1)
    status  = sh(f'systemctl is-active {used_svc} 2>/dev/null') or 'inactive'
    enabled = sh(f'systemctl is-enabled {used_svc} 2>/dev/null') == 'enabled'

    success = (action in ('stop','disable')) or (status == 'active')

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
    pool_conf = f'/etc/php/{version}/fpm/pool.d/www.conf'
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
    log_paths = [
        f'/var/log/php{version}-fpm.log',
        f'/var/log/php-fpm.log',
        f'/var/log/php/{version}/error.log',
    ]
    for p in log_paths:
        if os.path.exists(p):
            content = sh(f'tail -100 {p}')
            return jsonify({'ok':True, 'content':content, 'path':p})
    return jsonify({'ok':False, 'error':'Log file not found'})

@php_bp.route('/api/php/<version>/phpinfo')
def phpinfo(version):
    if not req(): return jsonify({'ok':False}), 401
    info = sh(f'php{version} -i 2>/dev/null | head -100')
    return jsonify({'ok':True, 'content':info})
