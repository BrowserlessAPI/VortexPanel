from flask import Blueprint, jsonify, request, session
import subprocess, re, os

php_bp = Blueprint('php', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except: return ''

INSTALLED_PHP_CACHE = None

def get_php_versions():
    versions = []
    for v in ['8.3','8.2','8.1','8.0','7.4']:
        if sh(f'which php{v}'):
            active = sh(f'systemctl is-active php{v}-fpm') == 'active'
            versions.append({'version':v,'active':active,'fpm':f'php{v}-fpm'})
    if not versions:
        default = sh('php -v | head -1')
        m = re.search(r'PHP (\d+\.\d+)', default)
        if m: versions.append({'version':m.group(1),'active':True,'fpm':'php-fpm'})
    return versions

@php_bp.route('/api/php/versions')
def versions():
    if not req(): return jsonify({'ok':False}),401
    return jsonify({'ok':True,'versions':get_php_versions()})

@php_bp.route('/api/php/<version>/extensions')
def extensions(version):
    if not req(): return jsonify({'ok':False}),401
    raw = sh(f'php{version} -m 2>/dev/null || php -m')
    installed = set(raw.lower().split('\n'))
    common = ['bcmath','curl','gd','imagick','intl','mbstring','memcached',
              'mongodb','mysqli','opcache','pdo','pdo_mysql','pdo_pgsql',
              'pgsql','redis','soap','sqlite3','xml','xsl','zip','zlib']
    exts = [{'name':e,'installed':e in installed or e.replace('_','').replace('-','') in installed} for e in common]
    return jsonify({'ok':True,'extensions':exts})

@php_bp.route('/api/php/<version>/ini')
def get_ini(version):
    if not req(): return jsonify({'ok':False}),401
    ini_path = sh(f'php{version} --ini 2>/dev/null | grep "Loaded Config" | cut -d: -f2').strip()
    if not ini_path or not os.path.exists(ini_path):
        ini_path = f'/etc/php/{version}/fpm/php.ini'
    if not os.path.exists(ini_path):
        return jsonify({'ok':False,'error':'php.ini not found'}),404
    with open(ini_path) as f: return jsonify({'ok':True,'content':f.read(),'path':ini_path})

@php_bp.route('/api/php/<version>/ini', methods=['PUT'])
def save_ini(version):
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    path = d.get('path','')
    content = d.get('content','')
    if not os.path.exists(path): return jsonify({'ok':False,'error':'File not found'}),404
    with open(path,'w') as f: f.write(content)
    sh(f'systemctl reload php{version}-fpm 2>/dev/null || service php{version}-fpm reload')
    return jsonify({'ok':True})

@php_bp.route('/api/php/<version>/fpm', methods=['POST'])
def control_fpm(version):
    if not req(): return jsonify({'ok':False}),401
    action = (request.get_json() or {}).get('action','status')
    out = sh(f'systemctl {action} php{version}-fpm 2>&1')
    return jsonify({'ok':True,'output':out})
