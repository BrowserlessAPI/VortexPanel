from flask import Blueprint, jsonify
import subprocess, os, re, glob

services_bp = Blueprint('services', __name__)
def req():
    from panel.routes.auth import check_ip_and_session
    return check_ip_and_session()

SERVICES = [
    {'name':'nginx',          'label':'Nginx',            'icon':'globe'},
    {'name':'apache2',        'label':'Apache2',          'icon':'dot'},
    {'name':'mysql',          'label':'MySQL',            'icon':'database'},
    {'name':'mariadb',        'label':'MariaDB',          'icon':'database'},
    {'name':'redis-server',   'label':'Redis',            'icon':'dot'},
    {'name':'memcached',      'label':'Memcached',        'icon':'hard-drive'},
    {'name':'php8.3-fpm',     'label':'PHP 8.3-FPM',      'icon':'code'},
    {'name':'php8.2-fpm',     'label':'PHP 8.2-FPM',      'icon':'code'},
    {'name':'php8.1-fpm',     'label':'PHP 8.1-FPM',      'icon':'code'},
    {'name':'postfix',        'label':'Postfix (Mail)',   'icon':'mail'},
    {'name':'dovecot',        'label':'Dovecot (IMAP)',   'icon':'mail'},
    {'name':'docker',         'label':'Docker',           'icon':'package'},
    {'name':'fail2ban',       'label':'Fail2ban',         'icon':'shield'},
    {'name':'ufw',            'label':'UFW Firewall',     'icon':'flame'},
    {'name':'bind9',          'label':'BIND9 (DNS)',      'icon':'globe'},
    {'name':'proftpd',        'label':'ProFTPD',          'icon':'folder'},
    {'name':'vsftpd',         'label':'vsftpd',           'icon':'folder'},
]

# RHEL-family unit names for the same services (shown under the same label).
SERVICES += [
    {'name':'httpd',          'label':'Apache (httpd)',   'icon':'dot'},
    {'name':'mysqld',         'label':'MySQL',            'icon':'database'},
    {'name':'redis',          'label':'Redis',            'icon':'dot'},
    {'name':'php-fpm',        'label':'PHP-FPM',          'icon':'code'},
    {'name':'named',          'label':'BIND (DNS)',       'icon':'globe'},
    {'name':'firewalld',      'label':'firewalld',        'icon':'flame'},
    {'name':'pure-ftpd',      'label':'Pure-FTPd',        'icon':'folder'},
    {'name':'postgresql',     'label':'PostgreSQL',       'icon':'database'},
    {'name':'mongod',         'label':'MongoDB',          'icon':'database'},
]

_UNIT_RE = re.compile(r'^[A-Za-z0-9@._:-]{1,128}$')


def _php_fpm_units():
    """Every installed versioned PHP-FPM unit (ondrej/sury 5.6-8.5, remi),
    instead of a hard-coded 8.1-8.3 list."""
    names = set()
    for d in ('/lib/systemd/system', '/usr/lib/systemd/system', '/etc/systemd/system'):
        for f in glob.glob(os.path.join(d, 'php*-fpm.service')):
            names.add(os.path.basename(f)[:-len('.service')])
    def key(n):
        m = re.search(r'(\d+)\.?(\d+)', n)
        return (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    return sorted(names, key=key, reverse=True)


def _unit_states(names):
    """{name: (LoadState, ActiveState, UnitFileState)} in ONE systemctl call.
    `systemctl is-active` exits 3 for inactive units, which check_output
    turned into '' - so stopped/failed services vanished from the list and
    could not be started from the panel."""
    if not names:
        return {}
    try:
        r = subprocess.run(['systemctl', 'show', '--property=Id,LoadState,ActiveState,UnitFileState', '--'] +
                           [n + '.service' for n in names], capture_output=True, text=True, timeout=15)
        out = r.stdout
    except Exception:
        return {}
    res = {}
    for name, block in zip(names, out.strip().split('\n\n')):
        props = dict(l.split('=', 1) for l in block.splitlines() if '=' in l)
        res[name] = (props.get('LoadState', ''), props.get('ActiveState', ''), props.get('UnitFileState', ''))
    return res


@services_bp.route('/api/services')
def list_svcs():
    if not req(): return jsonify({'ok':False}),401
    svcs = [s for s in SERVICES if not s['name'].startswith('php8.')]
    for n in _php_fpm_units():
        m = re.match(r'php(\d+)\.?(\d+)', n)
        v = f'{m.group(1)}.{m.group(2)}' if m else ''
        svcs.append({'name': n, 'label': f'PHP {v}-FPM' if v else 'PHP-FPM', 'icon': 'code'})
    seen, uniq = set(), []
    for s in svcs:
        if s['name'] not in seen:
            seen.add(s['name']); uniq.append(s)
    states = _unit_states([s['name'] for s in uniq])
    result = []
    for svc in uniq:
        load, active, ufs = states.get(svc['name'], ('', '', ''))
        if load != 'loaded':
            continue                     # not installed on this server
        result.append({**svc, 'status': active or 'unknown', 'enabled': ufs in ('enabled', 'enabled-runtime', 'alias')})
    return jsonify({'ok':True,'services':result})

@services_bp.route('/api/services/<name>/<action>', methods=['POST'])
def control(name, action):
    if not req(): return jsonify({'ok':False}),401
    if action not in ('start','stop','restart','reload','enable','disable'):
        return jsonify({'ok':False,'error':'Invalid action'}),400
    # `name` comes from the URL and was interpolated into a root shell.
    if not _UNIT_RE.match(name) or name.startswith('-'):
        return jsonify({'ok':False,'error':'Invalid service name'}),400
    if name in ('vortexpanel', 'vortexpanel.service') and action in ('stop', 'disable'):
        return jsonify({'ok':False,'error':'Refusing to stop the panel from the panel'}),400
    try:
        r = subprocess.run(['systemctl', action, name], capture_output=True, text=True, timeout=120)
        ok, err = r.returncode == 0, (r.stderr or r.stdout).strip()
    except subprocess.TimeoutExpired:
        ok, err = False, f'systemctl {action} {name} timed out'
    try:
        status = subprocess.run(['systemctl', 'is-active', name], capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        status = ''
    resp = {'ok':ok,'status':status}
    if not ok:
        resp['error'] = err[-400:] or f'systemctl {action} {name} failed'
    return jsonify(resp)
