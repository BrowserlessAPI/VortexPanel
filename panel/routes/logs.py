from flask import Blueprint, jsonify, request
import os, re, shlex, subprocess

logs_bp = Blueprint('logs', __name__)
def req():
    from panel.routes.auth import check_ip_and_session
    return check_ip_and_session()

def sh(c, t=20):
    try: return subprocess.check_output(c, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=t).strip()
    except: return ''

LOG_SOURCES = {
    'nginx_error':  '/var/log/nginx/error.log',
    'nginx_access': '/var/log/nginx/access.log',
    'vortexpanel':  '/var/log/vortexpanel/error.log',
    'syslog':       '/var/log/syslog',
    # RHEL family / Debian-family equivalents
    'messages':     '/var/log/messages',
    'auth':         '/var/log/auth.log',
    'secure':       '/var/log/secure',
    'apache_error': '/var/log/apache2/error.log',
    'httpd_error':  '/var/log/httpd/error_log',
}
# Debian 12+ and minimal Ubuntu images ship no rsyslog (journald only), so
# /var/log/syslog does not exist there; the journal is always available.
_JOURNAL_SOURCES = {
    'journal':          ('System journal', []),
    'journal:vortexpanel': ('VortexPanel service (journal)', ['-u', 'vortexpanel']),
}
_PM2_NAME_RE = re.compile(r'^[A-Za-z0-9._@-]{1,100}$')


@logs_bp.route('/api/logs/files')
def log_files():
    from flask import jsonify, session
    import os, glob
    if 'user' not in session: return jsonify({'ok':False}), 401
    log_paths = [
        '/var/log/nginx', '/var/log/apache2', '/var/log/httpd',
        '/var/log/mysql', '/var/log/mariadb', '/var/log/mongodb',
        '/var/log/syslog', '/var/log/auth.log',
        '/var/log/messages', '/var/log/secure', '/var/log/maillog', '/var/log/mail.log',
    ]
    files = []
    for p in log_paths:
        if os.path.isdir(p):
            for f in glob.glob(p + '/*.log') + glob.glob(p + '/*.err'):
                files.append({'name': os.path.basename(f), 'path': f, 'dir': p})
        elif os.path.isfile(p):
            files.append({'name': os.path.basename(p), 'path': p})
    return jsonify({'ok': True, 'files': files})

@logs_bp.route('/api/logs/sources')
def log_sources():
    if not req(): return jsonify({'ok':False}),401
    sources = []
    for key, path in LOG_SOURCES.items():
        if os.path.exists(path):
            sources.append({'id':key, 'label':key.replace('_',' ').title(), 'path':path})
    if os.path.exists('/run/systemd/journal') or os.path.isdir('/var/log/journal'):
        for key, (label, _) in _JOURNAL_SOURCES.items():
            sources.append({'id': key, 'label': label, 'path': ''})
    # PM2 apps (App Runner)
    pm2_out = sh('pm2 jlist 2>/dev/null')
    if pm2_out:
        import json
        try:
            apps = json.loads(pm2_out)
            for app in apps:
                sources.append({'id':'pm2:'+app['name'], 'label':'App: '+app['name'], 'path':''})
        except: pass
    return jsonify({'ok':True, 'sources':sources})

@logs_bp.route('/api/logs/tail')
def tail_log():
    if not req(): return jsonify({'ok':False}),401
    source = request.args.get('source','vortexpanel')
    search = request.args.get('search','').strip()
    try:
        lines = max(1, min(int(request.args.get('lines', 200)), 1000))
    except (TypeError, ValueError):
        lines = 200

    if source in _JOURNAL_SOURCES:
        try:
            out = subprocess.run(['journalctl', '--no-pager', '-n', str(lines), '-o', 'short-iso']
                                 + _JOURNAL_SOURCES[source][1],
                                 capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception:
            out = ''
    elif source.startswith('pm2:'):
        app_name = source[4:]
        # Was interpolated into a root shell straight from the query string.
        if not _PM2_NAME_RE.match(app_name):
            return jsonify({'ok':False,'error':'Invalid app name'}),400
        out = sh(f'pm2 logs {shlex.quote(app_name)} --lines {lines} --nostream 2>/dev/null')
    else:
        path = LOG_SOURCES.get(source)
        if not path or not os.path.exists(path):
            return jsonify({'ok':False,'error':'Log source not found'}),404
        out = sh(f'tail -n {lines} "{path}" 2>/dev/null')

    if search:
        out = '\n'.join(l for l in out.split('\n') if search.lower() in l.lower())

    return jsonify({'ok':True, 'lines': out or 'No log entries found'})
