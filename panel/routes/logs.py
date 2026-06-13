from flask import Blueprint, jsonify, request, session
import os, subprocess

logs_bp = Blueprint('logs', __name__)
def req(): return 'user' in session

def sh(c, t=20):
    try: return subprocess.check_output(c, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=t).strip()
    except: return ''

LOG_SOURCES = {
    'nginx_error':  '/var/log/nginx/error.log',
    'nginx_access': '/var/log/nginx/access.log',
    'vortexpanel':  '/var/log/vortexpanel/error.log',
    'syslog':       '/var/log/syslog',
}

@logs_bp.route('/api/logs/sources')
def log_sources():
    if not req(): return jsonify({'ok':False}),401
    sources = []
    for key, path in LOG_SOURCES.items():
        if os.path.exists(path):
            sources.append({'id':key, 'label':key.replace('_',' ').title(), 'path':path})
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
    lines  = min(int(request.args.get('lines', 200)), 1000)

    if source.startswith('pm2:'):
        app_name = source[4:]
        out = sh(f'pm2 logs {app_name} --lines {lines} --nostream 2>/dev/null')
    else:
        path = LOG_SOURCES.get(source)
        if not path or not os.path.exists(path):
            return jsonify({'ok':False,'error':'Log source not found'}),404
        out = sh(f'tail -n {lines} "{path}" 2>/dev/null')

    if search:
        out = '\n'.join(l for l in out.split('\n') if search.lower() in l.lower())

    return jsonify({'ok':True, 'lines': out or 'No log entries found'})
