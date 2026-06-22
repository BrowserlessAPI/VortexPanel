import os, re
from flask import jsonify, request

try:
    from panel.routes.websites_core import websites_bp, req, sh, get_nginx_dirs, reload_nginx
except ImportError:
    from websites_core import websites_bp, req, sh, get_nginx_dirs, reload_nginx


# --- HOTLINK PROTECTION ---------------------------------------------------------
@websites_bp.route('/api/websites/<domain>/hotlink')
def get_hotlink(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':True,'enabled':False})
    with open(fp) as f: content = f.read()
    enabled = '#VP_HOTLINK' in content
    suffixes='jpg,jpeg,gif,png,js,css'; access_domain=domain; allow_empty=False
    if enabled:
        m = re.search(r'#VP_HOTLINK_SUFFIXES:([^\n]+)', content)
        if m: suffixes=m.group(1).strip()
        m = re.search(r'#VP_HOTLINK_DOMAIN:([^\n]+)', content)
        if m: access_domain=m.group(1).strip()
        allow_empty='#VP_HOTLINK_ALLOW_EMPTY' in content
    return jsonify({'ok':True,'enabled':enabled,'suffixes':suffixes,'access_domain':access_domain,'allow_empty':allow_empty})


@websites_bp.route('/api/websites/<domain>/hotlink', methods=['POST'])
def set_hotlink(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    enable        = d.get('enable', True)
    suffixes      = d.get('suffixes', 'jpg,jpeg,gif,png,js,css').strip()
    access_domain = d.get('access_domain', domain).strip()
    allow_empty   = d.get('allow_empty', False)
    response_code = d.get('response', '404')
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site not found'}), 404
    with open(fp) as f: content = f.read()
    content = re.sub(r'\s*#VP_HOTLINK.*?#VP_HOTLINK_END\n?', '\n', content, flags=re.DOTALL)
    if enable:
        ext_list    = '|'.join(e.strip() for e in suffixes.split(','))
        empty_part  = 'none blocked ~' if allow_empty else 'none blocked'
        empty_marker = '#VP_HOTLINK_ALLOW_EMPTY\n    ' if allow_empty else ''
        block = (
            '\n    #VP_HOTLINK'
            '\n    #VP_HOTLINK_SUFFIXES:' + suffixes +
            '\n    #VP_HOTLINK_DOMAIN:' + access_domain +
            '\n    ' + empty_marker +
            'location ~* \\.(' + ext_list + ')$ {'
            '\n        valid_referers ' + empty_part + ' *.' + access_domain + ' ' + access_domain + ';'
            '\n        if ($invalid_referer) {'
            '\n            return ' + response_code + ';'
            '\n        }'
            '\n    }'
            '\n    #VP_HOTLINK_END'
        )
        content = re.sub(r'(}\s*)$', block + '\n' + r'\1', content, count=1)
    with open(fp,'w') as f: f.write(content)
    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower(): return jsonify({'ok':False,'error':test}), 400
    reload_nginx()
    return jsonify({'ok':True,'enabled':enable})


# --- LIMIT ACCESS ---------------------------------------------------------------
@websites_bp.route('/api/websites/<domain>/limit-access')
def get_limit_access(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    rules = []; deny_ips = []
    if os.path.exists(fp):
        with open(fp) as f: content = f.read()
        for m in re.finditer(r'#VP_LIMIT:([^|]+)\|([^\n]+)', content):
            rules.append({'name':m.group(1).strip(),'path':m.group(2).strip()})
        for m in re.finditer(r'#VP_DENY_IP:([^\n]+)', content):
            deny_ips.append(m.group(1).strip())
    return jsonify({'ok':True,'rules':rules,'deny_ips':deny_ips})


@websites_bp.route('/api/websites/<domain>/limit-access', methods=['POST'])
def manage_limit_access(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    action = d.get('action','add_rule')
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site not found'}), 404
    with open(fp) as f: content = f.read()
    if action == 'add_rule':
        name     = d.get('name','').strip()
        path     = d.get('path','/').strip()
        password = d.get('password','changeme').strip()
        if not name or not path: return jsonify({'ok':False,'error':'Name and path required'}), 400
        htdir  = '/etc/nginx/htpasswd'
        os.makedirs(htdir, exist_ok=True)
        htfile = htdir + '/' + domain + '_' + name
        sh('htpasswd -cb ' + htfile + ' "' + name + '" "' + password + '" 2>/dev/null || echo "' + name + ':$(openssl passwd -apr1 ' + password + ')" > ' + htfile)
        block = (
            '\n    #VP_LIMIT:' + name + '|' + path +
            '\n    location ' + path + ' {'
            '\n        auth_basic "Restricted";'
            '\n        auth_basic_user_file ' + htfile + ';'
            '\n        try_files $uri $uri/ /index.php?$query_string;'
            '\n    }'
        )
        content = re.sub(r'(}\s*)$', block + '\n' + r'\1', content, count=1)
    elif action == 'deny_ip':
        ip = d.get('ip','').strip()
        if not ip: return jsonify({'ok':False,'error':'IP required'}), 400
        deny_line = '\n    #VP_DENY_IP:' + ip + '\n    deny ' + ip + ';'
        content = re.sub(r'(server\s*\{[^\n]*\n)', r'\1' + deny_line + '\n', content, count=1)
    elif action == 'remove_rule':
        name = d.get('name','').strip()
        path = d.get('path','').strip()
        content = re.sub(r'\s*#VP_LIMIT:' + re.escape(name) + r'\|' + re.escape(path) + r'\n\s*location[^{]+\{[^}]+\}\n?', '\n', content)
    elif action == 'remove_deny_ip':
        ip = d.get('ip','').strip()
        content = re.sub(r'\s*#VP_DENY_IP:' + re.escape(ip) + r'\n\s*deny ' + re.escape(ip) + r';', '', content)
    with open(fp,'w') as f: f.write(content)
    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower(): return jsonify({'ok':False,'error':test}), 400
    reload_nginx()
    return jsonify({'ok':True})


@websites_bp.route('/api/websites/<domain>/limit-access/<name>', methods=['DELETE'])
def delete_limit_access(domain, name):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    conf_path = os.path.join(avail, f'{domain}.conf')
    htpasswd = f'/etc/nginx/.htpasswd_{domain}_{name}'
    try:
        if os.path.exists(htpasswd): os.unlink(htpasswd)
        if os.path.exists(conf_path):
            with open(conf_path) as f: content = f.read()
            content = re.sub(rf'#LIMIT-{re.escape(name)}-START.*?#LIMIT-{re.escape(name)}-END\s*', '', content, flags=re.DOTALL)
            with open(conf_path,'w') as f: f.write(content)
        reload_nginx()
        return jsonify({'ok':True})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)})


# --- MAINTENANCE MODE -----------------------------------------------------------
MAINTENANCE_HTML = '''<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Under Maintenance</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d0f14;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}}
.box{{text-align:center;padding:48px 40px;background:#1f2230;border:1px solid #1e2235;border-radius:16px;max-width:480px;width:90%}}
.logo{{width:64px;height:64px;background:linear-gradient(135deg,#5865f2,#06b6d4);border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:28px;margin:0 auto 20px}}
h1{{font-size:24px;font-weight:700;margin-bottom:12px}}
p{{color:#94a3b8;font-size:15px;line-height:1.6}}
.badge{{display:inline-block;background:rgba(245,158,11,.12);color:#f59e0b;border:1px solid rgba(245,158,11,.2);padding:6px 18px;border-radius:20px;font-size:13px;font-weight:600;margin-top:20px}}
</style></head>
<body><div class="box">
<div class="logo">⚡</div>
<h1>Under Maintenance</h1>
<p>{message}</p>
<div class="badge">🔧 We\'ll be back shortly</div>
</div></body></html>'''


@websites_bp.route('/api/websites/<domain>/maintenance', methods=['POST'])
def set_maintenance(domain):
    if not req(): return jsonify({'ok':False}), 401
    d       = request.get_json() or {}
    enable  = d.get('enable', True)
    message = d.get('message', 'We are currently performing scheduled maintenance. Please check back soon.')

    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site not found'}), 404

    # Write maintenance HTML file
    webroot_m = re.search(r'root\s+([^;]+);', open(fp).read())
    webroot = webroot_m.group(1).strip() if webroot_m else f'/www/wwwroot/{domain}'
    maint_file = f'{webroot}/maintenance.html'

    if enable:
        with open(maint_file,'w') as f:
            f.write(MAINTENANCE_HTML.format(message=message))
        with open(fp) as f: content = f.read()
        if '#VP_MAINTENANCE' not in content:
            maint_block = f'''
    #VP_MAINTENANCE
    set $maintenance 1;
    if ($remote_addr = "127.0.0.1") {{ set $maintenance 0; }}
    if ($maintenance = 1) {{
        return 503;
    }}
    error_page 503 /maintenance.html;
    location = /maintenance.html {{
        root {webroot};
        internal;
    }}
'''
            content = re.sub(r'(server\s*\{[^\n]*\n)', r'\1' + maint_block, content, count=1)
            with open(fp,'w') as f: f.write(content)
    else:
        with open(fp) as f: content = f.read()
        content = re.sub(r'\s*#VP_MAINTENANCE.*?(?=\n\s*location|\n\s*})', '', content, flags=re.DOTALL)
        with open(fp,'w') as f: f.write(content)
        try: os.unlink(maint_file)
        except: pass

    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower(): return jsonify({'ok':False,'error':test}), 400
    reload_nginx()
    return jsonify({'ok':True,'enabled':enable})


@websites_bp.route('/api/websites/<domain>/maintenance')
def get_maintenance(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':True,'enabled':False})
    with open(fp) as f: content = f.read()
    return jsonify({'ok':True,'enabled':'#VP_MAINTENANCE' in content})

