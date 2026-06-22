import os, re
from flask import jsonify, request

try:
    from panel.routes.websites_core import websites_bp, req, sh, get_nginx_dirs, reload_nginx
except ImportError:
    from websites_core import websites_bp, req, sh, get_nginx_dirs, reload_nginx


# --- REVERSE PROXY --------------------------------------------------------------
@websites_bp.route('/api/websites/<domain>/proxy', methods=['GET'])
def get_proxies(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    proxies = []
    if os.path.exists(fp):
        with open(fp) as f: content = f.read()
        for m in re.finditer(r'#VP_PROXY:([^\n]+)\n.*?location\s+(\S+)\s*\{[^}]*proxy_pass\s+([^;]+);', content, re.DOTALL):
            proxies.append({'name':m.group(1).strip(),'path':m.group(2),'target':m.group(3).strip()})
    return jsonify({'ok':True,'proxies':proxies})


@websites_bp.route('/api/websites/<domain>/proxy', methods=['POST'])
def add_proxy(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    name   = d.get('name', f'proxy_{domain[:6]}')
    path   = d.get('path', '/')
    target = d.get('target','').strip()
    sent_domain = d.get('sent_domain','$host')
    if not target: return jsonify({'ok':False,'error':'Target URL required'}), 400

    proxy_block = f"""
#VP_PROXY:{name}
location {path} {{
    proxy_pass {target};
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host {sent_domain};
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_cache_bypass $http_upgrade;
}}
"""
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site config not found'}), 404
    with open(fp) as f: content = f.read()
    # Insert before closing brace of first server block
    content = re.sub(r'(}\s*)$', proxy_block + r'\1', content, count=1)
    with open(fp,'w') as f: f.write(content)
    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower():
        return jsonify({'ok':False,'error':f'Nginx config error: {test}'}), 400
    reload_nginx()
    return jsonify({'ok':True})


@websites_bp.route('/api/websites/<domain>/proxy/<name>', methods=['DELETE'])
def del_proxy(domain, name):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Not found'}), 404
    with open(fp) as f: content = f.read()
    # Remove the proxy block
    content = re.sub(rf'\n#VP_PROXY:{re.escape(name)}\nlocation[^{{]+\{{[^}}]+\}}\n', '\n', content)
    with open(fp,'w') as f: f.write(content)
    reload_nginx()
    return jsonify({'ok':True})


# --- REDIRECT -------------------------------------------------------------------
@websites_bp.route('/api/websites/<domain>/redirect', methods=['POST'])
def set_redirect(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    target  = d.get('target','').strip()
    mode    = d.get('mode','301')
    keep_uri= d.get('keep_uri', True)
    if not target: return jsonify({'ok':False,'error':'Target URL required'}), 400

    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site not found'}), 404

    uri_part = '$request_uri' if keep_uri else ''
    redir_line = f'return {mode} {target}{uri_part};'

    with open(fp) as f: content = f.read()
    # Replace existing redirect or add to server block
    if re.search(r'#VP_REDIRECT', content):
        content = re.sub(r'#VP_REDIRECT\n\s*return [^\n]+;', f'#VP_REDIRECT\n    {redir_line}', content)
    else:
        content = re.sub(r'(server\s*\{[^\n]*\n)', rf'\1    #VP_REDIRECT\n    {redir_line}\n', content, count=1)
    with open(fp,'w') as f: f.write(content)
    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower():
        return jsonify({'ok':False,'error':test}), 400
    reload_nginx()
    return jsonify({'ok':True})


@websites_bp.route('/api/websites/<domain>/redirect', methods=['DELETE'])
def del_redirect(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Not found'}), 404
    with open(fp) as f: content = f.read()
    content = re.sub(r'\s*#VP_REDIRECT\n\s*return [^\n]+;\n', '\n', content)
    with open(fp,'w') as f: f.write(content)
    reload_nginx(); return jsonify({'ok':True})


# --- URL REWRITE ----------------------------------------------------------------
@websites_bp.route('/api/websites/<domain>/rewrite')
def get_rewrite(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':True,'content':''})
    with open(fp) as f: content = f.read()
    m = re.search(r'#VP_REWRITE_START(.*?)#VP_REWRITE_END', content, re.DOTALL)
    if m: return jsonify({'ok':True,'content':m.group(1).strip()})
    m2 = re.search(r'location\s*/\s*\{([^}]+)\}', content)
    default = m2.group(0) if m2 else 'location / {\n    try_files $uri $uri/ /index.php?$query_string;\n}'
    return jsonify({'ok':True,'content':default})


@websites_bp.route('/api/websites/<domain>/rewrite', methods=['POST'])
def save_rewrite(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    rewrite_content  = d.get('content','').strip()
    save_as_template = d.get('save_as_template', False)
    template_name    = d.get('template_name', '')
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site not found'}), 404
    if save_as_template and template_name:
        tdir = '/opt/vortexpanel/rewrite_templates'
        os.makedirs(tdir, exist_ok=True)
        with open(tdir + '/' + template_name + '.conf', 'w') as f2: f2.write(rewrite_content)
    with open(fp) as f: content = f.read()
    new_block = '#VP_REWRITE_START\n    ' + rewrite_content + '\n    #VP_REWRITE_END'
    if '#VP_REWRITE_START' in content:
        content = re.sub(r'#VP_REWRITE_START.*?#VP_REWRITE_END', new_block, content, flags=re.DOTALL)
    else:
        content = re.sub(r'location\s*/\s*\{[^}]+\}', new_block, content, count=1)
    with open(fp,'w') as f: f.write(content)
    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower(): return jsonify({'ok':False,'error':test}), 400
    reload_nginx()
    return jsonify({'ok':True})


@websites_bp.route('/api/websites/<domain>/rewrite/templates')
def get_rewrite_templates(domain):
    if not req(): return jsonify({'ok':False}), 401
    templates = [
        {'id':'current','label':'0.Current'},
        {'id':'wordpress','label':'WordPress'},
        {'id':'laravel','label':'Laravel'},
        {'id':'codeigniter','label':'CodeIgniter'},
        {'id':'thinkphp','label':'ThinkPHP'},
    ]
    tdir = '/opt/vortexpanel/rewrite_templates'
    if os.path.isdir(tdir):
        for fname in os.listdir(tdir):
            if fname.endswith('.conf'):
                templates.append({'id':fname[:-5],'label':fname[:-5]})
    return jsonify({'ok':True,'templates':templates})

