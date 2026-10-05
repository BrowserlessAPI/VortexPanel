import os, re
from flask import jsonify, request

try:
    from panel.routes.websites_core import (websites_bp, req, sh, get_nginx_dirs, reload_nginx,
        nginx_edit_site, nginx_insert_in_servers, selinux_allow_proxy)
except ImportError:
    from websites_core import (websites_bp, req, sh, get_nginx_dirs, reload_nginx,
        nginx_edit_site, nginx_insert_in_servers, selinux_allow_proxy)

# Request values end up verbatim inside the nginx vhost: anything that could
# close a block or start a new directive (`;`, `{`, `}`, quotes, newlines)
# would let one form field inject arbitrary nginx configuration.
_NAME_RE   = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')
_LOC_RE    = re.compile(r'^/[^\s{};#\'"\\]*$')
_URL_RE    = re.compile(r'^https?://[^\s{};#\'"\\]+$')
_HOSTHDR_RE = re.compile(r'^(\$host|\$http_host|\$proxy_host|[A-Za-z0-9.-]+(:\d{1,5})?)$')


# --- REVERSE PROXY --------------------------------------------------------------
@websites_bp.route('/api/websites/<domain>/proxy', methods=['GET'])
def get_proxies(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    proxies = []
    if os.path.exists(fp):
        with open(fp) as f: content = f.read()
        seen = set()
        for m in re.finditer(r'#VP_PROXY:([^\n]+)\n.*?location\s+(\S+)\s*\{[^}]*proxy_pass\s+([^;]+);', content, re.DOTALL):
            if m.group(1).strip() in seen:
                continue   # same rule in the HTTP and the HTTPS server block
            seen.add(m.group(1).strip())
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
    name, path, sent_domain = str(name).strip(), str(path).strip(), str(sent_domain).strip()
    if not _NAME_RE.match(name):
        return jsonify({'ok':False,'error':'Name may contain letters, digits, ".", "_" and "-" only'}), 400
    if not _LOC_RE.match(path):
        return jsonify({'ok':False,'error':'Path must start with / and contain no spaces, quotes, ";" or braces'}), 400
    if not _URL_RE.match(target):
        return jsonify({'ok':False,'error':'Target must be an http:// or https:// URL'}), 400
    if not _HOSTHDR_RE.match(sent_domain):
        return jsonify({'ok':False,'error':'Invalid "send domain" (use $host or a host name)'}), 400

    proxy_block = f"""    #VP_PROXY:{name}
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
    def fn(content):
        if f'#VP_PROXY:{name}\n' in content:
            return (None, f'A proxy named {name} already exists')
        # every server block (HTTP and HTTPS), validated with nginx -t
        return nginx_insert_in_servers(content, proxy_block, at='end')
    ok, err, code = nginx_edit_site(domain, fn)
    if not ok:
        return jsonify({'ok':False,'error':f'Nginx config error: {err}'}), code
    selinux_allow_proxy()
    return jsonify({'ok':True})


@websites_bp.route('/api/websites/<domain>/proxy/<name>', methods=['DELETE'])
def del_proxy(domain, name):
    if not req(): return jsonify({'ok':False}), 401
    ok, err, code = nginx_edit_site(domain, lambda c: re.sub(
        r'\n[ \t]*#VP_PROXY:' + re.escape(name) + r'[ \t]*\n[ \t]*location[^{]+\{[^}]+\}[ \t]*(?=\n)', '', c))
    if not ok:
        return jsonify({'ok':False,'error':err}), code
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

    mode = str(mode).strip()
    if mode not in ('301', '302', '307', '308'):
        return jsonify({'ok':False,'error':'Redirect type must be 301, 302, 307 or 308'}), 400
    if not _URL_RE.match(target):
        return jsonify({'ok':False,'error':'Target must be an http:// or https:// URL'}), 400
    if keep_uri in (False, 'false', '0', 0):
        keep_uri = False
    uri_part = '$request_uri' if keep_uri else ''
    if keep_uri:
        target = target.rstrip('/')
    redir_line = f'return {mode} {target}{uri_part};'

    def fn(content):
        # Replace an existing redirect, else add one to every server block
        # (previously only the first, so HTTPS requests were not redirected)
        if '#VP_REDIRECT' in content:
            return re.sub(r'#VP_REDIRECT\n[ \t]*return [^\n]+;', f'#VP_REDIRECT\n    {redir_line}', content)
        return nginx_insert_in_servers(content, f'    #VP_REDIRECT\n    {redir_line}\n', at='start')
    ok, err, code = nginx_edit_site(domain, fn)
    if not ok:
        return jsonify({'ok':False,'error':err}), code
    return jsonify({'ok':True})


@websites_bp.route('/api/websites/<domain>/redirect', methods=['DELETE'])
def del_redirect(domain):
    if not req(): return jsonify({'ok':False}), 401
    ok, err, code = nginx_edit_site(domain, lambda c: re.sub(r'\n[ \t]*#VP_REDIRECT\n[ \t]*return [^\n]+;[ \t]*(?=\n)', '', c))
    if not ok:
        return jsonify({'ok':False,'error':err}), code
    return jsonify({'ok':True})


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


_REWRITE_TEMPLATES = {
    'wordpress': 'location / {\n    try_files $uri $uri/ /index.php?$args;\n}\nrewrite /wp-admin$ $scheme://$host$uri/ permanent;',
    'laravel': 'location / {\n    try_files $uri $uri/ /index.php?$query_string;\n}',
    'codeigniter': 'location / {\n    try_files $uri $uri/ /index.php?/$request_uri;\n}',
    'thinkphp': 'location / {\n    if (!-e $request_filename) {\n        rewrite ^(.*)$ /index.php?s=$1 last;\n        break;\n    }\n}',
}
_TPL_DIR = '/opt/vortexpanel/rewrite_templates'


@websites_bp.route('/api/websites/<domain>/rewrite', methods=['POST'])
def save_rewrite(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    # The template picker posts {template: id} and expects the template text
    # back. It used to be treated as a save with empty content, which
    # replaced the site's `location /` with nothing (permalinks broke).
    if 'template' in d and 'content' not in d:
        tid = str(d.get('template') or '')
        if tid == 'current':
            return get_rewrite(domain)
        if tid in _REWRITE_TEMPLATES:
            return jsonify({'ok':True,'content':_REWRITE_TEMPLATES[tid]})
        if re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', tid) and os.path.isfile(os.path.join(_TPL_DIR, tid + '.conf')):
            with open(os.path.join(_TPL_DIR, tid + '.conf')) as f:
                return jsonify({'ok':True,'content':f.read()})
        return jsonify({'ok':False,'error':'Unknown template'}), 404
    rewrite_content  = str(d.get('content','')).strip()
    save_as_template = d.get('save_as_template', False)
    template_name    = str(d.get('template_name', '')).strip()
    if save_as_template and template_name:
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', template_name) or template_name.startswith('.'):
            return jsonify({'ok':False,'error':'Template name may contain letters, digits, ".", "_" and "-" only'}), 400
        os.makedirs(_TPL_DIR, exist_ok=True)
        with open(os.path.join(_TPL_DIR, template_name + '.conf'), 'w') as f2: f2.write(rewrite_content)
    body = '\n'.join('    ' + l if l.strip() else '' for l in rewrite_content.splitlines())
    new_block = '#VP_REWRITE_START\n' + body + '\n    #VP_REWRITE_END'

    def fn(content):
        if '#VP_REWRITE_START' in content:
            return re.sub(r'#VP_REWRITE_START.*?#VP_REWRITE_END', lambda m: new_block, content, flags=re.DOTALL)
        # replace `location / {...}` in every server block (HTTP and HTTPS)
        new, n = re.subn(r'location\s+/\s*\{[^{}]*\}', lambda m: new_block, content)
        if n:
            return new
        return nginx_insert_in_servers(content, '    ' + new_block + '\n', at='end')
    ok, err, code = nginx_edit_site(domain, fn)
    if not ok:
        return jsonify({'ok':False,'error':err}), code
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

