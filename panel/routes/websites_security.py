import os, re, subprocess
from flask import jsonify, request

import ipaddress, html, shutil

try:
    from panel.routes.websites_core import (websites_bp, req, sh, get_nginx_dirs, reload_nginx,
        nginx_edit_site, nginx_insert_in_servers, is_valid_domain, _get_site_path)
except ImportError:
    from websites_core import (websites_bp, req, sh, get_nginx_dirs, reload_nginx,
        nginx_edit_site, nginx_insert_in_servers, is_valid_domain, _get_site_path)

_LOC_RE  = re.compile(r'^/[^\s{};#\'"\\]*$')
_NAME_RE = re.compile(r'^[A-Za-z0-9_.-]{1,64}$')


def _htpasswd_line(user, password):
    """user:hash for nginx auth_basic. htpasswd (apache2-utils / httpd-tools)
    is often not installed on an nginx-only server; openssl's apr1 works there."""
    if shutil.which('htpasswd'):
        r = subprocess.run(['htpasswd', '-nbm', user, password], capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and ':' in r.stdout:
            return r.stdout.strip().splitlines()[0], ''
    r = subprocess.run(['openssl', 'passwd', '-apr1', '-stdin'], input=password + '\n',
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0 or not r.stdout.strip():
        return None, (r.stderr or 'could not hash the password').strip()
    return f'{user}:{r.stdout.strip()}', ''


# --- HOTLINK PROTECTION ---------------------------------------------------------
@websites_bp.route('/api/websites/<domain>/hotlink')
def get_hotlink(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':True,'enabled':False})
    with open(fp) as f: content = f.read()
    enabled = '#VP_HOTLINK' in content
    suffixes='jpg,jpeg,gif,png,js,css'; access_domain=domain; allow_empty=True; response='404'
    if enabled:
        m = re.search(r'#VP_HOTLINK_SUFFIXES:([^\n]+)', content)
        if m: suffixes=m.group(1).strip()
        m = re.search(r'#VP_HOTLINK_DOMAIN:([^\n]+)', content)
        if m: access_domain=m.group(1).strip()
        allow_empty='#VP_HOTLINK_ALLOW_EMPTY' in content
        m = re.search(r'#VP_HOTLINK.*?if \(\$invalid_referer\) \{\s*return (\d+);', content, re.S)
        if m: response = m.group(1)
    return jsonify({'ok':True,'enabled':enabled,'suffixes':suffixes,'access_domain':access_domain,'allow_empty':allow_empty,'response':response})


@websites_bp.route('/api/websites/<domain>/hotlink', methods=['POST'])
def set_hotlink(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    enable        = d.get('enable', True)
    suffixes      = d.get('suffixes', 'jpg,jpeg,gif,png,js,css').strip()
    access_domain = d.get('access_domain', domain).strip()
    allow_empty   = d.get('allow_empty', True)   # the UI has no toggle; keep the old behaviour (empty Referer allowed)
    response_code = d.get('response', '404')
    exts = [e.strip().lower() for e in str(suffixes).split(',') if e.strip()]
    if not exts or any(not re.fullmatch(r'[a-z0-9]{1,10}', e) for e in exts):
        return jsonify({'ok':False,'error':'Suffixes must be a comma-separated list of file extensions'}), 400
    doms = [x.strip().lower() for x in re.split(r'[\s,]+', str(access_domain)) if x.strip()] or [domain]
    if any(not is_valid_domain(x) for x in doms):
        return jsonify({'ok':False,'error':'Allowed domains must be valid domain names'}), 400
    response_code = str(response_code).strip()
    if not re.fullmatch(r'[1-5]\d\d', response_code):
        return jsonify({'ok':False,'error':'Response must be an HTTP status code'}), 400
    suffixes = ','.join(exts)

    def fn(content):
        content = re.sub(r'\n?[ \t]*#VP_HOTLINK\n.*?#VP_HOTLINK_END[^\n]*', '', content, flags=re.DOTALL)
        if not enable:
            return content
        empty_part   = 'none blocked' if allow_empty else 'blocked'   # 'none' = requests without a Referer
        empty_marker = '    #VP_HOTLINK_ALLOW_EMPTY\n' if allow_empty else ''
        refs = ' '.join(f'*.{x} {x}' for x in doms)
        block = (
            '    #VP_HOTLINK\n'
            '    #VP_HOTLINK_SUFFIXES:' + suffixes + '\n'
            '    #VP_HOTLINK_DOMAIN:' + ','.join(doms) + '\n' +
            empty_marker +
            '    location ~* \\.(' + '|'.join(exts) + ')$ {\n'
            '        valid_referers ' + empty_part + ' ' + refs + ';\n'
            '        if ($invalid_referer) {\n'
            '            return ' + response_code + ';\n'
            '        }\n'
            '    }\n'
            '    #VP_HOTLINK_END\n'
        )
        return nginx_insert_in_servers(content, block, at='end')
    ok, err, code = nginx_edit_site(domain, fn)
    if not ok:
        return jsonify({'ok':False,'error':err}), code
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
        for m in re.finditer(r'#VP_LIMIT:([^|\n]+)\|([^\n]+)', content):
            r = {'name':m.group(1).strip(),'path':m.group(2).strip()}
            if r not in rules: rules.append(r)          # HTTP + HTTPS copies
        for m in re.finditer(r'#VP_DENY_IP:([^\n]+)', content):
            if m.group(1).strip() not in deny_ips: deny_ips.append(m.group(1).strip())
    return jsonify({'ok':True,'rules':rules,'deny_ips':deny_ips})


@websites_bp.route('/api/websites/<domain>/limit-access', methods=['POST'])
def manage_limit_access(domain):
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    action = d.get('action','add_rule')
    if not os.path.exists(os.path.join('/etc/nginx/vortex', f'{domain}.conf')):
        return jsonify({'ok':False,'error':'Site not found'}), 404
    htfile = None
    if action == 'add_rule':
        name     = str(d.get('name','')).strip()
        path     = str(d.get('path','/')).strip()
        # the form sends user/pass; the old code read only 'password' and used
        # the rule name as the login, so every protected path ended up with
        # the password "changeme"
        user     = str(d.get('user') or name).strip()
        password = str(d.get('pass') or d.get('password') or '')
        if not name or not path: return jsonify({'ok':False,'error':'Name and path required'}), 400
        if not _NAME_RE.match(name):
            return jsonify({'ok':False,'error':'Name may contain letters, digits, ".", "_" and "-" only'}), 400
        if not _LOC_RE.match(path):
            return jsonify({'ok':False,'error':'Path must start with / and contain no spaces, quotes, ";" or braces'}), 400
        if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', user):
            return jsonify({'ok':False,'error':'User name may contain letters, digits and . _ @ - only'}), 400
        if len(password) < 6 or '\n' in password:
            return jsonify({'ok':False,'error':'Enter a password of at least 6 characters'}), 400
        line, herr = _htpasswd_line(user, password)
        if not line:
            return jsonify({'ok':False, 'error': f'Failed to create password file: {herr}'}), 500
        htdir  = '/etc/nginx/htpasswd'
        os.makedirs(htdir, exist_ok=True)
        htfile = htdir + '/' + domain + '_' + name
        fd = os.open(htfile + '.new', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
        with os.fdopen(fd, 'w') as f:
            f.write(line + '\n')
        try:
            import grp
            os.chown(htfile + '.new', 0, grp.getgrnam(_nginx_group()).gr_gid)
        except Exception:
            os.chmod(htfile + '.new', 0o644)
        os.replace(htfile + '.new', htfile)
        def fn(content):
            if f'#VP_LIMIT:{name}|' in content:
                return (None, f'A rule named {name} already exists')
            # ^~ wins over the site's `location ~ \.php$`, so PHP files in the
            # folder are protected too; the site's PHP handler is nested inside
            # so they still run (without it they would be downloaded as source)
            php = re.search(r'location\s+~\s+\\?\.php\$?\s*\{([^{}]*)\}', content)
            nested = ''
            if php:
                inner = '\n'.join('            ' + l.strip() for l in php.group(1).strip().splitlines() if l.strip())
                nested = '        location ~ \\.php$ {\n' + inner + '\n        }\n'
            block = (
                '    #VP_LIMIT:' + name + '|' + path + '\n'
                '    location ^~ ' + path + ' {\n'
                '        auth_basic "Restricted";\n'
                # bot protection on: the folder keeps its own password prompt
                + ('        auth_request off; error_page 401 = @vp_anubis_basic401; #VP_ANUBIS\n'
                   if '#VP_ANUBIS' in content else '') +
                '        auth_basic_user_file ' + htfile + ';\n'
                + nested +
                '        try_files $uri $uri/ /index.php?$query_string;\n'
                '    }\n'
            )
            return nginx_insert_in_servers(content, block, at='end')
    elif action == 'deny_ip':
        ip = str(d.get('ip','')).strip()
        if not ip: return jsonify({'ok':False,'error':'IP required'}), 400
        try:
            ip = str(ipaddress.ip_network(ip, strict=False)) if '/' in ip else str(ipaddress.ip_address(ip))
        except ValueError:
            return jsonify({'ok':False,'error':'Enter a valid IP address or CIDR range'}), 400
        def fn(content):
            if f'#VP_DENY_IP:{ip}\n' in content:
                return content
            # every server block: the deny used to be added to the first
            # (port 80) block only, so the IP could still reach the site over HTTPS
            return nginx_insert_in_servers(content, f'    #VP_DENY_IP:{ip}\n    deny {ip};\n', at='start')
    elif action == 'remove_rule':
        name = str(d.get('name','')).strip()
        path = str(d.get('path','')).strip()
        def fn(content):
            return re.sub(r'\n[ \t]*#VP_LIMIT:' + re.escape(name) + r'\|' + re.escape(path) + r'[ \t]*\n[ \t]*location[^{]+\{(?:[^{}]|\{[^{}]*\})*\}[ \t]*(?=\n)', '', content)
    elif action == 'remove_deny_ip':
        ip = str(d.get('ip','')).strip()
        def fn(content):
            return re.sub(r'\n[ \t]*#VP_DENY_IP:' + re.escape(ip) + r'[ \t]*\n[ \t]*deny ' + re.escape(ip) + r';[^\n]*', '', content)
    else:
        return jsonify({'ok':False,'error':'Unknown action'}), 400
    ok, err, code = nginx_edit_site(domain, fn)
    if not ok:
        return jsonify({'ok':False,'error':err}), code
    return jsonify({'ok':True})


def _nginx_group():
    import pwd
    for u in ('www-data', 'nginx'):
        try:
            pwd.getpwnam(u)
            return u
        except KeyError:
            continue
    return 'root'


@websites_bp.route('/api/websites/<domain>/limit-access/<name>', methods=['DELETE'])
def delete_limit_access(domain, name):
    """Matches the #VP_LIMIT:name|path marker and htpasswd path that
    add_rule() actually writes."""
    if not req(): return jsonify({'ok':False}), 401
    if not _NAME_RE.match(name or ''):
        return jsonify({'ok':False,'error':'Invalid rule name'}), 400
    path = (request.args.get('path') or '').strip()
    htfile = f'/etc/nginx/htpasswd/{domain}_{name}'
    pat = re.escape(path) if path else r'[^\n]+'
    ok, err, code = nginx_edit_site(domain, lambda c: re.sub(
        r'\n[ \t]*#VP_LIMIT:' + re.escape(name) + r'\|' + pat + r'[ \t]*\n[ \t]*location[^{]+\{(?:[^{}]|\{[^{}]*\})*\}[ \t]*(?=\n)', '', c))
    if not ok:
        return jsonify({'ok':False,'error':err}), code
    # only after nginx no longer references it
    try:
        if os.path.exists(htfile): os.unlink(htfile)
    except OSError:
        pass
    return jsonify({'ok':True})


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
<div class="logo"><svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></div>
<h1>Under Maintenance</h1>
<p>{message}</p>
<div class="badge">We\'ll be back shortly</div>
</div></body></html>'''


@websites_bp.route('/api/websites/<domain>/maintenance', methods=['POST'])
def set_maintenance(domain):
    if not req(): return jsonify({'ok':False}), 401
    d       = request.get_json() or {}
    enable  = d.get('enable', True)
    message = d.get('message', 'We are currently performing scheduled maintenance. Please check back soon.')

    fp = os.path.join('/etc/nginx/vortex', f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site not found'}), 404

    # The page lives outside the site (written as root: inside a docroot a
    # planted symlink could point the write anywhere)
    os.makedirs(MAINT_DIR, mode=0o755, exist_ok=True)
    maint_file = os.path.join(MAINT_DIR, f'{domain}.html')

    if enable:
        try:
            with open(maint_file,'w') as f:
                f.write(MAINTENANCE_HTML.format(message=html.escape(str(message))))
        except OSError as e:
            return jsonify({'ok':False,'error':f'Could not write {maint_file}: {e}'}), 500
        maint_block = f"""    #VP_MAINTENANCE
    set $maintenance 1;
    if ($remote_addr = "127.0.0.1") {{ set $maintenance 0; }}
    # error_page restarts at the server rewrite phase, so without this the
    # page itself got a 503 and visitors saw nginx's default error page.
    if ($uri = "/maintenance.html") {{ set $maintenance 0; }}
    if ($maintenance = 1) {{
        return 503;
    }}
    error_page 503 /maintenance.html;
    location = /maintenance.html {{
        alias {maint_file};
        add_header Retry-After 600 always;
        internal;
    }}
    #VP_MAINTENANCE_END
"""
        def fn(content):
            if '#VP_MAINTENANCE' in content:
                return content
            # Explicit start/end markers so the removal below can excise the
            # WHOLE block; added to every server block so HTTPS visitors get
            # the maintenance page too (it used to cover port 80 only)
            return nginx_insert_in_servers(content, maint_block, at='start')
    else:
        def fn(content):
            # Prefer the marker-delimited block; fall back to matching the exact
            # legacy block shape (start marker through the maintenance location's
            # closing brace) for configs written before markers existed.
            if '#VP_MAINTENANCE_END' in content:
                return re.sub(r'\n?[ \t]*#VP_MAINTENANCE\b.*?#VP_MAINTENANCE_END[^\n]*', '', content, flags=re.DOTALL)
            return re.sub(r'\n?[ \t]*#VP_MAINTENANCE\b.*?location\s*=\s*/maintenance\.html\s*\{.*?\}', '', content, flags=re.DOTALL)

    ok, err, code = nginx_edit_site(domain, fn)
    if not ok:
        return jsonify({'ok':False,'error':err}), code
    if not enable:
        try: os.unlink(maint_file)
        except OSError: pass
    return jsonify({'ok':True,'enabled':enable})


@websites_bp.route('/api/websites/<domain>/maintenance')
def get_maintenance(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':True,'enabled':False})
    with open(fp) as f: content = f.read()
    return jsonify({'ok':True,'enabled':'#VP_MAINTENANCE' in content})



# --- Maintenance mode for every site ------------------------------------------
# One switch for all nginx sites. Each server block gets an inert block once
# (#VP_MAINT_ALL); turning the mode on or off only rewrites the http-level
# map in MAINT_HTTP_CONF and reloads, so it is instant and cannot break a
# vhost. Addresses in the allow list (and the server itself) see the sites.
MAINT_DIR = '/etc/nginx/vortex-maint'
MAINT_HTTP_CONF = '/etc/nginx/conf.d/vortex-maintenance.conf'
MAINT_STATE = '/opt/vortexpanel/data/maintenance_all.json'
MAINT_ALL_BLOCK = """    #VP_MAINT_ALL
    set $vp_maint $vp_maint_all;
    if ($uri = "/vp-maintenance-all.html") {
        set $vp_maint 0;
    }
    if ($vp_maint = 1) {
        return 503;
    }
    error_page 503 /vp-maintenance-all.html;
    location = /vp-maintenance-all.html {
        internal;
        if ($vp_maint_all = 0) {
            return 503;
        }
        alias /etc/nginx/vortex-maint/all.html;
        default_type text/html;
        add_header Retry-After 600 always;
    }
    #VP_MAINT_ALL_END
"""


def _maint_state():
    try:
        import json
        return json.load(open(MAINT_STATE))
    except Exception:
        return {'enabled': False, 'message': '', 'allow': []}


def _maint_http_conf(enabled, allow):
    lines = ['# Managed by VortexPanel (Websites > Maintenance mode). Do not edit.',
             'geo $vp_maint_bypass {', '    default 0;', '    127.0.0.1 1;', '    ::1 1;']
    lines += [f'    {a} 1;' for a in allow]
    # certificate renewals (ACME http-01) keep working during maintenance
    lines += ['}', 'map "$vp_maint_bypass:$uri" $vp_maint_all {', f'    default {1 if enabled else 0};',
              '    "~^1:" 0;', '    "~^0:/\\.well-known/acme-challenge/" 0;', '}', '']
    return '\n'.join(lines)


def _nginx_conf_includes_confd():
    for p in ('/etc/nginx/nginx.conf', '/usr/local/nginx/conf/nginx.conf'):
        try:
            if re.search(r'include\s+/etc/nginx/conf\.d/\*\.conf', open(p).read()):
                return True
        except OSError:
            continue
    return False


def maintenance_all_block():
    """For new vhosts: the inert block, when the feature is set up."""
    return MAINT_ALL_BLOCK if os.path.exists(MAINT_HTTP_CONF) else ''


def maint_wrap(conf):
    """Add the block to every server of a generated nginx config (app and
    container proxies) when maintenance-for-all-sites is set up."""
    if not os.path.exists(MAINT_HTTP_CONF) or '#VP_MAINT_ALL' in conf:
        return conf
    return re.sub(r'(\n[ \t]*server_name[^;]*;[^\n]*\n)', lambda m: m.group(1) + MAINT_ALL_BLOCK, conf)


def _maint_targets():
    avail, _ = get_nginx_dirs()
    out = []
    for d, pat in ((avail, r'.+\.conf$'), ('/etc/nginx/conf.d', r'vortex-(node|go|py|docker)-.+\.conf$')):
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            fp = os.path.join(d, fn)
            if re.fullmatch(pat, fn) and os.path.isfile(fp):
                out.append(fp)
    return out


@websites_bp.route('/api/websites/maintenance-all')
def get_maintenance_all():
    if not req(): return jsonify({'ok':False}), 401
    st = _maint_state()
    total = covered = 0
    for fp in _maint_targets():
        total += 1
        try:
            covered += '#VP_MAINT_ALL' in open(fp).read()
        except OSError:
            pass
    from panel.routes.websites_core import list_sites
    others = [x['domain'] for x in list_sites() if x.get('webserver') not in (None, 'nginx')]
    ip = request.headers.get('X-Real-IP') or request.remote_addr or ''
    return jsonify({'ok':True, 'enabled':bool(st.get('enabled')), 'message':st.get('message',''),
                    'allow':st.get('allow',[]), 'nginx_sites':total, 'covered':covered,
                    'not_covered':others, 'your_ip':ip, 'since':st.get('since')})


@websites_bp.route('/api/websites/maintenance-all', methods=['POST'])
def set_maintenance_all():
    if not req(): return jsonify({'ok':False}), 401
    import json, time as _t
    from panel.routes.websites_core import nginx_test, nginx_insert_in_servers
    d = request.get_json() or {}
    enabled = bool(d.get('enabled'))
    message = str(d.get('message') or 'We are performing scheduled maintenance. Please check back soon.')[:600]
    allow = []
    for a in d.get('allow') or []:
        a = str(a).strip()
        if not a:
            continue
        try:
            allow.append(str(ipaddress.ip_network(a, strict=False)) if '/' in a else str(ipaddress.ip_address(a)))
        except ValueError:
            return jsonify({'ok':False,'error':f'Not an IP address or range: {a}'}), 400
    if not os.path.isdir('/etc/nginx'):
        return jsonify({'ok':False,'error':'Maintenance mode for all sites needs Nginx'}), 400
    os.makedirs(MAINT_DIR, mode=0o755, exist_ok=True)
    with open(os.path.join(MAINT_DIR, 'all.html'), 'w') as f:
        f.write(MAINTENANCE_HTML.format(message=html.escape(message)))
    os.chmod(os.path.join(MAINT_DIR, 'all.html'), 0o644)
    # http-level switch
    os.makedirs(os.path.dirname(MAINT_HTTP_CONF), exist_ok=True)
    old_http = open(MAINT_HTTP_CONF).read() if os.path.exists(MAINT_HTTP_CONF) else None
    if not _nginx_conf_includes_confd():
        return jsonify({'ok':False,'error':'nginx.conf does not include /etc/nginx/conf.d/*.conf'}), 400
    with open(MAINT_HTTP_CONF, 'w') as f:
        f.write(_maint_http_conf(enabled, allow))
    # the inert block in every server of every nginx site (once)
    changed = {}
    for fp in _maint_targets():
        content = open(fp).read()
        if '#VP_MAINT_ALL' in content and 'set $vp_maint $vp_maint_all' not in content:   # older block
            content_new = re.sub(r'[ \t]*#VP_MAINT_ALL\n.*?#VP_MAINT_ALL_END\n', MAINT_ALL_BLOCK, content, flags=re.S)
            changed[fp] = content
            with open(fp, 'w') as f:
                f.write(content_new)
            continue
        if '#VP_MAINT_ALL' in content or 'server' not in content:
            continue
        new = (maint_wrap(content) if fp.startswith('/etc/nginx/conf.d/')
               else nginx_insert_in_servers(content, MAINT_ALL_BLOCK, at='start'))
        if new and new != content:
            changed[fp] = content
            with open(fp, 'w') as f:
                f.write(new)
    ok, out = nginx_test()
    if not ok:
        for fp, content in changed.items():
            with open(fp, 'w') as f:
                f.write(content)
        if old_http is None:
            os.unlink(MAINT_HTTP_CONF)
        else:
            with open(MAINT_HTTP_CONF, 'w') as f:
                f.write(old_http)
        return jsonify({'ok':False,'error':'nginx rejected the change, nothing was changed: ' + out.strip()[-500:]}), 500
    reload_nginx()
    prev = _maint_state()
    st = {'enabled': enabled, 'message': message, 'allow': allow,
          'since': (prev.get('since') if prev.get('enabled') else _t.time()) if enabled else None}
    os.makedirs(os.path.dirname(MAINT_STATE), mode=0o700, exist_ok=True)
    with open(MAINT_STATE, 'w') as f:
        json.dump(st, f)
    return jsonify({'ok':True, 'enabled':enabled, 'sites_updated':len(changed)})
