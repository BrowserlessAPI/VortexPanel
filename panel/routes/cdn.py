from flask import Blueprint, jsonify, request, session
import urllib.request, urllib.error, urllib.parse, json, os, re, subprocess

cdn_bp = Blueprint('cdn', __name__)
def req(): return 'user' in session

CONFIG_FILE = '/opt/vortexpanel/cdn_config.json'

_SECRET_KEYS = ('api_key', 'api_token', 'auth_secret')
_CF_ID_RE = re.compile(r'^[0-9a-f]{32}$')
_CF_SETTING_RE = re.compile(r'^[a-z0-9_]{1,64}$')
# The settings GET returns friendly names; map them back to Cloudflare's ids
# (PATCHing settings/always_https or settings/dev_mode was a 404).
_CF_SETTING_ALIASES = {'always_https': 'always_use_https', 'dev_mode': 'development_mode'}
_DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9-]{2,63}$')

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            if os.stat(CONFIG_FILE).st_mode & 0o077: os.chmod(CONFIG_FILE, 0o600)
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
                if isinstance(cfg, dict): return cfg
        except Exception: pass
    return {}

def save_config(cfg):
    """API keys live here: 0600 and atomic (was created world-readable)."""
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    tmp = CONFIG_FILE + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(cfg, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_FILE)

def _cf_err(data, fallback='Cloudflare API error'):
    errs = (data or {}).get('errors') if isinstance(data, dict) else None
    if isinstance(errs, list) and errs:
        return '; '.join((f"{e.get('code','')} {e.get('message','')}".strip() if isinstance(e, dict) else str(e)) for e in errs)
    if isinstance(data, dict) and data.get('error'):
        return str(data['error'])
    return fallback

def http_request(url, method='GET', headers=None, data=None, timeout=15):
    """Generic HTTP request helper"""
    try:
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header('Content-Type', 'application/json')
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode('utf-8', 'replace')
            # 204 / empty bodies (BunnyCDN purge) used to raise in json.loads
            # and be reported as a failure with status 0.
            try: body = json.loads(raw) if raw.strip() else {}
            except ValueError: body = {'raw': raw[:500]}
            return body, resp.status
    except urllib.error.HTTPError as e:
        try: body = json.loads(e.read().decode())
        except Exception: body = {'error': str(e)}
        if not isinstance(body, (dict, list)): body = {'error': str(e)}
        return body, e.code
    except Exception as e:
        return {'error': str(e)}, 0

# --- CDN Config -----------------------------------------------------------------
@cdn_bp.route('/api/cdn/config')
def get_config():
    if not req(): return jsonify({'ok':False}), 401
    cfg = load_config()
    # Mask secrets. cfg also holds 'active_cdn' (a string): `{**v}` on it
    # raised TypeError, so this endpoint 500ed after the first save.
    safe = {}
    for k, v in cfg.items():
        if not isinstance(v, dict): continue
        safe[k] = dict(v, **{s: ('***' if v.get(s) else '') for s in _SECRET_KEYS})
    return jsonify({'ok':True, 'config':safe, 'active': cfg.get('active_cdn','')})

@cdn_bp.route('/api/cdn/config', methods=['PUT'])
def save_cdn_config():
    if not req(): return jsonify({'ok':False}), 401
    d   = request.get_json() or {}
    provider = d.get('provider','')
    if not provider: return jsonify({'ok':False,'error':'Provider required'}), 400
    if provider not in [p['id'] for p in CDN_PROVIDERS]:
        return jsonify({'ok':False,'error':'Unknown provider'}), 400
    cfg = load_config()
    # Don't overwrite masked values
    existing = cfg.get(provider, {})
    new_entry = {**existing}
    # Non-secret fields
    for key in ['provider','pull_zone_id','pull_zone_name','zone_id','account_id','region','email']:
        if key in d and d[key] != '***':
            new_entry[key] = d[key]
    # Secret fields - only update if not masked
    for key in ['api_key','api_token','auth_secret']:
        if key in d and d[key] and d[key] != '***':
            new_entry[key] = d[key]

    cfg[provider]       = new_entry
    cfg['active_cdn']   = provider
    save_config(cfg)
    return jsonify({'ok':True})

@cdn_bp.route('/api/cdn/config', methods=['DELETE'])
def disconnect_cdn():
    if not req(): return jsonify({'ok':False}), 401
    provider = (request.get_json() or {}).get('provider','')
    cfg = load_config()
    if provider in cfg: del cfg[provider]
    if cfg.get('active_cdn') == provider:
        del cfg['active_cdn']
    save_config(cfg)
    return jsonify({'ok':True})

# --- CLOUDFLARE -----------------------------------------------------------------
def cf_headers(cfg):
    if cfg.get('api_token'):
        return {'Authorization': f'Bearer {cfg["api_token"]}'}
    return {'X-Auth-Email': cfg.get('email',''), 'X-Auth-Key': cfg.get('api_key','')}

@cdn_bp.route('/api/cdn/cloudflare/test', methods=['POST'])
def cf_test():
    if not req(): return jsonify({'ok':False}), 401
    d = request.get_json() or {}
    cfg = load_config().get('cloudflare', {})
    # Use provided or stored credentials
    token   = d.get('api_token') or cfg.get('api_token')
    api_key = d.get('api_key')   or cfg.get('api_key')
    email   = d.get('email')     or cfg.get('email')
    headers = {'Authorization':f'Bearer {token}'} if token else {'X-Auth-Email':email,'X-Auth-Key':api_key}
    if not token and not (api_key and email):
        return jsonify({'ok':False,'error':'Enter an API token, or the account email plus Global API Key'})
    data, status = http_request('https://api.cloudflare.com/client/v4/user/tokens/verify' if token
                                else 'https://api.cloudflare.com/client/v4/user', 'GET', headers)
    ok = status == 200 and isinstance(data, dict) and data.get('success', False)
    return jsonify({'ok':ok, 'detail':data.get('result',{}) if isinstance(data, dict) else {},
                    'error': None if ok else _cf_err(data, f'HTTP {status}')})

@cdn_bp.route('/api/cdn/cloudflare/zones')
def cf_zones():
    if not req(): return jsonify({'ok':False}), 401
    cfg = load_config().get('cloudflare', {})
    zones = []
    for page in range(1, 21):
        data, status = http_request(f'https://api.cloudflare.com/client/v4/zones?per_page=50&page={page}', 'GET', cf_headers(cfg))
        if not isinstance(data, dict) or not data.get('success'):
            return jsonify({'ok':False, 'error':_cf_err(data)}), 400
        zones += [{'id':z['id'],'name':z['name'],'status':z['status'],'plan':(z.get('plan') or {}).get('name','')}
                  for z in data.get('result') or []]
        info = data.get('result_info') or {}
        if page >= (info.get('total_pages') or 1): break
    return jsonify({'ok':True, 'zones':zones})

@cdn_bp.route('/api/cdn/cloudflare/zone/<zone_id>/settings')
def cf_zone_settings(zone_id):
    if not req(): return jsonify({'ok':False}), 401
    if not _CF_ID_RE.match(zone_id): return jsonify({'ok':False,'error':'Invalid zone id'}), 400
    cfg = load_config().get('cloudflare', {})
    data, _ = http_request(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/settings', 'GET', cf_headers(cfg))
    if not isinstance(data, dict) or not data.get('success'):
        return jsonify({'ok':False, 'error':'Failed to fetch settings: ' + _cf_err(data)}), 400
    # Extract key settings
    settings = {s['id']: s['value'] for s in data.get('result',[])}
    return jsonify({'ok':True, 'settings':{
        'ssl':          settings.get('ssl','off'),
        'always_https': settings.get('always_use_https','off'),
        'minify':       settings.get('minify',{}),
        'cache_level':  settings.get('cache_level','basic'),
        'rocket_loader':settings.get('rocket_loader','off'),
        'brotli':       settings.get('brotli','off'),
        'http2':        settings.get('http2','off'),
        'http3':        settings.get('http3','off'),
        'dev_mode':     settings.get('development_mode','off'),
        'hotlink_protection': settings.get('hotlink_protection','off'),
    }})

@cdn_bp.route('/api/cdn/cloudflare/zone/<zone_id>/settings', methods=['PATCH', 'PUT'])
def cf_update_settings(zone_id):
    if not req(): return jsonify({'ok':False}), 401
    if not _CF_ID_RE.match(zone_id): return jsonify({'ok':False,'error':'Invalid zone id'}), 400
    cfg = load_config().get('cloudflare', {})
    settings = (request.get_json() or {}).get('settings', {})
    if not isinstance(settings, dict) or not settings:
        return jsonify({'ok':False,'error':'No settings given'}), 400
    results, errors = {}, []
    for key, val in settings.items():
        cf_key = _CF_SETTING_ALIASES.get(key, key)
        if not _CF_SETTING_RE.match(cf_key):
            results[key] = {'ok': False, 'status': 0}; errors.append(f'{key}: invalid setting name'); continue
        data, status = http_request(
            f'https://api.cloudflare.com/client/v4/zones/{zone_id}/settings/{cf_key}',
            'PATCH', cf_headers(cfg), {'value': val}
        )
        ok = isinstance(data, dict) and data.get('success', False)
        results[key] = {'ok': ok, 'status':status}
        if not ok: errors.append(f'{key}: {_cf_err(data, "HTTP " + str(status))}')
    # Was always ok:true, so the UI showed "updated" for rejected changes.
    return jsonify({'ok':not errors, 'results':results, 'error':'; '.join(errors) or None})

@cdn_bp.route('/api/cdn/cloudflare/zone/<zone_id>/purge', methods=['POST'])
def cf_purge(zone_id):
    if not req(): return jsonify({'ok':False}), 401
    if not _CF_ID_RE.match(zone_id): return jsonify({'ok':False,'error':'Invalid zone id'}), 400
    cfg  = load_config().get('cloudflare', {})
    d    = request.get_json() or {}
    urls = [u for u in (d.get('urls') or []) if isinstance(u, str) and u.strip()]
    body = {'purge_everything': True} if not urls else {'files': urls}
    data, status = http_request(
        f'https://api.cloudflare.com/client/v4/zones/{zone_id}/purge_cache',
        'POST', cf_headers(cfg), body
    )
    ok = isinstance(data, dict) and data.get('success', False)
    return jsonify({'ok': ok, 'errors': (data.get('errors',[]) if isinstance(data, dict) else []),
                    'error': None if ok else _cf_err(data, f'HTTP {status}')})

@cdn_bp.route('/api/cdn/cloudflare/zone/<zone_id>/dns')
def cf_dns(zone_id):
    if not req(): return jsonify({'ok':False}), 401
    if not _CF_ID_RE.match(zone_id): return jsonify({'ok':False,'error':'Invalid zone id'}), 400
    cfg  = load_config().get('cloudflare', {})
    data, _ = http_request(f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?per_page=100', 'GET', cf_headers(cfg))
    if not isinstance(data, dict) or not data.get('success'):
        return jsonify({'ok':False,'error':_cf_err(data, 'Failed to load DNS records')}), 400
    records = [{'id':r['id'],'type':r['type'],'name':r['name'],'content':r['content'],'proxied':r.get('proxied',False)}
               for r in data.get('result',[])]
    return jsonify({'ok':True,'records':records})

@cdn_bp.route('/api/cdn/cloudflare/zone/<zone_id>/analytics')
def cf_analytics(zone_id):
    if not req(): return jsonify({'ok':False}), 401
    if not _CF_ID_RE.match(zone_id): return jsonify({'ok':False,'error':'Invalid zone id'}), 400
    cfg = load_config().get('cloudflare', {})
    data, _ = http_request(
        f'https://api.cloudflare.com/client/v4/zones/{zone_id}/analytics/dashboard?since=-1440',
        'GET', cf_headers(cfg)
    )
    if not isinstance(data, dict) or not data.get('success'):
        return jsonify({'ok':False,'error':'Analytics unavailable (requires Pro plan or above)'}), 400
    result = data.get('result', {})
    totals = result.get('totals', {})
    return jsonify({'ok':True,'totals':{
        'requests':    totals.get('requests',{}).get('all',0),
        'bandwidth':   totals.get('bandwidth',{}).get('all',0),
        'cached':      totals.get('requests',{}).get('cached',0),
        'threats':     totals.get('threats',{}).get('all',0),
        'unique_ips':  totals.get('uniques',{}).get('all',0),
    }})

# --- BUNNYCDN -------------------------------------------------------------------
def bunny_headers(cfg):
    return {'AccessKey': cfg.get('api_key','')}

@cdn_bp.route('/api/cdn/bunnycdn/test', methods=['POST'])
def bunny_test():
    if not req(): return jsonify({'ok':False}), 401
    d   = request.get_json() or {}
    cfg = load_config().get('bunnycdn', {})
    key = d.get('api_key') or cfg.get('api_key','')
    if not key: return jsonify({'ok':False,'error':'API key required'})
    data, status = http_request('https://api.bunny.net/pullzone?page=1&perPage=1', 'GET', {'AccessKey':key})
    # With page/perPage the API returns {"Items": [...], "TotalItems": n},
    # not a bare list, so a valid key was always reported as "Auth failed".
    ok = status == 200 and isinstance(data, (list, dict))
    total = len(data) if isinstance(data, list) else (data.get('TotalItems', len(data.get('Items') or [])) if isinstance(data, dict) else 0)
    return jsonify({'ok':ok, 'detail':f'Found {total} pull zones' if ok else 'Auth failed', 'status':status,
                    'error': None if ok else f'Auth failed (HTTP {status})'})

@cdn_bp.route('/api/cdn/bunnycdn/zones')
def bunny_zones():
    if not req(): return jsonify({'ok':False}), 401
    cfg  = load_config().get('bunnycdn', {})
    data, status = http_request('https://api.bunny.net/pullzone?page=1&perPage=100', 'GET', bunny_headers(cfg))
    if status != 200 or not isinstance(data, (list, dict)): return jsonify({'ok':False,'error':f'API error {status}'}), 400
    zones = [{'id':z['Id'],'name':z['Name'],'hostname':z.get('CnameDomain',''),
              'origin':z.get('OriginUrl',''),'monthly_bw':z.get('MonthlyBandwidthLimit',0)}
             for z in (data if isinstance(data,list) else data.get('Items',[]))]
    return jsonify({'ok':True,'zones':zones})

@cdn_bp.route('/api/cdn/bunnycdn/purge/<int:zone_id>', methods=['POST'])
def bunny_purge(zone_id):
    if not req(): return jsonify({'ok':False}), 401
    cfg  = load_config().get('bunnycdn', {})
    d    = request.get_json() or {}
    url  = d.get('url','')
    if url:
        endpoint = f'https://api.bunny.net/purge?url={urllib.parse.quote(url)}'
        data, status = http_request(endpoint, 'POST', bunny_headers(cfg))
    else:
        data, status = http_request(f'https://api.bunny.net/pullzone/{zone_id}/purgeCache', 'POST', bunny_headers(cfg))
    ok = status in (200,204)
    return jsonify({'ok': ok, 'status':status, 'error': None if ok else f'Purge failed (HTTP {status})'})

@cdn_bp.route('/api/cdn/bunnycdn/stats/<int:zone_id>')
def bunny_stats(zone_id):
    if not req(): return jsonify({'ok':False}), 401
    cfg  = load_config().get('bunnycdn', {})
    data, status = http_request(f'https://api.bunny.net/statistics?pullZoneId={zone_id}', 'GET', bunny_headers(cfg))
    if status != 200 or not isinstance(data, dict): return jsonify({'ok':False,'error':f'Stats API error {status}'}), 400
    return jsonify({'ok':True,
        'bandwidth_used':    data.get('TotalBandwidthUsed',0),
        'requests_served':   data.get('TotalRequestsServed',0),
        'cache_hit_rate':    data.get('CacheHitRate',0),
        'pull_requests':     data.get('TotalPullRequests',0),
    })

# --- GENERIC CDNs (Nginx config-based integration) ------------------------------
# For KeyCDN, StackPath, Akamai, CloudFront, Google CDN, Sucuri
# These work by configuring the origin server to add cache headers
# and setting up the CDN pull zone manually, then managing via Nginx headers

@cdn_bp.route('/api/cdn/generic/test', methods=['POST'])
def generic_test():
    if not req(): return jsonify({'ok':False}), 401
    d        = request.get_json() or {}
    provider = d.get('provider','')
    test_url = d.get('test_url','')
    if not test_url: return jsonify({'ok':False,'error':'Test URL required'}), 400
    if urllib.parse.urlparse(test_url).scheme not in ('http', 'https'):
        return jsonify({'ok':False,'error':'Test URL must start with http:// or https://'}), 400
    try:
        req2 = urllib.request.Request(test_url)
        req2.add_header('User-Agent', 'VortexPanel/3.0 CDN-Test')
        with urllib.request.urlopen(req2, timeout=10) as resp:
            headers = dict(resp.headers)
            cf_ray   = headers.get('Cf-Ray','')
            x_cache  = headers.get('X-Cache','')
            x_cdn    = headers.get('X-Cdn','')
            cdn_hdr  = headers.get('X-Amz-Cf-Pop','') or headers.get('X-Served-By','') or headers.get('Server','')
            return jsonify({'ok':True,'status':resp.status,
                           'headers':{'cf_ray':cf_ray,'x_cache':x_cache,'x_cdn':x_cdn,'server':cdn_hdr},
                           'cdn_detected': bool(cf_ray or x_cache or x_cdn)})
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)})

@cdn_bp.route('/api/cdn/nginx-headers', methods=['POST'])
def apply_nginx_headers():
    """Apply cache-control headers to Nginx config for CDN optimization"""
    if not req(): return jsonify({'ok':False}), 401
    d        = request.get_json() or {}
    domain   = d.get('domain','')
    provider = d.get('provider','generic')
    if not domain: return jsonify({'ok':False,'error':'Domain required'}), 400

    # CDN-specific cache rules
    cache_rules = {
        'cloudflare':   'Cache-Control "public, max-age=14400, s-maxage=86400"',
        'bunnycdn':     'Cache-Control "public, max-age=2592000"',
        'keycdn':       'Cache-Control "public, max-age=31536000, immutable"',
        'akamai':       'Cache-Control "public, s-maxage=86400, max-age=3600"',
        'cloudfront':   'Cache-Control "public, max-age=86400, s-maxage=604800"',
        'stackpath':    'Cache-Control "public, max-age=2592000"',
        'google_cdn':   'Cache-Control "public, max-age=86400, s-maxage=604800"',
        'sucuri':       'Cache-Control "public, max-age=43200"',
        'generic':      'Cache-Control "public, max-age=86400"',
    }
    cache_header = cache_rules.get(provider, cache_rules['generic'])

    if not _DOMAIN_RE.match(domain):
        return jsonify({'ok':False,'error':'Invalid domain'}), 400

    nginx_snippet = f"""
    # VortexPanel CDN BEGIN ({provider})
    location ~* \\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|webp|avif)$ {{
        add_header {cache_header};
        add_header Vary "Accept-Encoding";
        expires 30d;
        access_log off;
    }}
    # CDN cache for HTML
    location ~* \\.html$ {{
        add_header Cache-Control "public, max-age=3600, s-maxage=86400";
    }}
    # VortexPanel CDN END
"""
    # Find nginx config. Panel-created sites live in /etc/nginx/vortex, which
    # was not searched at all ("Nginx config not found" for every panel site).
    conf_path = None
    for d_path in ['/etc/nginx/vortex', '/etc/nginx/sites-available', '/etc/nginx/conf.d']:
        p = os.path.join(d_path, f'{domain}.conf')
        if os.path.exists(p): conf_path = p; break

    if not conf_path:
        return jsonify({'ok':False,'error':f'Nginx config not found for {domain}'}), 404

    with open(conf_path) as f: original = f.read()

    # Remove a previous block: current BEGIN/END markers, and the legacy
    # unmarked format (whose removal regex stopped after the first location,
    # leaving the HTML location behind on every re-apply).
    content = re.sub(r'\n[ \t]*# VortexPanel CDN BEGIN.*?# VortexPanel CDN END[ \t]*\n', '\n', original, flags=re.DOTALL)
    content = re.sub(r'\n[ \t]*# VortexPanel CDN:.*?# CDN cache for HTML\s*location ~\* \\\.html\$ \{.*?\}[ \t]*\n',
                     '\n', content, flags=re.DOTALL)

    # Insert into every server block that serves files (has a root), right
    # before its closing brace - not just before the last '}' of the file,
    # which may belong to an HTTP->HTTPS redirect server.
    def server_blocks(text):
        out = []
        for m in re.finditer(r'(^|\n)\s*server\s*\{', text):
            depth, k = 0, text.index('{', m.start())
            while k < len(text):
                if text[k] == '{': depth += 1
                elif text[k] == '}':
                    depth -= 1
                    if depth == 0: break
                k += 1
            out.append((m.start(), k))
        return out
    targets = [(a, b) for a, b in server_blocks(content) if re.search(r'^\s*root\s', content[a:b], re.M)]
    if not targets:
        return jsonify({'ok':False,'error':'No server block with a root directive found in ' + conf_path}), 400
    for a, b in sorted(targets, reverse=True):
        content = content[:b] + nginx_snippet.lstrip('\n') + content[b:]
    with open(conf_path,'w') as f: f.write(content)

    # Test and reload; restore the original file if nginx rejects it so the
    # next reload/restart does not fail on a broken vhost.
    try:
        result = subprocess.run(['nginx', '-t'], capture_output=True, text=True, timeout=30)
        rc, out = result.returncode, (result.stderr or result.stdout)
    except (OSError, subprocess.TimeoutExpired) as e:
        rc, out = 1, str(e)
    if rc != 0:
        with open(conf_path,'w') as f: f.write(original)
        return jsonify({'ok':False,'error':f'Nginx error (change reverted): {out.strip()[-500:]}'}), 400
    subprocess.run('systemctl reload nginx 2>/dev/null || nginx -s reload', shell=True, timeout=60)
    return jsonify({'ok':True,'snippet':nginx_snippet})

CDN_PROVIDERS = [
    {
        'id': 'cloudflare',
        'name': 'Cloudflare',
        'icon': 'square',
        'color': '#F6821F',
        'desc': 'World largest CDN with DDoS protection, WAF, DNS and free SSL',
        'free_plan': True,
        'features': ['Auto HTTPS', 'DDoS Protection', 'WAF', 'DNS Management', 'Cache Purge', 'Analytics', 'Page Rules'],
        'api_type': 'token',
        'docs': 'https://developers.cloudflare.com/api/',
        'setup_url': 'https://dash.cloudflare.com',
        'fields': [
            {'key':'api_token','label':'API Token (recommended)','type':'password','placeholder':'Your Cloudflare API Token','required':True},
            {'key':'email','label':'Account Email','type':'email','placeholder':'user@example.com','required':False},
            {'key':'api_key','label':'Global API Key (legacy)','type':'password','placeholder':'Only if not using API Token','required':False},
            {'key':'zone_id','label':'Zone ID (optional, auto-detected)','type':'text','placeholder':'Auto-detected from zones list','required':False},
        ],
        'integration': 'full_api',
    },
    {
        'id': 'bunnycdn',
        'name': 'BunnyCDN (bunny.net)',
        'icon': 'package',
        'color': '#FF7F00',
        'desc': 'Affordable, high-performance global CDN with 114+ PoPs',
        'free_plan': False,
        'features': ['Pull Zones', 'Storage Zones', 'Cache Purge', 'Bandwidth Stats', 'Cache Hit Rate', 'Multi-CDN'],
        'api_type': 'key',
        'docs': 'https://docs.bunny.net/docs/cdn-api',
        'setup_url': 'https://dash.bunny.net',
        'fields': [
            {'key':'api_key','label':'Account API Key','type':'password','placeholder':'From dash.bunny.net → Account Settings','required':True},
            {'key':'pull_zone_id','label':'Pull Zone ID','type':'text','placeholder':'Numeric ID from your Pull Zone settings','required':False},
            {'key':'pull_zone_name','label':'Pull Zone Hostname','type':'text','placeholder':'yourzone.b-cdn.net','required':False},
        ],
        'integration': 'full_api',
    },
    {
        'id': 'keycdn',
        'name': 'KeyCDN',
        'icon': 'key',
        'color': '#29ABE2',
        'desc': 'High-performance CDN focused on speed and low cost',
        'free_plan': False,
        'features': ['Pull Zones', 'Push Zones', 'Cache Purge', 'Real-time Stats', 'HTTP/2', 'HTTPS'],
        'api_type': 'key',
        'docs': 'https://www.keycdn.com/api',
        'setup_url': 'https://app.keycdn.com',
        'fields': [
            {'key':'api_key','label':'API Key','type':'password','placeholder':'From KeyCDN Dashboard → Account','required':True},
            {'key':'zone_id','label':'Zone ID','type':'text','placeholder':'Your KeyCDN Zone ID','required':False},
        ],
        'integration': 'nginx_headers',
    },
    {
        'id': 'akamai',
        'name': 'Akamai',
        'icon': 'wind',
        'color': '#009BDE',
        'desc': 'Enterprise-grade CDN and security platform (Linode/Akamai Cloud)',
        'free_plan': False,
        'features': ['Global CDN', 'DDoS Protection', 'WAF', 'Image Optimization', 'Edge Computing'],
        'api_type': 'edgegrid',
        'docs': 'https://techdocs.akamai.com/cdn/',
        'setup_url': 'https://control.akamai.com',
        'fields': [
            {'key':'api_key','label':'Access Token','type':'password','placeholder':'EdgeGrid Access Token','required':True},
            {'key':'auth_secret','label':'Client Secret','type':'password','placeholder':'EdgeGrid Client Secret','required':True},
            {'key':'account_id','label':'Client Token','type':'text','placeholder':'EdgeGrid Client Token','required':True},
        ],
        'integration': 'nginx_headers',
    },
    {
        'id': 'cloudfront',
        'name': 'Amazon CloudFront',
        'icon': 'cloud',
        'color': '#FF9900',
        'desc': 'AWS global CDN integrated with S3, EC2 and Lambda@Edge',
        'free_plan': True,
        'features': ['Global Edge Locations', 'Lambda@Edge', 'S3 Integration', 'HTTPS', 'Cache Behaviors'],
        'api_type': 'aws',
        'docs': 'https://docs.aws.amazon.com/cloudfront/',
        'setup_url': 'https://console.aws.amazon.com/cloudfront',
        'fields': [
            {'key':'api_key','label':'AWS Access Key ID','type':'text','placeholder':'AKIA...','required':True},
            {'key':'auth_secret','label':'AWS Secret Access Key','type':'password','placeholder':'Your AWS Secret Key','required':True},
            {'key':'zone_id','label':'CloudFront Distribution ID','type':'text','placeholder':'E1ABCDEF...','required':False},
            {'key':'region','label':'Region','type':'text','placeholder':'us-east-1','required':False},
        ],
        'integration': 'nginx_headers',
    },
    {
        'id': 'stackpath',
        'name': 'StackPath',
        'icon': 'package',
        'color': '#00A8E0',
        'desc': 'Edge computing and CDN platform with WAF',
        'free_plan': False,
        'features': ['CDN', 'WAF', 'DDoS Protection', 'Serverless Scripting', 'Edge Computing'],
        'api_type': 'oauth',
        'docs': 'https://stackpath.dev/docs',
        'setup_url': 'https://control.stackpath.com',
        'fields': [
            {'key':'account_id','label':'Stack ID','type':'text','placeholder':'Your StackPath Stack ID','required':True},
            {'key':'api_key','label':'Client ID','type':'text','placeholder':'OAuth Client ID','required':True},
            {'key':'auth_secret','label':'Client Secret','type':'password','placeholder':'OAuth Client Secret','required':True},
        ],
        'integration': 'nginx_headers',
    },
    {
        'id': 'google_cdn',
        'name': 'Google Cloud CDN',
        'icon': 'dot',
        'color': '#4285F4',
        'desc': 'Google global CDN integrated with GCP load balancing',
        'free_plan': False,
        'features': ['Global Anycast', 'HTTP/2', 'HTTPS', 'Cache Invalidation', 'Cloud Armor WAF'],
        'api_type': 'service_account',
        'docs': 'https://cloud.google.com/cdn/docs',
        'setup_url': 'https://console.cloud.google.com',
        'fields': [
            {'key':'account_id','label':'GCP Project ID','type':'text','placeholder':'your-gcp-project','required':True},
            {'key':'api_key','label':'Service Account Key (JSON)','type':'password','placeholder':'Paste JSON service account key','required':True},
        ],
        'integration': 'nginx_headers',
    },
    {
        'id': 'sucuri',
        'name': 'Sucuri',
        'icon': 'shield',
        'color': '#1B7FC4',
        'desc': 'CDN + Website security, malware scanning and WAF',
        'free_plan': False,
        'features': ['DDoS Protection', 'WAF', 'Malware Scanning', 'CDN', 'SSL', 'Hack Repair'],
        'api_type': 'key',
        'docs': 'https://docs.sucuri.net/sucuri-api/',
        'setup_url': 'https://sucuri.net',
        'fields': [
            {'key':'api_key','label':'API Key','type':'password','placeholder':'From Sucuri Dashboard → API','required':True},
            {'key':'auth_secret','label':'API Secret','type':'password','placeholder':'Your Sucuri API Secret','required':True},
        ],
        'integration': 'nginx_headers',
    },
]

@cdn_bp.route('/api/cdn/providers')
def list_providers():
    if not req(): return jsonify({'ok':False}), 401
    cfg = load_config()
    result = []
    for p in CDN_PROVIDERS:
        connected = p['id'] in cfg and bool(cfg[p['id']].get('api_key') or cfg[p['id']].get('api_token'))
        result.append({**{k:v for k,v in p.items() if k!='fields'},
                       'connected': connected,
                       'active': cfg.get('active_cdn') == p['id'],
                       'fields': p['fields']})
    return jsonify({'ok':True, 'providers':result, 'active':cfg.get('active_cdn','')})

@cdn_bp.route('/api/cdn/keycdn/purge', methods=['POST'])
def keycdn_purge():
    if not req(): return jsonify({'ok':False}), 401
    cfg  = load_config().get('keycdn', {})
    d    = request.get_json() or {}
    zone = d.get('zone_id') or cfg.get('zone_id','')
    url  = d.get('url','')
    if not zone: return jsonify({'ok':False,'error':'Zone ID required'}), 400
    if not str(zone).isdigit(): return jsonify({'ok':False,'error':'Invalid zone ID'}), 400
    endpoint = f'https://api.keycdn.com/zones/purge/{zone}.json'
    if url: endpoint = f'https://api.keycdn.com/zones/purgeurl/{zone}.json'
    import base64
    auth = base64.b64encode(f"{cfg.get('api_key','')}:".encode()).decode()
    # KeyCDN: purge zone = GET /zones/purge/{id}.json, purge URLs =
    # DELETE /zones/purgeurl/{id}.json (the methods were swapped).
    data, status = http_request(endpoint, 'DELETE' if url else 'GET',
                                {'Authorization':f'Basic {auth}'},
                                {'urls':[url]} if url else None)
    return jsonify({'ok': status in (200,204), 'data':data})
