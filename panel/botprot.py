"""Bot protection (Anubis) for websites served by nginx.

Design (see the design review): nginx asks a website's own Anubis service
about each request with `auth_request`; Anubis never sits in the data path.

  visitor -> nginx -> [open path / verified crawler / private address?] -> website
                   -> otherwise: the site's Anubis decides: allow, check page, 403

* One Anubis service per protected website (`vortexpanel-anubis@<domain>`),
  listening on a Unix socket in a folder only nginx's group can enter, with
  its own rules file and signing key. Websites never share anything.
* Search-engine crawlers from their published address ranges, the paths
  search engines and ad networks read (robots.txt, sitemaps, feeds, ads.txt,
  /.well-known/ ...) and requests from the server itself are let through by
  nginx before Anubis is asked.
* Fail-open: if Anubis does not answer, nginx serves the website. A watchdog
  removes the protection from a website whose service stays down and alerts.

Command line (used by the App Store and the timers):
    python -m panel.botprot install|uninstall|watch|daily|refresh-lists
"""
import os, re, json, time, hashlib, secrets, shutil, subprocess, ipaddress, fcntl, socket, http.client, platform

VER = '1.28.1'
SHA = {'amd64': 'adcb3c2fdfd0fb91cbf7e8376dbcc479f654c85dd3795db3e9a06004786bbdc9',
       'arm64': '2eed4f6e40de35554aad6a66dfd017cdc76769c7141af3b0627824c910703060'}
URL = 'https://github.com/TecharoHQ/anubis/releases/download/v{v}/anubis-{v}-linux-{a}.tar.gz'
BASE = '/usr/local/lib/vortexpanel-anubis'
BIN = BASE + '/bin/anubis'
ETC = '/etc/vortexpanel/anubis'
STATE = '/opt/vortexpanel/data/botprot.json'
LOG = '/opt/vortexpanel/data/botprot_log.jsonl'
STATS_DIR = '/opt/vortexpanel/data/botprot_stats'
RUN = '/run/vortexpanel-anubis'
NGX_HTTP = '/etc/nginx/conf.d/vortex-anubis.conf'
NGX_DIR = '/etc/nginx/vortex-anubis'
NGX_MAPS = NGX_DIR + '/maps'
CRAWLER_GEO = NGX_DIR + '/crawler-ips.conf'
REALIP_CONF = '/etc/nginx/conf.d/vortex-cloudflare-realip.conf'
LISTS = ETC + '/crawler-lists.json'
SNAPSHOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'anubis_crawlers.json')
UNIT = '/etc/systemd/system/vortexpanel-anubis@.service'
TIMERS = {
    'vortexpanel-anubis-watch': ('*-*-* *:*:00', 'watch', 'VortexPanel bot protection watchdog'),
    'vortexpanel-anubis-daily': ('*-*-* 03:17:00', 'daily', 'VortexPanel bot protection: crawler lists and search engine test'),
}
USER = 'vp-anubis'
MARK = '#VP_ANUBIS'
LEVELS = ('standard', 'strict', 'attack')
LEVEL_WEIGHT = {'standard': 5, 'strict': 15, 'attack': 25}
LEVEL_NAMES = {'standard': 'Standard', 'strict': 'Strict', 'attack': 'Under attack'}
DOWN_MINUTES = 3

SITE_DEFAULTS = {
    'enabled': False, 'level': 'standard', 'block_ai_training': True, 'block_ai_search': False,
    'social': True, 'seo_tools': False, 'engines': [], 'check_media': False, 'open_paths': [],
    'pass_days': 7, 'tie_ip': True, 'attribution': True, 'email': '', 'language': '',
    'locked': False, 'paused_until': 0, 'auto_off': False, 'custom_rules': False, 'suspended': False,
}
SETTINGS_DEFAULTS = {
    'customers_allowed': True, 'memory_mb': 64,
    'defaults': {k: SITE_DEFAULTS[k] for k in ('level', 'block_ai_training', 'block_ai_search', 'social',
                                               'attribution', 'pass_days')},
    'alert_watchdog': True, 'alert_selftest': True,
}
OPTIONAL_ENGINES = {'baidu': ('Baidu', r'Baiduspider'), 'naver': ('Naver', r'Yeti/'),
                    'seznam': ('Seznam', r'SeznamBot'), 'petal': ('Petal', r'PetalBot')}
SOCIAL_UA = (r'facebookexternalhit|Facebot|WhatsApp|Twitterbot|LinkedInBot|Slackbot|Slack-ImgProxy|Discordbot|'
             r'TelegramBot|Pinterestbot|Pinterest/|redditbot|Embedly|SkypeUriPreview|Iframely|Viber|Snapchat|'
             r'Mastodon|Bluesky')
SEO_UA = r'AhrefsBot|AhrefsSiteAudit|SemrushBot|SiteAuditBot|rogerbot|dotbot|MJ12bot|Screaming Frog|SEOkicks'
# crawlers nginx lets through when they come from a published address range
CRAWLER_UA = (r'Googlebot|Google-InspectionTool|AdsBot-Google|Mediapartners-Google|APIs-Google|Storebot-Google|'
              r'Google-Safety|FeedFetcher-Google|Google-Read-Aloud|GoogleProducer|Google-Site-Verification|'
              r'Google-PageRenderer|bingbot|BingPreview|adidxbot|MicrosoftPreview|Applebot|DuckDuckBot')
GOOGLE_SPECIAL_UA = (r'AdsBot-Google|Mediapartners-Google|APIs-Google|Storebot-Google|Google-Safety|'
                     r'Google-InspectionTool|FeedFetcher-Google|Google-Site-Verification|GoogleProducer')

# Paths that are never checked, for every method unless noted (regex on "$request_method $request_uri").
OPEN_PATHS = [
    ('Crawling rules', ['/robots.txt'], r'~^\S+ /robots\.txt(\?|$)'),
    ('Sitemaps', ['*sitemap*.xml', '*sitemap*.xml.gz', 'wp-sitemap*.xml', '*.xsl'],
     r'~*^\S+ /[^?]*sitemap[^?/]*\.(xml|xml\.gz|xsl)(\?|$)'),
    ('Sitemap stylesheets', [], r'~*^\S+ /[^?]*\.xsl(\?|$)'),
    ('Feeds', ['/feed', '*/feed/', '/rss', '*.rss', '*.atom', '/comments/feed'],
     r'~*^\S+ (/feed|/rss|/[^?]*/feed/?|[^?]*\.(rss|atom))(/|\?|$)'),
    ('Ads and trust files', ['/ads.txt', '/app-ads.txt', '/sellers.json', '/humans.txt'],
     r'~^\S+ /(ads\.txt|app-ads\.txt|sellers\.json|humans\.txt)(\?|$)'),
    ('Certificates and standards', ['/.well-known/*'], r'~^\S+ /\.well-known/'),
    ('Ownership verification', ['/google*.html', '/BingSiteAuth.xml', '/yandex_*.html', '/pinterest-*.html',
                                'IndexNow key files'],
     r'~^\S+ /(google[0-9a-f]+\.html|BingSiteAuth\.xml|yandex_[0-9a-f]+\.html|pinterest-[0-9a-f]+\.html|[0-9a-f]{8,128}\.txt)(\?|$)'),
    ('Icons and app files', ['/favicon.*', '/apple-touch-icon*.png', '/site.webmanifest', '/manifest.json',
                             '/browserconfig.xml'],
     r'~*^\S+ /(favicon\.(ico|png|svg|gif|jpg)|apple-touch-icon[^/?]*\.png|site\.webmanifest|manifest\.json|browserconfig\.xml)(\?|$)'),
    ('Embeds', ['/wp-json/oembed/*', '/oembed*'], r'~^\S+ /(wp-json/oembed/|oembed)'),
    ('WordPress requests from logged-in browsers', ['POST /wp-json/*', 'POST /wp-admin/admin-ajax.php'],
     r'~^POST /(wp-json/|wp-admin/admin-ajax\.php)'),
    ('Shop callbacks', ['POST /wc-api/*', 'POST /?wc-api=*'], r'~^POST /(wc-api/|\?wc-api=)'),
]
STATIC_ALWAYS = r'~*^(GET|HEAD) /[^?]*\.(css|js|mjs|map|woff2?|ttf|otf|eot)(\?|$)'
STATIC_MEDIA = r'~*^(GET|HEAD) /[^?]*\.(png|jpe?g|gif|webp|avif|svg|ico|bmp|tiff?|mp4|webm|ogv|ogg|mp3|wav|m4a|flac|pdf|zip)(\?|$)'


# ---------------------------------------------------------------------------- helpers
def sh(cmd, t=60, inp=None):
    try:
        r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=t, input=inp)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f'timed out after {t}s'
    except FileNotFoundError as e:
        return 127, str(e)


def _write(path, data, mode=0o644, owner=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.vp-tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w') as f:
        f.write(data)
    os.chmod(tmp, mode)
    if owner:
        shutil.chown(tmp, *owner)
    os.replace(tmp, path)


def log_event(domain, text, kind='info'):
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, 'a') as f:
            f.write(json.dumps({'time': int(time.time()), 'site': domain or '', 'kind': kind, 'text': text}) + '\n')
        if os.path.getsize(LOG) > 2 * 1024 * 1024:
            lines = open(LOG).readlines()[-5000:]
            with open(LOG, 'w') as f:
                f.writelines(lines)
    except OSError:
        pass


def read_log(limit=300, domain=None):
    try:
        lines = open(LOG).readlines()
    except OSError:
        return []
    out = []
    for l in reversed(lines):
        try:
            e = json.loads(l)
        except ValueError:
            continue
        if domain and e.get('site') != domain:
            continue
        out.append(e)
        if len(out) >= limit:
            break
    return out


class _Lock:
    def __enter__(self):
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        self.f = open(STATE + '.lock', 'w')
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


def load_state():
    try:
        st = json.load(open(STATE))
    except Exception:
        st = {}
    st.setdefault('sites', {})
    s = dict(SETTINGS_DEFAULTS, **(st.get('settings') or {}))
    s['defaults'] = dict(SETTINGS_DEFAULTS['defaults'], **(s.get('defaults') or {}))
    st['settings'] = s
    st.setdefault('runtime', {})
    return st


def save_state(st):
    _write(STATE, json.dumps(st, indent=1), 0o600)


def site_cfg(st, domain):
    return dict(SITE_DEFAULTS, **(st['sites'].get(domain) or {}))


def valid_domain(d):
    return bool(re.fullmatch(r'(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}', d or ''))


def arch():
    m = platform.machine().lower()
    return {'x86_64': 'amd64', 'amd64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(m)


def installed():
    return os.path.isfile(BIN) and os.path.isfile(BASE + '/VERSION')


def version():
    try:
        return open(BASE + '/VERSION').read().strip()
    except OSError:
        return ''


def nginx_present():
    return bool(shutil.which('nginx')) and os.path.isdir('/etc/nginx')


def nginx_group():
    try:
        txt = open('/etc/nginx/nginx.conf').read()
        m = re.search(r'^\s*user\s+([a-z_][a-z0-9_-]*)(?:\s+([a-z_][a-z0-9_-]*))?\s*;', txt, re.M)
        if m:
            return m.group(2) or m.group(1)
    except OSError:
        pass
    for g in ('www-data', 'nginx'):
        if sh(['getent', 'group', g])[0] == 0:
            return g
    return 'root'


def unit_name(domain):
    rc, out = sh(['systemd-escape', '--template=vortexpanel-anubis@.service', domain])
    return out.strip() if rc == 0 and out.strip() else f'vortexpanel-anubis@{domain}.service'


def tag(domain):
    return hashlib.sha1(domain.encode()).hexdigest()[:10]


def site_dir(domain):
    return f'{ETC}/sites/{domain}'


def sock(domain):
    return f'{RUN}/{domain}/anubis.sock'


def msock(domain):
    return f'{RUN}/{domain}/metrics.sock'


def site_webserver(domain):
    from panel.routes.websites_core import _find_site_config
    return _find_site_config(domain)


def site_https(conf_text):
    return bool(re.search(r'listen[^;]*\b443\b', conf_text or '')) or 'ssl_certificate' in (conf_text or '')


# ---------------------------------------------------------------------------- crawler lists
def load_lists():
    for p in (LISTS, SNAPSHOT):
        try:
            d = json.load(open(p))
            if d.get('lists'):
                return d
        except Exception:
            continue
    return {'lists': {}}


def _parse_ranges(text):
    out = []
    try:
        data = json.loads(text)
        for p in data.get('prefixes') or []:
            v = p.get('ipv4Prefix') or p.get('ipv6Prefix')
            if v:
                out.append(v)
    except ValueError:
        out = [l.strip() for l in text.splitlines() if l.strip()]
    good = []
    for c in out:
        try:
            good.append(str(ipaddress.ip_network(c, strict=False)))
        except ValueError:
            pass
    return sorted(set(good), key=lambda x: (':' in x, x))


def refresh_lists(log=print):
    """Download the providers' published address lists. A list that fails, is
    empty or shrinks by more than half keeps its previous version."""
    cur = load_lists()
    lists = json.loads(json.dumps(cur.get('lists') or {}))
    changed = []
    for key, info in lists.items():
        urls = info.get('url', '').split()
        got, err = [], ''
        for u in urls:
            rc, out = sh(['curl', '-fsSL', '--max-time', '30', u], 45)
            if rc != 0:
                err = f'download failed ({out[-120:]})'
                break
            got += _parse_ranges(out)
        prev = info.get('ranges') or []
        if not err and (not got or len(got) < len(prev) // 2):
            err = f'got {len(got)} ranges, previously {len(prev)} - kept the previous list'
        if err:
            info['status'] = err
            log(f'{info.get("name", key)}: {err}')
            continue
        if sorted(got) != sorted(prev):
            changed.append(key)
        info.update(ranges=got, updated=int(time.time()), status='OK')
    _write(LISTS, json.dumps({'snapshot': cur.get('snapshot', ''), 'lists': lists}, indent=0), 0o644)
    write_crawler_geo()
    if 'cloudflare' in changed and os.path.exists(REALIP_CONF):
        write_realip()
    if changed and nginx_present():
        reload_nginx()
    return changed


def write_crawler_geo():
    lists = load_lists().get('lists') or {}
    lines = ['# VortexPanel bot protection: published crawler addresses (generated, do not edit)']
    seen = set()
    for key in ('googlebot', 'google-special', 'google-user', 'bingbot', 'applebot', 'duckduckbot'):
        for c in (lists.get(key) or {}).get('ranges') or []:
            if c not in seen:
                seen.add(c)
                lines.append(f'{c} 1;')
    _write(CRAWLER_GEO, '\n'.join(lines) + '\n')


# ---------------------------------------------------------------------------- nginx files
HTTP_CONF = '''# VortexPanel bot protection (Anubis): shared lookups. Generated - do not edit.
geo $vp_anubis_crawler_ip {
    default 0;
    include %(geo)s;
}
geo $vp_anubis_private {
    default 0;
    127.0.0.0/8 1;
    ::1/128 1;
    10.0.0.0/8 1;
    172.16.0.0/12 1;
    192.168.0.0/16 1;
    fc00::/7 1;
}
map $http_user_agent $vp_anubis_crawler_ua {
    default 0;
    "~*(%(ua)s)" 1;
}
map "$vp_anubis_crawler_ip$vp_anubis_crawler_ua$vp_anubis_private" $vp_anubis_skip {
    default 0;
    "~^11" 1;
    "~1$" 1;
}
include %(maps)s/*.conf;
'''


def write_http_conf():
    write_crawler_geo()
    os.makedirs(NGX_MAPS, exist_ok=True)
    _write(NGX_HTTP, HTTP_CONF % {'geo': CRAWLER_GEO, 'ua': CRAWLER_UA, 'maps': NGX_MAPS})


def _path_regex(p):
    p = p.strip()
    if not p.startswith('/') or len(p) > 200 or re.search(r'[\s"\'\\;{}$`]', p):
        return None
    return '~^\\S+ ' + re.escape(p).replace('\\*', '[^?]*')


def clean_open_paths(paths):
    out = []
    for p in paths or []:
        p = str(p).strip()
        if p and _path_regex(p) and p not in out:
            out.append(p)
    return out[:50]


def write_site_map(domain, cfg):
    h = tag(domain)
    lines = [f'# VortexPanel bot protection: never-checked requests for {domain} (generated)',
             f'map "$request_method $request_uri" $vp_ab_path_{h} {{', '    default 0;']
    for _name, _shown, rx in OPEN_PATHS:
        lines.append(f'    "{rx}" 1;')
    lines.append(f'    "{STATIC_ALWAYS}" 1;')
    if not cfg.get('check_media'):
        lines.append(f'    "{STATIC_MEDIA}" 1;')
    for p in cfg.get('open_paths') or []:
        rx = _path_regex(p)
        if rx:
            lines.append(f'    "{rx}" 1;')
    lines.append('}')
    lines.append(f'map "$vp_anubis_skip$vp_ab_path_{h}" $vp_ab_skip_{h} {{')
    lines.append('    default 0;')
    lines.append('    "~1" 1;')
    lines.append('}')
    _write(f'{NGX_MAPS}/{domain}.conf', '\n'.join(lines) + '\n')


def write_site_include(domain):
    h, s = tag(domain), sock(domain)
    inc = f'''# VortexPanel bot protection (Anubis) for {domain}. Generated - do not edit.
auth_request /.vp-anubis-auth;
error_page 401 = @vp_anubis_challenge;
location = /.vp-anubis-auth {{
    internal;
    if ($vp_ab_skip_{h}) {{ return 204; }}
    proxy_pass http://unix:{s}:/.within.website/x/cmd/anubis/api/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_connect_timeout 2s;
    proxy_read_timeout 5s;
    # fail-open: if Anubis does not answer, the website is served
    error_page 500 502 503 504 = @vp_anubis_open;
}}
location @vp_anubis_open {{ auth_request off; return 204; }}
location @vp_anubis_challenge {{
    auth_request off;
    add_header Cache-Control "no-store" always;
    return 307 /.within.website/?redir=$scheme://$http_host$request_uri;
}}
location @vp_anubis_basic401 {{ auth_request off; return 401 "Authorization required\\n"; }}
location ^~ /.within.website/ {{
    auth_request off;
    proxy_pass http://unix:{s};
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    access_log off;
}}
'''
    _write(f'{NGX_DIR}/{domain}.conf', inc)


def reload_nginx():
    rc, out = sh('nginx -t 2>&1')
    if rc != 0:
        return False, out
    sh('systemctl reload nginx 2>/dev/null || nginx -s reload')
    return True, ''


def _vhost_text(domain):
    fp, ws = site_webserver(domain)
    if not fp or ws != 'nginx':
        return None, None
    return fp, open(fp).read()


def vhost_with_include(text, domain):
    """Add the include to every server block (after server_name) and turn the
    check off in password-protected folders, which keep their own 401."""
    text = strip_include(text)
    inc = f'include {NGX_DIR}/{domain}.conf; {MARK}'
    out, n = re.subn(r'^([ \t]*)(server_name\s[^;]*;[^\n]*)$', lambda m: f'{m.group(1)}{m.group(2)}\n{m.group(1)}{inc}',
                     text, flags=re.M)
    if not n:
        return None

    lines = out.split('\n')
    res = []
    for line in lines:
        res.append(line)
        m = re.match(r'^([ \t]*)auth_basic\s+(?!off)["\'][^\n]*;', line)
        if m and MARK not in line:
            res.append(f'{m.group(1)}auth_request off; error_page 401 = @vp_anubis_basic401; {MARK}')
    return '\n'.join(res)


def strip_include(text):
    return re.sub(r'^[^\n]*' + re.escape(MARK) + r'[ \t]*\n', '', text, flags=re.M)


def vhost_apply(domain, on):
    from panel.routes.websites_core import _nginx_apply
    fp, text = _vhost_text(domain)
    if not fp:
        return False, 'nginx configuration of the website not found'
    new = vhost_with_include(text, domain) if on else strip_include(text)
    if new is None:
        return False, 'no server_name line found in the website configuration'
    return _nginx_apply(fp, new)


def vhost_has_include(domain):
    fp, text = _vhost_text(domain)
    return bool(text and f'{NGX_DIR}/{domain}.conf' in text)


# ---------------------------------------------------------------------------- Anubis files
def policy_for(cfg):
    bots = [{'import': '(data)/bots/_deny-pathological.yaml'},
            {'import': '(data)/bots/aggressive-brazilian-scrapers.yaml'},
            {'import': '(data)/common/domain-fronting.yaml'}]
    if not cfg.get('block_ai_search'):
        bots += [{'import': f'(data)/{p}.yaml'} for p in ('crawlers/openai-searchbot', 'crawlers/perplexitybot',
                                                           'clients/openai-chatgpt-user', 'clients/perplexity-user',
                                                           'clients/mistral-mistralai-user')]
    if cfg.get('block_ai_training'):
        bots += [{'import': '(data)/crawlers/ai-training.yaml'}, {'import': '(data)/bots/ai-catchall.yaml'},
                 {'name': 'vp-common-crawl', 'user_agent_regex': 'CCBot', 'action': 'DENY'}]
    if cfg.get('block_ai_search'):
        bots += [{'import': '(data)/crawlers/ai-search.yaml'}, {'import': '(data)/clients/ai.yaml'}]
    bots += [{'import': '(data)/crawlers/_allow-good.yaml'},
             {'import': '(data)/clients/google-user-triggered-fetchers.yaml'}]
    lists = load_lists().get('lists') or {}
    gr = sorted(set(((lists.get('googlebot') or {}).get('ranges') or [])
                    + ((lists.get('google-special') or {}).get('ranges') or [])))
    if gr:
        bots.append({'name': 'vp-google-special-crawlers', 'user_agent_regex': GOOGLE_SPECIAL_UA,
                     'action': 'ALLOW', 'remote_addresses': gr})
    for key in cfg.get('engines') or []:
        if key in OPTIONAL_ENGINES:
            bots.append({'name': f'vp-engine-{key}', 'user_agent_regex': OPTIONAL_ENGINES[key][1], 'action': 'ALLOW'})
    if cfg.get('social'):
        bots += [{'name': 'vp-social-previews', 'action': 'ALLOW',
                  'expression': {'all': ['method == "GET" || method == "HEAD"', f'userAgent.matches("{SOCIAL_UA}")']}},
                 {'import': '(data)/meta/messengers-preview.yaml'}]
    bots += [{'import': '(data)/services/uptime-robot.yaml'}, {'import': '(data)/services/updown.yaml'}]
    if cfg.get('seo_tools'):
        bots.append({'name': 'vp-seo-tools', 'user_agent_regex': SEO_UA, 'action': 'ALLOW'})
    bots += [{'import': '(data)/crawlers/xai.yaml'},
             {'import': '(data)/common/keep-internet-working.yaml'},
             {'import': '(data)/common/allow-private-addresses.yaml'},
             {'name': 'vp-browser', 'user_agent_regex': 'Mozilla|Opera', 'action': 'WEIGH',
              'weight': {'adjust': LEVEL_WEIGHT.get(cfg.get('level'), 5)}}]
    return {
        'bots': bots,
        'dnsbl': False,
        'honeypot': {'enabled': False},
        'openGraph': {'enabled': False},
        'status_codes': {'CHALLENGE': 200, 'DENY': 403},
        'store': {'backend': 'memory', 'parameters': {}},
        'thresholds': [
            {'name': 'vp-allow', 'expression': 'weight <= 0', 'action': 'ALLOW'},
            {'name': 'vp-light', 'expression': {'all': ['weight > 0', 'weight < 10']}, 'action': 'CHALLENGE',
             'challenge': {'algorithm': 'metarefresh', 'difficulty': 1}},
            {'name': 'vp-moderate', 'expression': {'all': ['weight >= 10', 'weight < 20']}, 'action': 'CHALLENGE',
             'challenge': {'algorithm': 'fast', 'difficulty': 2}},
            {'name': 'vp-strong', 'expression': {'all': ['weight >= 20', 'weight < 30']}, 'action': 'CHALLENGE',
             'challenge': {'algorithm': 'fast', 'difficulty': 4}},
            {'name': 'vp-extreme', 'expression': 'weight >= 30', 'action': 'CHALLENGE',
             'challenge': {'algorithm': 'fast', 'difficulty': 5}},
        ],
    }


def env_for(domain, cfg, https):
    hours = max(1, min(30, int(cfg.get('pass_days') or 7))) * 24
    if cfg.get('level') == 'attack':
        hours = min(hours, 24)
    hosts = [domain] + ([f'www.{domain}'] if domain.count('.') == 1 else [])
    try:
        from panel.routes.websites_core import _find_site_config
        fp, _ = _find_site_config(domain)
        m = re.search(r'^\s*server_name\s+([^;]+);', open(fp).read(), re.M) if fp else None
        if m:
            hosts = [h for h in m.group(1).split() if valid_domain(h)] or hosts
    except Exception:
        pass
    env = {
        'BIND': sock(domain), 'BIND_NETWORK': 'unix', 'SOCKET_MODE': '0660',
        'METRICS_BIND': msock(domain), 'METRICS_BIND_NETWORK': 'unix',
        'TARGET': ' ', 'POLICY_FNAME': f'{site_dir(domain)}/policy.yaml',
        'ED25519_PRIVATE_KEY_HEX_FILE': f'{site_dir(domain)}/key',
        'COOKIE_EXPIRATION_TIME': f'{hours}h',
        'COOKIE_SECURE': 'true' if https else 'false',
        'REDIRECT_DOMAINS': ','.join(sorted(set(hosts))),
        'PRESERVE_REFERER_QUERY_PARAM': 'true' if cfg.get('attribution') else 'false',
        'JWT_RESTRICTION_HEADER': 'X-Real-IP' if cfg.get('tie_ip', True) else '',
        'SERVE_ROBOTS_TXT': 'false',
        'SLOG_LEVEL': 'WARN',
        'COOKIE_PREFIX': 'vp-botprot',
    }
    if cfg.get('email') and re.fullmatch(r'[^@\s"]+@[^@\s"]+\.[a-z]{2,}', cfg['email'], re.I):
        env['WEBMASTER_EMAIL'] = cfg['email']
    if cfg.get('language') and re.fullmatch(r'[a-z]{2}(-[A-Za-z]{2,4})?', cfg['language']):
        env['FORCED_LANGUAGE'] = cfg['language']
    return ''.join(f'{k}="{v}"\n' for k, v in env.items())


def write_site_files(domain, cfg, https, memory_mb=64):
    d = site_dir(domain)
    os.makedirs(d, mode=0o750, exist_ok=True)
    shutil.chown(d, 'root', USER)
    os.chmod(d, 0o750)
    if not os.path.exists(f'{d}/key'):
        _write(f'{d}/key', secrets.token_hex(32) + '\n', 0o640, ('root', USER))
    if not cfg.get('custom_rules') or not os.path.exists(f'{d}/policy.yaml'):
        _write(f'{d}/policy.yaml', json.dumps(policy_for(cfg), indent=1) + '\n', 0o640, ('root', USER))
    _write(f'{d}/env', env_for(domain, cfg, https), 0o640, ('root', USER))
    unit = unit_name(domain)
    dropin = f'/etc/systemd/system/{unit}.d/vortexpanel.conf'
    _write(dropin, f'[Service]\nMemoryMax={int(memory_mb)}M\n')
    write_site_map(domain, cfg)
    write_site_include(domain)


def check_rules_file(path):
    """Ask Anubis itself whether a rules file is valid (a throw-away instance on a temp socket)."""
    tmp = f'/opt/vortexpanel/data/tmp/anubis-check-{os.getpid()}'
    os.makedirs(tmp, exist_ok=True)
    try:
        p = subprocess.Popen([BIN], env={'BIND': f'{tmp}/s', 'BIND_NETWORK': 'unix', 'TARGET': ' ',
                                         'POLICY_FNAME': path, 'METRICS_BIND': f'{tmp}/m', 'METRICS_BIND_NETWORK': 'unix',
                                         'ED25519_PRIVATE_KEY_HEX': secrets.token_hex(32)},
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(50):
            if os.path.exists(f'{tmp}/s') or p.poll() is not None:
                break
            time.sleep(0.1)
        ok = p.poll() is None and os.path.exists(f'{tmp}/s')
        p.kill()
        out = p.communicate()[0] if not ok else ''
        if not ok:
            plain = [l.split(' ', 2)[-1] if re.match(r'\d{4}/\d\d/\d\d ', l) else l
                     for l in (out or '').splitlines() if l.strip() and not l.lstrip().startswith('{')]
            errs = re.findall(r'"(?:err|error)":"([^"]+)"', out or '')
            msg = (plain[-1] if plain else '') or (errs[-1] if errs else '')
            msg = re.sub(r"(can't parse policy (file|config YAML) \S+: )+", '', msg)
            return msg[-400:] or (out or 'Anubis did not start')[-300:]
        return ''
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------- talking to Anubis
class _UnixConn(http.client.HTTPConnection):
    def __init__(self, path, timeout=3):
        super().__init__('localhost', timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def _check(domain, ip, ua, path='/'):
    try:
        c = _UnixConn(sock(domain))
        c.request('GET', '/.within.website/x/cmd/anubis/api/check',
                  headers={'Host': domain, 'X-Real-IP': ip, 'X-Forwarded-For': ip, 'User-Agent': ua,
                           'X-Original-URI': path, 'X-Forwarded-Proto': 'https'})
        r = c.getresponse()
        r.read()
        return r.status
    except OSError:
        return 0


def alive(domain):
    return _check(domain, '127.0.0.1', 'vortexpanel-watchdog') != 0


SELFTEST = [
    ('Googlebot', '66.249.66.1', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'allow'),
    ('Bingbot', '157.55.39.1', 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', 'allow'),
    ('Google Search Console test', '66.249.66.1',
     'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X) Chrome/130.0 Mobile Safari/537.36 (compatible; Google-InspectionTool/1.0;)',
     'allow'),
    ('Normal browser', '203.0.113.50', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36', 'check'),
]


def selftest(domain):
    res, ok = [], True
    for name, ip, ua, want in SELFTEST:
        code = _check(domain, ip, ua)
        got = 'allow' if 200 <= code < 300 else ('check' if code == 401 else ('blocked' if code == 403 else 'no answer'))
        good = got == want
        ok &= good
        res.append({'name': name, 'want': want, 'got': got, 'ok': good})
    return {'ok': ok, 'time': int(time.time()), 'results': res}


def metrics(domain):
    try:
        c = _UnixConn(msock(domain))
        c.request('GET', '/metrics')
        r = c.getresponse()
        text = r.read().decode(errors='replace')
    except OSError:
        return None
    out = {'ALLOW': 0, 'CHALLENGE': 0, 'DENY': 0, 'WEIGH': 0, 'issued': 0, 'validated': 0}
    for line in text.splitlines():
        if line.startswith('anubis_policy_results{'):
            m = re.search(r'action="([A-Z]+)".*\}\s+([0-9.e+]+)$', line)
            if m and m.group(1) in out:
                out[m.group(1)] += int(float(m.group(2)))
        elif line.startswith('anubis_challenges_issued'):
            out['issued'] += int(float(line.split()[-1]))
        elif line.startswith('anubis_challenges_validated'):
            out['validated'] += int(float(line.split()[-1]))
    return out


def record_stats(domain):
    m = metrics(domain)
    if m is None:
        return
    p = f'{STATS_DIR}/{domain}.json'
    try:
        hist = json.load(open(p))
    except Exception:
        hist = []
    hist.append([int(time.time()), m])
    cutoff = time.time() - 26 * 3600
    hist = [h for h in hist if h[0] >= cutoff][-400:]
    _write(p, json.dumps(hist), 0o600)


def stats_24h(domain):
    """Counts over the last 24 hours from the samples (counters restart with the service)."""
    try:
        hist = json.load(open(f'{STATS_DIR}/{domain}.json'))
    except Exception:
        hist = []
    now = metrics(domain)
    if now is not None:
        hist = hist + [[int(time.time()), now]]
    cutoff = time.time() - 24 * 3600
    hist = [h for h in hist if h[0] >= cutoff]
    tot = {'passed': 0, 'checks': 0, 'blocked': 0, 'solved': 0}
    for (t0, a), (t1, b) in zip(hist, hist[1:]):
        for k, src in (('passed', 'ALLOW'), ('checks', 'CHALLENGE'), ('blocked', 'DENY'), ('solved', 'validated')):
            d = b.get(src, 0) - a.get(src, 0)
            tot[k] += d if d >= 0 else b.get(src, 0)
    if len(hist) == 1:
        h = hist[0][1]
        tot = {'passed': h['ALLOW'], 'checks': h['CHALLENGE'], 'blocked': h['DENY'], 'solved': h['validated']}
    return tot


def memory_bytes(domain):
    rc, out = sh(['systemctl', 'show', '-p', 'MemoryCurrent', '--value', unit_name(domain)])
    try:
        v = int(out.strip())
        return v if v < 1 << 50 else 0
    except ValueError:
        return 0


def service_active(domain):
    return sh(['systemctl', 'is-active', unit_name(domain)])[1].strip() == 'active'


# ---------------------------------------------------------------------------- site actions
def can_protect(domain):
    """'' or the reason a website cannot be protected."""
    if not installed():
        return 'Bot protection is not installed (App Store).'
    if not nginx_present():
        return 'Bot protection needs Nginx.'
    fp, ws = site_webserver(domain)
    if not fp:
        return 'Website not found.'
    if ws != 'nginx':
        return f'This website is served by {ws or "another web server"}. Bot protection works with Nginx websites.'
    return ''


def clean_settings(cur, new, allow=None):
    """Merge new settings into cur, keeping only known, valid values. `allow`
    (hosting customers) limits what may change."""
    out = dict(cur)
    allow = allow or {}
    if 'level' in new and new['level'] in LEVELS:
        top = allow.get('max_level')
        if top and LEVELS.index(new['level']) > LEVELS.index(top):
            raise ValueError(f'Your plan allows up to "{LEVEL_NAMES[top]}"')
        out['level'] = new['level']
    for k in ('block_ai_training', 'block_ai_search', 'social', 'seo_tools', 'tie_ip', 'attribution'):
        if k in new:
            out[k] = bool(new[k])
    if 'check_media' in new:
        if new['check_media'] and allow.get('images') is False:
            raise ValueError('Your plan does not include checking images and media')
        out['check_media'] = bool(new['check_media'])
    if 'engines' in new:
        out['engines'] = [e for e in new.get('engines') or [] if e in OPTIONAL_ENGINES]
    if 'open_paths' in new:
        paths = new['open_paths']
        if isinstance(paths, str):
            paths = paths.splitlines()
        cleaned = clean_open_paths(paths)
        bad = [p for p in (x.strip() for x in paths) if p and p not in cleaned]
        if bad:
            raise ValueError(f'Open paths must start with / and contain no spaces or quotes: {bad[0]}')
        if cleaned and allow.get('open_paths') is False:
            raise ValueError('Your plan does not include custom open paths')
        out['open_paths'] = cleaned
    if 'pass_days' in new:
        try:
            out['pass_days'] = max(1, min(30, int(new['pass_days'])))
        except (TypeError, ValueError):
            pass
    if 'email' in new:
        e = str(new.get('email') or '').strip()
        if e and not re.fullmatch(r'[^@\s"]+@[^@\s"]+\.[A-Za-z]{2,}', e):
            raise ValueError('Enter a valid e-mail address')
        out['email'] = e
    if 'language' in new:
        l = str(new.get('language') or '').strip()
        out['language'] = l if re.fullmatch(r'([a-z]{2}(-[A-Za-z]{2,4})?)?', l) else ''
    return out


def _start(domain):
    sh(['systemctl', 'daemon-reload'])
    unit = unit_name(domain)
    sh(['systemctl', 'enable', unit])
    sh(['systemctl', 'restart', unit])
    for _ in range(40):
        if alive(domain):
            return True
        time.sleep(0.25)
    return False


def apply_site(domain, cfg, actor='admin'):
    """Write everything for a protected website, (re)start its service, run the
    search engine test and add the protection to the vhost. Returns (ok, message, test)."""
    reason = can_protect(domain)
    if reason:
        return False, reason, None
    with _Lock():
        st = load_state()
    fp, text = _vhost_text(domain)
    write_site_files(domain, cfg, site_https(text), st['settings'].get('memory_mb', 64))
    if cfg.get('custom_rules'):
        err = check_rules_file(f'{site_dir(domain)}/policy.yaml')
        if err:
            return False, f'The rules file is not valid: {err}', None
    if not _start(domain):
        rc, out = sh(['journalctl', '-u', unit_name(domain), '-n', '5', '--no-pager', '-o', 'cat'])
        return False, 'Anubis did not start for this website: ' + out[-300:], None
    test = selftest(domain)
    if not test['ok']:
        bad = ', '.join(f"{r['name']} ({r['got']})" for r in test['results'] if not r['ok'])
        return False, f'The search engine test failed ({bad}); protection was not turned on.', test
    ok, err = reload_nginx()
    if not ok:
        return False, 'nginx refused the bot protection files: ' + err[-300:], test
    paused = cfg.get('paused_until', 0) > time.time()
    if not paused:
        ok, err = vhost_apply(domain, True)
        if not ok:
            return False, 'nginx refused the website configuration: ' + str(err)[-300:], test
    cfg = dict(cfg, enabled=True, auto_off=False, suspended=False)
    if not actor.endswith('(restored)') and actor != 'account reactivated':
        cfg['changed_by'] = actor
    with _Lock():
        st = load_state()
        st['sites'][domain] = cfg
        st['runtime'].setdefault(domain, {})['test'] = test
        st['runtime'][domain].pop('down_since', None)
        save_state(st)
    log_event(domain, f'Protection on ({LEVEL_NAMES.get(cfg["level"], cfg["level"])}) by {actor}.')
    return True, 'Bot protection is on.', test


def disable_site(domain, actor='admin', forget=False):
    if (domain not in load_state()['sites'] and not os.path.isdir(site_dir(domain))
            and not vhost_has_include(domain)):
        return True   # never protected: nothing to undo
    if vhost_has_include(domain):
        vhost_apply(domain, False)
    unit = unit_name(domain)
    sh(['systemctl', 'disable', '--now', unit])
    for p in (f'{NGX_DIR}/{domain}.conf', f'{NGX_MAPS}/{domain}.conf'):
        try:
            os.remove(p)
        except OSError:
            pass
    reload_nginx()
    with _Lock():
        st = load_state()
        if forget:
            st['sites'].pop(domain, None)
            st['runtime'].pop(domain, None)
        elif domain in st['sites']:
            st['sites'][domain]['enabled'] = False
            st['sites'][domain]['paused_until'] = 0
        save_state(st)
    if forget:
        shutil.rmtree(site_dir(domain), ignore_errors=True)
        shutil.rmtree(f'/etc/systemd/system/{unit}.d', ignore_errors=True)
        try:
            os.remove(f'{STATS_DIR}/{domain}.json')
        except OSError:
            pass
        sh(['systemctl', 'daemon-reload'])
    log_event(domain, f'Protection off by {actor}.' if not forget else f'Protection removed ({actor}).')
    return True


def pause_site(domain, minutes, actor='admin'):
    with _Lock():
        st = load_state()
        if domain not in st['sites'] or not st['sites'][domain].get('enabled'):
            return False, 'Bot protection is not on for this website'
        st['sites'][domain]['paused_until'] = int(time.time() + minutes * 60) if minutes else 0
        save_state(st)
    ok, err = vhost_apply(domain, not minutes)
    log_event(domain, f'Paused for {minutes} minutes by {actor}.' if minutes else f'Resumed by {actor}.')
    return ok, err or ''


def _set_flag(domain, key, value):
    with _Lock():
        st = load_state()
        if domain in st['sites']:
            st['sites'][domain][key] = value
            save_state(st)


def suspend_site(domain):
    """Hosting account suspended: stop the service and remove the include, keep settings.
    The watchdog and the nightly test leave a suspended website alone."""
    if domain not in load_state()['sites']:
        return
    _set_flag(domain, 'suspended', True)
    if vhost_has_include(domain):
        vhost_apply(domain, False)
    sh(['systemctl', 'stop', unit_name(domain)])
    log_event(domain, 'Stopped: hosting account suspended.')


def resume_site(domain):
    _set_flag(domain, 'suspended', False)
    st = load_state()
    cfg = st['sites'].get(domain)
    if cfg and cfg.get('enabled'):
        ok, msg, _t = apply_site(domain, site_cfg(st, domain), actor='account reactivated')
        return ok, msg
    return True, ''


def migrate_strip(conf_text):
    """Vhost text copied to another server: drop the protection lines."""
    return strip_include(conf_text)


# ---------------------------------------------------------------------------- Cloudflare real IP
def _cf_nets():
    lists = load_lists().get('lists') or {}
    return [ipaddress.ip_network(c) for c in (lists.get('cloudflare') or {}).get('ranges') or []]


def realip_configured():
    if os.path.exists(REALIP_CONF):
        return True
    rc, out = sh("grep -rqs 'real_ip_header' /etc/nginx/nginx.conf /etc/nginx/conf.d && echo yes")
    return out.strip() == 'yes'


def behind_cloudflare(domain):
    """True when most recent visitors of the site arrive from Cloudflare addresses."""
    if realip_configured():
        return False
    nets = _cf_nets()
    log = f'/var/log/nginx/{domain}.access.log'
    try:
        with open(log, 'rb') as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 200000))
            lines = f.read().decode(errors='replace').splitlines()[-400:]
    except OSError:
        return False
    ips = [l.split(' ', 1)[0] for l in lines if l]
    if len(ips) < 20:
        return False
    cf = 0
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if any(a in n for n in nets):
            cf += 1
    return cf > len(ips) * 0.5


def write_realip():
    nets = [str(n) for n in _cf_nets()]
    body = '# VortexPanel: real visitor address behind Cloudflare (generated)\n'
    body += ''.join(f'set_real_ip_from {n};\n' for n in nets)
    body += 'real_ip_header CF-Connecting-IP;\n'
    _write(REALIP_CONF, body)
    ok, err = reload_nginx()
    if not ok:
        os.remove(REALIP_CONF)
        reload_nginx()
        return False, err
    return True, ''


# ---------------------------------------------------------------------------- install / uninstall
UNIT_TEXT = '''[Unit]
Description=VortexPanel bot protection (Anubis) for %I
After=network.target

[Service]
EnvironmentFile=/etc/vortexpanel/anubis/sites/%I/env
ExecStart=/usr/local/lib/vortexpanel-anubis/bin/anubis
User=vp-anubis
Group={group}
SupplementaryGroups=vp-anubis
RuntimeDirectory=vortexpanel-anubis/%I
RuntimeDirectoryMode=0750
Restart=always
RestartSec=1
LimitNOFILE=65536
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
MemoryMax=64M

[Install]
WantedBy=multi-user.target
'''


def _write_timers():
    for name, (cal, cmd, desc) in TIMERS.items():
        _write(f'/etc/systemd/system/{name}.service',
               f'[Unit]\nDescription={desc}\n\n[Service]\nType=oneshot\nWorkingDirectory=/opt/vortexpanel\n'
               f'ExecStart=/opt/vortexpanel/venv/bin/python -m panel.botprot {cmd}\nTimeoutStartSec=900\n')
        _write(f'/etc/systemd/system/{name}.timer',
               f'[Unit]\nDescription={desc}\n\n[Timer]\nOnCalendar={cal}\nPersistent=true\n'
               f'{"RandomizedDelaySec=30min" if cmd == "daily" else ""}\n\n[Install]\nWantedBy=timers.target\n')


def install(log=print):
    if not nginx_present():
        log('[VortexPanel] Bot protection needs Nginx. Install Nginx from the App Store first.')
        return False
    a = arch()
    ver, sha, url = VER, dict(SHA), {k: URL.format(v=VER, a=k) for k in SHA}
    # the App Store passes the chosen release (built in, or from the signed
    # tested-versions list, already checked there): version, address, checksum
    ev = os.environ.get('VP_ANUBIS_VER', '')
    if re.fullmatch(r'[1-9]\.[0-9]{1,2}\.[0-9]{1,2}', ev):
        got = {}
        for k in ('amd64', 'arm64'):
            u = os.environ.get(f'VP_ANUBIS_{k.upper()}_URL', '')
            h = os.environ.get(f'VP_ANUBIS_{k.upper()}_SHA', '').lower()
            if re.fullmatch(r'https://github\.com/[A-Za-z0-9._/-]+\.tar\.gz', u) and re.fullmatch(r'[0-9a-f]{64}', h):
                got[k] = (u, h)
        if len(got) != 2:
            log(f'[VortexPanel] The download addresses for Anubis {ev} are not valid - not installed.')
            return False
        ver = ev
        url = {k: v[0] for k, v in got.items()}
        sha = {k: v[1] for k, v in got.items()}
    elif ev:
        log(f'[VortexPanel] "{ev[:20]}" is not a valid Anubis version - not installed.')
        return False
    if a not in sha:
        log(f'[VortexPanel] Anubis is not available for this processor ({platform.machine()}).')
        return False
    tmp = '/opt/vortexpanel/data/tmp/anubis-install'
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, mode=0o700)
    try:
        if version() != ver:
            log(f'[VortexPanel] Downloading Anubis {ver} ({a})...')
            rc, out = sh(['curl', '-fsSL', '--max-time', '300', '-o', f'{tmp}/a.tgz', url[a]], 320)
            if rc:
                log('[VortexPanel] Download failed: ' + out[-300:])
                return False
            rc, out = sh(f'echo "{sha[a]}  {tmp}/a.tgz" | sha256sum -c --quiet -')
            if rc:
                log('[VortexPanel] The download does not match the expected checksum - not installed.')
                return False
            rc, out = sh(['tar', '-xzf', f'{tmp}/a.tgz', '-C', tmp])
            import glob
            found = glob.glob(f'{tmp}/*/bin/anubis')
            src = found[0] if found else ''
            if rc or not src or not os.path.isfile(src):
                log('[VortexPanel] Could not unpack Anubis: ' + out[-300:])
                return False
            os.makedirs(BASE + '/bin', exist_ok=True)
            shutil.copy2(src, BIN + '.new')
            os.chmod(BIN + '.new', 0o755)
            os.replace(BIN + '.new', BIN)
            lic = os.path.join(os.path.dirname(os.path.dirname(src)), 'doc', 'LICENSE')
            if os.path.exists(lic):
                shutil.copy2(lic, BASE + '/LICENSE')
            _write(BASE + '/VERSION', ver + '\n')
        rc, out = sh([BIN, '--version'])
        log('[VortexPanel] ' + (out.splitlines()[0] if out else 'Anubis installed'))
        if sh(['id', USER])[0] != 0:
            sh(['useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', USER])
        os.makedirs(ETC + '/sites', exist_ok=True)
        os.chmod(ETC, 0o755)
        os.makedirs(STATS_DIR, mode=0o700, exist_ok=True)
        _write(UNIT, UNIT_TEXT.replace('{group}', nginx_group()))
        _write_timers()
        if not os.path.exists(LISTS):
            shutil.copy2(SNAPSHOT, LISTS)
        write_http_conf()
        ok, err = reload_nginx()
        if not ok:
            os.remove(NGX_HTTP)
            reload_nginx()
            log('[VortexPanel] nginx refused the bot protection configuration: ' + err[-400:])
            return False
        sh('systemctl daemon-reload; systemctl enable --now vortexpanel-anubis-watch.timer vortexpanel-anubis-daily.timer')
        # restart services of websites that were already protected (update)
        st = load_state()
        for d, c in st['sites'].items():
            if c.get('enabled') and os.path.isdir(site_dir(d)):
                fp, text = _vhost_text(d)
                write_site_files(d, site_cfg(st, d), site_https(text or ''), st['settings'].get('memory_mb', 64))
                _start(d)
        reload_nginx()
        log('[VortexPanel] Bot protection is ready. Turn it on per website: website window > Bot Protection.')
        return True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def uninstall(log=print):
    st = load_state()
    for d in list(st['sites']):
        try:
            disable_site(d, actor='uninstall', forget=True)
            log(f'[VortexPanel] Protection removed from {d}')
        except Exception as e:
            log(f'[VortexPanel] {d}: {e}')
    sh('systemctl disable --now vortexpanel-anubis-watch.timer vortexpanel-anubis-daily.timer 2>/dev/null')
    sh("systemctl stop 'vortexpanel-anubis@*' 2>/dev/null")
    for name in TIMERS:
        for ext in ('service', 'timer'):
            try:
                os.remove(f'/etc/systemd/system/{name}.{ext}')
            except OSError:
                pass
    for p in (UNIT, NGX_HTTP):
        try:
            os.remove(p)
        except OSError:
            pass
    shutil.rmtree(NGX_DIR, ignore_errors=True)
    shutil.rmtree(BASE, ignore_errors=True)
    shutil.rmtree(ETC, ignore_errors=True)
    shutil.rmtree(STATS_DIR, ignore_errors=True)
    sh('systemctl daemon-reload')
    reload_nginx()
    sh(['userdel', USER])
    with _Lock():
        st = load_state()
        st['sites'] = {}
        st['runtime'] = {}
        save_state(st)
    log('[VortexPanel] Bot protection removed. Website configurations are as before.')
    return True


# ---------------------------------------------------------------------------- timers
def _alert(kind, title, detail):
    st = load_state()
    if (kind == 'watchdog' and not st['settings'].get('alert_watchdog')) or \
       (kind == 'selftest' and not st['settings'].get('alert_selftest')):
        return
    try:
        from panel import alerts
        alerts.notify_event('botprot', title, detail)
    except Exception:
        pass


def watch():
    """Every minute: watchdog, pause expiry, stats samples."""
    if not installed():
        return
    st = load_state()
    now = time.time()
    minute = int(now // 60)
    for d, c in list(st['sites'].items()):
        if not c.get('enabled') or c.get('suspended'):
            continue
        rt = st['runtime'].setdefault(d, {})
        if c.get('paused_until') and c['paused_until'] <= now:
            c['paused_until'] = 0
            if not c.get('auto_off'):
                vhost_apply(d, True)
            log_event(d, 'Pause ended; protection is on again.')
        up = alive(d)
        if not up:
            rt.setdefault('down_since', now)
            sh(['systemctl', 'restart', unit_name(d)])
            if not c.get('auto_off') and now - rt['down_since'] >= DOWN_MINUTES * 60:
                vhost_apply(d, False)
                c['auto_off'] = True
                log_event(d, f'Anubis did not answer for {DOWN_MINUTES} minutes; protection turned off automatically.', 'warn')
                _alert('watchdog', f'Bot protection turned off for {d}',
                       f'The bot protection service of {d} stopped answering for {DOWN_MINUTES} minutes. Protection was '
                       'removed from the website so it keeps working; it is turned on again by itself once the '
                       'service answers. Website window > Bot Protection shows the details.')
        else:
            if c.get('auto_off'):
                test = selftest(d)
                if test['ok'] and not (c.get('paused_until', 0) > now):
                    vhost_apply(d, True)
                    c['auto_off'] = False
                    rt['test'] = test
                    log_event(d, 'Anubis answers again; protection is back on.')
            rt.pop('down_since', None)
            if minute % 10 == 0:
                record_stats(d)
    with _Lock():
        cur = load_state()
        for d in st['sites']:
            if d in cur['sites']:
                cur['sites'][d]['paused_until'] = st['sites'][d].get('paused_until', 0)
                cur['sites'][d]['auto_off'] = st['sites'][d].get('auto_off', False)
            cur['runtime'][d] = st['runtime'].get(d, {})
        save_state(cur)


def daily():
    if not installed():
        return
    msgs = []
    refresh_lists(msgs.append)
    st = load_state()
    for d, c in st['sites'].items():
        if not c.get('enabled') or c.get('auto_off') or c.get('suspended'):
            continue
        test = selftest(d)
        st['runtime'].setdefault(d, {})['test'] = test
        if not test['ok']:
            bad = ', '.join(f"{r['name']} ({r['got']})" for r in test['results'] if not r['ok'])
            vhost_apply(d, False)
            c['auto_off'] = True
            log_event(d, f'Daily search engine test failed ({bad}); protection turned off.', 'warn')
            _alert('selftest', f'Bot protection test failed for {d}',
                   f'The daily search engine test failed for {d} ({bad}). Protection was turned off so search '
                   'engines are not affected. Open the website window > Bot Protection and run the test again.')
    with _Lock():
        cur = load_state()
        for d in st['sites']:
            if d in cur['sites']:
                cur['sites'][d]['auto_off'] = st['sites'][d].get('auto_off', False)
            cur['runtime'][d] = st['runtime'].get(d, {})
        save_state(cur)
    for m in msgs:
        log_event('', 'Crawler lists: ' + m, 'warn')


if __name__ == '__main__':
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'install':
        sys.exit(0 if install() else 1)
    elif cmd == 'uninstall':
        sys.exit(0 if uninstall() else 1)
    elif cmd == 'watch':
        watch()
    elif cmd == 'daily':
        daily()
    elif cmd == 'refresh-lists':
        print('changed:', refresh_lists())
    else:
        print(__doc__)
        sys.exit(2)
