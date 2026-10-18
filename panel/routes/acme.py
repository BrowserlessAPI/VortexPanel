"""ACME certificates through acme.sh: DNS-provider APIs and IP addresses.

* Website SSL through a DNS provider's API (DNS-01): works behind a CDN or a
  firewall that blocks port 80 and is the only way to get a wildcard
  certificate (*.example.com). Supported: the DNS server of this panel and
  the providers in PROVIDERS (credentials are stored root-only).
* Let's Encrypt certificates for an IP address (the panel reached as
  https://203.0.113.10:8888): Let's Encrypt issues these only with the
  6-day "shortlived" profile and only through HTTP validation, so a small
  vhost answers /.well-known/acme-challenge/ for the IP on port 80, and
  renewal runs twice a day.

certbot from the distribution (2.x on Ubuntu 24.04) supports neither IP
addresses nor ACME profiles, so this uses acme.sh (pinned release, checksum
verified) with its own state under /etc/vortexpanel/acme. Certificates
issued with certbot are not touched.
"""
import os, re, json, time, uuid, shlex, shutil, threading, subprocess, ipaddress
from flask import Blueprint, jsonify, request, current_app
from panel.utils.authctx import authed as _vp_authed
from panel.routes.job_state import save_job, load_job

acme_bp = Blueprint('acme', __name__)

ACME_VER = '3.1.6'
ACME_RAW = 'https://raw.githubusercontent.com/acmesh-official/acme.sh/v' + ACME_VER + '/'
# sha256 of each file at the pinned tag; nothing is installed unless all match
ACME_FILES = {
    'acme.sh': 'c7d68b021cfd6380ea83a82962abde5b484779fee0b97d38681dfa1396bbc8d7',
    'dnsapi/dns_cf.sh': '9628ee8238cb3f9cfa1b1a985c0e9593436a3e4f8a9d65a6f775b981be9e76c8',
    'dnsapi/dns_dgon.sh': 'ddc3b8f13b237c8f016d95594f3e4ab575643e248f68f9a348a9e30b9ee003f0',
    'dnsapi/dns_aws.sh': '5366bc36dfcf8dfb16440e99bd1c744b7fa99741a42986773ca269fd12d0550a',
    'dnsapi/dns_hetznercloud.sh': '6428e5c07720c9e90284be199f86429e4213b57625bccb5ab3e7af068c93d3f5',
    'dnsapi/dns_gd.sh': 'c91194c623bb6df91d1c731d636807d6f65b81ca9c44568f2409bebe6e8f7b75',
    'dnsapi/dns_namecheap.sh': '626215c93ad0df45b56bf6127c05b87013ad99c492cf4b2be49e85d1649df18c',
    'dnsapi/dns_porkbun.sh': 'f3f538e3ee70d1faf1922af3df038f2d0f8e027e366aceebf8e89ac7a49347ca',
    'dnsapi/dns_linode_v4.sh': '6b3ef9284f151be258e1783cf52794b507fad12dcc18d616b83b4e85b67370b5',
    'dnsapi/dns_vultr.sh': '7e62c1e13df02a931e1943258aa564688814d0ba4bdffb25a977fa9fb28b15cf',
    'dnsapi/dns_gandi_livedns.sh': '196f2c18394030a82760eb38108c2980c6826656e7656b57cad5069c699495e4',
    'dnsapi/dns_ovh.sh': 'a2a628f88d541672da673cf4b3cc2ffedc1b95585044bbff1ecc1171e778d2a6',
    'dnsapi/dns_bunny.sh': '7e6d55e0068b4c9f1fe6be33239db704ffaa4a297770a496dd7819dae9edc2b7',
    'dnsapi/dns_desec.sh': '7b54708d30b39adc8e5966643d6780a01676633c2a96d87205e1a8e55b47a349',
    'dnsapi/dns_duckdns.sh': '8be535b8d6270b7a37671da954d89c896df7af29c2f38d5029054ec315fe77af',
    'dnsapi/dns_ali.sh': '6cfcca209d54747dc7b48fea9aa4a2c04a6017c4464f8f23a077e3eaa187c427',
    'dnsapi/dns_dp.sh': 'a4b5b70c81235a033c6892359b09000097b88a0792b7029d14653a5494d282de',
    'dnsapi/dns_tencent.sh': 'bedbc48380d54e28d929c271495533beb77e254a50fefc258565246641163159',
}
ACME_HOME = '/opt/vortexpanel/acme'
ACME_CONF = '/etc/vortexpanel/acme'
ACME_CERTS = ACME_CONF + '/certs'
PROVIDERS_FILE = ACME_CONF + '/providers.json'
SETTINGS_FILE = '/opt/vortexpanel/data/acme.json'
WEBROOT = '/var/www/vp-acme'
PANEL_SSL_DIR = '/opt/vortexpanel/ssl'
PANEL_IP_MARK = '/opt/vortexpanel/data/acme_panel_ip.json'
NGINX_IP_CONF = '/etc/nginx/conf.d/vortex-acme-ip.conf'

# id: (name, acme.sh hook, [(variable, label, required, secret)])
PROVIDERS = {
    'vortexpanel': ('This server (VortexPanel DNS)', 'dns_vortexpanel', []),
    'cloudflare': ('Cloudflare', 'dns_cf', [('CF_Token', 'API token (Zone > DNS > Edit)', True, True),
                                            ('CF_Zone_ID', 'Zone ID (optional)', False, False),
                                            ('CF_Account_ID', 'Account ID (optional)', False, False)]),
    'digitalocean': ('DigitalOcean', 'dns_dgon', [('DO_API_KEY', 'API token', True, True)]),
    'route53': ('Amazon Route 53', 'dns_aws', [('AWS_ACCESS_KEY_ID', 'Access key ID', True, False),
                                               ('AWS_SECRET_ACCESS_KEY', 'Secret access key', True, True)]),
    'hetzner': ('Hetzner', 'dns_hetznercloud', [('HETZNER_TOKEN', 'API token (Hetzner Console)', True, True)]),
    'godaddy': ('GoDaddy', 'dns_gd', [('GD_Key', 'API key', True, False), ('GD_Secret', 'API secret', True, True)]),
    'namecheap': ('Namecheap', 'dns_namecheap', [('NAMECHEAP_USERNAME', 'Username', True, False),
                                                 ('NAMECHEAP_API_KEY', 'API key', True, True),
                                                 ('NAMECHEAP_SOURCEIP', 'Whitelisted IP of this server', True, False)]),
    'porkbun': ('Porkbun', 'dns_porkbun', [('PORKBUN_API_KEY', 'API key', True, False),
                                           ('PORKBUN_SECRET_API_KEY', 'Secret API key', True, True)]),
    'linode': ('Linode / Akamai', 'dns_linode_v4', [('LINODE_V4_API_KEY', 'Personal access token', True, True)]),
    'vultr': ('Vultr', 'dns_vultr', [('VULTR_API_KEY', 'API key', True, True)]),
    'gandi': ('Gandi LiveDNS', 'dns_gandi_livedns', [('GANDI_LIVEDNS_TOKEN', 'Personal access token', True, True)]),
    'ovh': ('OVHcloud', 'dns_ovh', [('OVH_END_POINT', 'Endpoint (ovh-eu, ovh-ca, ovh-us)', True, False),
                                    ('OVH_AK', 'Application key', True, False),
                                    ('OVH_AS', 'Application secret', True, True),
                                    ('OVH_CK', 'Consumer key', True, True)]),
    'bunny': ('Bunny DNS', 'dns_bunny', [('BUNNY_API_KEY', 'API key', True, True)]),
    'desec': ('deSEC', 'dns_desec', [('DEDYN_TOKEN', 'Token', True, True)]),
    'duckdns': ('Duck DNS', 'dns_duckdns', [('DuckDNS_Token', 'Token', True, True)]),
    'alibaba': ('Alibaba Cloud DNS', 'dns_ali', [('Ali_Key', 'AccessKey ID', True, False),
                                                 ('Ali_Secret', 'AccessKey secret', True, True)]),
    'dnspod': ('DNSPod', 'dns_dp', [('DP_Id', 'ID', True, False), ('DP_Key', 'Token', True, True)]),
    'tencent': ('Tencent Cloud DNS', 'dns_tencent', [('Tencent_SecretId', 'SecretId', True, False),
                                                     ('Tencent_SecretKey', 'SecretKey', True, True)]),
}

HOOK_SH = r'''#!/usr/bin/env sh
# VortexPanel: DNS-01 challenge records in this server's own DNS zones
dns_vortexpanel_add() {
  _vp_out=$(cd /opt/vortexpanel && ./venv/bin/python -m panel.acme_dns add "$1" "$2" 2>&1); _vp_rc=$?
  _info "$_vp_out"; return $_vp_rc
}
dns_vortexpanel_rm() {
  _vp_out=$(cd /opt/vortexpanel && ./venv/bin/python -m panel.acme_dns rm "$1" "$2" 2>&1); _vp_rc=$?
  _info "$_vp_out"; return $_vp_rc
}
'''

TIMER_SERVICE = f'''[Unit]
Description=VortexPanel certificate renewal (acme.sh)
After=network-online.target

[Service]
Type=oneshot
ExecStart={ACME_HOME}/acme.sh --cron --home {ACME_HOME} --config-home {ACME_CONF} --cert-home {ACME_CERTS}
'''
TIMER_UNIT = '''[Unit]
Description=VortexPanel certificate renewal, twice a day

[Timer]
OnCalendar=*-*-* 03,15:17:00
RandomizedDelaySec=45min
Persistent=true

[Install]
WantedBy=timers.target
'''


def req():
    return _vp_authed()


def _sh(cmd, t=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f'timed out after {t}s'


def _settings():
    try:
        with open(SETTINGS_FILE) as f:
            s = json.load(f)
    except Exception:
        s = {}
    return {'server': s.get('server') or 'letsencrypt', 'ca_bundle': s.get('ca_bundle') or '',
            'dnssleep': int(s.get('dnssleep') or 0)}


def _write_secret(path, data):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(data)
    os.chmod(path, 0o600)


# --- acme.sh installation ---------------------------------------------------
def ensure_acme(log=print):
    """Install the pinned acme.sh once, plus the local DNS hook and the
    renewal timer. Returns '' or an error."""
    os.makedirs(ACME_CONF, mode=0o700, exist_ok=True)
    os.chmod(ACME_CONF, 0o700)
    if not os.path.exists(f'{ACME_HOME}/acme.sh') or not os.path.exists(f'{ACME_HOME}/.vp-{ACME_VER}'):
        log(f'[VortexPanel] Installing acme.sh {ACME_VER}...')
        tmp = '/opt/vortexpanel/data/tmp/acme-inst'
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp, mode=0o700)
        try:
            src = f'{tmp}/acme.sh-{ACME_VER}'
            for rel, digest in ACME_FILES.items():
                dst = f'{src}/{rel}'
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                rc, out = _sh(f'curl -fsSL --max-time 60 -o {shlex.quote(dst)} {ACME_RAW}{rel}', 90)
                if rc:
                    return f'Could not download acme.sh ({rel}) from GitHub: {out[-300:]}'
                rc, out = _sh(f'echo "{digest}  {dst}" | sha256sum -c --quiet -')
                if rc:
                    return f'The acme.sh download ({rel}) does not match the expected checksum - not installed.'
            os.chmod(f'{src}/acme.sh', 0o755)
            rc, out = _sh(f'cd {src} && ./acme.sh --install --force --nocron --no-profile --home {ACME_HOME} '
                          f'--config-home {ACME_CONF} --cert-home {ACME_CERTS}', 120)
            if rc or not os.path.exists(f'{ACME_HOME}/acme.sh'):
                return f'acme.sh could not be installed: {out[-400:]}'
            open(f'{ACME_HOME}/.vp-{ACME_VER}', 'w').close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    hook = f'{ACME_HOME}/dnsapi/dns_vortexpanel.sh'
    os.makedirs(os.path.dirname(hook), exist_ok=True)
    if not os.path.exists(hook) or open(hook).read() != HOOK_SH:
        with open(hook, 'w') as f:
            f.write(HOOK_SH)
        os.chmod(hook, 0o755)
    unit = '/etc/systemd/system/vortexpanel-acme.service'
    timer = '/etc/systemd/system/vortexpanel-acme.timer'
    if not os.path.exists(timer) or open(unit).read() != TIMER_SERVICE:
        with open(unit, 'w') as f:
            f.write(TIMER_SERVICE)
        with open(timer, 'w') as f:
            f.write(TIMER_UNIT)
        _sh('systemctl daemon-reload && systemctl enable --now vortexpanel-acme.timer')
    return ''


def _base(server=None):
    s = _settings()
    cmd = (f'{ACME_HOME}/acme.sh --home {ACME_HOME} --config-home {ACME_CONF} --cert-home {ACME_CERTS} '
           f'--server {shlex.quote(server or s["server"])}')
    if s['ca_bundle']:
        cmd += f' --ca-bundle {shlex.quote(s["ca_bundle"])}'
    return cmd


def _run_logged(cmd, log, env=None, t=600):
    """Run a command, passing each output line to log(). Returns (rc, text)."""
    full = os.environ.copy()
    full.update(env or {})
    lines, pem = [], False
    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, env=full)
        start = time.time()
        for line in p.stdout:
            line = line.rstrip()
            # acme.sh prints timestamps in brackets; keep the message only
            line = re.sub(r'^\[[^\]]{10,40}\]\s*', '', line)
            # the certificate itself (PEM body) is noise in the log
            if pem or line.startswith('-----BEGIN'):
                pem = not line.startswith('-----END')
                continue
            for k, v in (env or {}).items():
                if v and len(v) > 4:
                    line = line.replace(v, '********')
            lines.append(line)
            log(line)
            if time.time() - start > t:
                p.kill()
                log(f'[VortexPanel] Stopped after {t} seconds.')
                break
        rc = p.wait()
    except Exception as e:
        return 1, str(e)
    return rc, '\n'.join(lines)


# --- providers ---------------------------------------------------------------
def _load_providers():
    try:
        with open(PROVIDERS_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_providers(data):
    _write_secret(PROVIDERS_FILE, json.dumps(data, indent=1))


def _local_zones():
    try:
        from panel.routes import dns as d
        zdir = d._zones_dir()
        return sorted(f[3:] for f in os.listdir(zdir) if f.startswith('db.'))
    except Exception:
        return []


def _zone_covers(domain):
    labels = domain.lower().split('.')
    zones = set(_local_zones())
    return any('.'.join(labels[i:]) in zones for i in range(len(labels) - 1))


@acme_bp.route('/api/ssl/acme/providers')
def list_providers():
    if not req(): return jsonify({'ok': False}), 401
    saved = _load_providers()
    domain = (request.args.get('domain') or '').lower()
    out = []
    for pid, (name, hook, fields) in PROVIDERS.items():
        have = saved.get(pid) or {}
        out.append({'id': pid, 'name': name,
                    'fields': [{'var': v, 'label': l, 'required': r, 'secret': s,
                                'saved': bool(have.get(v)),
                                'value': '' if s else have.get(v, '')} for v, l, r, s in fields],
                    'configured': pid == 'vortexpanel' or all(have.get(v) for v, l, r, s in fields if r)})
    local = _zone_covers(domain) if domain else None
    return jsonify({'ok': True, 'providers': out, 'local_zone': local,
                    'installed': os.path.exists(f'{ACME_HOME}/acme.sh')})


def _clean_creds(pid, creds, keep_saved=True):
    """Merge submitted credentials with saved ones. Returns (dict, error)."""
    if pid not in PROVIDERS:
        return None, 'Unknown DNS provider'
    fields = PROVIDERS[pid][2]
    saved = (_load_providers().get(pid) or {}) if keep_saved else {}
    out = {}
    for v, label, required, secret in fields:
        val = str((creds or {}).get(v) or '').strip()
        if not val:
            val = saved.get(v, '')
        if val and (len(val) > 400 or re.search(r'[\s\'"`$\\]', val)):
            return None, f'{label}: invalid characters'
        if required and not val:
            return None, f'{PROVIDERS[pid][0]}: {label} is required'
        if val:
            out[v] = val
    return out, ''


@acme_bp.route('/api/ssl/acme/providers/<pid>', methods=['POST', 'DELETE'])
def save_provider(pid):
    if not req(): return jsonify({'ok': False}), 401
    if pid not in PROVIDERS or pid == 'vortexpanel':
        return jsonify({'ok': False, 'error': 'Unknown DNS provider'}), 400
    data = _load_providers()
    if request.method == 'DELETE':
        data.pop(pid, None)
        _save_providers(data)
        return jsonify({'ok': True})
    creds, err = _clean_creds(pid, (request.get_json() or {}).get('creds') or {})
    if err:
        return jsonify({'ok': False, 'error': err}), 400
    data[pid] = creds
    _save_providers(data)
    return jsonify({'ok': True})


# --- jobs ----------------------------------------------------------------------
def _new_job():
    jid = 'acme-' + uuid.uuid4().hex[:12]
    save_job(jid, {'done': False, 'ok': False, 'log': []})
    return jid


class _JobLog:
    def __init__(self, jid):
        self.jid, self.lines = jid, []

    def __call__(self, line):
        self.lines.append(line)
        if len(self.lines) > 400:
            self.lines = self.lines[-400:]
        save_job(self.jid, {'done': False, 'ok': False, 'log': self.lines})

    def finish(self, ok, **extra):
        st = {'done': True, 'ok': ok, 'log': self.lines}
        st.update(extra)
        save_job(self.jid, st)


@acme_bp.route('/api/ssl/acme/job/<jid>')
def job_status(jid):
    if not req(): return jsonify({'ok': False}), 401
    if not re.fullmatch(r'acme-[0-9a-f]{12}', jid):
        return jsonify({'ok': False, 'error': 'Invalid job'}), 400
    st = load_job(jid)
    if not st:
        return jsonify({'ok': False, 'error': 'Job not found'}), 404
    return jsonify({'ok': True, **st})


# --- website certificates through DNS ------------------------------------------
def _cert_dir_conf(domain):
    for suffix in ('_ecc', ''):
        p = f'{ACME_CERTS}/{domain}{suffix}/{domain}.conf'
        if os.path.exists(p):
            return p
    return ''


def acme_info(domain):
    """{'provider': name, 'wildcard': bool} when acme.sh manages this site's certificate."""
    conf = _cert_dir_conf(domain)
    if not conf:
        return None
    txt = open(conf).read()
    hook = re.search(r"^Le_Webroot='([^']*)'", txt, re.M)
    alt = re.search(r"^Le_Alt='([^']*)'", txt, re.M)
    hook = hook.group(1) if hook else ''
    name = next((n for n, h, f in PROVIDERS.values() if h == hook), hook)
    return {'provider': name, 'wildcard': bool(alt and f'*.{domain}' in alt.group(1))}


def remove_site_cert(domain):
    """Stop renewing a site's acme.sh certificate (Disable SSL)."""
    if _cert_dir_conf(domain) and os.path.exists(f'{ACME_HOME}/acme.sh'):
        _sh(f'{_base()} --remove -d {shlex.quote(domain)} --ecc', 60)


def _reload_cmd(ws):
    if ws == 'apache':
        return 'systemctl reload apache2 2>/dev/null || systemctl reload httpd'
    if ws == 'openlitespeed':
        return '/usr/local/lsws/bin/lswsctrl reload'
    return 'systemctl reload nginx'


def _issue_site(app, jid, domain, pid, creds, wildcard, email, renew=False):
    log = _JobLog(jid)
    try:
        from panel.routes.websites_ssl import install_manual_cert, _find_site_config
        err = ensure_acme(log)
        if err:
            log('[VortexPanel] ' + err); log.finish(False); return
        name, hook, _ = PROVIDERS[pid]
        ws = _find_site_config(domain)[1] or 'nginx'
        names = [domain] + ([f'*.{domain}'] if wildcard else ([f'www.{domain}'] if domain.count('.') == 1 else []))
        s = _settings()
        if renew:
            log(f'[VortexPanel] Renewing the certificate for {domain}...')
            cmd = f'{_base()} --renew --force --ecc -d {shlex.quote(domain)}'
        else:
            log(f'[VortexPanel] Requesting a certificate for {", ".join(names)} through {name} (DNS validation)...')
            cmd = (f'{_base()} --issue --force --keylength ec-256 --dns {hook} '
                   + ' '.join(f'-d {shlex.quote(n)}' for n in names))
            if s['dnssleep']:
                cmd += f' --dnssleep {s["dnssleep"]}'
            if email:
                cmd += f' -m {shlex.quote(email)}'
        prev = os.path.dirname(_cert_dir_conf(domain))
        had_cert = bool(prev) and os.path.exists(f'{prev}/fullchain.cer')
        rc, out = _run_logged(cmd, log, env=creds, t=900)
        if rc != 0:
            if not had_cert and not renew:
                # nothing was issued: leave no entry the renewal timer would retry every day
                _sh(f'{_base()} --remove -d {shlex.quote(domain)} --ecc', 60)
                shutil.rmtree(f'{ACME_CERTS}/{domain}_ecc', ignore_errors=True)
            log('[VortexPanel] The certificate was not issued. The reason is in the lines above.')
            log.finish(False); return
        cdir = os.path.dirname(_cert_dir_conf(domain))
        cert = open(f'{cdir}/fullchain.cer').read()
        key = open(f'{cdir}/{domain}.key').read()
        with app.app_context():
            resp = install_manual_cert(domain, cert, key)
            if isinstance(resp, tuple):
                resp = resp[0]
            res = resp.get_json() or {}
        if not res.get('ok'):
            log('[VortexPanel] The certificate was issued but could not be installed: ' + str(res.get('error')))
            log.finish(False); return
        # register the installed files so every renewal copies them and reloads the web server
        rc, out = _run_logged(f'{_base()} --install-cert --ecc -d {shlex.quote(domain)} '
                              f'--fullchain-file {shlex.quote(res["cert_path"])} --key-file {shlex.quote(res["key_path"])} '
                              f'--reloadcmd {shlex.quote(_reload_cmd(ws))}', lambda l: None, t=120)
        if rc != 0:
            log('[VortexPanel] Installed, but automatic renewal could not be set up: ' + out[-300:])
            log.finish(False); return
        log(f'[VortexPanel] HTTPS is on for {domain}' + (f' and *.{domain}' if wildcard else '') +
            '. The certificate renews automatically.')
        log.finish(True)
    except Exception as e:
        log(f'[VortexPanel] Failed: {e}')
        log.finish(False)


@acme_bp.route('/api/websites/<domain>/ssl/dns', methods=['POST'])
def issue_dns(domain):
    if not req(): return jsonify({'ok': False}), 401
    from panel.routes.websites_core import is_valid_domain, _find_site_config
    if not is_valid_domain(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    fp, ws = _find_site_config(domain)
    if not fp:
        return jsonify({'ok': False, 'error': 'Website not found'}), 404
    if ws == 'caddy':
        return jsonify({'ok': False, 'error': 'Caddy obtains and renews this site\'s certificate itself.'}), 400
    d = request.get_json() or {}
    pid = d.get('provider') or ''
    if pid not in PROVIDERS:
        return jsonify({'ok': False, 'error': 'Choose a DNS provider'}), 400
    if pid == 'vortexpanel' and not _zone_covers(domain):
        return jsonify({'ok': False, 'error': f'This server has no DNS zone for {domain}. Add it in DNS first, '
                                              'or choose the provider that hosts the domain\'s DNS.'}), 400
    creds, err = _clean_creds(pid, d.get('creds') or {})
    if err:
        return jsonify({'ok': False, 'error': err}), 400
    if pid != 'vortexpanel' and d.get('save', True):
        data = _load_providers(); data[pid] = creds; _save_providers(data)
    email = (d.get('email') or '').strip()
    if email and not re.fullmatch(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', email):
        return jsonify({'ok': False, 'error': 'Enter a valid e-mail address'}), 400
    jid = _new_job()
    threading.Thread(target=_issue_site, daemon=True,
                     args=(current_app._get_current_object(), jid, domain, pid, creds,
                           bool(d.get('wildcard')), email)).start()
    return jsonify({'ok': True, 'job_id': jid})


@acme_bp.route('/api/websites/<domain>/ssl/acme-renew', methods=['POST'])
def renew_dns(domain):
    if not req(): return jsonify({'ok': False}), 401
    info = acme_info(domain)
    if not info:
        return jsonify({'ok': False, 'error': 'This certificate is not managed through a DNS provider'}), 400
    conf = open(_cert_dir_conf(domain)).read()
    hook = (re.search(r"^Le_Webroot='([^']*)'", conf, re.M) or [None, ''])[1]
    pid = next((k for k, v in PROVIDERS.items() if v[1] == hook), 'vortexpanel')
    creds = _load_providers().get(pid) or {}
    jid = _new_job()
    threading.Thread(target=_issue_site, daemon=True,
                     args=(current_app._get_current_object(), jid, domain, pid, creds,
                           info['wildcard'], '', True)).start()
    return jsonify({'ok': True, 'job_id': jid})


# --- certificate for the panel on an IP address ---------------------------------
def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _active(unit):
    return _sh(f'systemctl is-active {unit} 2>/dev/null')[1] == 'active'


def _prepare_ip_webroot(ip):
    """Make http://<ip>/.well-known/acme-challenge/ serve WEBROOT.
    Returns (mode, acme.sh args, error)."""
    os.makedirs(f'{WEBROOT}/.well-known/acme-challenge', exist_ok=True)
    _sh(f'chmod 755 {WEBROOT} {WEBROOT}/.well-known {WEBROOT}/.well-known/acme-challenge')
    names = f'{ip}' if ':' not in ip else f'[{ip}]'
    if _active('nginx') and os.path.isdir('/etc/nginx/conf.d'):
        v6 = os.path.exists('/proc/net/if_inet6') and bool(open('/proc/net/if_inet6').read().strip()) \
            and bool(_sh("grep -rqs 'listen \\[::\\]:80' /etc/nginx/ && echo y")[1])
        conf = (f'# VortexPanel: Let\'s Encrypt validation for the IP address {ip}\n'
                'server {\n    listen 80;\n' + ('    listen [::]:80;\n' if v6 else '') +
                f'    server_name {names};\n'
                f'    location ^~ /.well-known/acme-challenge/ {{ root {WEBROOT}; default_type text/plain; }}\n'
                '    location / { return 404; }\n}\n')
        old = open(NGINX_IP_CONF).read() if os.path.exists(NGINX_IP_CONF) else None
        with open(NGINX_IP_CONF, 'w') as f:
            f.write(conf)
        rc, out = _sh('nginx -t 2>&1')
        if rc:
            if old is None: os.remove(NGINX_IP_CONF)
            else:
                with open(NGINX_IP_CONF, 'w') as f: f.write(old)
            return '', '', 'nginx rejected the validation config: ' + out[-300:]
        _sh('systemctl reload nginx')
        return 'nginx', f'--webroot {WEBROOT}', ''
    apache = 'apache2' if _active('apache2') else ('httpd' if _active('httpd') else '')
    if apache:
        conf = (f'# VortexPanel: Let\'s Encrypt validation for the IP address {ip}\n'
                f'<VirtualHost *:80>\n  ServerName {names}\n'
                f'  Alias /.well-known/acme-challenge/ {WEBROOT}/.well-known/acme-challenge/\n'
                f'  <Directory {WEBROOT}/.well-known/acme-challenge/>\n    Require all granted\n  </Directory>\n'
                '</VirtualHost>\n')
        if apache == 'apache2':
            path = '/etc/apache2/sites-available/000-vortex-acme-ip.conf'
            with open(path, 'w') as f: f.write(conf)
            _sh('a2ensite -q 000-vortex-acme-ip >/dev/null 2>&1; a2enmod -q alias >/dev/null 2>&1')
            test, reload = 'apache2ctl configtest 2>&1', 'systemctl reload apache2'
        else:
            path = '/etc/httpd/conf.d/000-vortex-acme-ip.conf'
            with open(path, 'w') as f: f.write(conf)
            test, reload = 'httpd -t 2>&1', 'systemctl reload httpd'
        rc, out = _sh(test)
        if rc:
            _sh('a2dissite -q 000-vortex-acme-ip >/dev/null 2>&1'); os.remove(path)
            return '', '', 'Apache rejected the validation config: ' + out[-300:]
        _sh(reload)
        return 'apache', f'--webroot {WEBROOT}', ''
    if not _sh("ss -Hltn 'sport = :80' 2>/dev/null")[1]:
        if not shutil.which('socat'):
            _sh('DEBIAN_FRONTEND=noninteractive apt-get install -y socat 2>/dev/null || dnf install -y socat 2>/dev/null', 300)
        return 'standalone', '--standalone', ''
    running = [u for u in ('caddy', 'lsws', 'openresty') if _active(u)]
    if running:
        units = ' '.join(running)
        if not shutil.which('socat'):
            _sh('DEBIAN_FRONTEND=noninteractive apt-get install -y socat 2>/dev/null || dnf install -y socat 2>/dev/null', 300)
        return ('standalone', f"--standalone --pre-hook {shlex.quote('systemctl stop ' + units)} "
                              f"--post-hook {shlex.quote('systemctl start ' + units)}", '')
    return '', '', 'Port 80 is used by a program the panel does not manage; Let\'s Encrypt needs it to check the IP address.'


def issue_panel_ip(ip, email=''):
    """Issue a 6-day certificate for the panel's IP address and copy it to the
    panel's certificate files. Returns (ok, message)."""
    lines = []
    err = ensure_acme(lines.append)
    if err:
        return False, err
    mode, args, err = _prepare_ip_webroot(ip)
    if err:
        return False, err
    _sh('ufw allow 80/tcp 2>/dev/null; firewall-cmd --add-service=http --permanent 2>/dev/null; firewall-cmd --reload 2>/dev/null')
    cmd = (f'{_base()} --issue --force -d {shlex.quote(ip)} {args} --keylength ec-256 '
           '--certificate-profile shortlived --days -3')
    if email:
        cmd += f' -m {shlex.quote(email)}'
    rc, out = _run_logged(cmd, lines.append, t=100)
    if rc != 0:
        msg = '\n'.join(l for l in lines if l)[-900:]
        return False, 'Let\'s Encrypt did not issue the certificate:\n' + msg
    os.makedirs(PANEL_SSL_DIR, exist_ok=True)
    # The panel restarts on renewals only once the switch to HTTPS is done
    # (the marker file); the first install must not restart it mid-request.
    reload = (f'[ -f {PANEL_IP_MARK} ] && grep -q -- --certfile /etc/systemd/system/vortexpanel.service '
              '&& systemctl restart vortexpanel; true')
    if os.path.exists(PANEL_IP_MARK):
        os.remove(PANEL_IP_MARK)
    rc, out = _sh(f'{_base()} --install-cert --ecc -d {shlex.quote(ip)} --fullchain-file {PANEL_SSL_DIR}/panel.crt '
                  f'--key-file {PANEL_SSL_DIR}/panel.key --reloadcmd {shlex.quote(reload)}', 120)
    if rc != 0:
        return False, 'The certificate was issued but could not be copied for the panel: ' + out[-300:]
    os.chmod(f'{PANEL_SSL_DIR}/panel.key', 0o600)
    # a domain certificate for the panel from certbot must not overwrite this one on its next renewal
    hook = '/etc/letsencrypt/renewal-hooks/deploy/vortexpanel-panel-cert.sh'
    if os.path.exists(hook):
        os.remove(hook)
    with open(PANEL_IP_MARK, 'w') as f:
        json.dump({'ip': ip, 'mode': mode, 'issued': int(time.time())}, f)
    return True, f'Certificate for {ip} issued (valid 6 days, renewed automatically every few days).'


def remove_panel_ip_cert():
    """Another certificate is being set for the panel: stop renewing the IP one."""
    try:
        st = json.load(open(PANEL_IP_MARK))
    except Exception:
        return
    ip = st.get('ip', '')
    if ip and os.path.exists(f'{ACME_HOME}/acme.sh'):
        _sh(f'{_base()} --remove -d {shlex.quote(ip)} --ecc', 60)
    try:
        os.remove(PANEL_IP_MARK)
    except OSError:
        pass
    if os.path.exists(NGINX_IP_CONF):
        os.remove(NGINX_IP_CONF)
        _sh('nginx -t >/dev/null 2>&1 && systemctl reload nginx')
    for p in ('/etc/apache2/sites-available/000-vortex-acme-ip.conf', '/etc/httpd/conf.d/000-vortex-acme-ip.conf'):
        if os.path.exists(p):
            _sh('a2dissite -q 000-vortex-acme-ip >/dev/null 2>&1')
            os.remove(p)
            _sh('(apache2ctl configtest && systemctl reload apache2) >/dev/null 2>&1 || '
                '(httpd -t && systemctl reload httpd) >/dev/null 2>&1')
