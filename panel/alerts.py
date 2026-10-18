"""Alerts: notify by email, Telegram or webhook when something needs attention.

Evaluated every minute after the metrics sample (panel.tasks metrics):
  cpu / mem / disk above a threshold for N minutes
  a service stopped (web server, database, PHP-FPM, ...)
  a website not answering (HTTP check every 5 minutes)
  an SSL certificate expiring within N days (checked twice a day)
  a scheduled backup failed (sitebackup records failures)
  repeated failed panel sign-ins
  SSH sign-ins to the server (each successful login; bursts of failures)
  events reported by other parts of the panel through notify_event():
  a failed Git deploy, malware found by a scan
Each alert fires once, repeats at most every `repeat_minutes` while the
problem lasts, and sends a "resolved" message when it clears.

Settings: data/alerts.json (0600). History: data/alerts_history.jsonl.
"""
import json
import os
import re
import smtplib
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from email.message import EmailMessage

CONF = '/opt/vortexpanel/data/alerts.json'
STATE = '/opt/vortexpanel/data/alerts_state.json'
HISTORY = '/opt/vortexpanel/data/alerts_history.jsonl'

DEFAULTS = {
    'enabled': False,
    'channels': {
        'email': {'enabled': False, 'to': '', 'from': '', 'host': '', 'port': 587, 'security': 'starttls',
                  'username': '', 'password': ''},
        'telegram': {'enabled': False, 'bot_token': '', 'chat_id': ''},
        'webhook': {'enabled': False, 'url': '', 'format': 'json'},      # json | slack | discord
    },
    'rules': {
        'cpu': {'enabled': True, 'threshold': 90, 'minutes': 5},
        'mem': {'enabled': True, 'threshold': 90, 'minutes': 5},
        'disk': {'enabled': True, 'threshold': 90},
        'services': {'enabled': True},
        'sites': {'enabled': False, 'timeout': 10},
        'ssl': {'enabled': True, 'days': 14},
        'backups': {'enabled': True},
        'logins': {'enabled': True, 'failures': 20, 'minutes': 10},
        'ssh': {'enabled': False, 'success': True, 'failures': 30, 'minutes': 10},
        'deploy': {'enabled': True},
        'malware': {'enabled': True},
        'botprot': {'enabled': True},
    },
    'repeat_minutes': 180,
}

_SECRET_KEYS = ('password', 'bot_token')


def _merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = _merge(base[k], v) if isinstance(base.get(k), dict) and isinstance(v, dict) else v
    return out


def load():
    try:
        with open(CONF) as f:
            return _merge(DEFAULTS, json.load(f))
    except Exception:
        return json.loads(json.dumps(DEFAULTS))


def save(cfg):
    os.makedirs(os.path.dirname(CONF), mode=0o700, exist_ok=True)
    tmp = CONF + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CONF)


def public(cfg):
    """Settings for the browser: secrets replaced by a flag."""
    c = json.loads(json.dumps(cfg))
    for ch in c['channels'].values():
        for k in _SECRET_KEYS:
            if k in ch:
                ch[k + '_set'] = bool(ch[k])
                ch[k] = ''
    return c


def update_from(cfg, incoming):
    """Apply settings from the browser; empty secrets keep the stored ones."""
    new = _merge(cfg, {k: incoming[k] for k in ('enabled', 'rules', 'repeat_minutes') if k in incoming})
    for name, ch in (incoming.get('channels') or {}).items():
        if name not in new['channels'] or not isinstance(ch, dict):
            continue
        for k, v in ch.items():
            if k.endswith('_set'):
                continue
            if k in _SECRET_KEYS and not v:
                continue
            if k in DEFAULTS['channels'][name]:
                new['channels'][name][k] = v
    return new


def server_name():
    try:
        name = socket.gethostname()
    except Exception:
        name = 'server'
    try:
        cfg = json.load(open('/opt/vortexpanel/config.json'))
        if cfg.get('panel_name') and cfg['panel_name'] != 'VortexPanel':
            name = f'{cfg["panel_name"]} ({name})'
    except Exception:
        pass
    return name


# --- channels ----------------------------------------------------------------------
def _send_email(ch, subject, body):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = ch.get('from') or ch.get('username') or 'vortexpanel@' + socket.gethostname()
    msg['To'] = ch['to']
    msg.set_content(body)
    port = int(ch.get('port') or 587)
    sec = ch.get('security', 'starttls')
    ctx = ssl.create_default_context()
    if sec == 'ssl':
        s = smtplib.SMTP_SSL(ch['host'], port, timeout=20, context=ctx)
    else:
        s = smtplib.SMTP(ch['host'], port, timeout=20)
        if sec == 'starttls':
            s.starttls(context=ctx)
    try:
        if ch.get('username'):
            s.login(ch['username'], ch.get('password', ''))
        s.send_message(msg)
    finally:
        try:
            s.quit()
        except Exception:
            pass


def _post_json(url, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json',
                                                          'User-Agent': 'VortexPanel alerts'})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.status


def _send_telegram(ch, subject, body):
    url = f'https://api.telegram.org/bot{ch["bot_token"]}/sendMessage'
    _post_json(url, {'chat_id': ch['chat_id'], 'text': f'{subject}\n\n{body}'[:4000],
                     'disable_web_page_preview': True})


def _send_webhook(ch, subject, body, event):
    fmt = ch.get('format', 'json')
    if fmt == 'slack':
        payload = {'text': f'*{subject}*\n{body}'}
    elif fmt == 'discord':
        payload = {'content': f'**{subject}**\n{body}'[:1900]}
    else:
        payload = {'subject': subject, 'message': body, **(event or {})}
    _post_json(ch['url'], payload)


def send(subject, body, cfg=None, event=None, only=None):
    """Send to every enabled channel (or just `only`). Returns {channel: error|''}."""
    cfg = cfg or load()
    res = {}
    for name, ch in cfg['channels'].items():
        if only and name != only:
            continue
        if not only and not ch.get('enabled'):
            continue
        try:
            if name == 'email':
                if not (ch.get('host') and ch.get('to')):
                    raise ValueError('SMTP server and recipient are required')
                _send_email(ch, subject, body)
            elif name == 'telegram':
                if not (ch.get('bot_token') and ch.get('chat_id')):
                    raise ValueError('bot token and chat ID are required')
                _send_telegram(ch, subject, body)
            elif name == 'webhook':
                if not re.match(r'^https?://', ch.get('url') or ''):
                    raise ValueError('a webhook URL (https://...) is required')
                _send_webhook(ch, subject, body, event)
            res[name] = ''
        except Exception as e:
            res[name] = str(e)[:300]
    return res


# --- checks ------------------------------------------------------------------------
_SERVICES = ['nginx', 'apache2', 'httpd', 'lsws', 'caddy', 'mysql', 'mariadb', 'postgresql', 'mongod',
             'redis-server', 'redis', 'memcached', 'pure-ftpd', 'fail2ban', 'named', 'bind9', 'postfix',
             'dovecot', 'docker', 'supervisor', 'supervisord']


def _enabled_units():
    """Services that are enabled at boot (so 'stopped' is a problem)."""
    try:
        out = subprocess.run(['systemctl', 'list-unit-files', '--type=service', '--state=enabled',
                              '--no-legend', '--plain'], capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return []
    names = [l.split()[0][:-len('.service')] for l in out.splitlines() if l.split() and l.split()[0].endswith('.service')]
    want = [n for n in names if n in _SERVICES or re.fullmatch(r'php[\d.]*-fpm|php\d+-php-fpm|php-fpm', n)]
    return sorted(set(want))


def _inactive(units):
    if not units:
        return []
    try:
        out = subprocess.run(['systemctl', 'is-active'] + units, capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return []
    states = out.split()
    return [u for u, s in zip(units, states) if s not in ('active', 'activating', 'reloading')]


def _ssl_expiring(days):
    out = []
    try:
        from panel.routes.websites_core import list_sites
        for s in list_sites():
            d = s.get('ssl_days')
            if s.get('ssl') and isinstance(d, int) and d >= 0 and d <= days:
                out.append((s['domain'], d))
    except Exception:
        pass
    return out


def _site_down(timeout):
    down = []
    try:
        from panel.routes.websites_core import list_sites
        sites = [s for s in list_sites() if s.get('enabled', True)]
    except Exception:
        return []
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    for s in sites[:50]:
        dom = s['domain'].lstrip('*.')
        scheme = 'https' if s.get('ssl') else 'http'
        # Ask the local web server directly (no DNS): SNI/Host via the URL.
        url = f'{scheme}://{dom}/'
        try:
            req = urllib.request.Request(url, method='HEAD', headers={'User-Agent': 'VortexPanel uptime check'})
            # resolve to localhost so a DNS problem is not reported as an outage
            orig = socket.getaddrinfo
            socket.getaddrinfo = lambda host, *a, **k: orig('127.0.0.1' if host == dom else host, *a, **k)
            try:
                code = opener.open(req, timeout=timeout).status
            finally:
                socket.getaddrinfo = orig
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception as e:
            down.append((dom, str(e)[:120]))
            continue
        if code >= 500:
            down.append((dom, f'HTTP {code}'))
    return down


def _failed_logins(minutes):
    path = '/opt/vortexpanel/login_audit.log'
    n = 0
    cutoff = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time() - minutes * 60))
    try:
        with open(path) as f:
            for line in f.readlines()[-2000:]:
                if line[:19] >= cutoff and '| FAILED' in line:
                    n += 1
    except Exception:
        pass
    return n


def _failed_backups():
    try:
        from panel import sitebackup
        return sitebackup.recent_failures() if hasattr(sitebackup, 'recent_failures') else []
    except Exception:
        return []


def _load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return {'active': {}, 'last_sites': 0, 'last_ssl': 0, 'seen_backup_failures': []}


def _save_state(st):
    tmp = STATE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(st, f)
    os.replace(tmp, STATE)


def _record(entry):
    try:
        fd = os.open(HISTORY, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, 'a') as f:
            f.write(json.dumps(entry) + '\n')
        if os.path.getsize(HISTORY) > 1_000_000:
            lines = open(HISTORY).readlines()[-2000:]
            with open(HISTORY, 'w') as f:
                f.writelines(lines)
    except Exception:
        pass


def history(limit=200):
    try:
        lines = open(HISTORY).readlines()[-limit:]
    except Exception:
        return []
    out = []
    for l in reversed(lines):
        try:
            out.append(json.loads(l))
        except Exception:
            pass
    return out


def notify_event(rule, title, detail, extra=None):
    """Send a one-off event (no repeat/resolve cycle) when alerts and the
    rule are on. Returns the send result or None."""
    cfg = load()
    if not cfg.get('enabled') or not (cfg.get('rules', {}).get(rule) or {}).get('enabled'):
        return None
    host = server_name()
    subj = f'[{host}] {title}'
    res = send(subj, detail, cfg, dict({'event': rule, 'server': host}, **(extra or {})))
    _record({'time': int(time.time()), 'key': f'{rule}:{title}', 'title': subj, 'state': 'event', 'result': res})
    return res


def _ssh_events(cfg, st, now):
    """New SSH sign-ins since the last run (and failure bursts)."""
    r = cfg['rules'].get('ssh') or {}
    if not r.get('enabled'):
        return []
    try:
        from panel import sshlog
    except Exception:
        return []
    since = st.get('ssh_since') or (now - 120)
    evs = sshlog.events(since=since)
    st['ssh_since'] = now
    out = []
    if r.get('success', True):
        for e in evs:
            if e['result'] == 'accepted':
                out.append((f'SSH sign-in: {e["user"]} from {e["ip"]}',
                            f'{e["user"]} signed in over SSH from {e["ip"]} ({e["method"]}) at '
                            f'{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["time"]))}. '
                            f'If this was not you, change the password, check ~/.ssh/authorized_keys and block the address '
                            f'(Security > SSH sign-ins).'))
    fails = [e for e in evs if e['result'] != 'accepted']
    st.setdefault('ssh_fail_window', [])
    st['ssh_fail_window'] = [t for t in st['ssh_fail_window'] if t > now - int(r.get('minutes', 10)) * 60] + [e['time'] for e in fails]
    if len(st['ssh_fail_window']) >= int(r.get('failures', 30)) and now - st.get('ssh_fail_alerted', 0) > 3600:
        st['ssh_fail_alerted'] = now
        ips = {}
        for e in fails:
            ips[e['ip']] = ips.get(e['ip'], 0) + 1
        top = ', '.join(f'{ip} ({n})' for ip, n in sorted(ips.items(), key=lambda x: -x[1])[:5])
        out.append(('Many failed SSH sign-ins', f'{len(st["ssh_fail_window"])} failed SSH sign-ins in the last '
                    f'{r.get("minutes", 10)} minutes. Top addresses: {top or "-"}. Fail2ban (App Store) blocks these automatically.'))
    return out


def evaluate(now=None):
    """Run every rule once. Returns the list of messages sent."""
    cfg = load()
    if not cfg.get('enabled'):
        return []
    now = now or time.time()
    st = _load_state()
    rules = cfg['rules']
    problems = {}           # key -> (title, detail)

    try:
        from panel import metrics
        for key in ('cpu', 'mem'):
            r = rules[key]
            if r.get('enabled'):
                pts = metrics.recent(int(r.get('minutes', 5)))
                if len(pts) >= max(2, int(r.get('minutes', 5)) - 1) and all((p[key] or 0) >= float(r['threshold']) for p in pts):
                    avg = sum(p[key] for p in pts) / len(pts)
                    name = 'CPU' if key == 'cpu' else 'Memory'
                    problems[key] = (f'{name} usage is high', f'{name} has been above {r["threshold"]}% for '
                                     f'{r.get("minutes", 5)} minutes (average {avg:.0f}%).')
        r = rules['disk']
        if r.get('enabled'):
            pts = metrics.recent(2)
            if pts and (pts[-1]['disk'] or 0) >= float(r['threshold']):
                problems['disk'] = ('Disk almost full', f'The root disk is {pts[-1]["disk"]:.0f}% full '
                                    f'(alert at {r["threshold"]}%). Disk Usage shows what takes the space.')
    except Exception:
        pass

    if rules['services'].get('enabled'):
        for u in _inactive(_enabled_units()):
            problems[f'svc:{u}'] = (f'Service {u} is not running',
                                    f'{u} is enabled at boot but not running. Check it under App Store > {u} > Service, '
                                    f'or: journalctl -u {u} -n 50')

    if rules['sites'].get('enabled'):
        if now - st.get('last_sites', 0) >= 300:
            st['last_sites'] = now
            st['sites_down'] = _site_down(int(rules['sites'].get('timeout', 10)))
        for dom, why in st.get('sites_down', []):
            problems[f'site:{dom}'] = (f'Website {dom} is down', f'{dom} did not answer correctly: {why}')

    if rules['ssl'].get('enabled'):
        if now - st.get('last_ssl', 0) >= 12 * 3600:
            st['last_ssl'] = now
            st['ssl_expiring'] = _ssl_expiring(int(rules['ssl'].get('days', 14)))
        for dom, d in st.get('ssl_expiring', []):
            problems[f'ssl:{dom}'] = (f'SSL certificate for {dom} expires in {d} day{"s" if d != 1 else ""}',
                                      f'Renew it under Websites > {dom} > SSL. Let\'s Encrypt certificates renew '
                                      f'automatically; if this one did not, the renewal log explains why.')

    if rules['logins'].get('enabled'):
        n = _failed_logins(int(rules['logins'].get('minutes', 10)))
        if n >= int(rules['logins'].get('failures', 20)):
            problems['logins'] = ('Many failed panel sign-ins',
                                  f'{n} failed sign-ins in the last {rules["logins"].get("minutes", 10)} minutes. '
                                  f'Consider an IP allowlist or a login path (Settings).')

    sent = []
    host = server_name()
    repeat = int(cfg.get('repeat_minutes', 180)) * 60
    active = st.get('active', {})

    for title, detail in _ssh_events(cfg, st, now):
        subj = f'[{host}] {title}'
        res = send(subj, detail, cfg, {'event': 'ssh', 'server': host})
        _record({'time': int(now), 'key': 'ssh', 'title': subj, 'state': 'event', 'result': res})
        sent.append(subj)

    if rules['backups'].get('enabled'):
        seen = set(st.get('seen_backup_failures', []))
        for f in _failed_backups():
            fid = f.get('id') or f'{f.get("domain")}:{f.get("time")}'
            if fid in seen:
                continue
            seen.add(fid)
            subj = f'[{host}] Backup of {f.get("domain")} failed'
            body = f'The scheduled backup of {f.get("domain")} failed: {f.get("error", "")}'
            res = send(subj, body, cfg, {'event': 'backup_failed', 'server': host, 'domain': f.get('domain')})
            _record({'time': int(now), 'key': 'backup:' + str(f.get('domain')), 'title': subj, 'state': 'firing',
                     'result': res})
            sent.append(subj)
        st['seen_backup_failures'] = list(seen)[-200:]

    for key, (title, detail) in problems.items():
        a = active.get(key)
        if a and now - a.get('last_sent', 0) < repeat:
            continue
        subj = f'[{host}] {title}'
        res = send(subj, detail + f'\n\nServer: {host}\nTime: {time.strftime("%Y-%m-%d %H:%M %Z")}', cfg,
                   {'event': 'alert', 'key': key, 'state': 'firing', 'server': host})
        active[key] = {'since': (a or {}).get('since', now), 'last_sent': now, 'title': title}
        _record({'time': int(now), 'key': key, 'title': title, 'detail': detail, 'state': 'firing', 'result': res})
        sent.append(subj)
    for key in [k for k in active if k not in problems]:
        a = active.pop(key)
        subj = f'[{host}] Resolved: {a.get("title", key)}'
        mins = int((now - a.get('since', now)) / 60)
        res = send(subj, f'This is back to normal after {mins} minute{"s" if mins != 1 else ""}.', cfg,
                   {'event': 'alert', 'key': key, 'state': 'resolved', 'server': host})
        _record({'time': int(now), 'key': key, 'title': a.get('title', key), 'state': 'resolved', 'result': res})
        sent.append(subj)
    st['active'] = active
    _save_state(st)
    return sent
