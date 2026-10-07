"""Website Import: SSL certificate, cron jobs and mailboxes (v3.6.0).

Panel backups do not agree on where these live, so detection is generic and
works on the extracted backup tree:

  SSL   any PEM certificate whose names cover the domain and a private key
        that matches it (cPanel apache_tls/ and sslcerts/+sslkeys/,
        HestiaCP/Vesta ssl/, aaPanel vhost/cert/<domain>/ ...).
  Cron  crontab files (cPanel cron/<user>) and Hestia/Vesta cron.conf
        (JOB='..' MIN='..' ... CMD='..').
  Mail  Maildir mailboxes under <domain>/<user>/{cur,new}, with their
        password hashes from cPanel etc/<domain>/shadow or Hestia/Vesta
        accounts .conf (MD5='$6$...'), so users keep their passwords.

Everything found is shown in the import preview; only what the admin
leaves selected is imported.
"""
import os, re, json, shlex, shutil, subprocess, tempfile, time

DOMAIN_RE = re.compile(r'^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
CERT_EXT = ('.crt', '.pem', '.cert', '.cer', '.ca', '.cabundle', '.bundle')
MAX_PEM = 256 * 1024


def _run(args, inp=None, timeout=20):
    try:
        r = subprocess.run(args, input=inp, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return 1, '', str(e)


def _walk(root, max_files=200000):
    n = 0
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if not os.path.islink(os.path.join(dp, d))]
        for f in fns:
            n += 1
            if n > max_files:
                return
            yield dp, f


# --- nested archives (Hestia/Vesta keep mail and cron in inner tarballs) -------
def expand_nested(extract_dir, extract_fn, notes):
    for dp, f in list(_walk(extract_dir)):
        low = f.lower()
        if not re.match(r'^(mail|cron|accounts|ssl|conf)[\w.-]*\.(tar|tar\.gz|tgz|tar\.zst)$', low):
            continue
        dest = os.path.join(dp, '_' + re.sub(r'[^a-z0-9]', '_', low) + '_extracted')
        if os.path.isdir(dest):
            continue
        ok, err = extract_fn(os.path.join(dp, f), dest)
        notes.append(f'Extracted inner {f}' if ok else f'Could not extract inner {f}: {err}')


# --- SSL ---------------------------------------------------------------------------
_PEM_CERT = re.compile(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', re.S)
_PEM_KEY = re.compile(r'-----BEGIN (?:RSA |EC |)PRIVATE KEY-----.+?-----END (?:RSA |EC |)PRIVATE KEY-----', re.S)


def _cert_info(pem):
    rc, out, _ = _run(['openssl', 'x509', '-noout', '-subject', '-issuer', '-enddate', '-ext', 'subjectAltName', '-pubkey'],
                      inp=pem)
    if rc != 0:
        rc, out, _ = _run(['openssl', 'x509', '-noout', '-subject', '-issuer', '-enddate', '-text', '-pubkey'], inp=pem)
        if rc != 0:
            return None
    names = set(re.findall(r'DNS:([^,\s]+)', out))
    m = re.search(r'subject=.*?CN\s*=\s*([^,/\n]+)', out)
    if m:
        names.add(m.group(1).strip())
    end = re.search(r'notAfter=(.+)', out)
    pub = re.search(r'-----BEGIN PUBLIC KEY-----.+?-----END PUBLIC KEY-----', out, re.S)
    issuer = re.search(r'issuer=.*?(?:O\s*=\s*([^,/\n]+)|CN\s*=\s*([^,/\n]+))', out)
    expires = 0
    if end:
        try:
            import calendar
            expires = calendar.timegm(time.strptime(end.group(1).strip().replace(' GMT', ''), '%b %d %H:%M:%S %Y'))
        except Exception:
            expires = 0
    return {'names': sorted(n.lower() for n in names), 'expires': expires,
            'issuer': ((issuer.group(1) or issuer.group(2)).strip() if issuer else ''),
            'pub': pub.group(0).strip() if pub else ''}


def _covers(names, domain):
    for n in names:
        if n == domain:
            return True
        if n.startswith('*.') and domain.count('.') >= n.count('.') and domain.endswith(n[1:]) \
                and '.' not in domain[:-len(n) + 1]:
            return True
    return False


def detect_ssl(extract_dir, domain):
    """Best certificate (with matching key and chain) for `domain`, or None."""
    certs, keys = [], []
    for dp, f in _walk(extract_dir):
        p = os.path.join(dp, f)
        try:
            if os.path.islink(p) or os.path.getsize(p) > MAX_PEM:
                continue
            low = f.lower()
            if not (low.endswith(CERT_EXT) or low.endswith('.key') or 'apache_tls' in dp or 'ssl' in dp.lower()
                    or 'cert' in dp.lower()):
                continue
            with open(p, errors='ignore') as fh:
                txt = fh.read()
        except OSError:
            continue
        for c in _PEM_CERT.findall(txt):
            certs.append((p, c, txt))
        for k in _PEM_KEY.findall(txt):
            keys.append((p, k))
    if not certs or not keys:
        return None
    key_pubs = []
    for kp, k in keys:
        rc, out, _ = _run(['openssl', 'pkey', '-pubout'], inp=k)
        if rc == 0 and 'PUBLIC KEY' in out:
            key_pubs.append((kp, k, out.strip()))
    best = None
    for path, c, filetxt in certs:
        info = _cert_info(c)
        if not info or not _covers(info['names'], domain):
            continue
        key = next(((kp, k) for kp, k, pub in key_pubs if pub == info['pub']), None)
        if not key:
            continue
        # Chain: other certificates in the same file, else a CA bundle next to it
        chain = [x for x in _PEM_CERT.findall(filetxt) if x != c]
        if not chain:
            for cand in os.listdir(os.path.dirname(path)):
                cl = cand.lower()
                if cand != os.path.basename(path) and ('ca' in cl or 'bundle' in cl or 'chain' in cl) \
                        and cl.endswith(CERT_EXT):
                    try:
                        with open(os.path.join(os.path.dirname(path), cand), errors='ignore') as fh:
                            chain = _PEM_CERT.findall(fh.read())
                    except OSError:
                        chain = []
                    if chain:
                        break
        entry = {'cert_file': path, 'key_file': key[0], 'names': info['names'], 'expires': info['expires'],
                 'issuer': info['issuer'], 'expired': bool(info['expires']) and info['expires'] < time.time(),
                 'fullchain': c.strip() + '\n' + ''.join(x.strip() + '\n' for x in chain if x.strip() != c.strip()),
                 'key': key[1].strip() + '\n'}
        if not best or (not entry['expired'] and (best['expired'] or entry['expires'] > best['expires'])):
            best = entry
    return best


def public_ssl(s, extract_dir):
    if not s:
        return None
    return {'names': s['names'], 'expires': s['expires'], 'issuer': s['issuer'], 'expired': s['expired'],
            'cert_file': os.path.relpath(s['cert_file'], extract_dir), 'key_file': os.path.relpath(s['key_file'], extract_dir)}


# --- Cron --------------------------------------------------------------------------
_CRON_SPECIAL = {'@hourly': '0 * * * *', '@daily': '0 0 * * *', '@midnight': '0 0 * * *',
                 '@weekly': '0 0 * * 0', '@monthly': '0 0 1 * *', '@yearly': '0 0 1 1 *', '@annually': '0 0 1 1 *'}
_FIELD = re.compile(r'^[\d*/,\-A-Za-z]+$')


def _parse_crontab(txt):
    jobs = []
    for line in txt.splitlines():
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', s):
            continue  # MAILTO=, SHELL=, PATH=
        parts = s.split(None, 1)
        if parts and parts[0] in _CRON_SPECIAL and len(parts) == 2:
            jobs.append({'schedule': _CRON_SPECIAL[parts[0]], 'command': parts[1]})
            continue
        if parts and parts[0] == '@reboot':
            continue
        parts = s.split(None, 5)
        if len(parts) == 6 and all(_FIELD.match(p) for p in parts[:5]):
            jobs.append({'schedule': ' '.join(parts[:5]), 'command': parts[5]})
    return jobs


def _parse_hestia_cron(txt):
    jobs = []
    for line in txt.splitlines():
        kv = dict(re.findall(r"(\w+)='((?:[^'\\]|\\.)*)'", line))
        if 'CMD' not in kv or 'MIN' not in kv:
            continue
        if kv.get('SUSPENDED', 'no') == 'yes':
            continue
        sched = ' '.join(kv.get(k, '*') for k in ('MIN', 'HOUR', 'DAY', 'MONTH', 'WDAY'))
        cmd = kv['CMD'].replace("%quote%", "'").replace('%dquote%', '"')
        jobs.append({'schedule': sched, 'command': cmd})
    return jobs


def detect_cron(extract_dir):
    found = []
    for dp, f in _walk(extract_dir):
        p = os.path.join(dp, f)
        rel = os.path.relpath(p, extract_dir)
        low = rel.lower()
        try:
            if os.path.islink(p) or os.path.getsize(p) > 256 * 1024:
                continue
        except OSError:
            continue
        kind = None
        if f == 'cron.conf' or (low.endswith('.conf') and '/cron' in '/' + low):
            kind = 'hestia'
        elif re.search(r'(^|/)cron(tab)?s?/[^/]+$', low) or f in ('crontab', 'cron', 'crontab.txt') or f.endswith('.cron'):
            kind = 'crontab'
        if not kind:
            continue
        try:
            with open(p, errors='ignore') as fh:
                txt = fh.read()
        except OSError:
            continue
        jobs = _parse_hestia_cron(txt) if kind == 'hestia' else _parse_crontab(txt)
        for j in jobs:
            j['source'] = rel
            if j not in found:
                found.append(j)
    return found[:100]


def rewrite_paths(cmd, new_root, domain):
    """Point paths of the old account at the imported site."""
    pats = [
        r'/home/[A-Za-z0-9_.-]+/public_html',                              # cPanel
        r'/home/[A-Za-z0-9_.-]+/web/' + re.escape(domain) + r'/public_html',  # Hestia / Vesta
        r'/home/[A-Za-z0-9_.-]+/domains/' + re.escape(domain) + r'/public_html',  # DirectAdmin
        r'/home/' + re.escape(domain) + r'/public_html',                   # CyberPanel
        r'/www/wwwroot/' + re.escape(domain),                              # aaPanel
    ]
    out = cmd
    for p in pats:
        out = re.sub(p, new_root, out)
    return out


# --- Mail --------------------------------------------------------------------------
_SCHEMES = (('$6$', 'SHA512-CRYPT'), ('$5$', 'SHA256-CRYPT'), ('$1$', 'MD5-CRYPT'),
            ('$2y$', 'BLF-CRYPT'), ('$2b$', 'BLF-CRYPT'), ('$2a$', 'BLF-CRYPT'))


def dovecot_hash(h):
    h = (h or '').strip()
    if h.startswith('{') and '}' in h:
        return h
    for pre, scheme in _SCHEMES:
        if h.startswith(pre):
            return '{' + scheme + '}' + h
    return None


def _hashes(extract_dir):
    """{(domain, user): hash} from cPanel shadow files and Hestia/Vesta confs."""
    out = {}
    for dp, f in _walk(extract_dir):
        p = os.path.join(dp, f)
        try:
            if os.path.islink(p) or os.path.getsize(p) > 2 * 1024 * 1024:
                continue
        except OSError:
            continue
        parts = os.path.relpath(p, extract_dir).split('/')
        doms = [x.lower() for x in parts[:-1] if DOMAIN_RE.match(x.lower())]
        if f == 'shadow' and doms:
            try:
                with open(p, errors='ignore') as fh:
                    for line in fh:
                        bits = line.strip().split(':')
                        if len(bits) >= 2 and re.fullmatch(r'[A-Za-z0-9._+-]+', bits[0]) and dovecot_hash(bits[1]):
                            out[(doms[-1], bits[0].lower())] = dovecot_hash(bits[1])
            except OSError:
                pass
        elif f.endswith('.conf'):
            try:
                with open(p, errors='ignore') as fh:
                    txt = fh.read()
            except OSError:
                continue
            if "ACCOUNT='" not in txt:
                continue
            dom = doms[-1] if doms else (f[:-5].lower() if DOMAIN_RE.match(f[:-5].lower()) else '')
            for line in txt.splitlines():
                kv = dict(re.findall(r"(\w+)='([^']*)'", line))
                h = dovecot_hash(kv.get('MD5', ''))
                if kv.get('ACCOUNT') and h and dom:
                    out[(dom, kv['ACCOUNT'].lower())] = h
    return out


def detect_mail(extract_dir):
    boxes = []
    seen = set()
    for dp, dns, fns in os.walk(extract_dir):
        dns[:] = [d for d in dns if not os.path.islink(os.path.join(dp, d))]
        if 'cur' in dns and 'new' in dns:
            user = os.path.basename(dp).lower()
            dom = os.path.basename(os.path.dirname(dp)).lower()
            if user.startswith('.') or not DOMAIN_RE.match(dom) or not re.fullmatch(r'[a-z0-9._+-]{1,64}', user):
                continue
            key = (dom, user)
            if key in seen:
                continue
            seen.add(key)
            msgs = 0
            size = 0
            for sdp, sdns, sfns in os.walk(dp):
                if os.path.basename(sdp) in ('cur', 'new'):
                    msgs += len(sfns)
                for x in sfns:
                    try:
                        size += os.lstat(os.path.join(sdp, x)).st_size
                    except OSError:
                        pass
            boxes.append({'email': f'{user}@{dom}', 'domain': dom, 'user': user, 'maildir': dp,
                          'messages': msgs, 'size': size})
    hashes = _hashes(extract_dir) if boxes else {}
    for b in boxes:
        b['has_password'] = (b['domain'], b['user']) in hashes
    return boxes[:500], hashes


def mail_ready():
    try:
        from panel.routes.mail import _mail_configured
        return bool(_mail_configured())
    except Exception:
        return False


def import_mailbox(box, pw_hash, log):
    """Create the account (keeping its password hash when there is one) and
    copy its Maildir. Returns (ok, generated_password_or_None)."""
    from panel.routes import mail as m
    email = box['email']
    if not m._EMAIL_RE.match(email):
        log(f'[WARN] Skipping {email}: invalid address')
        return False, None
    if any(m._first_token(l) == email for l in m._read_lines(m.MAIL_USERS_FILE)):
        log(f'[WARN] Skipping {email}: the account already exists here')
        return False, None
    domain, user = box['domain'], box['user']
    path = '/etc/postfix/virtual_mailbox_domains'
    if os.path.isdir('/etc/postfix') and not any(m._first_token(l) == domain for l in m._read_lines(path)):
        with open(path, 'a') as f:
            f.write(f'{domain} OK\n')
        m.run(['postmap', path])
        log(f'[VortexPanel] Added mail domain {domain}')
    generated = None
    if not pw_hash:
        import secrets, string
        generated = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
        pw_hash, err = m._hash_password(generated)
        if not pw_hash:
            log(f'[ERROR] {email}: {err}')
            return False, None
    dest = os.path.join(m.VMAIL_BASE, domain, user)
    os.makedirs(dest, exist_ok=True)
    r = subprocess.run(['cp', '-a', '--', box['maildir'].rstrip('/') + '/.', dest + '/'], capture_output=True,
                       text=True, timeout=3600)
    if r.returncode != 0:
        log(f'[ERROR] {email}: copying the mailbox failed: {r.stderr.strip()[:200]}')
        return False, None
    for sub in ('cur', 'new', 'tmp'):
        os.makedirs(os.path.join(dest, sub), exist_ok=True)
    # Old Dovecot index files are rebuilt; stale ones only cause warnings.
    subprocess.run(['find', dest, '-name', 'dovecot.index*', '-type', 'f', '-delete'], capture_output=True, timeout=600)
    subprocess.run(['chown', '-R', 'vmail:vmail', os.path.join(m.VMAIL_BASE, domain)], capture_output=True, timeout=600)
    maps = '/etc/postfix/virtual_mailbox_maps'
    if os.path.exists(maps):
        with open(maps, 'a') as fh:
            fh.write(f'{email} {domain}/{user}/\n')
        m.run(['postmap', maps])
    m._write_private(m.MAIL_USERS_FILE, ''.join(m._read_lines(m.MAIL_USERS_FILE)) + f'{email}:{pw_hash}\n')
    m._sync_dovecot_users()
    return True, generated


def reload_mail():
    subprocess.run('systemctl reload postfix dovecot 2>/dev/null', shell=True, timeout=60)
