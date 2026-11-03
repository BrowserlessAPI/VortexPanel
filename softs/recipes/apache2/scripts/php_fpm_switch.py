#!/usr/bin/env python3
"""mod_php -> PHP-FPM, used when Apache moves from the OS packages to the VortexPanel build.

Without mod_php, php_value/php_flag/php_admin_* in Apache configuration and .htaccess are
errors (config test failure, HTTP 500), and PHP reads fpm/php.ini instead of apache2/php.ini.
Everything is converted so websites keep the same PHP settings:

  former mod_php traffic   -> its own pool vortex-modphp (socket /run/php/vortex-modphp-X.Y.sock)
                              carrying the apache2/php.ini values that differ from fpm/php.ini
                              and the server-level php_value/php_flag directives; websites that
                              were already on PHP-FPM (and the www pool) are not changed
  a website (VirtualHost)  -> its own pool (pool.d/vortex-<site>.conf): the same values plus the
                              website's own, and a SetHandler to that pool's socket
  <Directory /path>       -> php_value/php_flag: /path/.user.ini (php_admin_* in a VirtualHost:
                             that website's pool)
  .htaccess               -> .user.ini in the same folder
Directives inside <IfModule mod_php...> are left alone (they simply switch off).

    php_fpm_switch.py precheck VERSIONS   lists what cannot be converted (exit 1), changes nothing
    php_fpm_switch.py convert VERSION     converts; every file outside /etc/apache2 it changes is
                                          backed up and listed in STATE/changes.json
    php_fpm_switch.py undo                puts those files back (a failed switch)
    php_fpm_switch.py sites               converted websites to test: "host port scheme" lines
Paths can be moved for tests: VP_APACHE_ETC, VP_PHP_ETC, VP_SWITCH_STATE.
"""
import glob
import hashlib
import json
import os
import re
import shutil
import sys

E = os.environ.get('VP_APACHE_ETC', '/etc/apache2')
PHPE = os.environ.get('VP_PHP_ETC', '/etc/php')
ST = os.environ.get('VP_SWITCH_STATE', '/var/lib/vortex-apache-switch')
MARK_INI = '# VortexPanel (moved to .user.ini): '
MARK_FPM = '# VortexPanel (moved to PHP-FPM): '
DIRECTIVE = re.compile(r'^(\s*)(php_value|php_flag|php_admin_value|php_admin_flag)\s+(\S+)(?:\s+(.*?))?\s*$', re.I)
OPEN = re.compile(r'^\s*<\s*([A-Za-z]+)\s*([^>]*)>')
CLOSE = re.compile(r'^\s*<\s*/\s*([A-Za-z]+)\s*>')
WALK_DEPTH, WALK_MAX = 12, 60000          # .htaccess search per website: folders deep, entries


def log(msg):
    print(f'[apache2] {msg}', flush=True)


# ----------------------------------------------------------------------- reading

def conf_files():
    out = []
    pats = ['apache2.conf', 'ports.conf', 'conf-enabled/*.conf', 'sites-enabled/*', 'mods-enabled/*.conf']
    for p in pats:
        for f in sorted(glob.glob(os.path.join(E, p))):
            if os.path.isfile(f) and not re.match(r'php\d', os.path.basename(f)):
                out.append(f)
    seen, res = set(), []
    for f in out:
        r = os.path.realpath(f)
        if r not in seen:
            seen.add(r)
            res.append(r)
    return res


def unquote(v):
    v = (v or '').strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in '"\'':
        v = v[1:-1]
    return v


def scan(path):
    """-> (directives, vhosts). A directive: file, line, kind, name, value, ctx;
    ctx: ifmod_php, vhost (index), dir (path or None), other (block name or None)."""
    lines = open(path, errors='replace').read().split('\n')
    stack, dirs, vhosts = [], [], []
    for i, line in enumerate(lines):
        s = line.split('#', 1)[0] if not line.lstrip().startswith('#') else ''
        if not s.strip():
            continue
        m = CLOSE.match(s)
        if m:
            name = m.group(1).lower()
            for k in range(len(stack) - 1, -1, -1):
                if stack[k][0] == name:
                    if name == 'virtualhost':
                        vhosts[stack[k][2]]['end'] = i
                    del stack[k:]
                    break
            continue
        m = OPEN.match(s)
        if m:
            name, arg = m.group(1).lower(), unquote(m.group(2))
            idx = None
            if name == 'virtualhost':
                idx = len(vhosts)
                vhosts.append({'file': path, 'start': i, 'end': None, 'addr': arg, 'names': [], 'docroot': '',
                               'proxy': False})
            stack.append((name, arg, idx))
            continue
        vh = next((b[2] for b in reversed(stack) if b[0] == 'virtualhost'), None)
        w = s.split()
        if vh is not None and w:
            k = w[0].lower()
            if k == 'servername' and len(w) > 1:
                vhosts[vh]['names'].insert(0, w[1].split(':')[0].lower())
            elif k == 'serveralias':
                vhosts[vh]['names'] += [x.lower() for x in w[1:]]
            elif k == 'documentroot' and len(w) > 1:
                vhosts[vh]['docroot'] = unquote(' '.join(w[1:]))
            elif (k == 'sethandler' and 'proxy:unix:' in s) or (k in ('proxypassmatch', 'proxypass') and 'fcgi://' in s):
                vhosts[vh]['proxy'] = True
        d = DIRECTIVE.match(line)
        if d:
            ifmod = any(b[0] == 'ifmodule' and 'php' in b[1].lower() for b in stack)
            inner = [b for b in stack if b[0] not in ('ifmodule', 'ifdefine', 'virtualhost', 'ifversion')]
            dirblk = inner[-1] if inner else None
            ctx = {'ifmod_php': ifmod, 'vhost': vh, 'dir': None, 'other': None}
            if dirblk:
                if dirblk[0] == 'directory' and not re.search(r'[*?\[]', dirblk[1]) and dirblk[1].startswith('/'):
                    ctx['dir'] = dirblk[1].rstrip('/') or '/'
                else:
                    ctx['other'] = f'<{dirblk[0]} {dirblk[1]}>'
            dirs.append({'file': path, 'line': i, 'kind': d.group(2).lower(), 'name': d.group(3),
                         'value': unquote(d.group(4)), 'ctx': ctx})
    return dirs, vhosts


def load_all():
    allv, alld = [], []
    for f in conf_files():
        d, v = scan(f)
        base = len(allv)
        for x in d:
            if x['ctx']['vhost'] is not None:
                x['ctx']['vhost'] += base
        allv += v
        alld += d
    return alld, allv


def unconvertible(dirs):
    out = []
    for x in dirs:
        c = x['ctx']
        if c['ifmod_php']:
            continue
        if c['other']:
            out.append(f"{x['file']}:{x['line'] + 1}: {x['kind']} {x['name']} inside {c['other']} (PHP-FPM cannot apply "
                       f"settings per URL or file pattern; move it to the website's folder or .user.ini)")
        elif c['dir'] and x['kind'].startswith('php_admin') and c['vhost'] is None:
            out.append(f"{x['file']}:{x['line'] + 1}: {x['kind']} {x['name']} for {c['dir']} outside a website "
                       f"(no website pool to carry it)")
    return out


# -------------------------------------------------------------------- changing

class Changes:
    def __init__(self):
        os.makedirs(os.path.join(ST, 'backups'), exist_ok=True)
        self.path = os.path.join(ST, 'changes.json')
        try:
            self.items = json.load(open(self.path))
        except (OSError, ValueError):
            self.items = []
        self.known = {x['path'] for x in self.items}

    def touch(self, path):
        """Call before changing or creating path (outside /etc/apache2)."""
        if path in self.known:
            return
        bak = None
        if os.path.lexists(path):
            bak = os.path.join(ST, 'backups', hashlib.sha1(path.encode()).hexdigest())
            shutil.copy2(path, bak)
        self.items.append({'path': path, 'backup': bak})
        self.known.add(path)
        self.save()

    def save(self):
        tmp = self.path + '.tmp'
        json.dump(self.items, open(tmp, 'w'), indent=1)
        os.replace(tmp, self.path)


def ini_value(v, flag=False):
    if flag:
        return 'On' if v.lower() in ('on', '1', 'true', 'yes') else 'Off'
    if re.fullmatch(r'[A-Za-z0-9_.:/,+-]*', v) and v.lower() not in ('yes', 'no', 'null', 'none', 'true', 'false'):
        return v
    return '"' + v.replace('"', '\\"') + '"'


def read_ini(path):
    vals = {}
    try:
        for line in open(path, errors='replace'):
            s = line.strip()
            if not s or s[0] in ';#[':
                continue
            if '=' in s:
                k, v = s.split('=', 1)
                vals[k.strip()] = v.strip()
    except OSError:
        pass
    return vals


def merge_user_ini(ch, folder, entries):
    """entries: [(name, ini value)] -> folder/.user.ini; existing keys win."""
    if not os.path.isdir(folder):
        return False
    path = os.path.join(folder, '.user.ini')
    have = read_ini(path)
    add = [(k, v) for k, v in entries if k not in have]
    if not add:
        return True
    ch.touch(path)
    st = os.stat(folder)
    with open(path, 'a') as f:
        if have:
            f.write('\n')
        f.write('; VortexPanel: PHP settings moved here from Apache (mod_php -> PHP-FPM)\n')
        for k, v in add:
            f.write(f'{k} = {v}\n')
    try:
        os.chown(path, st.st_uid, st.st_gid)
    except OSError:
        pass
    return True


def comment_lines(path, linenos, mark):
    lines = open(path, errors='replace').read().split('\n')
    for n in sorted(set(linenos)):
        if not lines[n].lstrip().startswith('#'):
            indent = lines[n][:len(lines[n]) - len(lines[n].lstrip())]
            lines[n] = indent + mark + lines[n].strip()
    open(path, 'w').write('\n'.join(lines))


def htaccess_files(root):
    out, count = [], 0
    root = root.rstrip('/') or '/'
    if not os.path.isdir(root) or root in ('/', '/usr', '/etc', '/var'):
        return out, False
    for cur, dnames, fnames in os.walk(root):
        depth = cur[len(root):].count('/')
        count += len(dnames) + len(fnames)
        if count > WALK_MAX:
            return out, True
        dnames[:] = [d for d in dnames if d not in ('.git', 'node_modules', '.svn') and depth < WALK_DEPTH]
        if '.htaccess' in fnames:
            out.append(os.path.join(cur, '.htaccess'))
    return out, False


def site_key(vh, i):
    n = (vh['names'][0] if vh['names'] else os.path.basename(vh['file'])).lower()
    return re.sub(r'[^a-z0-9.-]+', '-', n).strip('-.')[:60] or f'site{i}'


def apache_user():
    u, g = 'www-data', 'www-data'
    for line in open(os.path.join(E, 'envvars'), errors='replace') if os.path.exists(os.path.join(E, 'envvars')) else []:
        m = re.match(r'\s*export\s+APACHE_RUN_(USER|GROUP)=(\S+)', line)
        if m and '$' not in m.group(2):
            if m.group(1) == 'USER':
                u = unquote(m.group(2))
            else:
                g = unquote(m.group(2))
    return u, g


def pool_user(ver):
    v = read_ini(os.path.join(PHPE, ver, 'fpm', 'pool.d', 'www.conf'))
    return v.get('user', 'www-data'), v.get('group', 'www-data')


# settings PHP only takes from the system configuration (php_admin_value in a pool)
ADMIN_KEYS = {'disable_functions', 'disable_classes', 'open_basedir', 'upload_tmp_dir', 'sys_temp_dir',
              'allow_url_fopen', 'allow_url_include', 'file_uploads', 'max_file_uploads', 'expose_php',
              'enable_dl', 'realpath_cache_size', 'realpath_cache_ttl', 'max_input_nesting_level',
              'mail.add_x_header', 'mail.log', 'zend.assertions', 'auto_globals_jit', 'register_argc_argv'}
SKIP_KEYS = {'extension', 'zend_extension', 'extension_dir'}


def pool_line(kind, name, value):
    if kind.endswith('flag'):
        return f'{kind}[{name}] = {"on" if value.lower() in ("on", "1", "true", "yes") else "off"}'
    return f'{kind}[{name}] = {value}'


def ini_to_pool(name, value):
    value = unquote(value.split(' ;', 1)[0].strip())
    admin = name in ADMIN_KEYS or name.startswith('opcache.')
    return ('php_admin_value' if admin else 'php_value'), name, value


def write_pool(ch, path, name, sock, users, entries, note):
    (pu, pg), (au, ag) = users
    ch.touch(path)
    body = [f'; VortexPanel: {note}', f'[{name}]', f'user = {pu}', f'group = {pg}', f'listen = {sock}',
            f'listen.owner = {au}', f'listen.group = {ag}', 'listen.mode = 0660', 'pm = ondemand',
            'pm.max_children = 50' if name == 'vortex-modphp' else 'pm.max_children = 20',
            'pm.process_idle_timeout = 30s', 'pm.max_requests = 1000']
    last = {}
    for kind, k, v in entries:                     # a later value for the same setting wins
        last[k] = (kind, k, v)
    body += [pool_line(*e) for e in last.values()]
    open(path, 'w').write('\n'.join(body) + '\n')


def convert(ver):
    ch = Changes()
    dirs, vhosts = load_all()
    bad = unconvertible(dirs)
    if bad:
        for b in bad:
            log('cannot convert: ' + b)
        sys.exit(1)
    sites = {}
    edits = {}                       # apache file -> [line numbers] (restored by the engine on abort)
    pools = {}                       # vhost index -> [(kind, name, value)]
    server = []                      # [(kind, name, value)] for the pools
    for x in dirs:
        c = x['ctx']
        if c['ifmod_php']:
            continue
        flag = x['kind'].endswith('flag')
        vh = vhosts[c['vhost']] if c['vhost'] is not None else None
        if c['dir'] and not x['kind'].startswith('php_admin'):
            merge_user_ini(ch, c['dir'], [(x['name'], ini_value(x['value'], flag))])
            if vh:
                sites[c['vhost']] = vh
        elif vh is not None:
            if not vh['proxy']:                     # already on PHP-FPM: the line never applied
                pools.setdefault(c['vhost'], []).append((x['kind'], x['name'], x['value']))
            sites[c['vhost']] = vh
        else:
            server.append((x['kind'], x['name'], x['value']))
        edits.setdefault(x['file'], []).append(x['line'])

    # what PHP had under mod_php: apache2/php.ini values that differ from fpm/php.ini, then the
    # server-level directives. Only the pools for former mod_php traffic get them.
    a = read_ini(os.path.join(PHPE, ver, 'apache2', 'php.ini'))
    f = read_ini(os.path.join(PHPE, ver, 'fpm', 'php.ini'))
    base = [ini_to_pool(k, v) for k, v in a.items() if f.get(k) != v and k not in SKIP_KEYS]
    base += server
    users = (pool_user(ver), apache_user())
    write_pool(ch, os.path.join(PHPE, ver, 'fpm', 'pool.d', 'vortex-modphp.conf'), 'vortex-modphp',
               f'/run/php/vortex-modphp-{ver}.sock', users, base,
               f'PHP {ver} for the websites mod_php served before Apache moved to the VortexPanel build '
               f'(their apache2/php.ini values and Apache-wide PHP settings)')
    log(f'PHP-FPM pool vortex-modphp ({ver}) for former mod_php websites, {len(base)} setting(s) carried over')

    # websites with their own settings: their own pool (the same values plus their own)
    inserts = {}
    for idx, items in pools.items():
        vh = vhosts[idx]
        key = site_key(vh, idx)
        sock = f'/run/php/vortex-{key}.sock'
        write_pool(ch, os.path.join(PHPE, ver, 'fpm', 'pool.d', f'vortex-{key}.conf'), f'vortex-{key}', sock, users,
                   base + items, f'website {key} (its PHP settings from the Apache configuration, mod_php -> PHP-FPM)')
        inserts.setdefault(vh['file'], []).append((vh['end'], sock))
        log(f'website {key}: own PHP-FPM pool vortex-{key} with {len(items)} setting(s) of its own')

    for path, lines in edits.items():
        comment_lines(path, lines, MARK_FPM)
    for path, items in inserts.items():
        lines = open(path, errors='replace').read().split('\n')
        for end, sock in sorted(items, reverse=True):
            if end is None:
                continue
            lines[end:end] = ['    # VortexPanel: PHP through this website\'s PHP-FPM pool (was mod_php)',
                              '    <FilesMatch "\\.php$">',
                              f'        SetHandler "proxy:unix:{sock}|fcgi://localhost"',
                              '    </FilesMatch>']
        open(path, 'w').write('\n'.join(lines))

    # .htaccess under every website
    roots = sorted({vh['docroot'] for vh in vhosts if vh['docroot']})
    for root in roots:
        files, cut = htaccess_files(root)
        if cut:
            log(f'{root}: more than {WALK_MAX} files; .htaccess files deeper in it were not checked')
        for h in files:
            try:
                lines = open(h, errors='replace').read().split('\n')
            except OSError:
                continue
            entries, nums, stack = [], [], []
            for i, line in enumerate(lines):
                s = line.strip()
                m = OPEN.match(s)
                if m:
                    stack.append((m.group(1).lower(), m.group(2).lower()))
                    continue
                if CLOSE.match(s):
                    stack.pop() if stack else None
                    continue
                d = DIRECTIVE.match(line)
                if not d or s.startswith('#'):
                    continue
                if any(b[0] == 'ifmodule' and 'php' in b[1] for b in stack):
                    continue
                if d.group(2).lower() in ('php_value', 'php_flag'):
                    entries.append((d.group(3), ini_value(unquote(d.group(4)), d.group(2).lower() == 'php_flag')))
                nums.append(i)                     # php_admin_* is not allowed in .htaccess: commented too
            if not nums:
                continue
            merge_user_ini(ch, os.path.dirname(h), entries)
            ch.touch(h)
            comment_lines(h, nums, MARK_INI)
            log(f'{h}: {len(nums)} PHP setting(s) moved to .user.ini')
            for idx, vh in enumerate(vhosts):
                if vh['docroot'] and (h + '/').startswith(vh['docroot'].rstrip('/') + '/'):
                    sites[idx] = vh

    res = []
    for vh in sites.values():
        if not vh['names']:
            continue
        port = re.search(r':(\d+)\s*$', vh['addr'])
        port = port.group(1) if port else '80'
        res.append({'host': vh['names'][0], 'port': port, 'scheme': 'https' if port == '443' else 'http'})
    json.dump(res, open(os.path.join(ST, 'sites.json'), 'w'), indent=1)


def undo():
    ch = Changes()
    for x in reversed(ch.items):
        p = x['path']
        try:
            if x['backup'] and os.path.exists(x['backup']):
                shutil.copy2(x['backup'], p)
            elif os.path.lexists(p):
                os.remove(p)
        except OSError as e:
            log(f'could not put back {p}: {e}')
    log(f'{len(ch.items)} file(s) outside /etc/apache2 put back')
    shutil.rmtree(ST, ignore_errors=True)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'precheck':
        bad = unconvertible(load_all()[0])
        for b in bad:
            print(f'[apache2] cannot be converted to PHP-FPM: {b}', file=sys.stderr)
        sys.exit(1 if bad else 0)
    elif cmd == 'convert':
        convert(sys.argv[2])
    elif cmd == 'undo':
        undo()
    elif cmd == 'sites':
        try:
            for s in json.load(open(os.path.join(ST, 'sites.json'))):
                print(s['host'], s['port'], s['scheme'])
        except (OSError, ValueError):
            pass
    else:
        sys.exit(__doc__)


if __name__ == '__main__':
    main()
