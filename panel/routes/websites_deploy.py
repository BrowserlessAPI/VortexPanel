"""One-click Deploy (Websites > Add Site > One-click Deploy).

Each app is installed completely, not just unpacked: the website, a new database
and its user, the app's own installer run from the command line, file ownership,
and an SSL certificate when the domain already points here. The result shows the
login details once. WordPress uses the WP Toolkit installer (/api/wp/install).

Runs as a background job (job_state 'deploy_<domain>'), with a step log the
dialog shows while it works.
"""
import json
import os
import re
import secrets
import shlex
import shutil
import string
import tempfile
import threading
import time
import urllib.request
from flask import jsonify, request
from panel.utils.sqlident import grant_db

try:
    from panel.routes.websites_core import (websites_bp, req, sh, get_webroot, ensure_web_ownership,
        _get_site_path, _find_site_config, valid_site_path, create_site_core, _site_php, site_webserver,
        is_valid_domain)
except ImportError:  # pragma: no cover
    from websites_core import (websites_bp, req, sh, get_webroot, ensure_web_ownership,
        _get_site_path, _find_site_config, valid_site_path, create_site_core, _site_php, site_webserver,
        is_valid_domain)

VERSION_CACHE = '/opt/vortexpanel/data/deploy_versions.json'
CACHE_SECONDS = 12 * 3600
UA = {'User-Agent': 'VortexPanel One-click Deploy'}

# icon: a panel icon name (VP_ICONS); php: [lowest supported, recommended];
# exts: PHP extensions the app needs (installed automatically when missing)
DEPLOY_APPS = {
    'wordpress': {'name': 'WordPress', 'icon': 'edit', 'pinned': '6.8.3', 'php': ['7.4', '8.3'],
                  'desc': 'The world\'s most popular CMS. Powers 43% of the web.',
                  'exts': ['mysqli', 'curl', 'gd', 'mbstring', 'xml', 'zip', 'intl'],
                  'fields': ['title', 'admin_user', 'admin_email']},
    'drupal': {'name': 'Drupal', 'icon': 'layers', 'pinned': '11.2.5', 'php': ['8.3', '8.3'],
               'desc': 'Enterprise-grade CMS trusted by governments & Fortune 500.',
               'exts': ['pdo_mysql', 'pdo_sqlite', 'gd', 'mbstring', 'xml', 'curl', 'zip', 'opcache'],
               'fields': ['title', 'admin_user', 'admin_email']},
    'joomla': {'name': 'Joomla', 'icon': 'grid', 'pinned': '5.3.4', 'php': ['8.1', '8.3'],
               'desc': 'Flexible CMS for complex websites and web applications.',
               'exts': ['mysqli', 'gd', 'mbstring', 'xml', 'zip', 'intl', 'curl'],
               'fields': ['title', 'admin_user', 'admin_email']},
    'laravel': {'name': 'Laravel', 'icon': 'code', 'pinned': '12.x', 'php': ['8.2', '8.3'],
                'desc': 'The PHP framework for web artisans. Elegant, expressive syntax.',
                'exts': ['pdo_mysql', 'mbstring', 'xml', 'curl', 'zip', 'bcmath', 'intl'],
                'fields': []},
    'opencart': {'name': 'OpenCart', 'icon': 'cart', 'pinned': '4.1.0.3', 'php': ['8.0', '8.3'],
                 'desc': 'Open source ecommerce solution: easy to use, feature-rich.',
                 'exts': ['mysqli', 'curl', 'gd', 'mbstring', 'zip', 'xml'],
                 'fields': ['admin_user', 'admin_email']},
}


# ------------------------------------------------------------------ versions (cached)
def _get(url, timeout=8):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


def _latest_wordpress():
    d = json.loads(_get('https://api.wordpress.org/core/version-check/1.7/'))
    return d['offers'][0]['current']


def _latest_drupal():
    xml = _get('https://updates.drupal.org/release-history/drupal/current').decode('utf-8', 'replace')
    for v in re.findall(r'<version>([\d.]+)</version>', xml):
        if re.fullmatch(r'\d+\.\d+\.\d+', v):
            return v
    raise ValueError('no Drupal release found')


def _github_latest(repo, pattern):
    d = json.loads(_get(f'https://api.github.com/repos/{repo}/releases/latest'))
    for a in d.get('assets') or []:
        if re.fullmatch(pattern, a.get('name') or ''):
            return d.get('tag_name', '').lstrip('v'), a['browser_download_url']
    raise ValueError(f'no matching download in the latest {repo} release')


def _latest_joomla():
    return _github_latest('joomla/joomla-cms', r'Joomla_[\d.]+-Stable-Full_Package\.tar\.gz')


def _latest_opencart():
    return _github_latest('opencart/opencart', r'opencart-[\d.]+\.zip')


def _latest_laravel():
    d = json.loads(_get('https://repo.packagist.org/p2/laravel/laravel.json'))
    for v in d['packages']['laravel/laravel']:
        ver = v.get('version', '').lstrip('v')
        if re.fullmatch(r'\d+\.\d+\.\d+', ver):
            return ver.split('.')[0] + '.x'
    raise ValueError('no Laravel release found')


def app_versions(force=False):
    """{app: {'version': '...', 'url': optional download}}; upstream is asked at most
    every 12 hours, pinned versions are used when it cannot be reached."""
    try:
        with open(VERSION_CACHE) as f:
            cache = json.load(f)
    except (OSError, ValueError):
        cache = {}
    if not force and cache.get('time', 0) > time.time() - CACHE_SECONDS:
        return cache.get('apps', {})
    from concurrent.futures import ThreadPoolExecutor
    fns = {'wordpress': _latest_wordpress, 'drupal': _latest_drupal, 'joomla': _latest_joomla,
           'laravel': _latest_laravel, 'opencart': _latest_opencart}
    apps = {}
    with ThreadPoolExecutor(max_workers=len(fns)) as ex:          # all at once: at most one timeout of waiting
        futs = {aid: ex.submit(fn) for aid, fn in fns.items()}
        for aid, fut in futs.items():
            try:
                r = fut.result(timeout=12)
                apps[aid] = {'version': r[0], 'url': r[1]} if isinstance(r, tuple) else {'version': r}
            except Exception:  # noqa: BLE001
                old = (cache.get('apps') or {}).get(aid)
                apps[aid] = old or {'version': DEPLOY_APPS[aid]['pinned']}
    try:
        os.makedirs(os.path.dirname(VERSION_CACHE), exist_ok=True)
        with open(VERSION_CACHE, 'w') as f:
            json.dump({'time': time.time(), 'apps': apps}, f)
    except OSError:
        pass
    return apps


# ------------------------------------------------------------------ helpers
def _rand(n=16, punct=False):
    chars = string.ascii_letters + string.digits + ('-_.!' if punct else '')
    while True:
        s = ''.join(secrets.choice(chars) for _ in range(n))
        if any(c.isdigit() for c in s) and any(c.isupper() for c in s) and any(c.islower() for c in s):
            return s


def _php_versions():
    try:
        from panel.routes.php import installed_php_layouts
        return [l['ver'] for l in installed_php_layouts()]
    except Exception:  # noqa: BLE001
        return []


def _vt(v):
    return tuple(int(x) for x in re.findall(r'\d+', v)[:2])


def _db_engine():
    from panel.routes.wp_toolkit import _available_db
    engines = _available_db()
    return engines[0] if engines else None


def _sql(query, engine):
    from panel.routes.wp_toolkit import _mysql_cmd
    out, err, rc = _mysql_cmd(query, engine=engine)
    return rc == 0, (err or out)


def _create_database(domain, engine, log):
    base = re.sub(r'[^a-z0-9_]', '_', domain.lower().replace('.', '_'))[:24]
    user = (base[:20] + '_' + _rand(4).lower())[:32]
    pw = _rand(20)
    name = base
    for _ in range(5):
        ok, err = _sql(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;", engine)
        if ok:
            break
        if 'exists' not in err.lower():
            raise RuntimeError(f'creating the database failed: {err[-200:]}')
        name = f'{base}_{_rand(4).lower()}'
    else:
        raise RuntimeError('could not find a free database name')
    ok, err = _sql(f"CREATE USER '{user}'@'localhost' IDENTIFIED BY '{pw}';", engine)
    if ok:
        ok, err = _sql(f"GRANT ALL PRIVILEGES ON `{grant_db(name)}`.* TO '{user}'@'localhost'; FLUSH PRIVILEGES;", engine)
    if not ok:
        _sql(f"DROP DATABASE IF EXISTS `{name}`;", engine)
        raise RuntimeError(f'creating the database user failed: {err[-200:]}')
    log(f'Database {name} and user {user} created')
    return name, user, pw


def _drop_database(name, user, engine):
    _sql(f"DROP DATABASE IF EXISTS `{name}`; DROP USER IF EXISTS '{user}'@'localhost';", engine)


def _download(url, dest, log):
    log(f'Downloading {url.split("?")[0].rsplit("/", 1)[-1]}...')
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=300) as r, open(dest, 'wb') as f:
            shutil.copyfileobj(r, f)
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f'download failed ({url}): {e}')
    if os.path.getsize(dest) < 100000:
        raise RuntimeError(f'download from {url} is too small ({os.path.getsize(dest)} bytes)')


def _run(cmd, cwd=None, t=900, env=None):
    import subprocess
    e = dict(os.environ, DEBIAN_FRONTEND='noninteractive', COMPOSER_ALLOW_SUPERUSER='1', HOME='/root',
             COMPOSER_NO_INTERACTION='1')
    e.update(env or {})
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=t, env=e)
        return r.returncode, ((r.stdout or '') + (r.stderr or '')).strip()
    except subprocess.TimeoutExpired:
        return 124, f'{cmd[0]} did not finish within {t} seconds'
    except FileNotFoundError:
        return 127, f'{cmd[0]} not found'


def _err(out, n=400):
    """The useful part of an installer's output: the lines that name the error,
    not the usage text some tools print after it."""
    lines = [l.strip() for l in (out or '').splitlines() if l.strip()]
    hits = [l for l in lines if re.search(r'error|failed|exception|could not|cannot|denied|refused', l, re.I)
            and not l.startswith(('create-project [', 'Composer plugins have been disabled', 'Do not run Composer'))]
    text = ' '.join(hits[:4]) if hits else ' '.join(lines[-6:])
    return text[-n:]


def _php_bin(ver):
    from panel.routes.php import php_layout
    lay = php_layout(ver)
    return lay['bin'] if lay else None


def _ensure_exts(ver, exts, log):
    from panel.routes.php import php_layout, php_loaded_modules, php_install_ext
    lay = php_layout(ver)
    have = php_loaded_modules(lay)
    for ext in exts:
        if ext in have or ext.replace('_', '') in have:
            continue
        log(f'Installing PHP {ver} extension {ext}...')
        ok, msg = php_install_ext(ver, ext)
        if not ok and ext not in ('intl', 'opcache', 'bcmath'):
            raise RuntimeError(f'PHP extension {ext}: {msg}')
        if not ok:
            log(f'  {msg} (optional, continuing)')


def _composer(php_bin, log):
    if shutil.which('composer'):
        return shutil.which('composer')
    log('Installing Composer...')
    if shutil.which('apt-get'):
        rc, out = _run(['apt-get', 'install', '-y', 'composer'], t=600)
        if rc == 0 and shutil.which('composer'):
            return shutil.which('composer')
    tmp = tempfile.mkdtemp(prefix='vp-composer-')
    try:
        try:
            data = _get('https://getcomposer.org/installer', timeout=60)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f'downloading Composer failed: {e}')
        with open(os.path.join(tmp, 'installer.php'), 'wb') as f:
            f.write(data)
        rc, out = _run([php_bin, os.path.join(tmp, 'installer.php'), '--install-dir=/usr/local/bin', '--filename=composer'], t=300)
        if rc != 0:
            raise RuntimeError('installing Composer failed: ' + _err(out))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return '/usr/local/bin/composer'


# ------------------------------------------------------------------ installers (files are in `path`)
def _install_drupal(ctx, log):
    ver = ctx['version']
    tmp = ctx['tmp']
    _download(f'https://ftp.drupal.org/files/projects/drupal-{ver}.tar.gz', f'{tmp}/drupal.tgz', log)
    rc, out = _run(['tar', '-xzf', f'{tmp}/drupal.tgz', '-C', ctx['path'], '--strip-components=1'], t=600)
    if rc != 0:
        raise RuntimeError('unpacking Drupal failed: ' + _err(out))
    sdir = os.path.join(ctx['path'], 'sites', 'default')
    shutil.copyfile(os.path.join(sdir, 'default.settings.php'), os.path.join(sdir, 'settings.php'))
    sync = f'sites/default/files/config_{_rand(24).lower()}/sync'
    with open(os.path.join(sdir, 'settings.php'), 'a') as f:
        f.write("\n// Added by VortexPanel One-click Deploy\n"
                "$databases['default']['default'] = [\n"
                f"  'database' => '{ctx['db_name']}', 'username' => '{ctx['db_user']}', 'password' => '{ctx['db_pass']}',\n"
                "  'host' => 'localhost', 'port' => '3306', 'prefix' => '', 'collation' => 'utf8mb4_general_ci',\n"
                "  'driver' => 'mysql', 'namespace' => 'Drupal\\\\mysql\\\\Driver\\\\Database\\\\mysql',\n"
                "  'autoload' => 'core/modules/mysql/src/Driver/Database/mysql/',\n];\n"
                f"$settings['hash_salt'] = '{_rand(64)}';\n"
                f"$settings['config_sync_directory'] = '{sync}';\n"
                f"$settings['trusted_host_patterns'] = ['^' . preg_quote('{ctx['domain']}') . '$', '^www\\\\.' . preg_quote('{ctx['domain']}') . '$'];\n")
    os.makedirs(os.path.join(sdir, 'files'), exist_ok=True)
    log('Running the Drupal installer...')
    rc, out = _run([ctx['php_bin'], 'core/scripts/drupal', 'install', 'standard', '--site-name', ctx['title'],
                    '--langcode', 'en'], cwd=ctx['path'], t=900)
    if rc != 0:
        raise RuntimeError('the Drupal installer failed: ' + _err(out))
    m = re.search(r'Password:\s*(\S+)', out)
    ctx['admin_pass'] = m.group(1) if m else ''
    if not ctx['admin_pass']:
        log('Drupal did not print the admin password: use "Forgot your password" on the login page.')
    # the quick installer names the first user "admin": apply the chosen name and email
    name, mail = ctx['admin_user'], ctx['admin_email']
    _sql(f"UPDATE `{ctx['db_name']}`.users_field_data SET name='{name}', mail='{mail}', init='{mail}' WHERE uid=1; "
         f"TRUNCATE `{ctx['db_name']}`.cache_entity;", ctx['engine'])
    for p in ('settings.php', '.'):
        try:
            os.chmod(os.path.join(sdir, p), 0o444 if p == 'settings.php' else 0o555)
        except OSError:
            pass
    ctx['admin_url'] = ctx['url'] + '/user/login'


def _install_joomla(ctx, log):
    url = ctx.get('download') or (f'https://github.com/joomla/joomla-cms/releases/download/{ctx["version"]}/'
                                  f'Joomla_{ctx["version"]}-Stable-Full_Package.tar.gz')
    tmp = ctx['tmp']
    _download(url, f'{tmp}/joomla.tgz', log)
    rc, out = _run(['tar', '-xzf', f'{tmp}/joomla.tgz', '-C', ctx['path']], t=600)
    if rc != 0:
        raise RuntimeError('unpacking Joomla failed: ' + _err(out))
    log('Running the Joomla installer...')
    prefix = _rand(4).lower() + '_'
    rc, out = _run([ctx['php_bin'], 'installation/joomla.php', 'install', '-n',
                    f'--site-name={ctx["title"]}', f'--admin-user={ctx["admin_user"]}',
                    f'--admin-username={ctx["admin_user"]}', f'--admin-password={ctx["admin_pass"]}',
                    f'--admin-email={ctx["admin_email"]}', '--db-type=mysqli', '--db-host=localhost',
                    f'--db-user={ctx["db_user"]}', f'--db-pass={ctx["db_pass"]}', f'--db-name={ctx["db_name"]}',
                    f'--db-prefix={prefix}', '--db-encryption=0'], cwd=ctx['path'], t=900)
    if rc != 0 or not os.path.exists(os.path.join(ctx['path'], 'configuration.php')):
        raise RuntimeError('the Joomla installer failed: ' + _err(out))
    shutil.rmtree(os.path.join(ctx['path'], 'installation'), ignore_errors=True)
    ctx['admin_url'] = ctx['url'] + '/administrator/'


def _install_opencart(ctx, log):
    url = ctx.get('download') or (f'https://github.com/opencart/opencart/releases/download/{ctx["version"]}/'
                                  f'opencart-{ctx["version"]}.zip')
    tmp = ctx['tmp']
    _download(url, f'{tmp}/oc.zip', log)
    import zipfile
    try:
        with zipfile.ZipFile(f'{tmp}/oc.zip') as z:
            z.extractall(f'{tmp}/oc')
    except zipfile.BadZipFile as e:
        raise RuntimeError(f'unpacking OpenCart failed: {e}')
    up = next((os.path.join(r, 'upload') for r, ds, _ in os.walk(f'{tmp}/oc') if 'upload' in ds), None)
    if not up:
        raise RuntimeError('the OpenCart download has no upload folder')
    rc, out = _run(['cp', '-a', up + '/.', ctx['path']], t=300)
    if rc != 0:
        raise RuntimeError('copying OpenCart failed: ' + _err(out))
    for d in ('', 'admin/'):
        src, dst = os.path.join(ctx['path'], d + 'config-dist.php'), os.path.join(ctx['path'], d + 'config.php')
        if os.path.exists(src) and not os.path.exists(dst):
            shutil.copyfile(src, dst)
        elif not os.path.exists(dst):
            open(dst, 'a').close()
    log('Running the OpenCart installer...')
    rc, out = _run([ctx['php_bin'], 'install/cli_install.php', 'install',
                    '--username', ctx['admin_user'], '--email', ctx['admin_email'], '--password', ctx['admin_pass'],
                    '--http_server', ctx['url'] + '/', '--db_driver', 'mysqli', '--db_hostname', 'localhost',
                    '--db_username', ctx['db_user'], '--db_password', ctx['db_pass'], '--db_database', ctx['db_name'],
                    '--db_port', '3306', '--db_prefix', 'oc_'], cwd=ctx['path'], t=900)
    if rc != 0 or 'success' not in out.lower():
        raise RuntimeError('the OpenCart installer failed: ' + _err(out))
    shutil.rmtree(os.path.join(ctx['path'], 'install'), ignore_errors=True)
    ctx['admin_url'] = ctx['url'] + '/admin/'


def _install_laravel(ctx, log):
    composer = _composer(ctx['php_bin'], log)
    app = os.path.join(ctx['tmp'], 'app')
    log('Creating the Laravel project with Composer (a few minutes)...')
    env = {'PATH': os.path.dirname(ctx['php_bin']) + ':' + os.environ.get('PATH', '/usr/bin:/bin')}
    rc, out = _run([ctx['php_bin'], composer, 'create-project', 'laravel/laravel', app, '--prefer-dist', '--no-interaction',
                    '--no-progress'], t=1500, env=env)
    if rc != 0:
        raise RuntimeError('composer create-project failed: ' + _err(out))
    rc, out = _run(['cp', '-a', app + '/.', ctx['base']], t=300)
    if rc != 0:
        raise RuntimeError('copying the project failed: ' + _err(out))
    envf = os.path.join(ctx['base'], '.env')
    text = open(envf).read() if os.path.exists(envf) else ''
    vals = {'APP_NAME': '"' + ctx['title'].replace('"', '') + '"', 'APP_ENV': 'production', 'APP_DEBUG': 'false',
            'APP_URL': ctx['url'], 'DB_CONNECTION': 'mysql', 'DB_HOST': '127.0.0.1', 'DB_PORT': '3306',
            'DB_DATABASE': ctx['db_name'], 'DB_USERNAME': ctx['db_user'], 'DB_PASSWORD': ctx['db_pass']}
    for k, v in vals.items():
        if re.search(rf'^#?\s*{k}=.*$', text, re.M):
            text = re.sub(rf'^#?\s*{k}=.*$', f'{k}={v}', text, count=1, flags=re.M)
        else:
            text += f'\n{k}={v}'
    open(envf, 'w').write(text.rstrip('\n') + '\n')
    os.chmod(envf, 0o640)
    log('Preparing the database (php artisan migrate)...')
    rc, out = _run([ctx['php_bin'], 'artisan', 'key:generate', '--force'], cwd=ctx['base'], t=120)
    rc, out = _run([ctx['php_bin'], 'artisan', 'migrate', '--force'], cwd=ctx['base'], t=600)
    if rc != 0:
        raise RuntimeError('php artisan migrate failed: ' + _err(out))
    _run([ctx['php_bin'], 'artisan', 'storage:link'], cwd=ctx['base'], t=60)
    ctx['admin_url'] = ''


INSTALLERS = {'drupal': _install_drupal, 'joomla': _install_joomla, 'opencart': _install_opencart,
              'laravel': _install_laravel}


# ------------------------------------------------------------------ API
@websites_bp.route('/api/websites/deploy-apps')
def deploy_apps():
    if not req(): return jsonify({'ok': False}), 401
    vers = app_versions(force=request.args.get('refresh') == '1')
    phps = _php_versions()
    apps = []
    for aid, a in DEPLOY_APPS.items():
        lo, rec = a['php']
        ok_php = [v for v in phps if _vt(v) >= _vt(lo)]
        apps.append({'id': aid, 'name': a['name'], 'icon': a['icon'], 'desc': a['desc'], 'fields': a['fields'],
                     'version': vers.get(aid, {}).get('version') or a['pinned'], 'php_versions': ok_php,
                     'php_recommended': rec if rec in ok_php else (ok_php[0] if ok_php else ''),
                     'php_min': lo})
    return jsonify({'ok': True, 'apps': apps, 'database': bool(_db_engine())})


@websites_bp.route('/api/websites/deploy', methods=['POST'])
def deploy_start():
    if not req(): return jsonify({'ok': False}), 401
    d = request.get_json() or {}
    return _start(d)


@websites_bp.route('/api/websites/<domain>/deploy', methods=['POST'])
def deploy_app(domain):
    """Older form of the call (domain in the path)."""
    if not req(): return jsonify({'ok': False}), 401
    d = dict(request.get_json() or {}, domain=domain)
    return _start(d)


@websites_bp.route('/api/websites/deploy/status')
def deploy_status():
    if not req(): return jsonify({'ok': False}), 401
    from panel.routes.job_state import load_job
    domain = (request.args.get('domain') or '').strip().lower()
    if not is_valid_domain(domain):
        return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    return jsonify(dict(load_job(f'deploy_{domain}', {'running': False, 'done': False}), ok=True))


def _start(d):
    from panel.routes.job_state import load_job, save_job
    app_id = str(d.get('app') or '')
    a = DEPLOY_APPS.get(app_id)
    if not a:
        return jsonify({'ok': False, 'error': 'Unknown app'}), 400
    if app_id == 'wordpress':
        return jsonify({'ok': False, 'error': 'WordPress is installed through /api/wp/install', 'use': 'wp'}), 400
    domain = (d.get('domain') or '').strip().lower()
    if not is_valid_domain(domain):
        return jsonify({'ok': False, 'error': 'Enter a valid domain'}), 400
    php = str(d.get('php') or '').strip()
    phps = _php_versions()
    if php not in phps:
        return jsonify({'ok': False, 'error': f'PHP {php or "?"} is not installed (installed: {", ".join(phps) or "none"})'}), 400
    if _vt(php) < _vt(a['php'][0]):
        return jsonify({'ok': False, 'error': f'{a["name"]} needs PHP {a["php"][0]} or newer'}), 400
    engine = _db_engine()
    if not engine:
        return jsonify({'ok': False, 'error': 'No MySQL or MariaDB server is installed. Install one from the App Store first.'}), 400
    title = str(d.get('title') or '').strip()[:100] or a['name'] + ' - ' + domain
    admin_user = str(d.get('admin_user') or '').strip() or ('admin_' + _rand(4).lower())
    admin_email = str(d.get('admin_email') or '').strip() or f'admin@{domain}'
    if not re.fullmatch(r'[A-Za-z0-9._-]{3,60}', admin_user):
        return jsonify({'ok': False, 'error': 'The admin user name may contain letters, digits and . _ - (3 to 60)'}), 400
    if not re.fullmatch(r'[^@\s\'"]+@[^@\s\'"]+\.[A-Za-z]{2,}', admin_email):
        return jsonify({'ok': False, 'error': 'Enter a valid admin email'}), 400
    if any(c in title for c in '\'"\\\r\n'):
        return jsonify({'ok': False, 'error': 'The site title may not contain quotes or backslashes'}), 400
    if load_job(f'deploy_{domain}', {}).get('running'):
        return jsonify({'ok': False, 'error': f'An install for {domain} is already running'}), 409
    existing = _find_site_config(domain)[0]
    if existing and app_id == 'laravel':
        return jsonify({'ok': False, 'error': f'{domain} already exists. Laravel needs a new website (its web '
                                              'folder is the project\'s public folder): use a new domain or '
                                              'delete the website first.'}), 409
    if existing:
        sp = _get_site_path(domain)
        if os.path.isdir(sp) and [f for f in os.listdir(sp) if f not in ('index.html', '.user.ini', '.well-known', '404.html')]:
            return jsonify({'ok': False, 'error': f'{domain} already exists and its folder is not empty. '
                                                  'One-click Deploy installs into new or empty websites only.'}), 409
    ctx = {'app': app_id, 'domain': domain, 'php': php, 'title': title, 'admin_user': admin_user,
           'admin_email': admin_email, 'admin_pass': _rand(18, punct=True), 'engine': engine,
           'version': app_versions().get(app_id, {}).get('version') or a['pinned'],
           'download': app_versions().get(app_id, {}).get('url'), 'existing': bool(existing)}
    save_job(f'deploy_{domain}', {'running': True, 'done': False, 'app': app_id, 'lines': ['Starting...'],
                                  'started': time.time()})
    threading.Thread(target=_job, args=(ctx,), daemon=True).start()
    return jsonify({'ok': True, 'started': True, 'domain': domain})


def _job(ctx):
    from panel.routes.job_state import load_job, save_job
    key = f'deploy_{ctx["domain"]}'
    state = {'running': True, 'done': False, 'app': ctx['app'], 'lines': [], 'started': time.time()}

    def log(msg):
        state['lines'].append(msg)
        save_job(key, state)

    a = DEPLOY_APPS[ctx['app']]
    db = None
    created_site = False
    ctx['tmp'] = tempfile.mkdtemp(prefix='vp-deploy-', dir='/var/tmp' if os.path.isdir('/var/tmp') else None)
    try:
        log(f'Installing {a["name"]} {ctx["version"]} on {ctx["domain"]} with PHP {ctx["php"]}')
        _ensure_exts(ctx['php'], a['exts'], log)
        ctx['php_bin'] = _php_bin(ctx['php'])
        if not ctx['existing']:
            webroot = get_webroot()
            base = f'{webroot}/{ctx["domain"]}'
            site_path = base + '/public' if ctx['app'] == 'laravel' else None
            ok, result = create_site_core(ctx['domain'], site_path, ctx['php'])
            if not ok:
                raise RuntimeError(result.get('error') or 'creating the website failed')
            created_site = True
            log(f'Website {ctx["domain"]} created')
        path = _get_site_path(ctx['domain']).rstrip('/')
        perr = valid_site_path(path)
        if perr:
            raise RuntimeError(perr)
        ctx['path'] = path
        ctx['base'] = os.path.dirname(path) if ctx['app'] == 'laravel' and path.endswith('/public') else path
        for f in ('index.html', '404.html'):
            try:
                os.unlink(os.path.join(path, f))
            except OSError:
                pass
        ctx['url'] = f'http://{ctx["domain"]}'
        db = _create_database(ctx['domain'], ctx['engine'], log)
        ctx['db_name'], ctx['db_user'], ctx['db_pass'] = db
        if ctx['app'] == 'laravel':
            for f in os.listdir(ctx['path']):
                p = os.path.join(ctx['path'], f)
                shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.unlink(p)
        INSTALLERS[ctx['app']](ctx, log)
        fp = _find_site_config(ctx['domain'])[0]
        ensure_web_ownership(ctx['base'], _site_php(fp) if fp else ctx['php'], site_webserver(ctx['domain']))
        log('File ownership set for the website')
        ssl_note = ''
        try:
            from panel.routes.websites_ssl import _issue_cert
            log('Requesting the SSL certificate...')
            ok, out, _m = _issue_cert(ctx['domain'], ctx['admin_email'])
            if ok:
                ctx['url'] = 'https://' + ctx['domain']
                log('SSL certificate issued')
                if ctx['app'] == 'laravel':
                    envf = os.path.join(ctx['base'], '.env')
                    t = open(envf).read()
                    open(envf, 'w').write(re.sub(r'^APP_URL=.*$', f'APP_URL={ctx["url"]}', t, flags=re.M))
                if ctx.get('admin_url'):
                    ctx['admin_url'] = ctx['admin_url'].replace('http://', 'https://', 1)
            else:
                ssl_note = 'No SSL certificate yet: point the domain to this server, then issue it under Websites > SSL.'
                log(ssl_note)
        except Exception as e:  # noqa: BLE001
            ssl_note = f'SSL: {e}'
        log(f'{a["name"]} is ready.')
        state.update({'running': False, 'done': True, 'success': True, 'url': ctx['url'],
                      'admin_url': ctx.get('admin_url', ''), 'admin_user': ctx['admin_user'] if a['fields'] else '',
                      'admin_pass': ctx.get('admin_pass', '') if a['fields'] else '', 'admin_email': ctx['admin_email'],
                      'db_name': ctx['db_name'], 'db_user': ctx['db_user'], 'db_pass': ctx['db_pass'],
                      'path': ctx['base'], 'ssl_note': ssl_note, 'app_name': a['name']})
        save_job(key, state)
    except Exception as e:  # noqa: BLE001
        log(f'FAILED: {e}')
        if db:
            _drop_database(db[0], db[1], ctx['engine'])
            log('The new database was removed again')
        if created_site:
            try:
                from panel.routes.websites_core import delete_site_core
                delete_site_core(ctx['domain'])
                if ctx.get('base') and ctx['base'].startswith(get_webroot().rstrip('/') + '/'):
                    shutil.rmtree(ctx['base'], ignore_errors=True)
                log('The new website was removed again')
            except Exception:  # noqa: BLE001
                log('The website was created; delete it under Websites before trying again')
        state.update({'running': False, 'done': True, 'success': False, 'error': str(e)})
        save_job(key, state)
    finally:
        shutil.rmtree(ctx['tmp'], ignore_errors=True)
