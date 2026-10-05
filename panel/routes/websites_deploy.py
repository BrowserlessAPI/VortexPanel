import os, re, shlex, tempfile
from flask import jsonify, request

try:
    from panel.routes.websites_core import (websites_bp, req, sh, get_nginx_dirs, get_webroot, ensure_web_ownership,
        _get_site_path, _find_site_config, valid_site_path, create_site_core, _site_php, site_webserver)
except ImportError:
    from websites_core import (websites_bp, req, sh, get_nginx_dirs, get_webroot, ensure_web_ownership,
        _get_site_path, _find_site_config, valid_site_path, create_site_core, _site_php, site_webserver)


DEPLOY_APPS = {
    'wordpress': {
        'name':'WordPress','version':'6.7.2','icon':'https://s.w.org/style/images/about/WordPress-logotype-standard.png',
        'desc':'The world\'s most popular CMS. Powers 43% of the web.',
        'url':'https://wordpress.org/latest.tar.gz','dir':'wordpress',
        'cmd':'''curl -fsSL https://wordpress.org/latest.tar.gz -o {tmp}/wp.tar.gz && \
tar -xzf {tmp}/wp.tar.gz -C {path}/ --strip-components=1 && \
cp -n {path}/wp-config-sample.php {path}/wp-config.php''',
    },
    'drupal': {
        'name':'Drupal','version':'11.1','icon':'https://www.drupal.org/files/druplicon-small.png',
        'desc':'Enterprise-grade CMS trusted by governments & Fortune 500.',
        'cmd':'''curl -fsSL https://ftp.drupal.org/files/projects/drupal-11.1.0.tar.gz -o {tmp}/drupal.tar.gz && \
tar -xzf {tmp}/drupal.tar.gz -C {path}/ --strip-components=1''',
    },
    'joomla': {
        'name':'Joomla','version':'5.2','icon':'https://www.joomla.org/images/joomla_logo_black.png',
        'desc':'Flexible CMS for complex websites and web applications.',
        'cmd':'''curl -fsSL https://github.com/joomla/joomla-cms/releases/download/5.2.6/Joomla_5.2.6-Stable-Full_Package.tar.gz -o {tmp}/joomla.tar.gz && \
tar -xzf {tmp}/joomla.tar.gz -C {path}/''',
    },
    'laravel': {
        'name':'Laravel','version':'11.x','icon':'https://laravel.com/img/logomark.min.svg',
        'desc':'The PHP framework for web artisans. Elegant, expressive syntax.',
        'cmd':'''(command -v composer >/dev/null 2>&1 || curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer) && \
COMPOSER_ALLOW_SUPERUSER=1 HOME=/root composer create-project laravel/laravel {tmp}/app --prefer-dist -q --no-interaction && \
cp -a {tmp}/app/. {path}/''',
    },
    'opencart': {
        'name':'OpenCart','version':'4.1.0','icon':'https://www.opencart.com/application/view/image/icon/opencart-logo.png',
        'desc':'Open source ecommerce solution — easy to use, feature-rich.',
        'cmd':'''curl -fsSL https://github.com/opencart/opencart/releases/download/4.1.0.3/opencart-4.1.0.3.zip -o {tmp}/oc.zip && \
(command -v unzip >/dev/null 2>&1 || apt-get install -y unzip >/dev/null 2>&1 || dnf install -y unzip >/dev/null 2>&1 || yum install -y unzip >/dev/null 2>&1) && \
unzip -q -o {tmp}/oc.zip -d {tmp}/oc_extract/ && \
cp -r {tmp}/oc_extract/upload/. {path}/''',
    },
}


@websites_bp.route('/api/websites/deploy-apps')
def deploy_apps():
    if not req(): return jsonify({'ok':False}), 401
    apps = [{**{k:v for k,v in a.items() if k!='cmd'}, 'id':aid} for aid,a in DEPLOY_APPS.items()]
    return jsonify({'ok':True,'apps':apps})


@websites_bp.route('/api/websites/<domain>/deploy', methods=['POST'])
def deploy_app(domain):
    if not req(): return jsonify({'ok':False}), 401
    d      = request.get_json() or {}
    app_id = d.get('app','wordpress')
    app    = DEPLOY_APPS.get(app_id)
    if not app: return jsonify({'ok':False,'error':'Unknown app'}), 404

    # Get site path (any web server)
    created = False
    if not _find_site_config(domain)[0]:
        # The Add Site -> Deploy tab posts a NEW domain here: only files were
        # unpacked before, no vhost was ever created, so the "deployed" site
        # never appeared in Websites nor answered on its domain.
        ok, result = create_site_core(domain, None, str(d.get('php') or '8.3'))
        if not ok:
            return jsonify({'ok':False,'error':result.get('error','Could not create the site')}), 400
        created = True
        try:
            os.unlink(os.path.join(result['path'], 'index.html'))   # placeholder page would shadow index.php
        except OSError:
            pass
    path = _get_site_path(domain)
    perr = valid_site_path(path)
    if perr:
        return jsonify({'ok':False,'error':perr}), 400

    os.makedirs(path, exist_ok=True)
    # the old commands interpolated the raw path, downloaded to fixed /tmp
    # names and chowned to www-data|nginx (wrong on RHEL + Apache); laravel's
    # create-project refused the non-empty site root (it holds index.html)
    tmp = tempfile.mkdtemp(prefix='vp-deploy-', dir='/var/tmp' if os.path.isdir('/var/tmp') else None)
    fp_site = _find_site_config(domain)[0]
    site_php = _site_php(fp_site) if fp_site else None
    # composer / laravel call `php` by name: a remi-only RHEL server has no
    # /usr/bin/php, so put the site's PHP (or the newest one) first on PATH
    path_env = ''
    try:
        from panel.routes.php import php_layout, installed_php_layouts
        lay = php_layout(site_php) if site_php else None
        if not lay:
            lays = installed_php_layouts()
            lay = lays[0] if lays else None
        if lay and lay['flavor'] == 'remi':
            path_env = f'export PATH={shlex.quote(os.path.dirname(lay["bin"]))}:$PATH; '
    except Exception:
        pass
    try:
        cmd = app['cmd'].replace('{path}', shlex.quote(path)).replace('{tmp}', shlex.quote(tmp))
        out = sh(f'export DEBIAN_FRONTEND=noninteractive; {path_env}( {cmd} ) 2>&1; echo "__rc=$?"', t=600)
    finally:
        import shutil as _sh
        _sh.rmtree(tmp, ignore_errors=True)
    m = re.search(r'__rc=(\d+)\s*$', out or '')
    rc = int(m.group(1)) if m else 1
    out = re.sub(r'\n?__rc=\d+\s*$', '', out or '')
    ensure_web_ownership(path, site_php, site_webserver(domain))
    ok = rc == 0 and os.path.exists(path) and len(os.listdir(path)) > 2
    res = {'ok':ok, 'output':out[-500:], 'path':path, 'site_created':created}
    if not ok:
        res['error'] = 'Deployment failed' + (f': {out.strip().splitlines()[-1][:200]}' if out.strip() else '')
    return jsonify(res)
