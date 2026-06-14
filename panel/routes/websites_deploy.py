import os, re
from flask import jsonify, request

try:
    from panel.routes.websites_core import websites_bp, req, sh, get_nginx_dirs, get_webroot, ensure_web_ownership
except ImportError:
    from websites_core import websites_bp, req, sh, get_nginx_dirs, get_webroot, ensure_web_ownership


DEPLOY_APPS = {
    'wordpress': {
        'name':'WordPress','version':'6.7.2','icon':'https://s.w.org/style/images/about/WordPress-logotype-standard.png',
        'desc':'The world\'s most popular CMS. Powers 43% of the web.',
        'url':'https://wordpress.org/latest.tar.gz','dir':'wordpress',
        'cmd':'''wget -q https://wordpress.org/latest.tar.gz -O /tmp/wp.tar.gz && \
tar -xzf /tmp/wp.tar.gz -C {path}/ --strip-components=1 && \
cp {path}/wp-config-sample.php {path}/wp-config.php && \
chown -R www-data:www-data {path}/ 2>/dev/null || true''',
    },
    'drupal': {
        'name':'Drupal','version':'11.1','icon':'https://www.drupal.org/files/druplicon-small.png',
        'desc':'Enterprise-grade CMS trusted by governments & Fortune 500.',
        'cmd':'''wget -q https://ftp.drupal.org/files/projects/drupal-11.1.0.tar.gz -O /tmp/drupal.tar.gz && \
tar -xzf /tmp/drupal.tar.gz -C {path}/ --strip-components=1 && \
chown -R www-data:www-data {path}/ 2>/dev/null || true''',
    },
    'joomla': {
        'name':'Joomla','version':'5.2','icon':'https://www.joomla.org/images/joomla_logo_black.png',
        'desc':'Flexible CMS for complex websites and web applications.',
        'cmd':'''wget -q https://github.com/joomla/joomla-cms/releases/download/5.2.6/Joomla_5.2.6-Stable-Full_Package.tar.gz -O /tmp/joomla.tar.gz && \
tar -xzf /tmp/joomla.tar.gz -C {path}/ && \
chown -R www-data:www-data {path}/ 2>/dev/null || true''',
    },
    'laravel': {
        'name':'Laravel','version':'11.x','icon':'https://laravel.com/img/logomark.min.svg',
        'desc':'The PHP framework for web artisans. Elegant, expressive syntax.',
        'cmd':'''which composer 2>/dev/null || curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer && \
composer create-project laravel/laravel {path} --prefer-dist -q && \
chown -R www-data:www-data {path}/ 2>/dev/null || true''',
    },
    'opencart': {
        'name':'OpenCart','version':'4.1.0','icon':'https://www.opencart.com/application/view/image/icon/opencart-logo.png',
        'desc':'Open source ecommerce solution — easy to use, feature-rich.',
        'cmd':'''wget -q https://github.com/opencart/opencart/releases/download/4.1.0.3/opencart-4.1.0.3.zip -O /tmp/oc.zip && \
apt-get install -y unzip -qq && \
unzip -q /tmp/oc.zip -d /tmp/oc_extract/ && \
cp -r /tmp/oc_extract/upload/. {path}/ && \
chown -R www-data:www-data {path}/ 2>/dev/null || true''',
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

    # Get site path
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    path = f'{get_webroot()}/{domain}'
    if os.path.exists(fp):
        with open(fp) as f: content = f.read()
        m = re.search(r'root\s+([^;]+);', content)
        if m: path = m.group(1).strip()

    os.makedirs(path, exist_ok=True)
    cmd = app['cmd'].replace('{path}', path)
    out = sh(f'DEBIAN_FRONTEND=noninteractive {cmd} 2>&1', t=300)
    # Belt-and-braces: ensure ownership even if the per-app cmd's chown failed for any reason
    ensure_web_ownership(path)
    ok  = os.path.exists(path) and len(os.listdir(path)) > 2
    return jsonify({'ok':ok, 'output':out[-500:], 'path':path})

