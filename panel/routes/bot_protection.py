"""Bot protection (Anubis) - admin API. The work is done in panel/botprot.py."""
import os, re, json, time
from flask import Blueprint, jsonify, request
from panel.utils.authctx import authed as _vp_authed, is_admin
from panel import botprot as bp

botprot_bp = Blueprint('botprot', __name__)


def req():
    return _vp_authed()


def _site_info(domain, st, with_stats=False):
    cfg = bp.site_cfg(st, domain)
    rt = st['runtime'].get(domain, {})
    fp, ws = bp.site_webserver(domain)
    out = {'domain': domain, 'webserver': ws, 'cfg': cfg, 'test': rt.get('test'),
           'down_since': rt.get('down_since'), 'reason': bp.can_protect(domain) if bp.installed() else 'not installed',
           'protected': bool(cfg.get('enabled')) and bp.vhost_has_include(domain),
           'service': bp.service_active(domain) if cfg.get('enabled') else False}
    out['owner'] = hosting_owner(domain)
    if with_stats and cfg.get('enabled'):
        out['stats'] = bp.stats_24h(domain)
        out['memory'] = bp.memory_bytes(domain)
    return out


def hosting_owner(domain):
    """Hosting Module account that owns the website, or ''."""
    try:
        from vphosting import ownership
        return (ownership.owner_of(ownership.KIND_WEBSITE, domain)
                or ownership.owner_of(ownership.KIND_WORDPRESS, domain) or '')
    except Exception:
        return ''


def suggestions(domain):
    """Callback paths found in the site (shown as one-click additions)."""
    from panel.routes.websites_core import _get_site_path
    path = _get_site_path(domain) or ''
    out = []
    if os.path.isdir(os.path.join(path, 'wp-content/plugins/woocommerce')):
        out.append({'path': '/wc-api/', 'why': 'WooCommerce payment callbacks'})
    if os.path.isdir(os.path.join(path, 'wp-content/plugins/jetpack')):
        out.append({'path': '/xmlrpc.php', 'why': 'Jetpack'})
    return out


@botprot_bp.route('/api/botprot/status')
def status():
    if not req(): return jsonify({'ok': False}), 401
    if not is_admin(): return jsonify({'ok': False, 'error': 'Administrators only'}), 403
    st = bp.load_state()
    from panel.routes.websites_core import list_sites
    sites = []
    for s in list_sites():
        d = s['domain']
        info = {'domain': d, 'webserver': s.get('webserver'), 'php': s.get('php'),
                'owner': hosting_owner(d)}
        cfg = st['sites'].get(d)
        if cfg:
            c = bp.site_cfg(st, d)
            info.update(enabled=c['enabled'], level=c['level'], ai_training=c['block_ai_training'],
                        ai_search=c['block_ai_search'], check_media=c['check_media'], locked=c['locked'],
                        paused=c.get('paused_until', 0) > time.time(), auto_off=c.get('auto_off'))
            if c['enabled']:
                info['stats'] = bp.stats_24h(d)
                info['memory'] = bp.memory_bytes(d)
                info['service'] = bp.service_active(d)
        sites.append(info)
    lists = bp.load_lists()
    return jsonify({'ok': True, 'installed': bp.installed(), 'version': bp.version(), 'nginx': bp.nginx_present(),
                    'settings': st['settings'], 'sites': sites,
                    'lists': [{'key': k, 'name': v.get('name'), 'covers': v.get('covers'), 'count': len(v.get('ranges') or []),
                               'updated': v.get('updated'), 'status': v.get('status', 'bundled' if not v.get('updated') else 'OK'),
                               'source': v.get('url')}
                              for k, v in (lists.get('lists') or {}).items()],
                    'realip': bp.realip_configured(), 'levels': bp.LEVEL_NAMES,
                    'engines': {k: v[0] for k, v in bp.OPTIONAL_ENGINES.items()}})


@botprot_bp.route('/api/botprot/settings', methods=['POST'])
def save_settings():
    if not req(): return jsonify({'ok': False}), 401
    if not is_admin(): return jsonify({'ok': False, 'error': 'Administrators only'}), 403
    d = request.get_json() or {}
    with bp._Lock():
        st = bp.load_state()
        s = st['settings']
        before = s.get('customers_allowed')
        for k in ('customers_allowed', 'alert_watchdog', 'alert_selftest'):
            if k in d:
                s[k] = bool(d[k])
        if 'memory_mb' in d:
            try:
                s['memory_mb'] = max(32, min(512, int(d['memory_mb'])))
            except (TypeError, ValueError):
                pass
        if isinstance(d.get('defaults'), dict):
            try:
                s['defaults'] = {k: v for k, v in bp.clean_settings(dict(bp.SITE_DEFAULTS, **s['defaults']),
                                                                    d['defaults']).items()
                                 if k in bp.SETTINGS_DEFAULTS['defaults']}
            except ValueError as e:
                return jsonify({'ok': False, 'error': str(e)}), 400
        bp.save_state(st)
    notes = []
    if before and not s['customers_allowed']:
        # customers lost the permission: stop protection on their websites
        for dom, c in list(st['sites'].items()):
            if c.get('enabled') and hosting_owner(dom) and not c.get('locked'):
                bp.disable_site(dom, actor='admin (customers not allowed)')
                notes.append(dom)
    return jsonify({'ok': True, 'settings': st['settings'], 'turned_off': notes})


@botprot_bp.route('/api/botprot/site/<domain>')
def site_get(domain):
    if not req(): return jsonify({'ok': False}), 401
    if not bp.valid_domain(domain): return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    st = bp.load_state()
    info = _site_info(domain, st, with_stats=True)
    if domain not in st['sites']:
        info['cfg'] = dict(bp.SITE_DEFAULTS, **st['settings']['defaults'])
    info['open_paths_fixed'] = [{'group': g, 'paths': shown} for g, shown, _rx in bp.OPEN_PATHS if shown]
    info['suggestions'] = suggestions(domain)
    info['behind_cloudflare'] = bp.behind_cloudflare(domain) if bp.installed() else False
    info['installed'] = bp.installed()
    info['version'] = bp.version()
    info['levels'] = bp.LEVEL_NAMES
    info['engines'] = {k: v[0] for k, v in bp.OPTIONAL_ENGINES.items()}
    info['log'] = bp.read_log(30, domain)
    return jsonify({'ok': True, **info})


def apply_settings(domain, new, actor='admin', allow=None):
    """Shared by the admin route and the customer portal. Returns a Flask response."""
    reason = bp.can_protect(domain)
    if reason:
        return jsonify({'ok': False, 'error': reason}), 400
    st = bp.load_state()
    cur = bp.site_cfg(st, domain)
    if domain not in st['sites']:
        cur.update(st['settings']['defaults'])
    try:
        cfg = bp.clean_settings(cur, new, allow)
    except ValueError as e:
        return jsonify({'ok': False, 'error': str(e)}), 400
    want = new.get('enabled', cur.get('enabled'))
    if want and cur.get('suspended'):
        return jsonify({'ok': False, 'error': 'The hosting account of this website is suspended.'}), 400
    if want and (bp.behind_cloudflare(domain) and not new.get('realip_ok')):
        return jsonify({'ok': False, 'need_realip': True,
                        'error': 'This website is behind Cloudflare. Set up the real visitor address first, '
                                 'otherwise Google\'s crawler would look like Cloudflare and be checked.'}), 409
    if not want:
        with bp._Lock():
            st = bp.load_state()
            st['sites'][domain] = dict(cfg, enabled=False)
            bp.save_state(st)
        if cur.get('enabled'):
            bp.disable_site(domain, actor=actor)
        return jsonify({'ok': True, 'message': 'Bot protection is off.'})
    ok, msg, test = bp.apply_site(domain, cfg, actor=actor)
    if not ok:
        with bp._Lock():
            st = bp.load_state()
            if domain in st['sites'] and st['sites'][domain].get('enabled'):
                pass   # the previous, working configuration stays
            bp.save_state(st)
        if cur.get('enabled'):
            # restore the previous settings
            bp.apply_site(domain, cur, actor=f'{actor} (restored)')
        return jsonify({'ok': False, 'error': msg, 'test': test}), 400
    return jsonify({'ok': True, 'message': msg, 'test': test})


def _locked_for_me(domain):
    return not is_admin() and bp.site_cfg(bp.load_state(), domain).get('locked')


@botprot_bp.route('/api/botprot/site/<domain>', methods=['POST'])
def site_save(domain):
    if not req(): return jsonify({'ok': False}), 401
    if not bp.valid_domain(domain): return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    if _locked_for_me(domain):
        return jsonify({'ok': False, 'error': 'The administrator has locked these settings.'}), 403
    return apply_settings(domain, request.get_json() or {}, actor='admin' if is_admin() else 'site manager')


@botprot_bp.route('/api/botprot/site/<domain>/pause', methods=['POST'])
def site_pause(domain):
    if not req(): return jsonify({'ok': False}), 401
    if not bp.valid_domain(domain): return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    try:
        minutes = max(0, min(24 * 60, int((request.get_json() or {}).get('minutes', 60))))
    except (TypeError, ValueError):
        minutes = 60
    if _locked_for_me(domain):
        return jsonify({'ok': False, 'error': 'The administrator has locked these settings.'}), 403
    ok, err = bp.pause_site(domain, minutes, actor='admin' if is_admin() else 'site manager')
    return jsonify({'ok': ok, 'error': err}) if ok else (jsonify({'ok': False, 'error': err}), 400)


@botprot_bp.route('/api/botprot/site/<domain>/test', methods=['POST'])
def site_test(domain):
    if not req(): return jsonify({'ok': False}), 401
    if not bp.valid_domain(domain): return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    st = bp.load_state()
    if not bp.site_cfg(st, domain).get('enabled'):
        return jsonify({'ok': False, 'error': 'Bot protection is not on for this website'}), 400
    test = bp.selftest(domain)
    with bp._Lock():
        st = bp.load_state()
        st['runtime'].setdefault(domain, {})['test'] = test
        bp.save_state(st)
    bp.log_event(domain, 'Search engine test ' + ('passed.' if test['ok'] else 'FAILED.'), 'info' if test['ok'] else 'warn')
    return jsonify({'ok': True, 'test': test})


@botprot_bp.route('/api/botprot/site/<domain>/lock', methods=['POST'])
def site_lock(domain):
    if not req(): return jsonify({'ok': False}), 401
    if not is_admin(): return jsonify({'ok': False, 'error': 'Administrators only'}), 403
    if not bp.valid_domain(domain): return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    locked = bool((request.get_json() or {}).get('locked'))
    with bp._Lock():
        st = bp.load_state()
        c = bp.site_cfg(st, domain)
        c['locked'] = locked
        st['sites'][domain] = c
        bp.save_state(st)
    bp.log_event(domain, 'Settings locked for the customer.' if locked else 'Settings unlocked for the customer.')
    return jsonify({'ok': True, 'locked': locked})


@botprot_bp.route('/api/botprot/site/<domain>/rules', methods=['GET', 'POST'])
def site_rules(domain):
    """Advanced: the generated rules file of a website (admin only)."""
    if not req(): return jsonify({'ok': False}), 401
    if not is_admin(): return jsonify({'ok': False, 'error': 'Administrators only'}), 403
    if not bp.valid_domain(domain): return jsonify({'ok': False, 'error': 'Invalid domain'}), 400
    st = bp.load_state()
    cfg = bp.site_cfg(st, domain)
    path = f'{bp.site_dir(domain)}/policy.yaml'
    if request.method == 'GET':
        try:
            text = open(path).read()
        except OSError:
            text = json.dumps(bp.policy_for(cfg), indent=1)
        return jsonify({'ok': True, 'rules': text, 'custom': cfg.get('custom_rules')})
    d = request.get_json() or {}
    if d.get('reset'):
        cfg['custom_rules'] = False
    else:
        text = str(d.get('rules') or '')
        if not text.strip() or len(text) > 500000:
            return jsonify({'ok': False, 'error': 'The rules file is empty or too large'}), 400
        tmp = f'/opt/vortexpanel/data/tmp/anubis-rules-{domain}.yaml'
        os.makedirs(os.path.dirname(tmp), exist_ok=True)
        with open(tmp, 'w') as f:
            f.write(text)
        err = bp.check_rules_file(tmp)
        if err:
            os.remove(tmp)
            return jsonify({'ok': False, 'error': f'Anubis refused the rules file: {err}'}), 400
        old = open(path).read() if os.path.exists(path) else None
        bp._write(path, text, 0o640, ('root', bp.USER))
        os.remove(tmp)
        cfg['custom_rules'] = True
    if not cfg.get('enabled'):
        with bp._Lock():
            st = bp.load_state()
            st['sites'][domain] = cfg
            bp.save_state(st)
        return jsonify({'ok': True})
    ok, msg, test = bp.apply_site(domain, cfg, actor='admin (rules file)')
    if not ok and not d.get('reset') and old is not None:
        bp._write(path, old, 0o640, ('root', bp.USER))
        bp.apply_site(domain, bp.site_cfg(bp.load_state(), domain), actor='admin (rules file restored)')
    return jsonify({'ok': ok, 'error': '' if ok else msg, 'test': test}), (200 if ok else 400)


@botprot_bp.route('/api/botprot/realip', methods=['POST'])
def setup_realip():
    if not req(): return jsonify({'ok': False}), 401
    if not is_admin(): return jsonify({'ok': False, 'error': 'Administrators only'}), 403
    ok, err = bp.write_realip()
    bp.log_event('', 'Real visitor address behind Cloudflare set up.' if ok else f'Real visitor address setup failed: {err}')
    return (jsonify({'ok': True}) if ok else (jsonify({'ok': False, 'error': err[-300:]}), 400))


@botprot_bp.route('/api/botprot/lists/refresh', methods=['POST'])
def lists_refresh():
    if not req(): return jsonify({'ok': False}), 401
    if not is_admin(): return jsonify({'ok': False, 'error': 'Administrators only'}), 403
    msgs = []
    changed = bp.refresh_lists(msgs.append)
    for m in msgs:
        bp.log_event('', 'Crawler lists: ' + m, 'warn')
    return jsonify({'ok': True, 'changed': changed, 'messages': msgs})


@botprot_bp.route('/api/botprot/log')
def activity_log():
    if not req(): return jsonify({'ok': False}), 401
    if not is_admin(): return jsonify({'ok': False, 'error': 'Administrators only'}), 403
    return jsonify({'ok': True, 'log': bp.read_log(300)})


@botprot_bp.route('/api/botprot/badges')
def badges():
    """{domain: level} of protected websites, for the Websites list."""
    if not req(): return jsonify({'ok': False}), 401
    st = bp.load_state()
    now = time.time()
    return jsonify({'ok': True, 'installed': bp.installed(), 'sites': {
        d: ('paused' if c.get('paused_until', 0) > now else 'auto_off' if c.get('auto_off') else c.get('level', 'standard'))
        for d, c in st['sites'].items() if c.get('enabled')}})
