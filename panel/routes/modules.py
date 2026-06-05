from flask import Blueprint, jsonify, request, session
import subprocess

modules_bp = Blueprint('modules', __name__)
def req(): return 'user' in session
def sh(c,t=120):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.STDOUT,timeout=t).strip()
    except subprocess.TimeoutExpired: return 'Timed out'
    except Exception as e: return str(e)

MODULES = [
    {'id':'phpmyadmin',   'name':'phpMyAdmin',        'desc':'MySQL web interface',         'category':'Database','icon':'🗄'},
    {'id':'redis',        'name':'Redis',              'desc':'In-memory data store',        'category':'Cache',   'icon':'🔴'},
    {'id':'memcached',    'name':'Memcached',          'desc':'Distributed memory cache',    'category':'Cache',   'icon':'💾'},
    {'id':'fail2ban',     'name':'Fail2ban',           'desc':'Brute-force protection',      'category':'Security','icon':'🛡'},
    {'id':'certbot',      'name':'Certbot (SSL)',      'desc':'Let\'s Encrypt SSL certs',    'category':'SSL',     'icon':'🔒'},
    {'id':'nodejs',       'name':'Node.js',            'desc':'JavaScript runtime',          'category':'Runtime', 'icon':'🟢'},
    {'id':'python3',      'name':'Python 3',           'desc':'Python runtime',              'category':'Runtime', 'icon':'🐍'},
    {'id':'composer',     'name':'Composer',           'desc':'PHP dependency manager',      'category':'Dev',     'icon':'🎼'},
    {'id':'git',          'name':'Git',                'desc':'Version control system',      'category':'Dev',     'icon':'📦'},
    {'id':'supervisor',   'name':'Supervisor',         'desc':'Process control system',      'category':'Server',  'icon':'⚙'},
    {'id':'imagemagick',  'name':'ImageMagick',        'desc':'Image processing library',    'category':'Media',   'icon':'🖼'},
    {'id':'ffmpeg',       'name':'FFmpeg',             'desc':'Video/audio processing',      'category':'Media',   'icon':'🎬'},
    {'id':'postfix',      'name':'Postfix',            'desc':'SMTP mail transfer agent',    'category':'Mail',    'icon':'📧'},
    {'id':'dovecot',      'name':'Dovecot',            'desc':'IMAP/POP3 server',            'category':'Mail',    'icon':'📬'},
    {'id':'bind9',        'name':'BIND9 DNS',          'desc':'DNS name server',             'category':'DNS',     'icon':'🌍'},
    {'id':'docker',       'name':'Docker',             'desc':'Container platform',          'category':'Containers','icon':'🐳'},
    {'id':'vsftpd',       'name':'vsftpd',             'desc':'FTP server',                  'category':'FTP',     'icon':'📂'},
    {'id':'opendkim',     'name':'OpenDKIM',           'desc':'DKIM email signing',          'category':'Mail',    'icon':'✍'},
    {'id':'spamassassin', 'name':'SpamAssassin',       'desc':'Email spam filter',           'category':'Mail',    'icon':'🚫'},
    {'id':'wordpress',    'name':'WP-CLI',             'desc':'WordPress command-line tool', 'category':'CMS',     'icon':'📝'},
]

def is_installed(mod_id):
    checks = {
        'phpmyadmin':   'dpkg -l phpmyadmin 2>/dev/null | grep -c "^ii" | grep -v "^0"',
        'redis':        'which redis-server 2>/dev/null || systemctl is-active redis-server 2>/dev/null | grep -c active',
        'memcached':    'which memcached 2>/dev/null',
        'fail2ban':     'which fail2ban-client 2>/dev/null',
        'certbot':      'which certbot 2>/dev/null',
        'nodejs':       'which node 2>/dev/null || which nodejs 2>/dev/null',
        'python3':      'which python3 2>/dev/null',
        'composer':     'which composer 2>/dev/null',
        'git':          'which git 2>/dev/null',
        'supervisor':   'which supervisord 2>/dev/null || which supervisorctl 2>/dev/null',
        'imagemagick':  'which convert 2>/dev/null',
        'ffmpeg':       'which ffmpeg 2>/dev/null',
        'postfix':      'which postfix 2>/dev/null',
        'dovecot':      'which dovecot 2>/dev/null',
        'bind9':        'which named 2>/dev/null',
        'docker':       'which docker 2>/dev/null',
        'vsftpd':       'which vsftpd 2>/dev/null',
        'opendkim':     'which opendkim 2>/dev/null',
        'spamassassin': 'which spamassassin 2>/dev/null',
        'wordpress':    'which wp 2>/dev/null',
    }
    try:
        cmd = checks.get(mod_id, 'false')
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        out = r.stdout.strip()
        return r.returncode == 0 and out not in ('', '0', 'inactive')
    except: return False

@modules_bp.route('/api/modules')
def list_modules():
    if not req(): return jsonify({'ok':False}),401
    result = [{**m, 'installed': is_installed(m['id'])} for m in MODULES]
    return jsonify({'ok':True,'modules':result})

@modules_bp.route('/api/modules/<mod_id>/install', methods=['POST'])
def install_module(mod_id):
    if not req(): return jsonify({'ok':False}),401
    install_cmds = {
        'redis':        'apt-get install -y redis-server && systemctl enable redis-server',
        'memcached':    'apt-get install -y memcached && systemctl enable memcached',
        'fail2ban':     'apt-get install -y fail2ban && systemctl enable fail2ban',
        'certbot':      'apt-get install -y certbot python3-certbot-nginx',
        'nodejs':       'curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs',
        'composer':     'curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer',
        'git':          'apt-get install -y git',
        'supervisor':   'apt-get install -y supervisor && systemctl enable supervisor',
        'imagemagick':  'apt-get install -y imagemagick php-imagick',
        'ffmpeg':       'apt-get install -y ffmpeg',
        'postfix':      'DEBIAN_FRONTEND=noninteractive apt-get install -y postfix',
        'dovecot':      'apt-get install -y dovecot-imapd dovecot-pop3d',
        'bind9':        'apt-get install -y bind9 bind9utils',
        'docker':       'curl -fsSL https://get.docker.com | sh && systemctl enable docker',
        'vsftpd':       'apt-get install -y vsftpd && systemctl enable vsftpd',
        'opendkim':     'apt-get install -y opendkim opendkim-tools',
        'spamassassin': 'apt-get install -y spamassassin',
        'wordpress':    'curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod +x wp-cli.phar && mv wp-cli.phar /usr/local/bin/wp',
    }
    cmd = install_cmds.get(mod_id)
    if not cmd: return jsonify({'ok':False,'error':'Unknown module'}),404
    out = sh(f'DEBIAN_FRONTEND=noninteractive {cmd} 2>&1', t=180)
    return jsonify({'ok':True,'output':out,'installed':is_installed(mod_id)})

@modules_bp.route('/api/modules/<mod_id>/uninstall', methods=['POST'])
def uninstall_module(mod_id):
    if not req(): return jsonify({'ok':False}),401
    pkg_map = {'redis':'redis-server','memcached':'memcached','fail2ban':'fail2ban',
               'certbot':'certbot','git':'git','supervisor':'supervisor',
               'imagemagick':'imagemagick','ffmpeg':'ffmpeg','postfix':'postfix',
               'dovecot':'dovecot-imapd','bind9':'bind9','vsftpd':'vsftpd',
               'opendkim':'opendkim','spamassassin':'spamassassin'}
    pkg = pkg_map.get(mod_id)
    if pkg: sh(f'apt-get remove -y {pkg} 2>&1')
    return jsonify({'ok':True,'installed':is_installed(mod_id)})
