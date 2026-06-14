import os, re
from flask import jsonify, request

try:
    from panel.routes.websites_core import websites_bp, req, sh, get_nginx_dirs, reload_nginx
except ImportError:
    from websites_core import websites_bp, req, sh, get_nginx_dirs, reload_nginx


@websites_bp.route('/api/websites/<domain>/nodejs', methods=['POST'])
def setup_nodejs(domain):
    if not req(): return jsonify({'ok':False}), 401
    d       = request.get_json() or {}
    port    = d.get('port', '3000')
    app_path = d.get('app_path', f'/www/wwwroot/{domain}')
    startup = d.get('startup', 'index.js')
    enable  = d.get('enable', True)

    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':False,'error':'Site not found'}), 404

    if enable:
        runtime_check = d.get('runtime','node')
        if runtime_check == 'go' and not sh('which go 2>/dev/null'):
            return jsonify({'ok':False,'error':'Go is not installed on this server. Install it via Terminal (e.g. apt-get install golang-go) or App Store, then try again.'}), 400
        # Install PM2 if not present
        if not sh('which pm2 2>/dev/null'):
            sh('npm install -g pm2 2>/dev/null', t=60)

        # Update nginx config to proxy to Node
        with open(fp) as f: content = f.read()
        # Replace PHP fastcgi with proxy_pass
        node_location = f'''    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache_bypass $http_upgrade;
    }}
    #VP_NODEJS:{port}'''
        # Remove existing location / and PHP fastcgi
        content = re.sub(r'location\s+/\s*\{[^}]+\}', '', content)
        content = re.sub(r'location\s+~\s+\\.php\$[^}]+\}', '', content, flags=re.DOTALL)
        content = re.sub(r'(}\s*)$', '    ' + node_location + '\n' + r'\1', content, count=1)
        with open(fp,'w') as f: f.write(content)

        # Start app with PM2 (supports node / python / go)
        pm2_name = domain.replace('.','_')
        runtime = d.get('runtime','node')
        if runtime == 'python':
            if os.path.exists(os.path.join(app_path,'requirements.txt')):
                sh(f'cd {app_path} && pip3 install -r requirements.txt --break-system-packages 2>/dev/null', t=180)
            sh(f'cd {app_path} && pm2 start {startup} --name {pm2_name} --interpreter python3 2>/dev/null || pm2 restart {pm2_name} 2>/dev/null')
        elif runtime == 'go':
            sh(f'cd {app_path} && go build -o vp_app . 2>&1', t=180)
            sh(f'cd {app_path} && pm2 start ./vp_app --name {pm2_name} 2>/dev/null || pm2 restart {pm2_name} 2>/dev/null')
        else:
            if os.path.exists(os.path.join(app_path,'package.json')) and not os.path.isdir(os.path.join(app_path,'node_modules')):
                sh(f'cd {app_path} && npm install 2>/dev/null', t=180)
            sh(f'cd {app_path} && pm2 start {startup} --name {pm2_name} 2>/dev/null || pm2 restart {pm2_name} 2>/dev/null')
        sh('pm2 save 2>/dev/null')
    else:
        # Stop PM2 app
        pm2_name = domain.replace('.','_')
        sh(f'pm2 stop {pm2_name} 2>/dev/null')
        # Remove nodejs marker from config
        with open(fp) as f: content = f.read()
        content = re.sub(r'\s*#VP_NODEJS:\d+', '', content)
        with open(fp,'w') as f: f.write(content)

    test = sh('nginx -t 2>&1')
    if 'failed' in test.lower(): return jsonify({'ok':False,'error':test}), 400
    reload_nginx()
    return jsonify({'ok':True,'port':port})


@websites_bp.route('/api/websites/<domain>/nodejs')
def get_nodejs(domain):
    if not req(): return jsonify({'ok':False}), 401
    avail, _ = get_nginx_dirs()
    fp = os.path.join(avail, f'{domain}.conf')
    if not os.path.exists(fp): return jsonify({'ok':True,'enabled':False})
    with open(fp) as f: content = f.read()
    m = re.search(r'#VP_NODEJS:(\d+)', content)
    return jsonify({'ok':True,'enabled':bool(m),'port':m.group(1) if m else ''})

