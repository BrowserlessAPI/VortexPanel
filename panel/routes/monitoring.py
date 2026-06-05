from flask import Blueprint, jsonify, request, session
import subprocess, os, re, time

monitoring_bp = Blueprint('monitoring', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except: return ''

@monitoring_bp.route('/api/monitoring/processes')
def processes():
    if not req(): return jsonify({'ok':False}),401
    raw = sh("ps aux --sort=-%cpu | head -21 | awk 'NR>1{print $1,$2,$3,$4,$11}'")
    procs = []
    for line in raw.split('\n'):
        parts = line.strip().split(None,4)
        if len(parts)>=5:
            procs.append({'user':parts[0],'pid':parts[1],'cpu':parts[2],'mem':parts[3],'cmd':parts[4][:60]})
    return jsonify({'ok':True,'processes':procs})

@monitoring_bp.route('/api/monitoring/logs')
def logs():
    if not req(): return jsonify({'ok':False}),401
    log = request.args.get('log','nginx_error')
    paths = {
        'nginx_error':  '/var/log/nginx/error.log',
        'nginx_access': '/var/log/nginx/access.log',
        'mysql':        '/var/log/mysql/error.log',
        'syslog':       '/var/log/syslog',
        'auth':         '/var/log/auth.log',
        'mail':         '/var/log/mail.log',
    }
    path = paths.get(log,'/var/log/syslog')
    lines = int(request.args.get('lines', 100))
    content = sh(f'tail -n {lines} {path} 2>/dev/null')
    return jsonify({'ok':True,'content':content,'path':path})

@monitoring_bp.route('/api/monitoring/diskio')
def diskio():
    if not req(): return jsonify({'ok':False}),401
    raw = sh('iostat -d 1 1 2>/dev/null | tail -n +4')
    disks = []
    for line in raw.split('\n'):
        parts = line.strip().split()
        if len(parts)>=6:
            disks.append({'device':parts[0],'reads':parts[3],'writes':parts[4]})
    return jsonify({'ok':True,'disks':disks})

@monitoring_bp.route('/api/monitoring/netstat')
def netstat():
    if not req(): return jsonify({'ok':False}),401
    raw = sh('ss -tlnp 2>/dev/null | head -30')
    return jsonify({'ok':True,'output':raw})

@monitoring_bp.route('/api/monitoring/fail2ban')
def fail2ban():
    if not req(): return jsonify({'ok':False}),401
    raw = sh('fail2ban-client status 2>/dev/null')
    return jsonify({'ok':True,'output':raw})
