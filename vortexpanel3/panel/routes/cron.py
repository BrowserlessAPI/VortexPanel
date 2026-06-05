from flask import Blueprint, jsonify, request, session
import subprocess, re

cron_bp = Blueprint('cron', __name__)
def req(): return 'user' in session
def sh(c):
    try: return subprocess.check_output(c,shell=True,text=True,stderr=subprocess.DEVNULL).strip()
    except: return ''

@cron_bp.route('/api/cron/jobs')
def list_jobs():
    if not req(): return jsonify({'ok':False}),401
    raw = sh('crontab -l 2>/dev/null')
    jobs = []
    for i, line in enumerate(raw.split('\n')):
        line = line.strip()
        if not line or line.startswith('#'): continue
        parts = line.split(None, 5)
        if len(parts)>=6:
            jobs.append({'id':i,'schedule':' '.join(parts[:5]),'command':parts[5],'line':line})
        elif len(parts)==5:
            jobs.append({'id':i,'schedule':' '.join(parts[:4]),'command':parts[4],'line':line})
    return jsonify({'ok':True,'jobs':jobs,'raw':raw})

@cron_bp.route('/api/cron/jobs', methods=['POST'])
def add_job():
    if not req(): return jsonify({'ok':False}),401
    d  = request.get_json() or {}
    schedule = d.get('schedule','0 * * * *')
    command  = d.get('command','')
    if not command: return jsonify({'ok':False,'error':'Command required'}),400
    raw = sh('crontab -l 2>/dev/null')
    new_line = f'{schedule} {command}'
    new_cron = raw + f'\n{new_line}\n'
    p = subprocess.run('crontab -', input=new_cron, shell=True, text=True)
    return jsonify({'ok': p.returncode==0, 'line':new_line})

@cron_bp.route('/api/cron/jobs/<int:job_id>', methods=['DELETE'])
def delete_job(job_id):
    if not req(): return jsonify({'ok':False}),401
    raw = sh('crontab -l 2>/dev/null')
    lines = raw.split('\n')
    real_lines = [l for l in lines if l.strip() and not l.startswith('#')]
    all_lines  = [l for l in lines]
    if job_id >= len(real_lines): return jsonify({'ok':False,'error':'Not found'}),404
    target = real_lines[job_id]
    new_lines = [l for l in all_lines if l != target]
    subprocess.run('crontab -', input='\n'.join(new_lines)+'\n', shell=True, text=True)
    return jsonify({'ok':True})
