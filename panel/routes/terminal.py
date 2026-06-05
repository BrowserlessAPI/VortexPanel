from flask import Blueprint, jsonify, request, session
import subprocess, threading, uuid, time

terminal_bp = Blueprint('terminal', __name__)
def req(): return 'user' in session

# Store running processes
_procs = {}

@terminal_bp.route('/api/terminal/exec', methods=['POST'])
def exec_cmd():
    if not req(): return jsonify({'ok':False}),401
    d = request.get_json() or {}
    cmd = d.get('cmd','').strip()
    cwd = d.get('cwd','/')
    if not cmd: return jsonify({'ok':False,'error':'No command'}),400
    # Block dangerous commands
    danger = ['rm -rf /', 'mkfs', 'dd if=', ':(){:|:&};:']
    for bad in danger:
        if bad in cmd: return jsonify({'ok':False,'error':'Blocked dangerous command'}),403
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30, cwd=cwd)
        return jsonify({'ok':True,'stdout':r.stdout,'stderr':r.stderr,'code':r.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({'ok':False,'error':'Command timed out (30s limit)'}),408
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)}),500
