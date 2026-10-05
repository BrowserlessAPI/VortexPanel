from flask import Blueprint, jsonify, request
import subprocess, os, signal

terminal_bp = Blueprint('terminal', __name__)
def req():
    from panel.routes.auth import check_ip_and_session
    return check_ip_and_session()

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
    if not isinstance(cwd, str) or not os.path.isdir(cwd):
        cwd = '/'
    # Own process group so a timeout kills everything the command started
    # (subprocess.run only killed /bin/sh, leaving e.g. `tail -f` running).
    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             stdin=subprocess.DEVNULL, text=True, cwd=cwd, start_new_session=True)
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)}),500
    try:
        out, err = p.communicate(timeout=30)
        return jsonify({'ok':True,'stdout':out,'stderr':err,'code':p.returncode})
    except subprocess.TimeoutExpired:
        try: os.killpg(p.pid, signal.SIGKILL)
        except Exception: p.kill()
        try: p.communicate(timeout=5)
        except Exception: pass
        return jsonify({'ok':False,'error':'Command timed out (30s limit)'}),408
    except Exception as e:
        return jsonify({'ok':False,'error':str(e)}),500
