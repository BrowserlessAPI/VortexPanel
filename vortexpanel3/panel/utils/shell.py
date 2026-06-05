import subprocess, shlex

def run(cmd, timeout=30):
    """Run a shell command and return (stdout, stderr, returncode)"""
    try:
        r = subprocess.run(
            cmd if isinstance(cmd, list) else shlex.split(cmd),
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return '', 'Command timed out', 1
    except Exception as e:
        return '', str(e), 1

def run_ok(cmd, timeout=30):
    stdout, stderr, code = run(cmd, timeout)
    return code == 0, stdout or stderr
