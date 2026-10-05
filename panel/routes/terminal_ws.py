from flask_sock import Sock
import os, pty, fcntl, struct, termios, select, subprocess, threading, signal, time

sock = Sock()

def req():
    # Full check (2FA done, fingerprint, IP allowlist, session_version), not
    # just 'user' in session: this endpoint is a root shell.
    from panel.routes.auth import check_ip_and_session
    return check_ip_and_session()

@sock.route('/ws/terminal')
def terminal_ws(ws):
    if not req():
        ws.close()
        return

    # Spawn a shell with a PTY
    pid, fd = pty.fork()
    if pid == 0:
        # Child process. Never let an exception here fall back into the
        # copied gunicorn worker code: always exec or _exit.
        try:
            os.environ['TERM'] = 'xterm-256color'
            for k in ('SECRET_KEY',):
                os.environ.pop(k, None)
            home = os.environ.get('HOME') or '/root'
            os.environ['HOME'] = home
            try:
                os.chdir(home)
            except Exception:
                pass
            if os.path.exists('/bin/bash'):
                os.execv('/bin/bash', ['/bin/bash', '--login'])
            os.execv('/bin/sh', ['/bin/sh', '-l'])
        finally:
            os._exit(127)
    else:
        # Parent — set non-blocking
        try:
            fl = fcntl.fcntl(fd, fcntl.F_GETFL)
            fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        except Exception:
            pass

        stop = threading.Event()

        def read_loop():
            while not stop.is_set():
                try:
                    r, _, _ = select.select([fd], [], [], 0.05)
                    if fd in r:
                        try:
                            data = os.read(fd, 4096)
                        except OSError:
                            break
                        if not data:
                            break
                        try:
                            ws.send(data.decode('utf-8', errors='replace'))
                        except Exception:
                            break
                except Exception:
                    break
            stop.set()

        t = threading.Thread(target=read_loop, daemon=True)
        t.start()

        try:
            while not stop.is_set():
                msg = ws.receive(timeout=1)
                if msg is None:
                    if stop.is_set():
                        break
                    continue
                # Control messages are JSON: {"resize":[cols,rows]}
                if isinstance(msg, str) and msg.startswith('\x00RESIZE\x00'):
                    try:
                        cols, rows = msg.split('\x00')[2].split(',')
                        cols = max(1, min(1000, int(cols))); rows = max(1, min(1000, int(rows)))
                        winsize = struct.pack('HHHH', rows, cols, 0, 0)
                        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
                    except Exception:
                        pass
                    continue
                try:
                    os.write(fd, msg.encode('utf-8') if isinstance(msg, str) else msg)
                except OSError:
                    break
        except Exception:
            pass
        finally:
            stop.set()
            # The shell is a session leader (pty.fork -> setsid): signal the
            # whole process group so programs started from it (top, tail -f,
            # an editor) die with the tab instead of running on, then reap
            # the shell - it was never waited for and stayed a zombie per
            # terminal session for the life of the worker.
            for sig in (signal.SIGHUP, signal.SIGKILL):
                try:
                    os.killpg(pid, sig)
                except Exception:
                    try: os.kill(pid, sig)
                    except Exception: pass
                if sig == signal.SIGHUP:
                    time.sleep(0.2)
            try:
                os.close(fd)
            except Exception:
                pass
            try:
                t.join(timeout=1)
            except Exception:
                pass
            for _ in range(20):
                try:
                    wpid, _st = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    break
                if wpid:
                    break
                time.sleep(0.05)
