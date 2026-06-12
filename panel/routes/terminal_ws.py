from flask_sock import Sock
from flask import session
import os, pty, fcntl, struct, termios, select, subprocess, threading, signal, time

sock = Sock()

def req(): return 'user' in session

@sock.route('/ws/terminal')
def terminal_ws(ws):
    if not req():
        ws.close()
        return

    # Spawn a shell with a PTY
    pid, fd = pty.fork()
    if pid == 0:
        # Child process
        os.environ['TERM'] = 'xterm-256color'
        os.execvp('/bin/bash', ['/bin/bash', '--login'])
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
                        winsize = struct.pack('HHHH', int(rows), int(cols), 0, 0)
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
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
            try:
                os.close(fd)
            except Exception:
                pass
