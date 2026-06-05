import subprocess
from fastapi import APIRouter, Depends, HTTPException
from ..auth import current_user
from ..database import User

router = APIRouter()

# services we care about on a typical server
KNOWN = {
    "nginx":        {"label": "Nginx",       "port": "80, 443"},
    "apache2":      {"label": "Apache",      "port": "80, 443"},
    "mysql":        {"label": "MySQL",       "port": "3306"},
    "mariadb":      {"label": "MariaDB",     "port": "3306"},
    "postgresql":   {"label": "PostgreSQL",  "port": "5432"},
    "redis-server": {"label": "Redis",       "port": "6379"},
    "mongod":       {"label": "MongoDB",     "port": "27017"},
    "php8.3-fpm":   {"label": "PHP 8.3-FPM","port": "socket"},
    "php8.2-fpm":   {"label": "PHP 8.2-FPM","port": "socket"},
    "php8.1-fpm":   {"label": "PHP 8.1-FPM","port": "socket"},
    "php7.4-fpm":   {"label": "PHP 7.4-FPM","port": "socket"},
    "postfix":      {"label": "Postfix",     "port": "25, 587"},
    "dovecot":      {"label": "Dovecot",     "port": "993, 995"},
    "pure-ftpd":    {"label": "Pure-FTPd",   "port": "21"},
    "fail2ban":     {"label": "Fail2Ban",    "port": "-"},
    "docker":       {"label": "Docker",      "port": "-"},
    "vortexpanel":  {"label": "VortexPanel", "port": "8888"},
}


def _status(name: str) -> dict:
    try:
        r = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True, text=True, timeout=3,
        )
        active = r.stdout.strip() == "active"

        r2 = subprocess.run(
            ["systemctl", "show", name, "--property=MainPID,MemoryCurrent,CPUUsageNSec"],
            capture_output=True, text=True, timeout=3,
        )
        props = {}
        for line in r2.stdout.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                props[k] = v

        pid = props.get("MainPID", "0")

        return {
            "name":   name,
            "active": active,
            "pid":    pid if pid != "0" else None,
        }
    except Exception:
        return {"name": name, "active": False, "pid": None}


@router.get("")
async def list_services(_: User = Depends(current_user)):
    result = []
    for name, meta in KNOWN.items():
        s = _status(name)
        if s["active"] or _is_installed(name):
            result.append({**meta, "name": name, **s})
    return result


def _is_installed(name: str) -> bool:
    r = subprocess.run(
        ["systemctl", "list-unit-files", f"{name}.service"],
        capture_output=True, text=True, timeout=3,
    )
    return name in r.stdout


@router.post("/{name}/{action}")
async def service_action(name: str, action: str, _: User = Depends(current_user)):
    if name not in KNOWN:
        raise HTTPException(400, f"Unknown service: {name}")
    if action not in ("start", "stop", "restart", "reload"):
        raise HTTPException(400, f"Invalid action: {action}")

    r = subprocess.run(
        ["systemctl", action, name],
        capture_output=True, text=True, timeout=30,
    )
    if r.returncode != 0:
        raise HTTPException(500, r.stderr.strip() or f"Failed to {action} {name}")

    return {"ok": True, "service": name, "action": action}


@router.get("/{name}/logs")
async def service_logs(name: str, lines: int = 100, _: User = Depends(current_user)):
    if name not in KNOWN:
        raise HTTPException(400, f"Unknown service: {name}")

    r = subprocess.run(
        ["journalctl", "-u", name, "-n", str(lines), "--no-pager", "--output=short-iso"],
        capture_output=True, text=True, timeout=10,
    )
    return {"logs": r.stdout}
