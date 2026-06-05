import asyncio
import os
import time

import psutil
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from ..auth import current_user
from ..database import User

router = APIRouter()


def _get_metrics():
    cpu  = psutil.cpu_percent(interval=0.2)
    mem  = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net  = psutil.net_io_counters()
    load = os.getloadavg()

    boot = psutil.boot_time()
    up   = int(time.time() - boot)

    return {
        "cpu": {
            "percent": cpu,
            "cores":   psutil.cpu_count(),
        },
        "memory": {
            "total":   mem.total,
            "used":    mem.used,
            "free":    mem.available,
            "percent": mem.percent,
        },
        "disk": {
            "total":   disk.total,
            "used":    disk.used,
            "free":    disk.free,
            "percent": disk.percent,
        },
        "network": {
            "sent":     net.bytes_sent,
            "recv":     net.bytes_recv,
            "sent_pps": net.packets_sent,
            "recv_pps": net.packets_recv,
        },
        "uptime": up,
        "load":   list(load),
    }


def _get_processes(limit=15):
    procs = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent", "status"]):
        try:
            procs.append(p.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    procs.sort(key=lambda x: x.get("cpu_percent", 0), reverse=True)
    return procs[:limit]


@router.get("/metrics")
async def metrics(_: User = Depends(current_user)):
    return _get_metrics()


@router.get("/processes")
async def processes(_: User = Depends(current_user)):
    return _get_processes()


@router.get("/metrics/stream")
async def metrics_stream(request, _: User = Depends(current_user)):
    """SSE stream for live dashboard updates."""
    import json

    async def generate():
        while True:
            if await request.is_disconnected():
                break
            data = json.dumps(_get_metrics())
            yield f"data: {data}\n\n"
            await asyncio.sleep(3)

    return StreamingResponse(generate(), media_type="text/event-stream")


@router.get("/info")
async def sysinfo(_: User = Depends(current_user)):
    import platform
    import subprocess

    def cmd(c):
        try:
            return subprocess.check_output(c, shell=True, text=True, timeout=3).strip()
        except Exception:
            return ""

    return {
        "os":       platform.platform(),
        "hostname": platform.node(),
        "kernel":   platform.release(),
        "arch":     platform.machine(),
        "python":   platform.python_version(),
        "ip":       cmd("hostname -I | awk '{print $1}'"),
    }
