import asyncio
import time
from collections import deque

import psutil

# in-memory ring buffer — last 5 minutes of readings
_history = deque(maxlen=100)


def get_history():
    return list(_history)


def _snapshot():
    cpu  = psutil.cpu_percent()
    mem  = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "ts":   int(time.time()),
        "cpu":  round(cpu, 1),
        "mem":  round(mem.percent, 1),
        "disk": round(disk.percent, 1),
    }


async def _run():
    while True:
        try:
            _history.append(_snapshot())
        except Exception:
            pass
        await asyncio.sleep(3)


def start_monitor():
    return asyncio.create_task(_run())
