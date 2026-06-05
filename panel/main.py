import os
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

from .database import init_db
from .routes import auth, system, websites, databases, files
from .routes import modules, services, firewall, cron, backups
from .routes import dns, mail, ftp, docker, php, settings, terminal, pages
from .tasks.monitor import start_monitor

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR  = os.path.join(BASE_DIR, "web")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    monitor = start_monitor()
    yield
    monitor.cancel()


app = FastAPI(
    title="VortexPanel",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# static files
app.mount("/static", StaticFiles(directory=os.path.join(WEB_DIR, "static")), name="static")

templates = Jinja2Templates(directory=os.path.join(WEB_DIR, "templates"))

# API routes
app.include_router(auth.router,      prefix="/api/auth",      tags=["auth"])
app.include_router(system.router,    prefix="/api/system",    tags=["system"])
app.include_router(websites.router,  prefix="/api/websites",  tags=["websites"])
app.include_router(databases.router, prefix="/api/databases", tags=["databases"])
app.include_router(files.router,     prefix="/api/files",     tags=["files"])
app.include_router(modules.router,   prefix="/api/modules",   tags=["modules"])
app.include_router(services.router,  prefix="/api/services",  tags=["services"])
app.include_router(firewall.router,  prefix="/api/firewall",  tags=["firewall"])
app.include_router(cron.router,      prefix="/api/cron",      tags=["cron"])
app.include_router(backups.router,   prefix="/api/backups",   tags=["backups"])
app.include_router(dns.router,       prefix="/api/dns",       tags=["dns"])
app.include_router(mail.router,      prefix="/api/mail",      tags=["mail"])
app.include_router(ftp.router,       prefix="/api/ftp",       tags=["ftp"])
app.include_router(docker.router,    prefix="/api/docker",    tags=["docker"])
app.include_router(php.router,       prefix="/api/php",       tags=["php"])
app.include_router(settings.router,  prefix="/api/settings",  tags=["settings"])
app.include_router(terminal.router,  prefix="/api/terminal",  tags=["terminal"])


# Serve the login page
app.include_router(pages.router, tags=["pages"])

# Serve the SPA for all non-API routes
@app.get("/")
async def root():
    return RedirectResponse(url="/dashboard")


@app.get("/{full_path:path}")
async def spa(request: Request, full_path: str):
    # API calls that didn't match a router return 404 here
    if full_path.startswith("api/"):
        from fastapi.responses import JSONResponse
        return JSONResponse({"error": "Not found"}, status_code=404)
    return templates.TemplateResponse("index.html", {"request": request})
