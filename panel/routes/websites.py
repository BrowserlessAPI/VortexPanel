import os
import subprocess
import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from ..auth import current_user
from ..database import User

router = APIRouter()

SITES_DIR = "/www/wwwroot"
NGINX_CONF = "/etc/nginx/sites-available"
NGINX_EN   = "/etc/nginx/sites-enabled"


def _nginx_reload():
    subprocess.run(["nginx", "-t"], check=True, capture_output=True)
    subprocess.run(["systemctl", "reload", "nginx"], capture_output=True)


def _site_status(domain: str) -> dict:
    conf = os.path.join(NGINX_EN, domain)
    active = os.path.exists(conf)
    path   = os.path.join(SITES_DIR, domain)
    return {
        "id":        domain,
        "domain":    domain,
        "path":      path,
        "active":    active,
        "ssl":       os.path.exists(f"/etc/letsencrypt/live/{domain}/fullchain.pem"),
        "ssl_days":  _ssl_days(domain),
        "php":       _detect_php(domain),
    }


def _ssl_days(domain: str) -> Optional[int]:
    cert = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
    if not os.path.exists(cert):
        return None
    try:
        r = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", cert],
            capture_output=True, text=True, timeout=5
        )
        from datetime import datetime
        date_str = r.stdout.strip().replace("notAfter=", "")
        exp = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        return max(0, (exp - datetime.utcnow()).days)
    except Exception:
        return None


def _detect_php(domain: str) -> str:
    conf = os.path.join(NGINX_CONF, f"{domain}.conf")
    if os.path.exists(conf):
        content = open(conf).read()
        for ver in ["8.3", "8.2", "8.1", "8.0", "7.4"]:
            if f"php{ver}" in content or f"php/{ver}" in content:
                return ver
    return "8.3"


def _list_sites() -> list:
    sites = []
    if os.path.isdir(NGINX_EN):
        for f in os.listdir(NGINX_EN):
            if f.startswith("."):
                continue
            try:
                sites.append(_site_status(f))
            except Exception:
                pass
    return sites


class SiteCreate(BaseModel):
    domain:      str
    path:        Optional[str] = None
    php:         str = "8.3"
    type:        str = "php"
    description: str = ""
    create_db:   bool = False
    create_ftp:  bool = False


def _nginx_vhost(domain: str, path: str, php: str, site_type: str) -> str:
    if site_type == "static":
        php_block = ""
    else:
        php_block = f"""
    location ~ \\.php$ {{
        fastcgi_pass  unix:/var/run/php/php{php}-fpm.sock;
        fastcgi_index index.php;
        include       fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }}"""

    return f"""server {{
    listen 80;
    server_name {domain} www.{domain};
    root {path};
    index index.php index.html index.htm;
    access_log /var/log/nginx/{domain}.access.log;
    error_log  /var/log/nginx/{domain}.error.log;

    location / {{
        try_files $uri $uri/ /index.php?$query_string;
    }}
{php_block}
    location ~ /\\.ht {{
        deny all;
    }}
}}
"""


@router.get("")
async def list_sites(_: User = Depends(current_user)):
    return _list_sites()


@router.post("")
async def create_site(body: SiteCreate, _: User = Depends(current_user)):
    domain = body.domain.strip().lower().lstrip("www.")
    path   = body.path or os.path.join(SITES_DIR, domain)

    os.makedirs(path, exist_ok=True)

    # write default index
    idx = os.path.join(path, "index.html")
    if not os.path.exists(idx):
        with open(idx, "w") as f:
            f.write(f"<h1>Welcome to {domain}</h1>\n")

    # write nginx vhost
    conf_path = os.path.join(NGINX_CONF, f"{domain}.conf")
    os.makedirs(NGINX_CONF, exist_ok=True)
    os.makedirs(NGINX_EN,   exist_ok=True)

    with open(conf_path, "w") as f:
        f.write(_nginx_vhost(domain, path, body.php, body.type))

    # enable
    link = os.path.join(NGINX_EN, domain)
    if not os.path.exists(link):
        os.symlink(conf_path, link)

    try:
        _nginx_reload()
    except Exception as e:
        raise HTTPException(500, f"Nginx reload failed: {e}")

    return _site_status(domain)


@router.get("/{domain}")
async def get_site(domain: str, _: User = Depends(current_user)):
    conf = os.path.join(NGINX_CONF, f"{domain}.conf")
    if not os.path.exists(conf):
        raise HTTPException(404, "Site not found")
    return _site_status(domain)


@router.get("/{domain}/config")
async def get_config(domain: str, _: User = Depends(current_user)):
    conf = os.path.join(NGINX_CONF, f"{domain}.conf")
    if not os.path.exists(conf):
        raise HTTPException(404, "Config not found")
    return {"content": open(conf).read()}


@router.put("/{domain}/config")
async def save_config(domain: str, body: dict, _: User = Depends(current_user)):
    conf = os.path.join(NGINX_CONF, f"{domain}.conf")
    with open(conf, "w") as f:
        f.write(body.get("content", ""))
    try:
        _nginx_reload()
        return {"ok": True}
    except Exception as e:
        raise HTTPException(500, str(e))


@router.post("/{domain}/toggle")
async def toggle_site(domain: str, _: User = Depends(current_user)):
    link = os.path.join(NGINX_EN, domain)
    if os.path.exists(link):
        os.remove(link)
        msg = "disabled"
    else:
        conf = os.path.join(NGINX_CONF, f"{domain}.conf")
        os.symlink(conf, link)
        msg = "enabled"
    _nginx_reload()
    return {"ok": True, "status": msg}


@router.delete("/{domain}")
async def delete_site(domain: str, remove_files: bool = False, _: User = Depends(current_user)):
    for f in [
        os.path.join(NGINX_EN,   domain),
        os.path.join(NGINX_CONF, f"{domain}.conf"),
    ]:
        if os.path.exists(f): os.remove(f)

    if remove_files:
        path = os.path.join(SITES_DIR, domain)
        if os.path.isdir(path):
            import shutil
            shutil.rmtree(path)

    try:
        _nginx_reload()
    except Exception:
        pass

    return {"ok": True}
