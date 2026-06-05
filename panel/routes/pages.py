"""
Serves the login HTML page.
The main SPA is served by the catch-all in main.py.
This just makes /login explicit.
"""
import os
from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB_DIR  = os.path.join(BASE_DIR, "web")

router    = APIRouter()
templates = Jinja2Templates(directory=os.path.join(WEB_DIR, "templates"))


@router.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})
