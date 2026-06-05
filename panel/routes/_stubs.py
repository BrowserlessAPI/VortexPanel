"""
Stub routes — each module has its own file.
Real implementation goes in each route file.
"""
from fastapi import APIRouter, Depends
from ..auth import current_user
from ..database import User

# ── websites ──────────────────────────────────────────────
websites_router = APIRouter()

@websites_router.get("")
async def list_sites(_: User = Depends(current_user)):
    return []

# ── databases ─────────────────────────────────────────────
databases_router = APIRouter()

@databases_router.get("")
async def list_dbs(_: User = Depends(current_user)):
    return []
