from fastapi import APIRouter, Depends
from ..auth import current_user
from ..database import User

router = APIRouter()


@router.get("")
async def list_items(_: User = Depends(current_user)):
    return []
