import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from ..database import get_db, User
from ..auth import check_password, make_token, current_user, hash_password

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str = ""


class ChangePasswordRequest(BaseModel):
    current: str
    new_password: str


@router.post("/login")
async def login(body: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(User).where(
            (User.username == body.username) | (User.email == body.username)
        )
    )
    user = result.scalar_one_or_none()

    if not user or not check_password(body.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # update last login
    await db.execute(
        update(User).where(User.id == user.id).values(last_login=datetime.now(timezone.utc))
    )
    await db.commit()

    token = make_token(user.id, user.username, user.role)

    # set cookie for browser + return token for API clients
    response.set_cookie("vp_token", token, httponly=True, samesite="strict", max_age=604800)

    return {
        "token": token,
        "user": {
            "id":       user.id,
            "username": user.username,
            "email":    user.email,
            "role":     user.role,
        }
    }


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("vp_token")
    return {"ok": True}


@router.get("/me")
async def me(user: User = Depends(current_user)):
    return {
        "id":       user.id,
        "username": user.username,
        "email":    user.email,
        "role":     user.role,
    }


@router.post("/change-password")
async def change_password(
    body: ChangePasswordRequest,
    user: User = Depends(current_user),
    db: AsyncSession = Depends(get_db),
):
    if not check_password(body.current, user.password):
        raise HTTPException(status_code=400, detail="Current password is wrong")

    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    await db.execute(
        update(User).where(User.id == user.id).values(password=hash_password(body.new_password))
    )
    await db.commit()
    return {"ok": True}
