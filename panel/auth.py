import os
import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from .database import get_db, User

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer(auto_error=False)

SECRET  = os.environ.get("VP_JWT_SECRET", secrets.token_hex(32))
ALG     = "HS256"
EXPIRES = int(os.environ.get("VP_SESSION_HOURS", "168"))  # 7 days default


def hash_password(plain: str) -> str:
    return pwd.hash(plain)


def check_password(plain: str, hashed: str) -> bool:
    return pwd.verify(plain, hashed)


def make_token(user_id: str, username: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=EXPIRES)
    return jwt.encode(
        {"sub": user_id, "username": username, "role": role, "exp": exp},
        SECRET, algorithm=ALG,
    )


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET, algorithms=[ALG])
    except JWTError:
        return {}


async def current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    token = None

    # check header first, then cookie
    if creds:
        token = creds.credentials
    else:
        token = request.cookies.get("vp_token")

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    data = decode_token(token)
    if not data or "sub" not in data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    result = await db.execute(select(User).where(User.id == data["sub"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role not in ("admin", "super_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
