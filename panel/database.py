import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy import Column, String, Boolean, Integer, DateTime, Text
from sqlalchemy.sql import func

DATA_DIR = os.environ.get("VP_DATA_DIR", "/etc/vortexpanel")
DB_PATH  = os.path.join(DATA_DIR, "panel.db")

engine = create_async_engine(
    f"sqlite+aiosqlite:///{DB_PATH}",
    echo=False,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id         = Column(String(32), primary_key=True)
    username   = Column(String(64), unique=True, nullable=False)
    email      = Column(String(128), unique=True, nullable=False)
    password   = Column(String(256), nullable=False)
    role       = Column(String(32), default="admin")
    mfa_secret = Column(String(64), nullable=True)
    mfa_on     = Column(Boolean, default=False)
    created_at = Column(DateTime, server_default=func.now())
    last_login = Column(DateTime, nullable=True)


class Setting(Base):
    __tablename__ = "settings"

    key        = Column(String(128), primary_key=True)
    value      = Column(Text, nullable=True)
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class AuditLog(Base):
    __tablename__ = "audit_log"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    user       = Column(String(64), nullable=False)
    action     = Column(String(128), nullable=False)
    detail     = Column(Text, nullable=True)
    ip         = Column(String(64), nullable=True)
    created_at = Column(DateTime, server_default=func.now())


async def get_db():
    async with SessionLocal() as session:
        yield session


async def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # seed default settings on first run
    async with SessionLocal() as db:
        from sqlalchemy import select, insert
        result = await db.execute(select(Setting).where(Setting.key == "panel_port"))
        if not result.scalar_one_or_none():
            defaults = [
                ("panel_port",    "8888"),
                ("panel_name",    "VortexPanel"),
                ("theme",         "blue"),
                ("panel_path",    ""),
                ("ssl_enabled",   "false"),
                ("session_hours", "168"),
            ]
            for k, v in defaults:
                await db.execute(insert(Setting).values(key=k, value=v))
            await db.commit()
