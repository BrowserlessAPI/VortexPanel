#!/usr/bin/env python3
"""
Run on install — creates or updates admin account.
Usage: python init.py --username admin --password <pass> --email <email>
"""
import asyncio
import argparse
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


async def seed(username, password, email):
    from panel.database import init_db, SessionLocal, User
    from panel.auth import hash_password
    from sqlalchemy import select, update

    await init_db()

    async with SessionLocal() as db:
        result = await db.execute(
            select(User).where(User.username == username)
        )
        existing = result.scalar_one_or_none()

        hashed = hash_password(password)

        if existing:
            # update password on reinstall
            await db.execute(
                update(User).where(User.username == username)
                .values(password=hashed, email=email)
            )
            await db.commit()
            print(f"Admin updated: {username}")
        else:
            user = User(
                id=uuid.uuid4().hex,
                username=username,
                email=email,
                password=hashed,
                role="super_admin",
            )
            db.add(user)
            await db.commit()
            print(f"Admin created: {username}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--username", default="admin")
    p.add_argument("--password", required=True)
    p.add_argument("--email",    default="admin@vortexpanel.local")
    args = p.parse_args()

    asyncio.run(seed(args.username, args.password, args.email))
