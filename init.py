#!/usr/bin/env python3
"""
Run once on install — creates admin account and default settings.
Usage: python init.py --username admin --password <pass> --email admin@localhost
"""
import asyncio
import argparse
import secrets
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


async def seed(username, password, email):
    from panel.database import init_db, SessionLocal, User, Setting
    from panel.auth import hash_password
    from sqlalchemy import select, insert
    import uuid

    await init_db()

    async with SessionLocal() as db:
        # check if any user exists
        existing = await db.execute(select(User).limit(1))
        if existing.scalar_one_or_none():
            print("Admin account already exists — skipping.")
            return

        uid = uuid.uuid4().hex
        user = User(
            id=uid,
            username=username,
            email=email,
            password=hash_password(password),
            role="super_admin",
        )
        db.add(user)
        await db.commit()

    print(f"Admin created: {username} / {email}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--username", default="admin")
    p.add_argument("--password", required=True)
    p.add_argument("--email",    default="admin@vortexpanel.local")
    args = p.parse_args()

    asyncio.run(seed(args.username, args.password, args.email))
