#!/usr/bin/env python3
"""
VortexPanel — entry point
Usage: python run.py [--port 8888] [--host 0.0.0.0]
"""
import os
import sys
import argparse
import secrets
import uvicorn

def main():
    parser = argparse.ArgumentParser(description="VortexPanel")
    parser.add_argument("--host",   default="127.0.0.1")
    parser.add_argument("--port",   type=int, default=8888)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    # generate JWT secret if not set
    if not os.environ.get("VP_JWT_SECRET"):
        secret_file = "/etc/vortexpanel/.jwt_secret"
        if os.path.exists(secret_file):
            os.environ["VP_JWT_SECRET"] = open(secret_file).read().strip()
        else:
            secret = secrets.token_hex(32)
            os.makedirs("/etc/vortexpanel", exist_ok=True)
            with open(secret_file, "w") as f:
                f.write(secret)
            os.chmod(secret_file, 0o600)
            os.environ["VP_JWT_SECRET"] = secret

    uvicorn.run(
        "panel.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="warning",
        access_log=False,
    )

if __name__ == "__main__":
    main()
