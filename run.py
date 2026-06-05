#!/usr/bin/env python3
import os
import sys
import argparse
import secrets
import uvicorn

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host",   default="127.0.0.1")
    parser.add_argument("--port",   type=int, default=8889)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    # load JWT secret from file
    secret_file = os.environ.get("VP_JWT_SECRET_FILE", "/etc/vortexpanel/.jwt_secret")
    if os.path.exists(secret_file):
        os.environ["VP_JWT_SECRET"] = open(secret_file).read().strip()
    elif not os.environ.get("VP_JWT_SECRET"):
        os.environ["VP_JWT_SECRET"] = secrets.token_hex(32)

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
