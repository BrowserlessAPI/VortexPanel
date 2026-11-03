#!/bin/bash
set -e
V="$VP_TRACK"; d="$(mktemp -d)"
"/usr/local/bin/python$V" -m venv "$d/venv" && "$d/venv/bin/python" -c 'print("ok")' >/dev/null && echo "Python smoke test passed"
