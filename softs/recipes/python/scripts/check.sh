#!/bin/bash
. "$(dirname "$0")/lib.sh"
V="$VP_TRACK"
v="$("/usr/local/bin/python$V" -c 'import platform; print(platform.python_version())' 2>/dev/null)"
[ "$v" = "$VP_VERSION" ] || fail "expected Python $VP_VERSION, found '$v'"
"/usr/local/bin/python$V" -c 'import ssl, sqlite3, venv, ctypes' || fail "Python standard modules missing"
say "Python $v"
