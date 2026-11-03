# Supervisor from PyPI in a virtual environment on this OS's own python3.
# The environment is created at its final path (the build container is thrown away),
# so its scripts point at the right interpreter, then copied into the package.
python3 -m venv "$PREFIX"
"$PREFIX/bin/pip" install --quiet --no-cache-dir --upgrade pip >/dev/null 2>&1 || true
"$PREFIX/bin/pip" install --quiet --no-cache-dir "supervisor==$VERSION"
"$PREFIX/bin/supervisord" --version | grep -qx "$VERSION" || { echo "supervisord reports the wrong version"; exit 3; }
find "$PREFIX" -name '__pycache__' -type d -prune -exec rm -rf {} +
rm -f "$PREFIX"/bin/activate* "$PREFIX"/bin/Activate.ps1
mkdir -p "$DEST$(dirname "$PREFIX")"
cp -a "$PREFIX" "$DEST$PREFIX"
