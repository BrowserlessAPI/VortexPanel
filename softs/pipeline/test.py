"""Install a built zip on a fresh container of its OS with the real panel engine
(panel/softs.py install-zip), run the recipe's smoke test, then uninstall it.

    python3 test.py dist/nginx-1.31.8-el9-x86_64.zip [--image almalinux:9]

Universal builds ('linux' target) are tested on the oldest and newest supported
systems of each family. A failure exits non-zero and the zip is not published.
"""
import argparse
import json
import os
import subprocess
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402

PANEL = os.path.join(os.path.dirname(C.ROOT), 'panel')
UNIVERSAL_TEST_TARGETS = ['el8', 'el10', 'ubuntu22', 'debian13']

SCRIPT = r'''
set -e
. /etc/os-release
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq python3 curl procps ca-certificates >/dev/null
  PY=python3
else
  if [ "${VERSION_ID%%.*}" = 8 ]; then dnf -y -q install python3.11 curl procps-ng >/dev/null; PY=python3.11
  else dnf -y -q install python3 procps-ng >/dev/null; PY=python3; fi
  command -v curl >/dev/null || dnf -y -q install curl >/dev/null   # EL9/10 images already have curl-minimal
fi
mkdir -p /vp && cp /panel/softs.py /vp/softs.py
echo "=== install"
$PY /vp/softs.py install-zip /dist/$ZIP --init none
export VP_APP=$APP VP_VERSION=$VERSION VP_TRACK=$TRACK
echo "=== smoke test"
[ -n "$SMOKE" ] && bash /softs/recipes/$APP/$SMOKE
echo "=== state"
cat /var/lib/vortex-softs/state.json
echo "=== uninstall"
$PY /vp/softs.py uninstall $APP --init none
[ -z "$(ls -A /usr/local/vortex/$APP 2>/dev/null)" ] || { echo "files left after uninstall"; ls -la /usr/local/vortex/$APP; exit 1; }
echo "=== passed"
'''


def test(zip_path, image):
    with zipfile.ZipFile(zip_path) as z:
        man = json.loads(z.read('manifest.json'))
    recipe = C.recipes()[man['app']]
    args = ['docker', 'run', '--rm',
            '-v', f'{os.path.dirname(os.path.abspath(zip_path))}:/dist:ro', '-v', f'{C.ROOT}:/softs:ro',
            '-v', f'{PANEL}:/panel:ro',
            '-e', f'ZIP={os.path.basename(zip_path)}', '-e', f'APP={man["app"]}', '-e', f'VERSION={man["version"]}',
            '-e', f'TRACK={man["track"]}', '-e', f'SMOKE={recipe.get("smoke", "")}',
            image, 'bash', '-c', SCRIPT]
    C.log(f'testing {os.path.basename(zip_path)} on {image}')
    return subprocess.run(args).returncode


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('zip')
    ap.add_argument('--image', default='')
    a = ap.parse_args()
    with zipfile.ZipFile(a.zip) as z:
        man = json.loads(z.read('manifest.json'))
    if a.image:
        images = [a.image]
    elif man['target'] == 'linux':
        images = [C.TARGETS['targets'][t]['image'] for t in UNIVERSAL_TEST_TARGETS]
    else:
        images = [C.TARGETS['targets'][man['target']]['image']]
    failed = [img for img in images if test(a.zip, img) != 0]
    if failed:
        raise SystemExit(f'TEST FAILED on {", ".join(failed)}')
    C.log('all tests passed')


if __name__ == '__main__':
    main()
