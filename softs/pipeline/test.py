"""Install a built zip on a fresh container of its OS with the real panel engine
(panel/softs.py install-zip), run the recipe's smoke test, then uninstall it.

The container is made like a real server: systemd runs as init (the build's units are
started, restarted and checked by systemd, not by hand) and the install runs with the
panel service's umask 0077. Both once let broken builds through: ClamAV's units handed
/run/clamav back to root under systemd, and installs inside the panel left programs
readable by root only (issue #36). If systemd cannot boot in a container on this runner,
the test runs without it and says so loudly.

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
# glibc of each supported system (the oldest one is what a universal build must run on)
TARGET_GLIBC = {'el8': (2, 28), 'el9': (2, 34), 'el10': (2, 39), 'ubuntu22': (2, 35), 'ubuntu24': (2, 39), 'ubuntu26': (2, 42),
                'debian12': (2, 36), 'debian13': (2, 41)}
UNIVERSAL_TEST_TARGETS = ['el8', 'el10', 'ubuntu22', 'ubuntu26', 'debian13']

SCRIPT = r'''
set -e
# read only the OS version: sourcing os-release would overwrite VERSION (the software version)
VERSION_ID="$(. /etc/os-release; echo "$VERSION_ID")"
# package mirrors fail now and then (broken index, timeout): retry with a fresh index
try3() { local i; for i in 1 2 3; do "$@" && return 0; echo "(attempt $i failed, retrying)"; dnf clean metadata >/dev/null 2>&1 || apt-get update -qq >/dev/null 2>&1 || true; sleep 10; done; return 1; }
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  try3 sh -c 'apt-get update -qq && apt-get install -y -qq python3 curl procps ca-certificates >/dev/null'
  PY=python3
else
  if [ "${VERSION_ID%%.*}" = 8 ]; then try3 dnf -y -q install python3.11 curl procps-ng >/dev/null; PY=python3.11
  else try3 dnf -y -q install python3 procps-ng >/dev/null; PY=python3; fi
  command -v curl >/dev/null || try3 dnf -y -q install curl >/dev/null   # EL9/10 images already have curl-minimal
fi
mkdir -p /vp && cp /panel/softs.py /vp/softs.py
echo "=== install (init: $INIT, umask 0077 like the panel service)"
( umask 077; $PY /vp/softs.py install-zip /dist/$ZIP --init $INIT )
export VP_APP=$APP VP_VERSION=$VERSION VP_TRACK=$TRACK
echo "=== smoke test"
[ -n "$SMOKE" ] && bash /softs/recipes/$APP/$SMOKE
if [ "$INIT" = systemd ]; then
  echo "=== services restarted by systemd"
  for u in $(systemctl list-units --type=service --state=active --no-legend --plain | awk '{print $1}' | grep -vE '^(systemd-|dbus|getty|console|user@|cron|rsyslog|ssh)'); do
    systemctl restart "$u" || { systemctl status "$u" --no-pager | tail -20; exit 1; }
  done
  sleep 5
  [ -n "$SMOKE" ] && bash /softs/recipes/$APP/$SMOKE
  failed="$(systemctl --failed --no-legend --plain | awk '{print $1}' | grep -vE '^(systemd-|ssh)' || true)"
  [ -z "$failed" ] || { echo "failed units: $failed"; for u in $failed; do journalctl -u "$u" --no-pager | tail -20; done; exit 1; }
fi
echo "=== state"
cat /var/lib/vortex-softs/state.json
echo "=== uninstall"
( umask 077; $PY /vp/softs.py uninstall $APP --init $INIT )
[ -z "$(ls -A /usr/local/vortex/$APP 2>/dev/null)" ] || { echo "files left after uninstall"; ls -la /usr/local/vortex/$APP; exit 1; }
echo "=== passed"
'''


SYSTEMD_IMAGE = {
    'deb': ('FROM {image}\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq '
            'systemd systemd-sysv dbus python3 curl procps ca-certificates >/dev/null && apt-get clean\n'
            'STOPSIGNAL SIGRTMIN+3\nCMD ["/sbin/init"]\n'),
    'rpm': ('FROM {image}\nRUN dnf -y -q install systemd procps-ng {py} >/dev/null && dnf clean all >/dev/null\n'
            'STOPSIGNAL SIGRTMIN+3\nCMD ["/usr/sbin/init"]\n'),
}


def _net():
    """Local runs behind a proxy (VP_TEST_NETWORK=host): containers use the host network and
    its proxy. CI does not set it."""
    if os.environ.get('VP_TEST_NETWORK') != 'host':
        return [], []
    px = [f'{k}={os.environ[k]}' for k in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'no_proxy')
          if os.environ.get(k)]
    return ['--network', 'host'], px


def systemd_image(image):
    """The OS image with systemd as init (built once per runner). '' when it cannot be built."""
    tag = 'vptest-sd:' + image.replace(':', '-').replace('/', '-')
    if subprocess.run(['docker', 'image', 'inspect', tag], capture_output=True).returncode == 0:
        return tag
    fam = 'rpm' if image.startswith(('almalinux', 'rockylinux', 'centos')) else 'deb'
    py = 'python3.11' if image.endswith(':8') else 'python3'
    df = SYSTEMD_IMAGE[fam].format(image=image, py=py)
    for _ in range(3):           # package mirrors fail now and then
        net, px = _net()
        r = subprocess.run(['docker', 'build', '-q', '-t', tag] + net + [a for p in px for a in ('--build-arg', p)] + ['-'],
                           input=df, text=True, capture_output=True, timeout=900)
        if r.returncode == 0:
            return tag
    C.log(f'could not build a systemd image of {image}: {r.stderr.strip()[-300:]}')
    return ''


def _boot(name, tag, mounts, env):
    """Start a container with systemd as init; True once systemd is up."""
    import time
    net, px = _net()
    r = subprocess.run(['docker', 'run', '-d', '--name', name, '--privileged', '--cgroupns=host',
                        '-v', '/sys/fs/cgroup:/sys/fs/cgroup:rw', '--tmpfs', '/run', '--tmpfs', '/run/lock']
                       + net + [a for p in px for a in ('-e', p)] + mounts + env + [tag], capture_output=True, text=True)
    if r.returncode != 0:
        C.log(f'systemd container did not start: {r.stderr.strip()[-300:]}')
        return False
    for _ in range(60):
        st = subprocess.run(['docker', 'exec', name, 'systemctl', 'is-system-running'], capture_output=True, text=True)
        if st.stdout.strip() in ('running', 'degraded'):
            return True
        time.sleep(1)
    C.log(f'systemd did not come up in the container: {st.stdout.strip()} {st.stderr.strip()[-200:]}')
    subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
    return False


def test(zip_path, image):
    with zipfile.ZipFile(zip_path) as z:
        man = json.loads(z.read('manifest.json'))
    recipe = C.recipes()[man['app']]
    mounts = ['-v', f'{os.path.dirname(os.path.abspath(zip_path))}:/dist:ro', '-v', f'{C.ROOT}:/softs:ro',
              '-v', f'{PANEL}:/panel:ro']
    env = ['-e', f'ZIP={os.path.basename(zip_path)}', '-e', f'APP={man["app"]}', '-e', f'VERSION={man["version"]}',
           '-e', f'TRACK={man["track"]}', '-e', f'SMOKE={recipe.get("smoke", "")}']
    name = f'vptest-{os.getpid()}-{abs(hash(image)) % 100000}'
    C.log(f'testing {os.path.basename(zip_path)} on {image}')
    tag = '' if os.environ.get('VP_TEST_NO_SYSTEMD') else systemd_image(image)
    if tag and _boot(name, tag, mounts, env):
        try:
            return subprocess.run(['docker', 'exec', '-e', 'INIT=systemd'] + [a for p in _net()[1] for a in ('-e', p)]
                                  + [name, 'bash', '-c', SCRIPT],
                                  timeout=1200).returncode
        except subprocess.TimeoutExpired:
            return 124
        finally:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
    C.log(f'WARNING: {image}: systemd cannot run in a container on this runner; testing without systemd '
          '(units are not started by systemd in this test)')
    net, px = _net()
    args = (['docker', 'run', '--rm', '--name', name] + net + [a for p in px for a in ('-e', p)] + mounts + env
            + ['-e', 'INIT=none', image, 'bash', '-c', SCRIPT])
    # extra privileges a real server has and the service asks for (e.g. Pure-FTPd keeps
    # CAP_DAC_READ_SEARCH and CAP_SYS_NICE); only names from a fixed list are accepted
    caps = [c for c in recipe.get('test_caps') or [] if c in ('DAC_READ_SEARCH', 'SYS_NICE', 'NET_ADMIN', 'SYS_RESOURCE', 'IPC_LOCK')]
    for c in reversed(caps):
        args[3:3] = ['--cap-add', c]
    try:
        return subprocess.run(args, timeout=1200).returncode
    except subprocess.TimeoutExpired:
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
        return 124


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
        # systems with their own build (also_targets) never get the universal one: test the
        # next system of that family instead (el8 -> el9)
        own = set(C.recipes()[man['app']].get('also_targets') or [])
        need = tuple(int(x) for x in man['needs_glibc'].split('.')) if man.get('needs_glibc') else ()
        # systems with their own build, or a glibc older than the build needs (they are not
        # offered this build), are replaced by the next system of their family
        own |= {t for t, g in TARGET_GLIBC.items() if need and g < need}
        tg = []
        for t in UNIVERSAL_TEST_TARGETS:
            if t in own:
                fam = [x for x in C.TARGETS['targets'] if x[:2] == t[:2] and x not in own and x not in UNIVERSAL_TEST_TARGETS]
                t = fam[0] if fam else None
            if t and t not in tg:
                tg.append(t)
        images = [C.TARGETS['targets'][t]['image'] for t in tg]
    else:
        tg = [man['target']]
        images = [C.TARGETS['targets'][man['target']]['image']]
    failed = []
    for img in images:
        rc = test(a.zip, img)
        if rc != 0:
            C.log(f'test on {img} failed or timed out (rc {rc}); trying once more')
            rc = test(a.zip, img)
        if rc != 0:
            failed.append(img)
    if failed:
        raise SystemExit(f'TEST FAILED on {", ".join(failed)}')
    # the systems this build was installed and smoke-tested on: publish puts them in the
    # catalog, and a panel takes a universal build only on a system it was tested on or
    # one of the original seven (new systems such as Ubuntu 26.04 need their own test)
    if not a.image:
        with open(a.zip + '.tested', 'w') as f:
            json.dump(tg, f)
    C.log('all tests passed')


if __name__ == '__main__':
    main()
