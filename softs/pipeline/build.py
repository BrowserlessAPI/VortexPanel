"""Build one (app, version, target, arch) and pack it into the release zip.

    python3 build.py --app nginx --version 1.31.8 --target el9 --arch x86_64 [--plan plan.json] [--native]

--native runs the build on this machine instead of in a container (used for local
tests on a matching OS). Output: dist/<app>-<version>-<target>-<arch>.zip

Zip layout (read by panel/softs.py):
    manifest.json      app, version, track, target, arch, prefix, service, run deps,
                       replaces (OS packages it takes over), coexist, payload sha256
    payload.tar.xz     the files under the install prefix (symlinks and modes kept)
    scripts/           install.sh activate.sh check.sh uninstall.sh [migrate.sh]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C  # noqa: E402

BASE = '/usr/local/vortex'          # every VortexPanel build lives under BASE/<app>/<version>


def plan_item(path, app, version):
    try:
        for p in json.load(open(path)):
            if p['app'] == app and p['version'] == version:
                return p
    except (OSError, ValueError):
        pass
    return {'app': app, 'version': version}


def env_for(recipe, item, target, arch, prefix, dest):
    fam = (C.TARGETS['targets'].get(target) or {}).get('family', 'deb')
    e = {'APP': recipe['id'], 'VERSION': item['version'], 'TRACK': item.get('track') or C.track_of(item['version']),
         'PREFIX': prefix, 'DEST': dest, 'TARGET': target, 'ARCH': arch, 'FAMILY': fam,
         'JOBS': str(os.cpu_count() or 2)}
    for k in ('url', 'sha256', 'tag', 'build', 'plugin'):
        if item.get(k):
            e['VP_' + k.upper()] = str(item[k])
    for k, v in ((item.get('resolved') or {}).get(f'{target}-{arch}') or {}).items():
        if re.fullmatch(r'VP_[A-Z0-9_]{1,40}', k) and isinstance(v, str):
            e[k] = v                        # exact upstream file for this system (recipe resolve.py)
    for a, u in (item.get('assets') or {}).items():
        if isinstance(u, str) and a in ('x86_64', 'aarch64'):
            e['VP_ASSET_' + a] = u
    if item.get('assets') and recipe.get('asset_pattern'):
        # pick the asset for this architecture by pattern, e.g. caddy_{version}_linux_{goarch}.tar.gz
        goarch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(arch, arch)
        name = recipe['asset_pattern'].format(version=item['version'], goarch=goarch, arch=arch)
        if name in item['assets']:
            e['VP_URL'] = item['assets'][name]
    return e


def run_build(recipe, item, target, arch, native, work):
    prefix = f"{BASE}/{recipe['id']}/{item['version']}"
    out = os.path.join(work, 'out')
    dest = os.path.join(out, 'root')
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(dest)
    image = (C.TARGETS['targets'].get(target) or {}).get('image', 'ubuntu:24.04')
    if native:
        env = dict(os.environ, **env_for(recipe, item, target, arch, prefix, dest))
        env.update(SOFTS_ROOT=C.ROOT, WORK=os.path.join(work, 'w'), OUT=out)
        os.makedirs(env['WORK'], exist_ok=True)
        r = subprocess.run(['bash', os.path.join(C.ROOT, 'pipeline', 'in_container.sh')], env=env)
    else:
        e = env_for(recipe, item, target, arch, prefix, '/out/root')
        args = ['docker', 'run', '--rm', '-v', f'{C.ROOT}:/softs:ro', '-v', f'{out}:/out']
        for k, v in e.items():
            args += ['-e', f'{k}={v}']
        args += [image, 'bash', '/softs/pipeline/in_container.sh']
        r = subprocess.run(args)
    if r.returncode != 0:
        raise SystemExit(f'build failed ({r.returncode})')
    return out, prefix


def pack(recipe, item, target, arch, out, prefix, dist):
    root = os.path.join(out, 'root') + prefix
    if not os.path.isdir(root) or not os.listdir(root):
        raise SystemExit(f'the build installed nothing into {prefix}')
    os.makedirs(dist, exist_ok=True)
    tmp = os.path.join(out, 'payload.tar.xz')
    def as_root(ti):
        ti.uid = ti.gid = 0
        ti.uname = ti.gname = 'root'
        ti.mode &= ~0o6022          # no setuid/setgid, nothing group/world-writable
        return ti
    with tarfile.open(tmp, 'w:xz', preset=6) as t:
        for name in sorted(os.listdir(root)):
            t.add(os.path.join(root, name), arcname=name, filter=as_root)
    fam = (C.TARGETS['targets'].get(target) or {}).get('family', '')
    detected = []
    try:
        detected = [x.strip() for x in open(os.path.join(out, 'run-deps.txt')) if x.strip()]
    except OSError:
        pass
    glibc = ''
    try:
        glibc = open(os.path.join(out, 'glibc.txt')).read().strip()
    except OSError:
        pass
    man = {
        'format': 1, 'app': recipe['id'], 'panel_id': recipe.get('panel_id', recipe['id']), 'name': recipe.get('name', recipe['id']),
        'version': item['version'], 'track': item.get('track') or C.track_of(item['version']),
        'target': target, 'arch': arch, 'prefix': prefix, 'base': BASE,
        'coexist': bool(recipe.get('coexist')), 'service': recipe.get('service', ''),
        'run_deps': {'deb': (recipe.get('deps') or {}).get('run', {}).get('deb', []) + (detected if fam == 'deb' else []),
                     'rpm': (recipe.get('deps') or {}).get('run', {}).get('rpm', []) + (detected if fam == 'rpm' else [])},
        'rpm_repos': recipe.get('rpm_repos', []),
        'replaces': recipe.get('replaces', {}), 'keep_on_switch': recipe.get('keep_on_switch', []), 'family': fam, 'built': int(time.time()), 'built_on': glibc,
        'payload_sha256': C.sha256_file(tmp),
    }
    name = C.file_name(recipe['id'], item['version'], target, arch)
    path = os.path.join(dist, name)
    with zipfile.ZipFile(path + '.part', 'w', zipfile.ZIP_STORED) as z:
        z.writestr('manifest.json', json.dumps(man, indent=1, sort_keys=True))
        z.write(tmp, 'payload.tar.xz')
        sdir = os.path.join(recipe['dir'], 'scripts')
        for fn in sorted(os.listdir(sdir)):
            zi = zipfile.ZipInfo('scripts/' + fn, date_time=time.gmtime()[:6])
            zi.external_attr = 0o755 << 16
            z.writestr(zi, open(os.path.join(sdir, fn), 'rb').read())
        common_sh = os.path.join(C.ROOT, 'pipeline', 'lib.sh')
        zi = zipfile.ZipInfo('scripts/lib.sh', date_time=time.gmtime()[:6])
        zi.external_attr = 0o644 << 16
        z.writestr(zi, open(common_sh, 'rb').read())
    os.replace(path + '.part', path)
    C.log(f'packed {path} ({os.path.getsize(path) // 1024} KB)')
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--app', required=True)
    ap.add_argument('--version', required=True)
    ap.add_argument('--target', required=True)
    ap.add_argument('--arch', required=True)
    ap.add_argument('--plan', default='plan.json')
    ap.add_argument('--native', action='store_true')
    ap.add_argument('--work', default='')
    ap.add_argument('--dist', default='dist')
    a = ap.parse_args()
    recipe = C.recipes()[a.app]
    item = plan_item(a.plan, a.app, a.version)
    work = a.work or os.path.abspath(f'work-{a.app}-{a.target}-{a.arch}')
    out, prefix = run_build(recipe, item, a.target, a.arch, a.native, work)
    path = pack(recipe, item, a.target, a.arch, out, prefix, os.path.abspath(a.dist))
    C.gh_output('zip', path)


if __name__ == '__main__':
    main()
