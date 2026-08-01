"""
Kernel live patching — VortexPanel
-----------------------------------
WHAT THIS DOES, AND WHAT IT DELIBERATELY DOES NOT

Live patching applies kernel security fixes to a RUNNING kernel, so a critical
CVE can be closed without the reboot that would otherwise take every hosted
site offline. It is genuinely valuable for a shared-hosting box.

VortexPanel does NOT implement live patching. It cannot: building a live patch
requires the vendor's own binary-diffing toolchain against each specific kernel
build, plus signing infrastructure. Any panel claiming to live-patch a kernel
by itself is either wrapping someone else's service or lying.

What this module does instead is manage the two real providers:

  * Canonical Livepatch  — free for a small number of machines, Ubuntu ONLY,
                           and covers a limited subset of Ubuntu CVEs.
  * TuxCare KernelCare   — paid, but covers all the distro families this panel
                           supports (RHEL/Alma/Rocky/Oracle/CloudLinux/Debian/
                           Ubuntu) and a far larger share of CVEs.

Both are third-party services requiring the admin's own token/key. This module
detects what is installed, reports real status read from the provider's own
client, and installs/enables on request. It never invents a status.
"""
from flask import Blueprint, jsonify, request, session
import subprocess, os, re, json

livepatch_bp = Blueprint('livepatch', __name__)


def req():
    return 'user' in session


def sh(c, t=60):
    try:
        r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return '', str(e), 1


def _os_family():
    """Match the panel's corrected detection: read ID *and* ID_LIKE.

    Reading ID_LIKE alone silently misdetects Fedora, which ships no ID_LIKE
    field at all (it is the upstream of the RHEL family, not a derivative).
    """
    out, _, _ = sh('. /etc/os-release 2>/dev/null && echo "$ID $ID_LIKE"')
    out = (out or '').lower()
    if re.search(r'rhel|fedora|centos|almalinux|rocky|cloudlinux|oracle|\bol\b', out):
        return 'rhel'
    return 'debian'


def _is_ubuntu():
    out, _, _ = sh('. /etc/os-release 2>/dev/null && echo "$ID"')
    return (out or '').strip().lower() == 'ubuntu'


def _running_kernel():
    out, _, _ = sh('uname -r')
    return out


def _canonical_status():
    """Read Canonical Livepatch's real state from its own client."""
    if not sh('command -v canonical-livepatch')[0]:
        return {'installed': False}
    out, err, rc = sh('canonical-livepatch status --format json', t=30)
    if rc != 0 or not out:
        # Fall back to the human-readable form; still real data, just less structured.
        out2, _, rc2 = sh('canonical-livepatch status', t=30)
        return {'installed': True, 'enabled': rc2 == 0,
                'raw': out2 or err or 'status unavailable'}
    try:
        data = json.loads(out)
        status = (data.get('Status') or [{}])[0]
        return {
            'installed': True,
            'enabled': True,
            'kernel': status.get('Kernel', ''),
            'patch_state': (status.get('Livepatch') or {}).get('State', ''),
            'fixes': (status.get('Livepatch') or {}).get('Fixes', ''),
        }
    except Exception:
        return {'installed': True, 'enabled': rc == 0, 'raw': out}


def _kernelcare_status():
    """Read KernelCare's real state from its own client."""
    if not sh('command -v kcarectl')[0]:
        return {'installed': False}
    info, _, rc = sh('kcarectl --info', t=30)
    uname, _, _ = sh('kcarectl --uname', t=30)
    patched = 'patch level' in (info or '').lower() or bool(uname)
    return {'installed': True, 'enabled': rc == 0, 'patched': patched,
            'raw': (info or '')[:800]}


@livepatch_bp.route('/api/livepatch/status')
def livepatch_status():
    """Real, provider-reported status — never a guess."""
    if not req():
        return jsonify({'ok': False}), 401

    canonical = _canonical_status()
    kernelcare = _kernelcare_status()
    active = bool(canonical.get('enabled') or kernelcare.get('enabled'))

    # Is a newer kernel already installed but not yet booted? That is the exact
    # situation live patching exists to avoid, and it is worth stating plainly
    # because 'uname -r' alone will not reveal it.
    reboot_required = os.path.exists('/var/run/reboot-required')
    pending_kernel = ''
    if reboot_required:
        try:
            pending_kernel = open('/var/run/reboot-required.pkgs').read().strip()[:200]
        except Exception:
            pass

    available = []
    if _is_ubuntu():
        available.append({
            'id': 'canonical',
            'name': 'Canonical Livepatch',
            'cost': 'Free for a limited number of machines (Ubuntu Pro token required)',
            'scope': 'Ubuntu LTS kernels only',
            'caveat': 'Covers a subset of Ubuntu kernel CVEs, not all of them — '
                      'some fixes will still require a reboot.',
            'signup': 'https://ubuntu.com/pro',
        })
    available.append({
        'id': 'kernelcare',
        'name': 'TuxCare KernelCare',
        'cost': 'Paid subscription (per server)',
        'scope': 'Ubuntu, Debian, RHEL, AlmaLinux, Rocky, Oracle, CloudLinux, CentOS',
        'caveat': 'Requires a licence key from TuxCare.',
        'signup': 'https://tuxcare.com/live-patching-services/',
    })

    return jsonify({
        'ok': True,
        'kernel': _running_kernel(),
        'os_family': _os_family(),
        'active': active,
        'reboot_required': reboot_required,
        'pending_kernel_packages': pending_kernel,
        'providers': {'canonical': canonical, 'kernelcare': kernelcare},
        'available': available,
    })


@livepatch_bp.route('/api/livepatch/install', methods=['POST'])
def livepatch_install():
    """Install and enable a live patching provider.

    The admin supplies their own token/key — this panel never holds or proxies
    provider credentials, and there is no VortexPanel account involved.
    """
    if not req():
        return jsonify({'ok': False}), 401
    d = request.get_json(silent=True) or {}
    provider = (d.get('provider') or '').strip().lower()
    token = (d.get('token') or '').strip()

    if provider not in ('canonical', 'kernelcare'):
        return jsonify({'ok': False, 'error': 'Unknown provider'}), 400
    if not token:
        return jsonify({'ok': False, 'error': 'A token/licence key from the provider is required'}), 400
    # Tokens go into shell commands below; refuse anything that isn't a plain
    # credential rather than trying to escape it.
    if not re.match(r'^[A-Za-z0-9._:-]{8,256}$', token):
        return jsonify({'ok': False, 'error': 'That does not look like a valid token — expected letters, digits, dots, colons, underscores or hyphens'}), 400

    log = []

    if provider == 'canonical':
        if not _is_ubuntu():
            return jsonify({'ok': False,
                            'error': 'Canonical Livepatch only supports Ubuntu. On this OS, use KernelCare instead.'}), 400
        out, err, rc = sh('command -v pro || command -v ubuntu-advantage', t=20)
        if rc != 0:
            o, e, rc2 = sh('DEBIAN_FRONTEND=noninteractive apt-get install -y ubuntu-advantage-tools 2>&1', t=300)
            if rc2 != 0:
                return jsonify({'ok': False, 'error': f'Could not install ubuntu-advantage-tools: {(e or o)[:400]}'}), 500
            log.append('Installed ubuntu-advantage-tools')
        o, e, rc = sh(f'pro attach {token} 2>&1', t=300)
        if rc != 0:
            return jsonify({'ok': False, 'error': f'Attach failed: {(o or e)[:500]}', 'log': log}), 500
        log.append('Attached Ubuntu Pro subscription')
        o, e, rc = sh('pro enable livepatch 2>&1', t=300)
        # Already-enabled is a success, not a failure.
        if rc != 0 and 'already enabled' not in (o or '').lower():
            return jsonify({'ok': False, 'error': f'Enable failed: {(o or e)[:500]}', 'log': log}), 500
        log.append('Livepatch enabled')

    else:  # kernelcare
        o, e, rc = sh('command -v kcarectl', t=20)
        if rc != 0:
            # TuxCare's own documented installer.
            o, e, rc2 = sh('curl -fsSL https://repo.tuxcare.com/kcare/kcare-installer -o /tmp/kcare-installer '
                           '&& bash /tmp/kcare-installer 2>&1', t=600)
            if rc2 != 0:
                return jsonify({'ok': False,
                                'error': f'KernelCare installer failed: {(o or e)[:500]}'}), 500
            log.append('Installed KernelCare client')
        o, e, rc = sh(f'kcarectl --register {token} 2>&1', t=180)
        if rc != 0:
            return jsonify({'ok': False, 'error': f'Registration failed: {(o or e)[:500]}', 'log': log}), 500
        log.append('Registered licence key')
        o, e, rc = sh('kcarectl --update 2>&1', t=300)
        log.append('Applied available patches' if rc == 0 else f'Patch apply reported: {(o or e)[:200]}')

    return jsonify({'ok': True, 'log': log, 'status': livepatch_status().get_json()})


@livepatch_bp.route('/api/livepatch/update', methods=['POST'])
def livepatch_update():
    """Force an immediate patch check against whichever provider is active."""
    if not req():
        return jsonify({'ok': False}), 401
    if sh('command -v kcarectl')[0]:
        o, e, rc = sh('kcarectl --update 2>&1', t=300)
        return jsonify({'ok': rc == 0, 'output': (o or e)[:800]})
    if sh('command -v canonical-livepatch')[0]:
        o, e, rc = sh('canonical-livepatch refresh 2>&1', t=300)
        return jsonify({'ok': rc == 0, 'output': (o or e)[:800]})
    return jsonify({'ok': False, 'error': 'No live patching provider is installed'}), 400
