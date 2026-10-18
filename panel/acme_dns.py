"""DNS-01 hook for zones served by this server's own DNS (BIND).

Called by the acme.sh hook dns_vortexpanel.sh:
    python -m panel.acme_dns add|rm <fqdn> <txt value>

Adds or removes the _acme-challenge TXT record in the zone that holds the
name (longest matching zone), bumps the serial, checks the zone with
named-checkzone and reloads BIND. The zone file is restored if the check
fails, so a challenge can never leave a broken zone behind.
"""
import os, re, sys, fcntl


def _zone_for(fqdn):
    from panel.routes import dns as d
    zdir = d._zones_dir()
    labels = fqdn.rstrip('.').lower().split('.')
    for i in range(len(labels) - 1):
        zone = '.'.join(labels[i:])
        if os.path.exists(f'{zdir}/db.{zone}'):
            return zone, f'{zdir}/db.{zone}'
    return None, None


def change(action, fqdn, value):
    from panel.routes import dns as d
    fqdn = fqdn.rstrip('.').lower()
    if not re.fullmatch(r'[a-z0-9_.*-]{1,253}', fqdn) or not re.fullmatch(r'[A-Za-z0-9_-]{8,128}', value or ''):
        print('[VortexPanel] invalid challenge name or value', file=sys.stderr)
        return 1
    zone, zf = _zone_for(fqdn)
    if not zone:
        print(f'[VortexPanel] No DNS zone on this server holds {fqdn}. Add the zone in DNS first, '
              'or choose the DNS provider that serves this domain.', file=sys.stderr)
        return 1
    host = fqdn[:-len(zone)].rstrip('.') or '@'
    os.makedirs('/opt/vortexpanel/data', exist_ok=True)
    with open('/opt/vortexpanel/data/.acme_dns.lock', 'w') as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        content = open(zf).read()
        line = f'{host}\t60\tIN\tTXT\t"{value}" ; vp-acme'
        lines = content.split('\n')
        present = any(l.startswith(f'{host}\t') and f'"{value}"' in l and 'vp-acme' in l for l in lines)
        if action == 'add':
            if present:
                return 0
            new = content.rstrip('\n') + '\n' + line + '\n'
        else:
            kept = [l for l in lines if not (l.startswith(f'{host}\t') and f'"{value}"' in l and 'vp-acme' in l)]
            if len(kept) == len(lines):
                return 0
            new = '\n'.join(kept)
        err = d._write_zone_checked(zone, zf, d._bump_serial(new))
        if err:
            print(f'[VortexPanel] zone {zone} rejected the challenge record: {err}', file=sys.stderr)
            return 1
    print(f'[VortexPanel] {"Added" if action == "add" else "Removed"} TXT {fqdn} in zone {zone}')
    return 0


if __name__ == '__main__':
    if len(sys.argv) != 4 or sys.argv[1] not in ('add', 'rm'):
        print('usage: python -m panel.acme_dns add|rm <fqdn> <value>', file=sys.stderr)
        sys.exit(2)
    sys.exit(change(sys.argv[1], sys.argv[2], sys.argv[3]))
