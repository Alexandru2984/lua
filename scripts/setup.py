#!/usr/bin/env python3
"""Create private runtime state; never overwrite the signing key or database."""
import json
import os
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parent.parent
for name in ('data', 'logs'):
    (root / 'app' / name).mkdir(mode=0o700, exist_ok=True)
    (root / 'app' / name).chmod(0o700)
key = root / 'app/data/session.key'
try:
    fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except FileExistsError:
    if key.stat().st_size != 32:
        raise SystemExit('Existing session key has an invalid size.')
else:
    with os.fdopen(fd, 'wb') as f:
        f.write(os.urandom(32))
addresses = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show']))
ips = {a['local'] for iface in addresses for a in iface.get('addr_info', [])}
(root / 'app/data/denied-ips').write_text('\n'.join(sorted(ips)) + '\n')
print('Runtime directories, workspace signing key and local-IP denylist are ready.')
