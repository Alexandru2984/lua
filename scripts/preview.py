#!/usr/bin/env python3
"""Launch an isolated origin with a disposable DB; never touches production data."""
import argparse
import pathlib
import re
import shutil
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--port', type=int, default=18084)
parser.add_argument('--fixtures', action='store_true', help='Use deterministic test network responses, never live providers')
args = parser.parse_args()
root = pathlib.Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='lualens-test-') as tmp:
    prefix = pathlib.Path(tmp)
    for name in ('data', 'logs'):
        (prefix / name).mkdir()
    (prefix / 'static').symlink_to(root / 'app/static', target_is_directory=True)
    if args.fixtures:
        shutil.copytree(root / 'app/modules', prefix / 'modules')
        shutil.copy(root / 'app/tests/fixtures/network.lua', prefix / 'modules/network.lua')
    else:
        (prefix / 'modules').symlink_to(root / 'app/modules', target_is_directory=True)
    for name in ('app.lua', 'init.lua'):
        (prefix / name).symlink_to(root / 'app' / name)
    import os
    (prefix / 'data/session.key').write_bytes(os.urandom(32))
    shutil.copy(root / 'app/data/denied-ips', prefix / 'data/denied-ips') if (root / 'app/data/denied-ips').exists() else None
    text = (root / 'deploy/inner-nginx.conf').read_text()
    if os.geteuid() == 0:
        # A root CI container has no unprivileged owner for its private tempdir.
        # This applies only to the disposable preview, never the service config.
        text = 'user root;\n' + text
    text = text.replace('/run/recon-dashboard-canary/nginx.pid', str(prefix / 'nginx.pid'))
    text = text.replace('127.0.0.1:8084', f'127.0.0.1:{args.port}')
    text = text.replace('https://lua.micutu.com;', f'http://127.0.0.1:{args.port};')
    # The source config names the production root. Override it independently of
    # the checkout location, including GitHub's disposable runner directories.
    text = re.sub(r'(?m)^(\s*)root\s+[^;]+;', lambda m: m[1] + 'root ' + str(prefix / 'static') + ';', text)
    config = prefix / 'nginx.conf'
    config.write_text(text)
    print(f'Isolated preview: http://127.0.0.1:{args.port}', flush=True)
    process = subprocess.Popen(['/usr/sbin/nginx', '-p', str(prefix) + '/', '-c', str(config)])
    try:
        process.wait()
    except KeyboardInterrupt:
        process.terminate()
        process.wait(timeout=10)
