#!/usr/bin/env python3
"""Check native TLS metadata on temporary local TLS 1.2 and 1.3 servers."""
import hashlib
import json
import os
import pathlib
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request

root = pathlib.Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='lualens-native-tls-') as tmp:
    prefix = pathlib.Path(tmp)
    key, cert = prefix / 'test.key', prefix / 'test.crt'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(key), '-out', str(cert), '-days', '45',
                    '-subj', '/CN=fixture.example'], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    reservations = []
    for _ in range(3):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        reservations.append(listener)
    control, tls12, tls13 = [s.getsockname()[1] for s in reservations]
    (prefix / 'probe.lua').write_text('''
local sock=ngx.socket.tcp();sock:settimeout(2000)
local port=tonumber(ngx.var.arg_port)
local ok,err=sock:connect('127.0.0.1',port)
if not ok then ngx.status=500;ngx.say(err);return end
local session,message=sock:sslhandshake(nil,'fixture.example',false)
if not session then ngx.status=500;ngx.say(message);return end
local certificate,failure=require('tls_metadata').inspect(session,ngx.time())
sock:close();collectgarbage('collect')
if not certificate then ngx.status=500;ngx.say(failure);return end
ngx.header.content_type='application/json'
ngx.say(require('cjson.safe').encode(certificate))
''')
    config = ('user root;\n' if os.geteuid() == 0 else '') + f'''
load_module /usr/lib/nginx/modules/ndk_http_module.so;
load_module /usr/lib/nginx/modules/ngx_http_lua_module.so;
daemon off;
worker_processes 1;
pid {prefix}/nginx.pid;
error_log {prefix}/error.log warn;
events {{ worker_connections 64; }}
http {{
    access_log off;
    lua_package_path "{root}/app/modules/?.lua;;";
    server {{ listen 127.0.0.1:{control}; location / {{ content_by_lua_file {prefix}/probe.lua; }} }}
    server {{ listen 127.0.0.1:{tls12} ssl; ssl_certificate {cert}; ssl_certificate_key {key}; ssl_protocols TLSv1.2; location / {{ return 204; }} }}
    server {{ listen 127.0.0.1:{tls13} ssl; ssl_certificate {cert}; ssl_certificate_key {key}; ssl_protocols TLSv1.3; location / {{ return 204; }} }}
}}
'''
    path = prefix / 'nginx.conf'
    path.write_text(config)
    for listener in reservations:
        listener.close()
    process = subprocess.Popen(['/usr/sbin/nginx', '-p', str(prefix) + '/', '-c', str(path)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError('Native TLS test server failed: ' + process.stderr.read().decode())
            try:
                with socket.create_connection(('127.0.0.1', control), timeout=.2):
                    break
            except OSError:
                time.sleep(.05)
        for port, protocol in [(tls12, 'TLS 1.2'), (tls13, 'TLS 1.3')]:
            with urllib.request.urlopen(f'http://127.0.0.1:{control}/?port={port}', timeout=5) as response:
                data = json.load(response)
            assert data['fingerprint_sha256'] == expected, data
            assert data['subject_cn'] == 'fixture.example' and data['issuer_cn'] == 'fixture.example', data
            assert data['protocol'] == protocol and data['cipher'], data
            assert data['not_after'] - data['not_before'] == 45 * 86400, data
            assert abs(data['observed_at'] - time.time()) < 10, data
            assert data['validity_at_scan'] == 'valid' and 43 <= data['days_remaining_at_scan'] <= 45, data
            print(f'Native {protocol}: certificate fingerprint, dates, issuer and cipher verified.')
    except Exception:
        if (prefix / 'error.log').exists():
            print((prefix / 'error.log').read_text()[-3000:])
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
