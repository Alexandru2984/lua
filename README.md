# Passive Recon Dashboard

A lightweight, OpenResty-based (Lua) web application for performing passive reconnaissance on domains and IPs.

## Features
- Input field for domain or IP
- Perform passive recon:
  - DNS resolution (A, AAAA, MX)
  - HTTP headers
  - TLS certificate info
  - Basic endpoint discovery (safe GET requests)
- Store results locally (SQLite)
- Display results in a simple web UI
- Keep history of scans
- Fully passive and safe

## Setup steps
1. Install OpenResty and LuaRocks.
2. The app uses `lua-resty-http` for HTTP requests, `lua-resty-dns` for DNS, and `sqlite3` for storage.

## How to run
The service runs via systemd (`recon-dashboard.service`). It listens on an internal port and is proxied through the main Nginx server.

```bash
sudo systemctl start recon-dashboard
```

## Security notes
- This app performs ONLY passive scanning.
- No brute force or aggressive fuzzing.
- Inputs are sanitized to prevent injection.
- Rate limiting is configured in Nginx.
