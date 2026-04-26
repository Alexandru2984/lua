local dns = require "dns"
local http_recon = require "http_recon"
local storage = require "storage"
local validator = require "validator"
local whois = require "whois"
local cjson = require "cjson"

-- Rate Limiting Logic
local limit_dict = ngx.shared.rate_limit_store
local client_ip = ngx.var.http_x_real_ip or ngx.var.remote_addr or "unknown"

local count, err = limit_dict:incr(client_ip, 1, 0)
if count == 1 then
    -- Allow 3 scans per minute
    limit_dict:expire(client_ip, 60)
end

-- Initialize storage
storage.init()

local method = ngx.req.get_method()
local error_msg = nil

if method == "POST" then
    if count > 3 then
        ngx.status = 429
        ngx.header.content_type = "text/plain"
        ngx.say("Rate limit exceeded. Please wait a minute before scanning again.")
        return
    end

    ngx.req.read_body()
    local args, err = ngx.req.get_post_args()
    if not args then
        ngx.say("Failed to get post args: ", err)
        return
    end

    local target = args.target
    if target and target ~= "" then
        local safe_target, val_err = validator.sanitize_and_validate(target)
        
        if not safe_target then
            error_msg = val_err
        else
            local dns_res = dns.resolve(safe_target)
            local http_headers, endpoints = http_recon.get_headers_and_endpoints(safe_target)
            local tls_info = http_recon.get_tls_info(safe_target)
            local whois_info = whois.get_whois(safe_target)
            
            storage.save_scan(safe_target, dns_res, http_headers, tls_info, endpoints, whois_info)
            
            -- Redirect back to home to see results
            ngx.redirect("/")
            return
        end
    end
end

-- Render UI
local history = storage.get_history()

-- JSON Export endpoint
if method == "GET" and ngx.var.arg_format == "json" then
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode(history))
    return
end

ngx.header.content_type = "text/html"
ngx.say([[
<!DOCTYPE html>
<html>
<head>
    <title>Passive Recon Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f4f4f9; color: #333; }
        .container { max-width: 1000px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1, h2, h3 { color: #2c3e50; }
        .form-group { margin-bottom: 15px; }
        input[type="text"] { width: 70%; padding: 10px; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 10px 20px; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #2980b9; }
        button:disabled { background: #95a5a6; cursor: not-allowed; }
        .scan-result { margin-top: 20px; border-top: 2px solid #eee; padding-top: 20px; }
        pre { background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }
        .history-item { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 4px; background: #fafafa; }
        .error-msg { color: #e74c3c; font-weight: bold; background: #fadbd8; padding: 10px; border-radius: 4px; margin-bottom: 15px; }
        #loading { display: none; margin-top: 10px; font-weight: bold; color: #e67e22; }
        .json-link { float: right; color: #3498db; text-decoration: none; font-weight: bold; }
        .json-link:hover { text-decoration: underline; }
    </style>
    <script>
        function showLoading() {
            document.getElementById('submitBtn').disabled = true;
            document.getElementById('loading').style.display = 'block';
        }
    </script>
</head>
<body>
    <div class="container">
        <a href="/?format=json" class="json-link">Export as JSON</a>
        <h1>Passive Recon Dashboard</h1>
        <p>Enter a domain or IP for safe, passive reconnaissance.</p>
]])

if error_msg then
    ngx.say("<div class='error-msg'>Error: " .. error_msg .. "</div>")
end

ngx.say([[
        <form method="POST" action="/" onsubmit="showLoading()">
            <div class="form-group">
                <input type="text" name="target" placeholder="e.g., example.com" required>
                <button type="submit" id="submitBtn">Scan</button>
            </div>
            <div id="loading">Scanning in progress... This may take up to 10 seconds.</div>
        </form>

        <h2>Recent Scans</h2>
]])

if #history == 0 then
    ngx.say("<p>No scans yet.</p>")
else
    for _, scan in ipairs(history) do
        ngx.say("<div class='history-item'>")
        ngx.say("<h3>Target: " .. scan.target .. " <small>(" .. scan.timestamp .. ")</small></h3>")
        
        ngx.say("<h4>DNS Records</h4><pre>" .. (scan.dns_results or "N/A") .. "</pre>")
        ngx.say("<h4>HTTP Headers & Endpoints</h4><pre>" .. (scan.http_headers or "") .. "\n" .. (scan.endpoints or "") .. "</pre>")
        ngx.say("<h4>TLS Info</h4><pre>" .. (scan.tls_info or "N/A") .. "</pre>")
        ngx.say("<h4>WHOIS</h4><pre>" .. (scan.whois_info or "N/A") .. "</pre>")
        
        ngx.say("</div>")
    end
end

ngx.say([[
    </div>
</body>
</html>
]])
