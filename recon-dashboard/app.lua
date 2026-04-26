local dns = require "dns"
local http_recon = require "http_recon"
local storage = require "storage"

-- Initialize storage
storage.init()

local method = ngx.req.get_method()

if method == "POST" then
    ngx.req.read_body()
    local args, err = ngx.req.get_post_args()
    if not args then
        ngx.say("Failed to get post args: ", err)
        return
    end

    local target = args.target
    if target and target ~= "" then
        -- Sanitize input (basic check)
        target = target:gsub("[%s;'\"`|<>&$]", "")
        
        local dns_res = dns.resolve(target)
        local http_headers, endpoints = http_recon.get_headers_and_endpoints(target)
        local tls_info = http_recon.get_tls_info(target)
        
        storage.save_scan(target, dns_res, http_headers, tls_info, endpoints)
        
        -- Redirect back to home to see results
        ngx.redirect("/")
        return
    end
end

-- Render UI
local history = storage.get_history()

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
        .scan-result { margin-top: 20px; border-top: 2px solid #eee; padding-top: 20px; }
        pre { background: #2c3e50; color: #ecf0f1; padding: 10px; border-radius: 4px; overflow-x: auto; }
        .history-item { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 4px; background: #fafafa; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Passive Recon Dashboard</h1>
        <p>Enter a domain or IP for safe, passive reconnaissance.</p>
        
        <form method="POST" action="/">
            <div class="form-group">
                <input type="text" name="target" placeholder="e.g., example.com" required>
                <button type="submit">Scan</button>
            </div>
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
        ngx.say("<h4>HTTP Headers</h4><pre>" .. (scan.http_headers or "N/A") .. "</pre>")
        ngx.say("<h4>TLS Info</h4><pre>" .. (scan.tls_info or "N/A") .. "</pre>")
        ngx.say("<h4>Endpoints</h4><pre>" .. (scan.endpoints or "N/A") .. "</pre>")
        
        ngx.say("</div>")
    end
end

ngx.say([[
    </div>
</body>
</html>
]])
