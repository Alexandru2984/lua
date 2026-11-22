local http = require "resty.http"
local M = {}

function M.get_headers_and_endpoints(target)
    local httpc = http.new()
    local url = target
    if not url:match("^https?://") then
        url = "http://" .. target
    end
    
    local res, err = httpc:request_uri(url, {
        method = "GET",
        ssl_verify = false,
        headers = {
            ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PassiveRecon/1.0"
        }
    })

    local headers_str = ""
    local endpoints_str = ""

    if not res then
        headers_str = "Failed to connect: " .. (err or "unknown")
    else
        local h_list = {}
        for k, v in pairs(res.headers) do
            if type(v) == "table" then
                table.insert(h_list, k .. ": " .. table.concat(v, ", "))
            else
                table.insert(h_list, k .. ": " .. v)
            end
        end
        headers_str = table.concat(h_list, "\n")
        
        endpoints_str = "Checked " .. url .. " -> Status: " .. res.status
    end

    -- Check robots.txt
    local robots_url = url .. "/robots.txt"
    if url:sub(-1) == "/" then
        robots_url = url .. "robots.txt"
    end
    
    local rob_res, rob_err = httpc:request_uri(robots_url, {
        method = "GET",
        ssl_verify = false,
        headers = { ["User-Agent"] = "PassiveRecon/1.0" }
    })
    
    if rob_res and rob_res.status == 200 then
        endpoints_str = endpoints_str .. "\nFound robots.txt (length: " .. #(rob_res.body or "") .. " bytes)"
    else
        endpoints_str = endpoints_str .. "\nNo robots.txt found."
    end

    return headers_str, endpoints_str
end

function M.get_tls_info(target)
    local host = target:gsub("^https?://", ""):gsub("/.*$", "")
    
    local cmd = "echo | timeout 5 openssl s_client -connect " .. host .. ":443 -servername " .. host .. " 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null"
    local f = io.popen(cmd)
    if not f then return "Failed to run openssl" end
    local output = f:read("*a")
    f:close()
    
    if output == "" or not output then
        return "No TLS info found or not an HTTPS target."
    end
    return output
end

return M
