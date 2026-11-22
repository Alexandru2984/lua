local http = require "resty.http"
local cjson = require "cjson.safe"

local M = {}

function M.get_subdomains(target)
    -- Ignore IPs for subdomain enumeration
    if target:match("^%d+%.%d+%.%d+%.%d+$") then
        return "N/A (Target is an IP)"
    end

    local httpc = http.new()
    local url = "https://crt.sh/?q=%25." .. target .. "&output=json"
    
    local res, err = httpc:request_uri(url, {
        method = "GET",
        ssl_verify = false,
        headers = {
            ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PassiveRecon/1.0"
        }
    })

    if not res or res.status ~= 200 then
        return "Failed to fetch from crt.sh: " .. (err or (res and res.status) or "unknown")
    end

    local data, decode_err = cjson.decode(res.body)
    if not data or type(data) ~= "table" then
        return "Failed to parse JSON from crt.sh or empty response"
    end

    local subdomains = {}
    local unique = {}

    for _, entry in ipairs(data) do
        local name = entry.name_value
        if name then
            for sub in name:gmatch("[^\r\n]+") do
                sub = sub:gsub("^%*%.", "") -- remove wildcards
                if not unique[sub] then
                    unique[sub] = true
                    table.insert(subdomains, sub)
                end
            end
        end
    end

    if #subdomains == 0 then
        return "No subdomains found in Certificate Transparency logs."
    end
    
    table.sort(subdomains)
    return table.concat(subdomains, "\n")
end

return M
