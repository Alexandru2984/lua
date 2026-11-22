local M = {}

-- Function to check if an IP is private/internal
local function is_private_ip(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    
    if a == 10 then return true end
    if a == 127 then return true end
    if a == 172 and b >= 16 and b <= 31 then return true end
    if a == 192 and b == 168 then return true end
    if a == 169 and b == 254 then return true end
    if a == 0 then return true end
    
    return false
end

function M.sanitize_and_validate(target)
    if not target or target == "" then return nil, "Empty target" end
    
    -- Extract host if it's a URL
    local host = target:match("^https?://([^/:]+)")
    if not host then
        host = target
    end
    
    -- Basic cleanup
    host = host:gsub("[%s;'\"`|<>&$]", "")
    
    -- Check if IPv4
    local a, b, c, d = host:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if a then
        if tonumber(a) > 255 or tonumber(b) > 255 or tonumber(c) > 255 or tonumber(d) > 255 then
            return nil, "Invalid IPv4 format"
        end
        if is_private_ip(host) then
            return nil, "Private or internal IPs are not allowed"
        end
        return host, nil
    end
    
    -- Check domain format (simplistic regex for domains)
    if not host:match("^([%w_.-]+%.[a-zA-Z][a-zA-Z]+)$") then
        return nil, "Invalid domain format"
    end
    
    return host, nil
end

return M
