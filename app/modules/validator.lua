local M = {}

function M.is_ipv4(host)
    return type(host) == "string" and host:match("^%d+%.%d+%.%d+%.%d+$") ~= nil
end

function M.is_public_ipv4(ip)
    if not M.is_ipv4(ip) then return false end
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if a > 255 or b > 255 or c > 255 or d > 255 then return false end
    if a == 0 or a == 10 or a == 127 or a >= 224 then return false end
    if a == 100 and b >= 64 and b <= 127 then return false end
    if a == 169 and b == 254 then return false end
    if a == 172 and b >= 16 and b <= 31 then return false end
    if a == 192 and (b == 168 or (b == 0 and (c == 0 or c == 2)) or (b == 88 and c == 99)) then return false end
    if a == 198 and (b == 18 or b == 19 or (b == 51 and c == 100)) then return false end
    if a == 203 and b == 0 and c == 113 then return false end
    return true
end

function M.sanitize_and_validate(target)
    if type(target) ~= "string" or #target == 0 then return nil, "Enter a domain or public IPv4 address." end
    if #target > 2048 then return nil, "The target is too long." end
    target = target:match("^%s*(.-)%s*$"):lower()
    if target:find("[%s%c\\@'\"`|<>&$;%%#]") then return nil, "The target contains unsupported characters." end
    local host = target
    if target:match("^https?://") then
        host = target:match("^https?://([^/?]+)")
        if not host then return nil, "Invalid URL." end
    elseif target:find("[/:?]") then
        return nil, "Use a domain, IPv4 address, or an HTTP(S) URL." end
    if host:find(":", 1, true) then return nil, "Custom ports and IPv6 targets are not supported." end
    host = host:gsub("%.$", "")
    if #host > 253 or #host == 0 then return nil, "Invalid domain length." end
    if M.is_ipv4(host) then
        for part in host:gmatch("[^.]+") do
            if tonumber(part) > 255 or (#part > 1 and part:sub(1, 1) == "0") then return nil, "Invalid IPv4 format." end
        end
        if not M.is_public_ipv4(host) then return nil, "Only public IPv4 addresses are allowed." end
        return host
    end
    if not host:match("^[a-z0-9.-]+$") or host:find("..", 1, true) or not host:find(".", 1, true) then
        return nil, "Invalid domain format." end
    for label in host:gmatch("[^.]+") do
        if #label > 63 or not label:match("^[a-z0-9]") or not label:match("[a-z0-9]$") then return nil, "Invalid domain label." end
    end
    local tld = host:match("%.([^.]+)$")
    if not tld or (#tld < 2) or (not tld:match("^[a-z]+$") and not tld:match("^xn%-%-[a-z0-9-]+$")) then
        return nil, "Invalid top-level domain." end
    for _, suffix in ipairs({"localhost", "local", "internal", "test", "invalid", "onion", "home", "arpa"}) do
        if host == suffix or host:sub(-#suffix - 1) == "." .. suffix then return nil, "Internal and reserved domains are not allowed." end
    end
    return host
end

return M
