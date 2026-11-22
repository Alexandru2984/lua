local M = {}

function M.get_whois(target)
    -- Remove protocol and path if present
    local host = target:gsub("^https?://", ""):gsub("/.*$", "")
    
    local cmd = "timeout 5 whois " .. host .. " 2>&1"
    local f = io.popen(cmd)
    if not f then return "Failed to run whois command" end
    
    local output = f:read("*a")
    f:close()
    
    if not output or output == "" then
        return "No WHOIS info found."
    end
    
    -- Truncate to 2000 chars to avoid massive DB blobs
    if #output > 2000 then
        return output:sub(1, 2000) .. "\n... (truncated)"
    end
    return output
end

return M
