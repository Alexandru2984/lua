local resolver = require "resty.dns.resolver"
local M = {}

function M.resolve(target)
    local r, err = resolver:new{
        nameservers = {"8.8.8.8", {"8.8.4.4", 53}},
        retrans = 5,
        timeout = 2000,
    }
    if not r then
        return "Failed to instantiate DNS resolver: " .. (err or "unknown")
    end

    local results = {}
    
    local function query_type(qtype, type_name)
        local answers, err, tries = r:query(target, { qtype = qtype })
        if not answers then
            table.insert(results, type_name .. " Query failed: " .. (err or "unknown"))
            return
        end
        if answers.errcode then
            table.insert(results, type_name .. " Query server returned error code: " .. answers.errcode .. ": " .. answers.errstr)
            return
        end
        
        table.insert(results, type_name .. " Records:")
        if #answers == 0 then
            table.insert(results, "  (None)")
        else
            for i, ans in ipairs(answers) do
                if ans.address then
                    table.insert(results, "  " .. ans.address)
                elseif ans.cname then
                    table.insert(results, "  CNAME " .. ans.cname)
                elseif ans.exchange then
                    table.insert(results, "  MX " .. ans.exchange .. " (pref: " .. ans.preference .. ")")
                else
                    table.insert(results, "  " .. (ans.rdata or "unknown record"))
                end
            end
        end
    end

    query_type(r.TYPE_A, "A")
    query_type(r.TYPE_AAAA, "AAAA")
    query_type(r.TYPE_MX, "MX")

    return table.concat(results, "\n")
end

return M
