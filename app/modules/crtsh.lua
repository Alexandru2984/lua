local network = require 'network'
local validator = require 'validator'
local json = require 'cjson.safe'
local M = {}
function M.get_subdomains(target, deadline)
    if validator.is_ipv4(target) then return {names={},note='Certificate transparency requires a domain.'} end
    local res, err=network.request('crt.sh','/?q=%25.'..target..'&output=json',{max_body=524288,deadline=deadline})
    if not res or res.status~=200 then return {names={},error=err or 'Certificate transparency provider is unavailable.'} end
    local data=json.decode(res.body)
    if type(data)~='table' then return {names={},error='Certificate transparency returned an invalid response.'} end
    local names, seen, truncated={}, {}, false
    for _, entry in ipairs(data) do
        if type(entry)=='table' and type(entry.name_value)=='string' then
            for name in entry.name_value:gmatch('[^\r\n]+') do
                name=name:lower():gsub('^%*%.','')
                local valid=validator.sanitize_and_validate(name)
                if valid==name and (name==target or name:sub(-#target-1)=='.'..target) and not seen[name] then
                    if #names>=300 then truncated=true; break end
                    names[#names+1]=name; seen[name]=true
                end
            end
        end
    end
    table.sort(names)
    return {names=names,truncated=truncated,source='crt.sh',note='Historical certificates do not prove a hostname is currently live.'}
end
return M
