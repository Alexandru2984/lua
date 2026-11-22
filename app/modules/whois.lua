-- RDAP replaces the blocking WHOIS subprocess. Every HTTPS redirect is validated
-- and resolved through the same pinned public-IP client.
local network = require 'network'
local validator = require 'validator'
local json = require 'cjson.safe'
local M = {}
function M.get_whois(target, deadline)
    local host, path='rdap.org', (validator.is_ipv4(target) and '/ip/' or '/domain/')..target
    for _=1,4 do
        local res, err=network.request(host,path,{max_body=131072,deadline=deadline})
        if not res then return {error=err} end
        if res.status==301 or res.status==302 or res.status==307 or res.status==308 then
            local location=res.headers.location or ''
            local newhost,newpath=location:match('^https://([^/]+)(/.*)$')
            if not newhost or validator.sanitize_and_validate(newhost)~=newhost or newpath:find('[%c%s]') then return {error='RDAP returned an unsupported redirect.'} end
            host,path=newhost,newpath
        elseif res.status==200 then
            local data=json.decode(res.body)
            if type(data)~='table' then return {error='RDAP returned invalid JSON.'} end
            local events={}
            for _, e in ipairs(type(data.events)=='table' and data.events or {}) do
                if type(e)=='table' and type(e.eventAction)=='string' and type(e.eventDate)=='string' and #events<20 then
                    events[#events+1]={action=e.eventAction:sub(1,80),date=e.eventDate:sub(1,80)}
                end
            end
            local statuses={}
            for _, status in ipairs(type(data.status)=='table' and data.status or {}) do
                if type(status)=='string' and #statuses<20 then statuses[#statuses+1]=status:sub(1,120) end
            end
            return {name=type(data.ldhName)=='string' and data.ldhName:sub(1,253) or target,
                handle=type(data.handle)=='string' and data.handle:sub(1,200) or nil,
                status=statuses,events=events,source=host}
        else return {error='RDAP returned HTTP '..res.status..'. Subdomains may not have a registration record.'} end
    end
    return {error='RDAP redirect limit reached.'}
end
return M
