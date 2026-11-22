local network = require 'network'
local validator = require 'validator'
local M = {}
function M.resolve(target, deadline)
    if validator.is_ipv4(target) then return {records={}, note='DNS record queries apply to domain names.'} end
    local r, err = network.resolver()
    if not r then return {records={},error=err} end
    local records, errors = {}, {}
    local queries = {{1,'A',target},{28,'AAAA',target},{15,'MX',target},{2,'NS',target},{16,'TXT',target},{257,'CAA',target},{16,'DMARC','_dmarc.'..target}}
    for _, query in ipairs(queries) do
        if ngx.now() >= deadline then errors[#errors+1]='DNS time budget exceeded.'; break end
        local answers, e = r:query(query[3], {qtype=query[1]})
        if not answers or answers.errcode then
            errors[#errors+1] = query[2] .. ': ' .. (e or (answers and answers.errstr) or 'lookup unavailable')
        else
            for _, a in ipairs(answers) do
                local value = a.address or a.exchange or a.nsdname or a.cname or a.txt or a.rdata
                if type(value) == 'table' then value=table.concat(value) end
                if value and #records < 150 then
                    if query[1] == 257 and a.rdata then
                        local data=a.rdata; local taglen=data:byte(2)
                        if taglen and #data>=2+taglen then value=tostring(data:byte(1))..' '..data:sub(3,2+taglen)..' '..data:sub(3+taglen) end
                    end
                    records[#records+1]={type=a.cname and 'CNAME' or query[2],name=query[3],value=tostring(value):sub(1,4096),ttl=a.ttl,priority=a.preference}
                end
            end
        end
    end
    return {records=records,errors=errors}
end
return M
