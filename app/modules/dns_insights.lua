-- Direct DNS observations only: no SMTP probing, SPF expansion, message
-- authentication, organizational-domain discovery or inherited-policy verdicts.
local validator=require 'validator'
local M={}
local function check(key,label,state,summary,value,advice)
    return {key=key,label=label,state=state,summary=summary,value=value,advice=advice}
end
local function values(dns,record_type)
    local out={}
    for _,record in ipairs(dns.records or {}) do
        if record.type==record_type and type(record.value)=='string' then out[#out+1]=record.value end
    end
    return out
end
local function available(dns,name)
    local state=dns.query_status and dns.query_status[name]
    return state=='answered' or state=='absent'
end
function M.analyze(target,dns)
    if validator.is_ipv4(target) then
        return {check('domain-only','DNS and email policies','info','These observations require a domain name.',nil,'IPv4 scans do not establish an email domain.')}
    end
    local checks={}
    local function unavailable(key,label)
        checks[#checks+1]=check(key,label,'unavailable','The DNS lookup did not complete.',nil,'Retry before drawing a conclusion about this record.')
    end
    if not available(dns,'TXT') then unavailable('spf','SPF policy') else
        local candidates={}
        for _,value in ipairs(values(dns,'TXT')) do
            local lower=value:lower()
            if lower=='v=spf1' or lower:match('^v=spf1%s') then candidates[#candidates+1]=value end
        end
        local advice='Direct TXT observation only. Includes, redirects, lookup limits and sending-IP authorization are not evaluated.'
        if #candidates==0 then checks[#checks+1]=check('spf','SPF policy','info','No SPF record was observed at this domain.',nil,advice)
        elseif #candidates>1 then checks[#checks+1]=check('spf','SPF policy','review','Multiple SPF records were observed; SPF selection is ambiguous.',table.concat(candidates,'\n'):sub(1,8192),advice)
        else
            local value=candidates[1]
            local qualifier,redirect
            for token in value:lower():gmatch('%S+') do
                if token=='all' or token=='+all' then qualifier='+';break end
                if token=='-all' or token=='~all' or token=='?all' then qualifier=token:sub(1,1);break end
                if token:match('^redirect=') then redirect=true end
            end
            local summary,state='No all mechanism observed; default handling can be neutral.','review'
            if qualifier=='-' then summary,state='An explicit -all fail mechanism was observed.','observed'
            elseif qualifier=='+' then summary='The +all mechanism permits every sender that reaches it.'
            elseif qualifier=='~' then summary='The ~all mechanism requests softfail handling.'
            elseif qualifier=='?' then summary='The ?all mechanism requests neutral handling.'
            elseif redirect then summary,state='An SPF redirect was observed; its destination was not evaluated.','info' end
            checks[#checks+1]=check('spf','SPF policy',state,summary,value,advice)
        end
    end
    if not available(dns,'DMARC') then unavailable('dmarc','DMARC policy') else
        local candidates={}
        for _,value in ipairs(values(dns,'DMARC')) do
            if value:match('^%s*v%s*=%s*DMARC1%s*;') or value:match('^%s*v%s*=%s*DMARC1%s*$') then candidates[#candidates+1]=value end
        end
        local advice='Only the direct _dmarc record is inspected. Parent policy discovery, DKIM, identifier alignment and message delivery are not evaluated.'
        if #candidates==0 then checks[#checks+1]=check('dmarc','DMARC policy','info','No direct DMARC1 policy was observed; a parent policy may apply.',nil,advice)
        elseif #candidates>1 then checks[#checks+1]=check('dmarc','DMARC policy','review','Multiple direct DMARC policies were observed.',table.concat(candidates,'\n'):sub(1,8192),advice)
        else
            local value=candidates[1]
            local tags,duplicate={},false
            for part in value:gmatch('[^;]+') do
                local key,val=part:match('^%s*([a-zA-Z]+)%s*=%s*(.-)%s*$')
                if key then
                    key=key:lower()
                    if tags[key] and (key=='p' or key=='v' or key=='sp' or key=='np' or key=='t') then duplicate=true end
                    tags[key]=val
                end
            end
            local policy=(tags.p or 'none'):lower()
            local testing=(tags.t or 'n'):lower()
            local summary,state
            if duplicate then summary,state='Repeated policy tags make this direct record ambiguous.','review'
            elseif policy~='none' and policy~='quarantine' and policy~='reject' then summary,state='The p policy value was not recognized.','review'
            elseif testing~='n' and testing~='y' then summary,state='The t testing-mode value was not recognized.','review'
            elseif tags.sp and not ({none=true,quarantine=true,reject=true})[tags.sp:lower()] or tags.np and not ({none=true,quarantine=true,reject=true})[tags.np:lower()] then
                summary,state='A subdomain policy value was not recognized.','review'
            elseif policy=='none' then summary,state=tags.p and 'A monitoring policy (p=none) was observed.' or 'No p tag was found; RFC 9989 defaults to monitoring.','review'
            elseif testing=='y' then summary,state='Testing mode (t=y) requests softer handling than p='..policy..'.','review'
            elseif tags.pct then summary,state='p='..policy..' with a legacy pct tag; receiver behavior can differ.','review'
            else summary,state='A direct p='..policy..' policy was observed.','observed' end
            checks[#checks+1]=check('dmarc','DMARC policy',state,summary,value,advice)
        end
    end
    if not available(dns,'CAA') then unavailable('caa','CAA records') else
        local records=values(dns,'CAA')
        checks[#checks+1]=check('caa','CAA records',#records>0 and 'observed' or 'info',
            #records>0 and #records..' direct CAA record(s) were observed.' or 'No direct CAA records were observed; a parent policy may apply.',
            #records>0 and table.concat(records,'\n'):sub(1,8192) or nil,
            'Presence alone does not establish effective issuance restrictions. Parent/CNAME policy and CA-specific parameters are not evaluated.')
    end
    if not available(dns,'MX') then unavailable('mx','Mail routing') else
        local records,nulls={},0
        for _,record in ipairs(dns.records or {}) do
            if record.type=='MX' then
                records[#records+1]=tostring(record.priority or '')..' '..(record.value or '')
                if (record.value=='' or record.value=='.') and record.priority==0 then nulls=nulls+1 end
            end
        end
        local summary,state
        if nulls>0 and #records>1 then summary,state='Null MX is mixed with other MX records.','review'
        elseif nulls==1 then summary,state='Null MX explicitly announces no incoming mail service.','observed'
        elseif #records>0 then summary,state=#records..' mail exchanger(s) were observed.','observed'
        else summary,state='No MX was observed; address-record fallback may still apply.','info' end
        checks[#checks+1]=check('mx','Mail routing',state,summary,#records>0 and table.concat(records,'\n'):sub(1,8192) or nil,
            'No mail server connections or delivery tests are made. A null MX record is distinct from a failed MX lookup.')
    end
    return checks
end
return M
