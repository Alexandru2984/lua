local storage = require 'storage'
local network = require 'network'
local M = {}
local state = ngx.shared.rate_limit_store

function M.acquire(owner)
    local personal = state:add('job:'..owner, true, 120)
    if not personal then return nil, 'A scan is already running in this workspace.' end
    for slot=1,3 do
        if state:add('slot:'..slot, owner, 120) then return true end
    end
    state:delete('job:'..owner)
    return nil, 'All scan slots are busy. Try again shortly.'
end
function M.release(owner)
    state:delete('job:'..owner)
    for slot=1,3 do
        if state:get('slot:'..slot)==owner then state:delete('slot:'..slot) end
    end
end
function M.run(premature, id, owner, target, profile)
    if premature then M.release(owner); return end
    local started = ngx.now()
    local ok, err = xpcall(function()
        local ip, resolve_error=network.resolve_public(target)
        if not ip then
            assert(storage.finish(id,{error=resolve_error},'failed',math.floor((ngx.now()-started)*1000)))
            return
        end
        storage.progress(id, profile=='deep' and 'Checking DNS, HTTPS, transparency and registration' or 'Checking DNS, HTTPS and public resources')
        local deadline=started+40
        local tasks={
            {'dns',function() return require('dns').resolve(target,math.min(deadline,ngx.now()+14)) end},
            {'http',function() return require('http_recon').analyze(target,ip,math.min(deadline,ngx.now()+22)) end}
        }
        if profile=='deep' then
            tasks[#tasks+1]={'transparency',function() return require('crtsh').get_subdomains(target,math.min(deadline,ngx.now()+12)) end}
            tasks[#tasks+1]={'registration',function() return require('whois').get_whois(target,math.min(deadline,ngx.now()+14)) end}
        end
        local threads={}
        for i, task in ipairs(tasks) do threads[i]=ngx.thread.spawn(task[2]) end
        local report={version=2,target=target,ip=ip,profile=profile,errors={}}
        for i, task in ipairs(tasks) do
            local success,result=ngx.thread.wait(threads[i])
            if not success or type(result)~='table' then result={error='This check could not finish.'} end
            report[task[1]]=result
            if result.error then report.errors[#report.errors+1]=task[1]..': '..result.error end
            if task[1]=='dns' and result.errors then
                for _, message in ipairs(result.errors) do report.errors[#report.errors+1]=message end
            end
        end
        report.score=report.http.score
        local status=#report.errors>0 and 'partial' or 'completed'
        if report.http.error and #report.dns.records==0 then status='failed' end
        assert(storage.finish(id,report,status,math.floor((ngx.now()-started)*1000)))
    end, debug.traceback)
    M.release(owner)
    if not ok then
        ngx.log(ngx.ERR, 'Scan ',id,' failed: ',err)
        storage.finish(id,{error='The scan was interrupted. Please retry.'},'failed',math.floor((ngx.now()-started)*1000))
    end
end
return M
