local json=require 'cjson.safe'
local storage=require 'storage'
local session=require 'session'
local method=ngx.req.get_method()
local path=ngx.var.uri
local function reply(status,data)
    ngx.status=status
    ngx.header.content_type='application/json; charset=utf-8'
    ngx.header['Cache-Control']='private, no-store'
    ngx.say(json.encode(data) or '{"error":"Response encoding failed."}')
end
local function error_response(status,message) return reply(status,{error=message}) end
if path=='/api/health' then
    if method~='GET' then return error_response(405,'Method not allowed.') end
    local ready=storage.healthy()
    return reply(ready and 200 or 503,{status=ready and 'ok' or 'unavailable'})
end
local bootstrap=path=='/api/bootstrap'
local owner,csrf=session.get(bootstrap and method=='GET')
if not owner then return error_response(401,'Your workspace session has expired. Reload this page.') end
if method~='GET' and not session.check(csrf) then return error_response(403,'Request verification failed. Reload this page and retry.') end
if bootstrap and method=='GET' then
    if ngx.var.http_sec_fetch_site=='cross-site' then return error_response(403,'Open the workspace directly to begin.') end
    return reply(200,{csrf=csrf,limits={per_minute=3,retention_days=30,cache_seconds=600,saved_targets=50},capabilities={saved_targets=true},version='2.1'})
end
if path=='/api/scans' and method=='GET' then
    local page=tonumber(ngx.var.arg_page or '1')
    if not page or page%1~=0 or page<1 or page>100 then return error_response(400,'Invalid history page.') end
    local target=ngx.var.arg_target
    if target then
        local normalized=require('validator').sanitize_and_validate(target)
        if not normalized then return error_response(422,'Invalid domain filter.') end
        target=normalized
    end
    local rows,err=storage.history(owner,page,target)
    local total,count_err=storage.count(owner,target)
    if not rows or not total then return error_response(503,err or count_err) end
    return reply(200,{scans=#rows>0 and rows or json.empty_array or {},total=total,page=page,page_size=50})
end
local function body()
    local content_type=(ngx.var.content_type or ''):lower():match('^%s*([^;%s]+)')
    if content_type~='application/json' then return nil,'Send application/json.' end
    ngx.req.read_body()
    local raw=ngx.req.get_body_data()
    if not raw or #raw>4096 then return nil,'Request body is missing or too large.' end
    local value=json.decode(raw)
    if type(value)~='table' then return nil,'Invalid JSON body.' end
    return value
end
if path=='/api/targets' then
    if method=='GET' then
        local rows,err=storage.targets(owner)
        if not rows then return error_response(503,err) end
        return reply(200,{targets=#rows>0 and rows or json.empty_array or {},limit=50})
    end
    if method=='POST' then
        local data,err=body()
        if not data then return error_response(400,err) end
        local target
        target,err=require('validator').sanitize_and_validate(data.target)
        if not target then return error_response(422,err) end
        local label=data.label or ''
        if type(label)~='string' or #label>320 or label:find('[%c]') or not ngx.re.match(label,'^.{0,80}$','ju') then
            return error_response(422,'Use a label of up to 80 characters, without control characters.') end
        label=label:match('^%s*(.-)%s*$')
        local profile=data.profile or 'quick'
        if profile~='quick' and profile~='deep' then return error_response(422,'Choose a quick or deep scan.') end
        local row,message=storage.save_target(owner,target,label,profile)
        if not row then return error_response(message=='Save up to 50 domains per workspace.' and 409 or 503,message) end
        return reply(200,row)
    end
    ngx.header.Allow='GET, POST'
    return error_response(405,'Method not allowed.')
end
local target_id=path:match('^/api/targets/(%d+)$')
if target_id and #target_id<12 then
    if method~='DELETE' then ngx.header.Allow='DELETE';return error_response(405,'Method not allowed.') end
    local changed,err=storage.delete_target(owner,tonumber(target_id))
    if not changed then return error_response(503,err) end
    if changed==0 then return error_response(404,'Saved domain not found in this workspace.') end
    return reply(200,{deleted=true})
end
if path=='/api/scans' and method=='POST' then
    local data,err=body()
    if not data then return error_response(400,err) end
    local target
    target,err=require('validator').sanitize_and_validate(data.target)
    if not target then return error_response(422,err) end
    local profile=data.profile or 'quick'
    if profile~='quick' and profile~='deep' then return error_response(422,'Choose a quick or deep scan.') end
    if data.fresh~=nil and type(data.fresh)~='boolean' then return error_response(422,'Invalid cache option.') end
    local recent,recent_err=storage.recent(owner,target,profile)
    if recent_err then return error_response(503,recent_err) end
    if recent and (recent.status=='pending' or not data.fresh) then return reply(200,{id=recent.id,cached=recent.status~='pending'}) end
    local limits=ngx.shared.rate_limit_store
    -- Only an outer proxy on loopback may set X-Real-IP; Nginx normalizes it
    -- into remote_addr. Never consume arbitrary forwarded headers here.
    local count=limits:incr('scan:'..ngx.var.remote_addr,1,0,60)
    if not count then return error_response(503,'Scan limiter is busy. Try again shortly.') end
    if count>3 then ngx.header['Retry-After']='60'; return error_response(429,'Three scans per minute are allowed. Please wait a minute.') end
    local jobs=require 'jobs'
    local acquired,message=jobs.acquire(owner)
    if not acquired then ngx.header['Retry-After']='10'; return error_response(429,message) end
    local id
    id,err=storage.create(owner,target,profile)
    if not id then jobs.release(owner); return error_response(503,err) end
    local ok,timer_error=ngx.timer.at(0,jobs.run,id,owner,target,profile)
    if not ok then
        jobs.release(owner)
        storage.finish(id,{error='Could not start the background scan.'},'failed',0)
        ngx.log(ngx.ERR,'Scan timer: ',timer_error)
        return error_response(503,'Could not start this scan. Please retry.')
    end
    return reply(202,{id=id,cached=false})
end
local id=path:match('^/api/scans/(%d+)$')
if id and #id<12 then
    id=tonumber(id)
    local row,err=storage.get(owner,id)
    if err then return error_response(503,err) end
    if not row then return error_response(404,'Report not found in this workspace.') end
    if method=='GET' then return reply(200,row) end
    if method=='DELETE' then
        if row.status=='pending' then return error_response(409,'Wait for the scan to finish before deleting it.') end
        local changed
        changed,err=storage.delete(owner,id)
        if not changed then return error_response(503,err) end
        return reply(200,{deleted=true})
    end
    if method=='PATCH' then
        local data,message=body()
        if not data or type(data.favorite)~='boolean' then return error_response(400,message or 'A boolean favorite value is required.') end
        local changed
        changed,err=storage.favorite(owner,id,data.favorite)
        if not changed then return error_response(503,err) end
        return reply(200,{favorite=data.favorite})
    end
    ngx.header.Allow='GET, PATCH, DELETE'
    return error_response(405,'Method not allowed.')
end
if path=='/api/scans' or bootstrap then ngx.header.Allow=bootstrap and 'GET' or 'GET, POST'; return error_response(405,'Method not allowed.') end
return error_response(404,'Endpoint not found.')
