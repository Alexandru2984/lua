local storage=require 'storage'
local ok,err=storage.init()
if not ok then error(err) end
assert(storage.maintain())
local timer_ok,timer_err=ngx.timer.every(60,function(premature)
    if premature then return end
    local success,message=storage.maintain()
    if not success then ngx.log(ngx.ERR,'Maintenance: ',message) end
end)
if not timer_ok then error(timer_err) end
