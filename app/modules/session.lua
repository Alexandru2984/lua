local M = {}
local key
local function hex(value) return (value:gsub('.', function(c) return string.format('%02x', c:byte()) end)) end
local function secret()
    if key then return key end
    local f = assert(io.open(ngx.config.prefix() .. 'data/session.key', 'rb'), 'Workspace key is missing. Run scripts/setup.py.')
    key = f:read('*a'); f:close()
    assert(#key == 32, 'Invalid workspace key')
    return key
end
local function sign(value) return hex(ngx.hmac_sha1(secret(), value)) end
local function equal(a, b)
    if type(a) ~= 'string' or type(b) ~= 'string' or #a ~= #b then return false end
    local delta = 0
    for i = 1, #a do delta = delta + (a:byte(i) - b:byte(i)) ^ 2 end
    return delta == 0
end
function M.get(create)
    local cookie
    -- Nginx cookie variables cannot portably normalize hyphens; parse the exact
    -- cookie name rather than accepting a second, weaker alias.
    cookie = (ngx.var.http_cookie or ''):match('__Host%-lualens=([^;]+)')
    local id, timestamp, signature
    if cookie then id, timestamp, signature = cookie:match('^([a-f0-9]+)%.(%d+)%.([a-f0-9]+)$') end
    if id and #id == 64 and #timestamp <= 12 and tonumber(timestamp) <= ngx.time() and
        ngx.time() - tonumber(timestamp) < 2592000 and equal(signature, sign(id .. '.' .. timestamp)) then
        return id, sign('csrf:' .. id)
    end
    if not create then return nil end
    local f = assert(io.open('/dev/urandom', 'rb'))
    local random = f:read(32); f:close()
    assert(random and #random == 32, 'Random source failed')
    id, timestamp = hex(random), tostring(ngx.time())
    ngx.header['Set-Cookie'] = '__Host-lualens=' .. id .. '.' .. timestamp .. '.' .. sign(id .. '.' .. timestamp) ..
        '; Path=/; Max-Age=2592000; Secure; HttpOnly; SameSite=Strict'
    return id, sign('csrf:' .. id)
end
function M.check(csrf)
    if not equal(ngx.var.http_x_csrf_token, csrf) then return false end
    local origin = ngx.var.http_origin
    if origin and origin ~= ngx.var.app_origin then return false end
    if ngx.var.http_sec_fetch_site == 'cross-site' then return false end
    return true
end
return M
