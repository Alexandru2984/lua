-- Single outbound HTTP implementation: fixed ports, public pinned IPs, verified
-- TLS, bounded headers/body, and an absolute request deadline. No shell or proxy.
local validator = require "validator"
local resolver = require "resty.dns.resolver"
local M = {}
local denied = {}
local file = io.open(ngx.config.prefix() .. "data/denied-ips", "r")
if file then for ip in file:lines() do denied[ip] = true end file:close() end

function M.public_ip(ip)
    return validator.is_public_ipv4(ip) and not denied[ip]
end

function M.resolver()
    return resolver:new { nameservers = {"1.1.1.1", "8.8.8.8"}, retrans = 1, timeout = 1500 }
end

function M.resolve_public(host, depth)
    if validator.is_ipv4(host) then
        if M.public_ip(host) then return host end
        return nil, "Destination is not an allowed public IP."
    end
    if (depth or 0) > 4 then return nil, "DNS alias chain is too long." end
    local r, err = M.resolver()
    if not r then return nil, err end
    local answers
    answers, err = r:query(host, { qtype = r.TYPE_A })
    if not answers or answers.errcode then return nil, "Public IPv4 DNS lookup failed." end
    local chosen, alias
    for _, answer in ipairs(answers) do
        if answer.address and answer.type == r.TYPE_A then
            if not M.public_ip(answer.address) then return nil, "DNS points to a blocked IP address." end
            chosen = chosen or answer.address
        end
        if answer.cname then alias = answer.cname end
    end
    if chosen then return chosen end
    if alias then return M.resolve_public(alias, (depth or 0) + 1) end
    return nil, "No public IPv4 address found. IPv6-only hosts are not supported yet."
end

function M.request(host, path, opts)
    opts = opts or {}
    local valid = validator.sanitize_and_validate(host)
    if valid ~= host or type(path) ~= "string" or path:sub(1, 1) ~= "/" or path:find("[%c%s]") then
        return nil, "Invalid outbound destination." end
    local started = ngx.now()
    local deadline = opts.deadline or (started + 6)
    if started >= deadline then return nil, "Request budget exceeded." end
    local ip, err = opts.ip, nil
    if ip and not M.public_ip(ip) then return nil, "Blocked destination." end
    if not ip then ip, err = M.resolve_public(host) end
    if not ip then return nil, err end
    local sock = ngx.socket.tcp()
    local function remaining()
        local ms = math.floor((deadline - ngx.now()) * 1000)
        if ms <= 0 then return nil end
        sock:settimeout(math.min(ms, 2500))
        return true
    end
    local function fail(message) sock:close() return nil, message end
    if not remaining() then return fail("Request budget exceeded.") end
    local secure = opts.scheme ~= "http"
    local ok,certificate,metadata_error
    ok, err = sock:connect(ip, secure and 443 or 80)
    if not ok then return fail("Connection failed: " .. (err or "unknown")) end
    if secure then
        if not remaining() then return fail("Request budget exceeded.") end
        ok, err = sock:sslhandshake(nil, host, true)
        if not ok then return fail("TLS verification failed: " .. (err or "unknown")) end
        if opts.capture_tls then
            certificate,metadata_error=require('tls_metadata').inspect(ok,ngx.time())
        end
    end
    if not remaining() then return fail("Request budget exceeded.") end
    local method = opts.method == "HEAD" and "HEAD" or "GET"
    ok, err = sock:send(method .. " " .. path .. " HTTP/1.1\r\nHost: " .. host ..
        "\r\nUser-Agent: LuaLens/2.2 (+https://lua.micutu.com)\r\nAccept: application/json, text/plain, */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
    if not ok then return fail("Request failed: " .. (err or "unknown")) end
    local reader = sock:receiveuntil("\r\n\r\n")
    if not remaining() then return fail("Request budget exceeded.") end
    local raw
    raw, err = reader(32769)
    if not raw or #raw > 32768 then return fail("Response headers missing or exceed 32 KiB.") end
    local status = tonumber(raw:match("^HTTP/1%.[01] (%d%d%d)"))
    if not status or status < 200 then return fail("Unsupported HTTP response.") end
    local headers, n = {}, 0
    for line in (raw .. "\r\n"):gmatch("([^\r\n]+)\r\n") do
        n = n + 1
        if n > 100 or #line > 8192 then return fail("Response header limits exceeded.") end
        if n > 1 then
            local key, value = line:match("^([!#$%%&'*+.^_`|~%w-]+):%s*(.-)%s*$")
            if not key then return fail("Malformed response header.") end
            key = key:lower()
            if headers[key] then headers[key] = headers[key] .. ", " .. value else headers[key] = value end
        end
    end
    local res = { status = status, headers = headers, body = "", ip = ip,
        tls_verified = secure, certificate=certificate,tls_metadata_error=metadata_error,
        elapsed_ms = math.floor((ngx.now() - started) * 1000) }
    if method == "HEAD" or status == 204 or status == 304 or opts.max_body == 0 then sock:close() return res end
    local max_body = opts.max_body or 65536
    local chunks, size = {}, 0
    local function read_bytes(length)
        while length > 0 do
            if not remaining() then return nil, "Request budget exceeded." end
            local chunk, e, partial = sock:receive(math.min(length, 4096))
            chunk = chunk or partial
            if chunk and #chunk > 0 then
                size = size + #chunk
                if size > max_body then return nil, "Response body exceeds the configured limit." end
                chunks[#chunks + 1] = chunk
                length = length - #chunk
            end
            if e then return nil, "Response body incomplete: " .. e end
        end
        return true
    end
    local transfer = headers["transfer-encoding"]
    if transfer and transfer:lower() ~= "chunked" then return fail("Unsupported transfer encoding.") end
    if transfer then
        while true do
            if not remaining() then return fail("Request budget exceeded.") end
            local line = sock:receiveuntil("\r\n")(128)
            if not line or #line >= 128 then return fail("Invalid HTTP chunk.") end
            local hex = line:match("^([a-fA-F0-9]+)[;]?.*$")
            local length = hex and #hex <= 8 and tonumber(hex, 16)
            if not length or length > max_body - size then return fail("Response body exceeds the configured limit.") end
            if length == 0 then break end
            ok, err = read_bytes(length)
            if not ok then return fail(err) end
            if not remaining() or sock:receive(2) ~= "\r\n" then return fail("Invalid HTTP chunk delimiter.") end
        end
    elseif headers["content-length"] then
        local length = tonumber(headers["content-length"])
        if not length or length < 0 or length % 1 ~= 0 or length > max_body then return fail("Response body exceeds the configured limit.") end
        ok, err = read_bytes(length)
        if not ok then return fail(err) end
    else
        while true do
            if not remaining() then return fail("Request budget exceeded.") end
            local chunk, e, partial = sock:receive(math.min(4096, max_body - size + 1))
            chunk = chunk or partial
            if chunk and #chunk > 0 then
                size = size + #chunk
                if size > max_body then return fail("Response body exceeds the configured limit.") end
                chunks[#chunks + 1] = chunk
            end
            if e == "closed" then break end
            if e then return fail("Response read failed: " .. e) end
        end
    end
    sock:close()
    res.body = table.concat(chunks)
    res.elapsed_ms = math.floor((ngx.now() - started) * 1000)
    return res
end

return M
