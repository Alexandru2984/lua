-- Used exclusively in a copied, disposable preview via --fixtures.
local M={}
local count=0
function M.resolve_public(host)
    if host=='rebind.example.com' then return nil,'DNS points to a blocked IP address.' end
    return '93.184.215.14'
end
function M.resolver()
    local r={TYPE_A=1}
    function r:query(host,opts)
        if host=='dnsfailed.example.com' or host=='_dmarc.dnsfailed.example.com' then return nil,'timeout' end
        local t=opts.qtype
        if t==1 then return {{address='93.184.215.14',type=1,ttl=300}} end
        if t==28 then return {{address='2606:2800::1',type=28,ttl=300}} end
        if t==15 then return {{exchange='mail.example.com',preference=10,type=15,ttl=300}} end
        if t==2 then return {{nsdname='ns.example.com',type=2,ttl=300}} end
        if t==16 then return {{txt=host:match('^_dmarc') and 'v=DMARC1; p=reject' or 'v=spf1 -all',type=16,ttl=300}} end
        return {}
    end
    return r
end
function M.request(host,path,opts)
    count=count+1
    if host=='timeout.example.com' then return nil,'Connection timed out.' end
    if host=='crt.sh' then return {status=200,body='[{"name_value":"www.example.com\\n*.example.com\\n<script>.example.com\\nevil-example.com"}]'} end
    if host=='rdap.org' then return {status=302,headers={location='https://registry.example.com/domain/example.com'},body=''} end
    if host=='registry.example.com' then return {status=200,body='{"ldhName":"EXAMPLE.COM","events":[{"eventAction":"registration","eventDate":"1995-08-14T00:00:00Z"}],"status":["active"]}'} end
    return {status=path=='/' and 200 or 404,headers={['content-type']='text/html',
        ['strict-transport-security']='max-age=31536000',['x-content-type-options']='nosniff',
        ['content-security-policy']="default-src 'self'; frame-ancestors 'none'",['referrer-policy']='no-referrer',
        ['permissions-policy']='camera=()', ['x-danger']='<img src=x onerror="window.__xss=1">', ['x-formula']='=HYPERLINK("https://attacker.example")', ['x-observation']=tostring(count)},
        body='',ip='93.184.215.14',tls_verified=not opts or opts.scheme~='http',elapsed_ms=10}
end
return M
