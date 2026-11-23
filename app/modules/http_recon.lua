local network = require 'network'
local M = {}
local controls = {
    {'strict-transport-security','HSTS',20,'Use max-age=31536000 or longer after checking HTTPS coverage.'},
    {'content-security-policy','Content Security Policy',25,'Restrict allowed sources and avoid unsafe-inline and unsafe-eval.'},
    {'x-content-type-options','Content type protection',15,'Send X-Content-Type-Options: nosniff.'},
    {'frame-protection','Frame protection',15,"Use CSP frame-ancestors or X-Frame-Options: DENY / SAMEORIGIN."},
    {'referrer-policy','Referrer policy',10,'Set strict-origin-when-cross-origin, same-origin or no-referrer.'},
    {'permissions-policy','Permissions policy',10,'Limit browser features the site does not need.'},
    {'https','Verified HTTPS',5,'Serve HTTPS with a trusted certificate matching the hostname.'}
}
function M.assess(headers, verified)
    local checks, score = {}, 0
    local csp = headers['content-security-policy'] or ''
    local directives = {}
    for directive in csp:gmatch('[^;]+') do
        local name, sources=directive:match('^%s*([a-z-]+)%s+(.+)%s*$')
        if name then directives[name]=sources end
    end
    local function restricted(sources)
        if not sources or sources:find(',',1,true) then return false end
        for token in sources:gmatch('%S+') do
            if token=='*' or token=='http:' or token=='https:' or token=='data:' or token=='blob:' or
                token=="'unsafe-inline'" or token=="'unsafe-eval'" then return false end
        end
        return true
    end
    for _, control in ipairs(controls) do
        local key, value = control[1], headers[control[1]]
        local pass, weak = false, false
        if key == 'https' then value=verified and 'Certificate chain and hostname verified' or 'HTTPS unavailable'; pass=verified
        elseif key == 'strict-transport-security' then
            pass=verified and value and (tonumber(value:lower():match('max%-age%s*=%s*(%d+)')) or 0)>=31536000
        elseif key == 'content-security-policy' then
            pass=value and restricted(directives['script-src-elem'] or directives['script-src'] or directives['default-src']) and
                not csp:find("'unsafe%-eval'") and not csp:find("'unsafe%-inline'")
        elseif key == 'x-content-type-options' then pass=value and value:lower()=='nosniff'
        elseif key == 'frame-protection' then
            value=directives['frame-ancestors'] or headers['x-frame-options']
            if directives['frame-ancestors'] then pass=restricted(value) and (value:find("'none'",1,true) or value:find("'self'",1,true))
            else pass=value and (value:lower()=='deny' or value:lower()=='sameorigin') end
        elseif key == 'referrer-policy' then
            pass=value and (value=='no-referrer' or value=='same-origin' or value=='strict-origin' or value=='strict-origin-when-cross-origin')
        else pass=value and value:match('[a-z-]+%s*=%s*%(') and not value:find('*',1,true) end
        weak=value and not pass
        if pass then score=score+control[3] end
        checks[#checks+1]={key=key,label=control[2],state=pass and 'pass' or (weak and 'review' or 'missing'),value=value,weight=control[3],advice=control[4]}
    end
    return checks, score
end
function M.analyze(target, ip, deadline)
    local res, err = network.request(target,'/',{ip=ip,method='HEAD',capture_tls=true,deadline=math.min(deadline,ngx.now()+6)})
    local tls_error, scheme = err, 'https'
    if not res then
        scheme='http'
        res, err=network.request(target,'/',{ip=ip,method='HEAD',scheme='http',deadline=math.min(deadline,ngx.now()+4)})
    end
    if not res then return {error=err,tls={verified=false,error=tls_error},checks={},resources={}} end
    if res.status==405 or res.status==501 then
        local get=network.request(target,'/',{ip=ip,scheme=scheme,capture_tls=scheme=='https',max_body=0,deadline=math.min(deadline,ngx.now()+4)})
        if get then res=get end
    end
    local checks, score=M.assess(res.headers,res.tls_verified)
    local resources={}
    for _, path in ipairs({'/robots.txt','/sitemap.xml','/.well-known/security.txt'}) do
        local resource,e
        if ngx.now()>=deadline then e='Request budget exceeded.'
        else resource,e=network.request(target,path,{ip=ip,scheme=scheme,method='HEAD',deadline=math.min(deadline,ngx.now()+3)}) end
        resources[#resources+1]={path=path,status=resource and resource.status,error=e,found=resource and resource.status==200 or false}
    end
    return {status=res.status,headers=res.headers,ip=ip,scheme=scheme,elapsed_ms=res.elapsed_ms,
        redirect=res.headers.location,checks=checks,score=score,resources=resources,
        tls={verified=res.tls_verified,hostname=target,certificate=res.certificate,metadata_error=res.tls_metadata_error,error=res.tls_verified and nil or tls_error},
        note='Headers are observed on the requested root response. Redirects are shown, not followed. The score is a header configuration indicator, not a vulnerability assessment.'}
end
return M
