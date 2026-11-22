local original_ngx, original_dns, original_network
local network, sock, answers, now, queries
local function socket()
    local s={body='',head='HTTP/1.1 200 OK\r\nContent-Length: 0',closed=false}
    function s:settimeout(ms) self.timeout=ms end
    function s:connect(ip,port) self.ip,self.port=ip,port; return true end
    function s:sslhandshake(_,host,verify) self.sni,self.verify=host,verify; return true end
    function s:send(request) self.request=request; return #request end
    function s:close() self.closed=true; return true end
    function s:receiveuntil(delimiter)
        return function(limit)
            if self.head then local h=self.head;self.head=nil;return h:sub(1,limit) end
            local at=self.body:find(delimiter,1,true)
            if not at then return nil,'closed' end
            local out=self.body:sub(1,at-1);self.body=self.body:sub(at+#delimiter);return out:sub(1,limit)
        end
    end
    function s:receive(length)
        if #self.body<length then local rest=self.body;self.body='';return nil,'closed',rest end
        local out=self.body:sub(1,length);self.body=self.body:sub(length+1);return out
    end
    return s
end
describe('Outbound network boundary',function()
    before_each(function()
        original_ngx=_G.ngx;original_dns=package.loaded['resty.dns.resolver'];original_network=package.loaded.network
        now,queries=100,0;answers={{type=1,address='93.184.215.14'}};sock=socket()
        _G.ngx={config={prefix=function()return '/nonexistent/'end},now=function()return now end,socket={tcp=function()return sock end}}
        package.loaded['resty.dns.resolver']={new=function()
            return {TYPE_A=1,query=function()queries=queries+1;return answers end}
        end}
        package.loaded.network=nil;network=require 'network'
    end)
    after_each(function()_G.ngx=original_ngx;package.loaded['resty.dns.resolver']=original_dns;package.loaded.network=original_network end)
    it('pins the validated IP and verifies hostname and trust chain',function()
        local res=assert(network.request('example.com','/'))
        assert.equal(200,res.status);assert.equal('93.184.215.14',sock.ip);assert.equal(443,sock.port)
        assert.equal('example.com',sock.sni);assert.is_true(sock.verify);assert.equal(1,queries)
        assert.matches('Host: example.com',sock.request,1,true);assert.is_true(sock.closed)
    end)
    it('rejects mixed public and private DNS answers before connecting',function()
        answers[2]={type=1,address='127.0.0.1'}
        local res,err=network.request('example.com','/')
        assert.is_nil(res);assert.matches('blocked',err);assert.is_nil(sock.ip)
    end)
    it('does not connect to a supplied private pinned IP',function()
        assert.is_nil(network.request('example.com','/',{ip='169.254.169.254'}));assert.is_nil(sock.ip)
    end)
    it('never follows upstream redirects',function()
        sock.head='HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/admin\r\nContent-Length: 0'
        local res=assert(network.request('example.com','/'))
        assert.equal(302,res.status);assert.equal(1,queries);assert.equal('93.184.215.14',sock.ip)
    end)
    it('bounds headers before accepting a response',function()
        sock.head='HTTP/1.1 200 OK\r\nX-Huge: '..string.rep('A',40000)
        local res,err=network.request('example.com','/')
        assert.is_nil(res);assert.matches('32 KiB',err);assert.is_true(sock.closed)
    end)
    it('rejects oversized declared bodies',function()
        sock.head='HTTP/1.1 200 OK\r\nContent-Length: 90000'
        assert.is_nil(network.request('example.com','/',{max_body=32}));assert.is_true(sock.closed)
    end)
    it('bounds chunked bodies and rejects missing chunk delimiters',function()
        sock.head='HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked';sock.body='4\r\ntest\r\n0\r\n'
        assert.equal('test',assert(network.request('example.com','/',{max_body=4})).body)
        sock.head='HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked';sock.body='5\r\nhello\r\n0\r\n'
        assert.is_nil(network.request('example.com','/',{max_body=4}))
    end)
    it('bounds connection-close responses',function()
        sock.head='HTTP/1.1 200 OK\r\nConnection: close';sock.body=string.rep('A',40)
        assert.is_nil(network.request('example.com','/',{max_body=32}))
    end)
    it('fails closed on TLS verification errors',function()
        sock.sslhandshake=function()return nil,'certificate verify failed'end
        local res,err=network.request('example.com','/')
        assert.is_nil(res);assert.matches('TLS verification failed',err);assert.is_nil(sock.request)
    end)
    it('rejects expired deadlines and request-line injection',function()
        assert.is_nil(network.request('example.com','/',{deadline=99}));assert.is_nil(sock.ip)
        assert.is_nil(network.request('example.com','/\r\nHost: internal'));assert.is_nil(sock.ip)
    end)
end)
