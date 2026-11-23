local old_ngx,old_network,old_dns,resolve,clock
local dns
describe('DNS query observation states',function()
    before_each(function()
        old_ngx=_G.ngx;old_network=package.loaded.network;old_dns=package.loaded.dns;clock=10
        resolve=function(name,opts)
            if name:match('^_dmarc')then return {errcode=3,errstr='NXDOMAIN'}end
            if opts.qtype==1 then return nil,'timeout' end
            return {}
        end
        _G.ngx={now=function()return clock end}
        package.loaded.network={resolver=function()return {query=function(_,name,opts)return resolve(name,opts)end}end}
        package.loaded.dns=nil;dns=require 'dns'
    end)
    after_each(function()_G.ngx=old_ngx;package.loaded.network=old_network;package.loaded.dns=old_dns end)
    it('separates NXDOMAIN absence from resolver timeouts',function()
        local result=dns.resolve('example.com',20)
        assert.equal('absent',result.query_status.DMARC);assert.equal('error',result.query_status.A)
        assert.equal('answered',result.query_status.TXT);assert.equal(1,#result.errors)
    end)
    it('leaves checks unknown after the time budget is exhausted',function()
        local result=dns.resolve('example.com',9)
        assert.is_nil(result.query_status.TXT);assert.is_nil(result.query_status.DMARC);assert.equal(1,#result.errors)
    end)
end)
