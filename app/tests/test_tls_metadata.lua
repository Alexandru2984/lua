local tls=require 'tls_metadata'
local now=1800000000
describe('Certificate snapshot validity',function()
    it('separates expired, not-yet-valid and approaching-expiry certificates',function()
        assert.equal('not_yet_valid',tls.validity(now+1,now+90*86400,now))
        assert.equal('expired',tls.validity(now-86400,now,now))
        assert.equal('urgent',tls.validity(now-86400,now+7*86400,now))
        assert.equal('soon',tls.validity(now-86400,now+30*86400,now))
        assert.equal('valid',tls.validity(now-86400,now+31*86400,now))
    end)
    it('does not round a certificate with hours remaining up to a full day',function()
        local status,days=tls.validity(now-1000,now+3600,now)
        assert.equal('urgent',status);assert.equal(0,days)
    end)
    it('never treats malformed or absent dates as valid',function()
        for _,row in ipairs({{now,now-1,now},{now,math.huge,now},{now,0/0,now},{now,now+1000,math.huge}})do
            assert.equal('unavailable',tls.validity(unpack(row)))
        end
        assert.equal('unavailable',tls.validity(nil,now,now))
    end)
    it('declines non-native sessions without attempting to interpret a pointer',function()
        for _,value in ipairs({true,{},'fake pointer',42})do assert.is_nil(tls.inspect(value,now))end
        assert.is_nil(tls.inspect(nil,now))
    end)
    it('escapes controls and non-ASCII certificate name bytes for safe display',function()
        assert.equal('Example CA',tls.clean_name('Example CA'))
        assert.equal('A\\x00\\x0A\\xFF',tls.clean_name('A\0\n'..string.char(255)))
    end)
end)
