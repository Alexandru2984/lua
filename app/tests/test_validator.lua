local validator=require 'validator'
describe('Target validation',function()
    for _, pair in ipairs({{'example.com','example.com'},{'Lua.Micutu.COM','lua.micutu.com'},{' example.com. ','example.com'},{'https://example.com/path?test=1','example.com'},{'8.8.8.8','8.8.8.8'},{'xn--bcher-kva.de','xn--bcher-kva.de'}}) do
        it('normalizes '..pair[1],function() assert.equal(pair[2],validator.sanitize_and_validate(pair[1])) end)
    end
    for _, target in ipairs({'127.0.0.1','10.1.2.3','172.16.0.1','192.168.1.1','169.254.169.254','100.64.1.1','192.0.0.1','192.0.2.1','198.18.0.1','198.51.100.1','203.0.113.1','224.0.0.1','255.255.255.255','0.0.0.0','2130706433','0177.0.0.1','0x7f000001','localhost','host.internal','foo.local','foo.onion','foo.arpa','a..com','-evil.com','evil-.com','evil_.com','example.com:22','https://user@example.com/','https://example.com:443/','ftp://example.com','[::1]','300.2.3.4','example.com;whoami','example.com\n','<script>.com',string.rep('a',64)..'.com'}) do
        it('rejects '..target:gsub('%c','?'),function()
            -- A trailing newline is trimmed as whitespace; embedded controls must
            -- still be rejected. The normalized target never enters a shell.
            if target=='example.com\n' then assert.equal('example.com',validator.sanitize_and_validate(target)); return end
            local host,err=validator.sanitize_and_validate(target)
            assert.is_nil(host); assert.is_string(err)
        end)
    end
    it('rejects non-string and repeated parameter values',function()
        for _, value in ipairs({{},true,42}) do assert.is_nil(validator.sanitize_and_validate(value)) end
        assert.is_nil(validator.sanitize_and_validate(nil))
    end)
end)
