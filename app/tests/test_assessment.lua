local old_network=package.loaded.network
package.loaded.network={}
local assessment=require 'http_recon'
package.loaded.network=old_network
local function state(checks,key) for _,check in ipairs(checks)do if check.key==key then return check.state end end end
describe('Header findings',function()
    it('never treats permissive or unsafe script policies as configured',function()
        for _,value in ipairs({"default-src *","script-src https:","default-src 'self'; script-src 'unsafe-inline'","default-src 'self'; script-src 'unsafe-eval'"})do
            local checks=assessment.assess({['content-security-policy']=value},true)
            assert.equal('review',state(checks,'content-security-policy'))
        end
    end)
    it('reviews disabled HSTS and broad frame or browser permissions',function()
        local checks=assessment.assess({['strict-transport-security']='max-age=0',['content-security-policy']="frame-ancestors *",['permissions-policy']='camera=*'},true)
        for _,key in ipairs({'strict-transport-security','frame-protection','permissions-policy'}) do assert.equal('review',state(checks,key)) end
    end)
    it('recognizes a restrictive configuration without implying website safety',function()
        local checks,score=assessment.assess({['strict-transport-security']='max-age=31536000',['content-security-policy']="default-src 'self'; frame-ancestors 'none'",['permissions-policy']='camera=()', ['x-content-type-options']='nosniff',['referrer-policy']='no-referrer'},true)
        assert.equal(100,score);for _,check in ipairs(checks)do assert.equal('pass',check.state)end
    end)
end)
