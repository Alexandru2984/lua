local insights=require 'dns_insights'
local function inspect(records,status)
    local found={}
    local dns={records=records or {},query_status=status or {TXT='answered',DMARC='answered',CAA='answered',MX='answered'}}
    for _,c in ipairs(insights.analyze('example.com',dns)) do found[c.key]=c end
    return found
end
local function txt(value) return {type='TXT',value=value} end
local function dmarc(value) return {type='DMARC',value=value} end
describe('Direct DNS and email observations',function()
    it('keeps unavailable lookups distinct from absent records',function()
        local found=inspect({}, {})
        for _,key in ipairs({'spf','dmarc','caa','mx'})do assert.equal('unavailable',found[key].state)end
    end)
    it('does not infer email-domain policies from IPv4 targets',function()
        local found=insights.analyze('8.8.8.8',{records={}})
        assert.equal(1,#found);assert.equal('domain-only',found[1].key)
    end)
    for _,row in ipairs({
        {'v=spf1 -all','observed'},{'v=spf1 +all','review'},{'v=spf1 all','review'},
        {'v=spf1 ~all','review'},{'v=spf1 ?all','review'},
        {'v=spf1 include:mail.example.com','review'},
        {'v=spf1 redirect=mail.example.com','info'},{'V=SPF1 -ALL','observed'}
    }) do
        it('describes SPF '..row[1]..' without expanding external policies',function()
            local found=inspect({txt(row[1])});assert.equal(row[2],found.spf.state);assert.equal(row[1],found.spf.value)
        end)
    end
    it('reports multiple SPF policies rather than selecting the last one',function()
        assert.equal('review',inspect({txt('v=spf1 -all'),txt('v=spf1 +all')}).spf.state)
    end)
    it('does not confuse SPF versions or unrelated TXT records',function()
        assert.equal('info',inspect({txt('v=spf10 +all'),txt('site-verification=abc')}).spf.state)
    end)
    it('recognizes direct reject and quarantine policies as observations',function()
        for _,p in ipairs({'reject','quarantine'})do assert.equal('observed',inspect({dmarc('v=DMARC1; p='..p)}).dmarc.state)end
    end)
    it('uses the modern monitoring default when p is absent',function()
        local c=inspect({dmarc('v=DMARC1; rua=mailto:dmarc@example.com')}).dmarc
        assert.equal('review',c.state);assert.matches('defaults to monitoring',c.summary)
    end)
    it('marks RFC 9989 testing mode separately from the declared policy',function()
        local c=inspect({dmarc('v=DMARC1; p=reject; t=y')}).dmarc
        assert.equal('review',c.state);assert.matches('softer handling',c.summary)
    end)
    it('does not infer enforcement percentages from a legacy pct tag',function()
        local c=inspect({dmarc('v=DMARC1; p=reject; pct=100')}).dmarc
        assert.equal('review',c.state);assert.matches('legacy pct',c.summary)
    end)
    it('reviews conflicting policy tags and multiple records',function()
        for _,rows in ipairs({{dmarc('v=DMARC1; p=none; p=reject')},{dmarc('v=DMARC1; p=reject'),dmarc('v=DMARC1; p=none')}})do
            assert.equal('review',inspect(rows).dmarc.state)
        end
    end)
    it('reviews unknown policy and testing values',function()
        for _,suffix in ipairs({'p=invalid','p=reject; sp=invalid','p=reject; np=invalid','p=reject; t=invalid'})do
            assert.equal('review',inspect({dmarc('v=DMARC1; '..suffix)}).dmarc.state)
        end
    end)
    it('requires the case-sensitive DMARC1 version first',function()
        for _,value in ipairs({'v=dmarc1; p=reject','p=reject; v=DMARC1'})do assert.equal('info',inspect({dmarc(value)}).dmarc.state)end
    end)
    it('does not label missing direct CAA or DMARC as missing inherited policy',function()
        local found=inspect({})
        assert.equal('info',found.caa.state);assert.matches('parent policy may apply',found.caa.summary)
        assert.equal('info',found.dmarc.state);assert.matches('parent policy may apply',found.dmarc.summary)
    end)
    it('does not treat a CAA reporting record as a proven issuance restriction',function()
        local c=inspect({{type='CAA',value='0 iodef mailto:security@example.com'}}).caa
        assert.equal('observed',c.state);assert.matches('does not establish',c.advice)
    end)
    it('recognizes null MX and its conflict with other exchangers',function()
        for _,value in ipairs({'','.'})do
            local rows={{type='MX',priority=0,value=value}}
            assert.matches('Null MX explicitly',inspect(rows).mx.summary)
            rows[2]={type='MX',priority=10,value='mail.example.com'}
            assert.equal('review',inspect(rows).mx.state)
        end
    end)
    it('does not assume that a domain without MX cannot receive mail',function()
        local c=inspect({}).mx;assert.equal('info',c.state);assert.matches('fallback',c.summary)
    end)
end)
