local response=require 'json_response'
local json=require 'cjson.safe'
describe('Portable JSON collections',function()
    it('always emits an array for zero results and retains zero/false metadata',function()
        local encoded=assert(response.collection('targets',{}, {total=0,cached=false}))
        assert.matches('"targets":%[%]',encoded)
        local decoded=json.decode(encoded);assert.equal(0,decoded.total);assert.is_false(decoded.cached)
    end)
    it('preserves nonempty arrays and escapes hostile text and field names',function()
        local rows={{label='"},"owner":"other","html":"<script>'}}
        local field='targets"attack'
        local encoded=assert(response.collection(field,rows,{page=1}))
        assert.same(rows,json.decode(encoded)[field]);assert.is_nil(json.decode(encoded).owner)
    end)
    it('rejects ambiguous metadata and non-array collection values',function()
        assert.is_nil(response.collection('targets',{}, {targets={}}))
        assert.is_nil(response.collection('targets',{owner='alice'},{}))
        assert.is_nil(response.collection('targets',{[1]='first',[3]='third'},{}))
    end)
    it('fails closed when a nested value cannot be encoded',function()
        assert.is_nil(response.collection('targets',{}, {invalid=math.huge}))
    end)
end)
