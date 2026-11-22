local lfs=require 'lfs'
local sqlite=require 'lsqlite3'
local storage,prefix,old_ngx,old_storage
describe('Private report storage and retention',function()
    before_each(function()
        prefix=os.tmpname();os.remove(prefix);assert(lfs.mkdir(prefix));assert(lfs.mkdir(prefix..'/data'))
        old_ngx=_G.ngx;old_storage=package.loaded.storage
        _G.ngx={config={prefix=function()return prefix..'/'end},time=function()return 1800000000 end,log=function()end,ERR=3}
        package.loaded.storage=nil;storage=require 'storage';assert(storage.init())
    end)
    after_each(function()
        package.loaded.storage=old_storage;_G.ngx=old_ngx
        for file in lfs.dir(prefix..'/data') do if file~='.' and file~='..' then os.remove(prefix..'/data/'..file) end end
        lfs.rmdir(prefix..'/data');lfs.rmdir(prefix)
    end)
    it('enforces ownership on reads favorites and deletion',function()
        local id=assert(storage.create('alice','example.com','quick'))
        assert.is_nil(storage.get('bob',id));assert.equal(0,storage.favorite('bob',id,true));assert.equal(0,storage.delete('bob',id))
        assert.equal(1,storage.count('alice'));assert.equal(0,storage.count('bob'))
        assert.equal(1,storage.favorite('alice',id,true));assert.equal(1,storage.get('alice',id).favorite)
        assert.equal(0,storage.delete('alice',id)) -- A running report is protected.
        assert(storage.finish(id,{error='Unavailable'},'failed',10));assert.is_nil(storage.get('alice',id).score)
        assert.equal(1,storage.delete('alice',id))
    end)
    it('keeps SQL payloads as bound text and preserves a real zero score',function()
        local id=assert(storage.create('alice',"example.com'; DROP TABLE scans;--",'quick'))
        assert(storage.finish(id,{score=0},'completed',10));assert.equal(0,storage.get('alice',id).score)
        assert.equal(1,storage.count('alice'));assert(storage.init())
    end)
    it('expires old owned reports while preserving unclaimed legacy data',function()
        local db=sqlite.open(prefix..'/data/recon.db')
        assert.equal(sqlite.OK,db:exec("INSERT INTO scans(target,created_epoch,status) VALUES ('legacy.example.com',1,'completed')"))
        assert.equal(sqlite.OK,db:exec("INSERT INTO scans(target,owner,created_epoch,status) VALUES ('old.example.com','alice',1,'completed')"))
        db:close();assert(storage.maintain());assert.equal(0,storage.count('alice'))
        db=sqlite.open(prefix..'/data/recon.db');local count
        for row in db:nrows('SELECT COUNT(*) AS n FROM scans WHERE owner IS NULL')do count=row.n end
        db:close();assert.equal(1,count)
    end)
    it('recovers stale pending jobs after interruptions',function()
        local id=assert(storage.create('alice','example.com','deep'))
        local db=sqlite.open(prefix..'/data/recon.db');db:exec('UPDATE scans SET created_epoch=1');db:close()
        assert(storage.maintain());assert.is_nil(storage.get('alice',id)) -- Stale and past retention.
    end)
end)
