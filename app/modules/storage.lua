local sqlite = require 'lsqlite3'
local json = require 'cjson.safe'
local M = {}
local NULL = {}
local path = ngx.config.prefix() .. 'data/recon.db'
local function open()
    local db = sqlite.open(path)
    if not db then return nil, 'Database unavailable.' end
    db:busy_timeout(100)
    return db
end
local function query(sql, args, mode)
    local db, err = open()
    if not db then return nil, err end
    local stmt = db:prepare(sql)
    if not stmt then ngx.log(ngx.ERR, 'SQLite prepare: ', db:errmsg()); db:close(); return nil, 'Database query failed.' end
    if args then
        for i, value in ipairs(args) do
            if value == NULL then stmt:bind(i, nil) else stmt:bind(i, value) end
        end
    end
    local rows = {}
    local code = stmt:step()
    while code == sqlite.ROW do
        rows[#rows + 1] = stmt:get_named_values()
        code = stmt:step()
    end
    local id, changed = db:last_insert_rowid(), db:changes()
    if code ~= sqlite.DONE then err = 'Database operation failed.'; ngx.log(ngx.ERR, 'SQLite step: ', db:errmsg()) end
    stmt:finalize(); db:close()
    if err then return nil, err end
    if mode == 'insert' then return id end
    if mode == 'change' then return changed end
    return rows
end
function M.init()
    local db, err = open()
    if not db then return nil, err end
    local schema = [[CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, dns_results TEXT,
        http_headers TEXT, tls_info TEXT, endpoints TEXT, whois_info TEXT,
        status TEXT DEFAULT 'completed', subdomains TEXT
    );]]
    if db:exec(schema) ~= sqlite.OK then db:close(); return nil, 'Cannot initialize database.' end
    local columns = {}
    for row in db:nrows('PRAGMA table_info(scans)') do columns[row.name] = true end
    local additions = {owner='TEXT', profile="TEXT DEFAULT 'quick'", stage="TEXT DEFAULT 'queued'",
        report='TEXT', favorite='INTEGER DEFAULT 0', score='INTEGER', duration_ms='INTEGER', created_epoch='INTEGER',
        dns_count='INTEGER',http_status='INTEGER',tls_verified='INTEGER',certificate_not_after='INTEGER',certificate_sha256='TEXT'}
    for name, definition in pairs(additions) do
        if not columns[name] and db:exec('ALTER TABLE scans ADD COLUMN ' .. name .. ' ' .. definition) ~= sqlite.OK then
            db:close(); return nil, 'Database migration failed.' end
    end
    for _, sql in ipairs({"UPDATE scans SET created_epoch=CAST(strftime('%s', timestamp) AS INTEGER) WHERE created_epoch IS NULL",
        'CREATE INDEX IF NOT EXISTS scans_owner_id ON scans(owner, id DESC)',
        'CREATE INDEX IF NOT EXISTS scans_owner_target_id ON scans(owner, target, id DESC)',
        [[CREATE TABLE IF NOT EXISTS saved_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL,
            target TEXT NOT NULL, label TEXT NOT NULL DEFAULT '',
            profile TEXT NOT NULL DEFAULT 'quick', created_epoch INTEGER NOT NULL,
            updated_epoch INTEGER NOT NULL, UNIQUE(owner,target)
        )]],
        'CREATE INDEX IF NOT EXISTS scans_created ON scans(created_epoch)', 'PRAGMA journal_mode=WAL'}) do
        if db:exec(sql) ~= sqlite.OK then db:close(); return nil, 'Database setup failed.' end
    end
    db:close()
    return true
end
function M.create(owner, target, profile)
    return query("INSERT INTO scans(owner,target,profile,status,stage,created_epoch) VALUES (?,?,?,'pending','Resolving public addresses',?)", {owner,target,profile,ngx.time()}, 'insert')
end
function M.progress(id, stage)
    return query("UPDATE scans SET stage=? WHERE id=? AND status='pending'", {stage,id}, 'change')
end
function M.finish(id, report, status, duration)
    local encoded, err = json.encode(report)
    if not encoded or #encoded > 262144 then return nil, err or 'Report is too large.' end
    local http=report.http or {}
    local tls=http.tls or {}
    local cert=tls.certificate or {}
    local dns=report.dns or {}
    local verified=NULL
    if type(tls.verified)=='boolean' then verified=tls.verified and 1 or 0 end
    return query([[UPDATE scans SET report=?,status=?,stage=?,score=?,duration_ms=?,dns_count=?,http_status=?,
        tls_verified=?,certificate_not_after=?,certificate_sha256=? WHERE id=? AND status='pending']],
        {encoded,status,status == 'failed' and 'Analysis failed' or 'Analysis finished',report.score or NULL,duration,
        type(dns.records)=='table' and #dns.records or NULL,http.status or NULL,verified,cert.not_after or NULL,
        cert.fingerprint_sha256 or NULL,id}, 'change')
end
function M.get(owner, id)
    local rows, err = query('SELECT * FROM scans WHERE owner=? AND id=?', {owner,id})
    if not rows then return nil, err end
    local row = rows[1]
    if row then
        row.report = row.report and json.decode(row.report) or nil
        for _, key in ipairs({'owner','dns_results','http_headers','tls_info','endpoints','whois_info','subdomains'}) do row[key] = nil end
    end
    return row
end
function M.history(owner, page, target)
    local args={owner}
    local filter=''
    if target then filter=' AND target=?';args[#args+1]=target end
    args[#args+1]=(page-1)*50
    return query('SELECT id,target,timestamp,status,profile,stage,favorite,score,duration_ms FROM scans WHERE owner=?'..filter..' ORDER BY id DESC LIMIT 50 OFFSET ?', args)
end
function M.domain_history(owner,target,before_id)
    local args={owner,target}
    local filter=''
    if before_id then filter=' AND id<?';args[#args+1]=before_id end
    local rows,err=query([[SELECT id,target,timestamp,created_epoch,status,profile,stage,score,duration_ms,
        dns_count,http_status,tls_verified,certificate_not_after,certificate_sha256
        FROM scans WHERE owner=? AND target=?]]..filter..' ORDER BY id DESC LIMIT 51',args)
    if not rows then return nil,err end
    local more=#rows>50
    if more then table.remove(rows) end
    for _,row in ipairs(rows) do
        if row.tls_verified~=nil then row.tls_verified=row.tls_verified==1 end
    end
    return rows,nil,more
end
function M.count(owner, target)
    local args={owner}
    local filter=''
    if target then filter=' AND target=?';args[#args+1]=target end
    local rows, err = query('SELECT COUNT(*) AS total FROM scans WHERE owner=?'..filter, args)
    return rows and rows[1].total, err
end
function M.healthy()
    local rows=query('SELECT owner,report,dns_count,http_status,tls_verified,certificate_not_after,certificate_sha256 FROM scans LIMIT 1')
    return rows ~= nil and query('SELECT id FROM saved_targets LIMIT 0') ~= nil
end
function M.targets(owner)
    return query([[SELECT t.id,t.target,t.label,t.profile,t.created_epoch,t.updated_epoch,
        s.id AS last_scan_id,s.timestamp AS last_scan_timestamp,
        s.status AS last_scan_status,s.score AS last_score,s.certificate_not_after AS last_certificate_not_after
        FROM saved_targets t LEFT JOIN scans s ON s.id=(
            SELECT id FROM scans WHERE owner=t.owner AND target=t.target ORDER BY id DESC LIMIT 1)
        WHERE t.owner=? ORDER BY t.updated_epoch DESC,t.id DESC LIMIT 50]], {owner})
end
function M.save_target(owner,target,label,profile)
    -- The capacity check and upsert are one statement, so concurrent requests
    -- cannot race past the per-workspace bound. Existing entries remain editable.
    local changed,err=query([[INSERT INTO saved_targets(owner,target,label,profile,created_epoch,updated_epoch)
        SELECT ?,?,?,?,?,? WHERE
        (SELECT COUNT(*) FROM saved_targets WHERE owner=?)<50 OR
        EXISTS(SELECT 1 FROM saved_targets WHERE owner=? AND target=?)
        ON CONFLICT(owner,target) DO UPDATE SET label=excluded.label,
            profile=excluded.profile,updated_epoch=excluded.updated_epoch]],
        {owner,target,label,profile,ngx.time(),ngx.time(),owner,owner,target}, 'change')
    if not changed then return nil,err end
    if changed==0 then return nil,'Save up to 50 domains per workspace.' end
    local rows,message=query('SELECT id,target,label,profile FROM saved_targets WHERE owner=? AND target=?',{owner,target})
    return rows and rows[1],message
end
function M.delete_target(owner,id)
    return query('DELETE FROM saved_targets WHERE owner=? AND id=?',{owner,id},'change')
end
function M.recent(owner, target, profile)
    local rows, err = query("SELECT id,status FROM scans WHERE owner=? AND target=? AND profile=? AND (status='pending' OR (status IN ('completed','partial') AND created_epoch>?)) ORDER BY id DESC LIMIT 1", {owner,target,profile,ngx.time()-600})
    return rows and rows[1], err
end
function M.favorite(owner,id,value)
    return query('UPDATE scans SET favorite=? WHERE owner=? AND id=?', {value and 1 or 0,owner,id}, 'change')
end
function M.delete(owner,id)
    return query("DELETE FROM scans WHERE owner=? AND id=? AND status!='pending'", {owner,id}, 'change')
end
function M.maintain()
    local changed, err = query("UPDATE scans SET status='failed',stage='Interrupted or timed out' WHERE status='pending' AND created_epoch<?", {ngx.time()-120}, 'change')
    if not changed then return nil, err end
    changed,err=query([[DELETE FROM saved_targets WHERE updated_epoch<? OR id IN
        (SELECT id FROM saved_targets ORDER BY updated_epoch DESC,id DESC LIMIT -1 OFFSET 5000)]],
        {ngx.time()-2592000},'change')
    if not changed then return nil,err end
    -- Original shared records have no owner. Preserve them as an offline legacy
    -- archive rather than publishing them to a newly created browser workspace.
    return query("DELETE FROM scans WHERE owner IS NOT NULL AND status!='pending' AND (created_epoch<? OR id IN (SELECT id FROM scans WHERE owner IS NOT NULL AND status!='pending' ORDER BY id DESC LIMIT -1 OFFSET 5000))", {ngx.time()-2592000}, 'change')
end
return M
