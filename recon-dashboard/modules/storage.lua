local sqlite3 = require("lsqlite3")
local M = {}

local db_path = ngx.config.prefix() .. "data/recon.db"

function M.init()
    local db = sqlite3.open(db_path)
    if not db then return false end
    
    local create_table = [[
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            dns_results TEXT,
            http_headers TEXT,
            tls_info TEXT,
            endpoints TEXT,
            whois_info TEXT,
            status TEXT DEFAULT 'completed',
            subdomains TEXT
        );
    ]]
    db:exec(create_table)
    db:close()
    return true
end

function M.create_pending_scan(target)
    local db = sqlite3.open(db_path)
    if not db then return nil end
    local stmt = db:prepare("INSERT INTO scans (target, status) VALUES (?, 'pending')")
    if not stmt then db:close() return nil end
    stmt:bind_values(target)
    stmt:step()
    local id = db:last_insert_rowid()
    stmt:finalize()
    db:close()
    return id
end

function M.update_scan(id, dns_results, http_headers, tls_info, endpoints, whois_info, subdomains, status)
    local db = sqlite3.open(db_path)
    if not db then return false end
    local stmt = db:prepare("UPDATE scans SET dns_results=?, http_headers=?, tls_info=?, endpoints=?, whois_info=?, subdomains=?, status=? WHERE id=?")
    if not stmt then db:close() return false end
    stmt:bind_values(dns_results, http_headers, tls_info, endpoints, whois_info, subdomains, status, id)
    stmt:step()
    stmt:finalize()
    db:close()
    return true
end

function M.get_history()
    local db = sqlite3.open(db_path)
    if not db then return {} end
    
    local history = {}
    for row in db:nrows("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 50") do
        table.insert(history, row)
    end
    db:close()
    return history
end

return M
