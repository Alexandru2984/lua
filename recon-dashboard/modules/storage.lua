local sqlite3 = require("lsqlite3")
local M = {}

local db_path = ngx.config.prefix() .. "data/recon.db"

function M.init()
    local db = sqlite3.open(db_path)
    if not db then
        ngx.log(ngx.ERR, "Could not open database at ", db_path)
        return false
    end
    
    local create_table = [[
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            dns_results TEXT,
            http_headers TEXT,
            tls_info TEXT,
            endpoints TEXT,
            whois_info TEXT
        );
    ]]
    
    local res = db:exec(create_table)
    if res ~= sqlite3.OK then
        ngx.log(ngx.ERR, "Error creating table: ", db:errmsg())
    end
    
    db:close()
    return true
end

function M.save_scan(target, dns_results, http_headers, tls_info, endpoints, whois_info)
    local db = sqlite3.open(db_path)
    if not db then return false end
    
    local stmt = db:prepare("INSERT INTO scans (target, dns_results, http_headers, tls_info, endpoints, whois_info) VALUES (?, ?, ?, ?, ?, ?)")
    if not stmt then
        ngx.log(ngx.ERR, "Error preparing statement: ", db:errmsg())
        db:close()
        return false
    end
    
    stmt:bind_values(target, dns_results, http_headers, tls_info, endpoints, whois_info)
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
