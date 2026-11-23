-- lua-cjson distributions disagree on whether an empty table is {} or [].
-- Encode collection fields explicitly rather than relying on fork-only sentinels.
local json=require 'cjson.safe'
local M={}
function M.collection(name,rows,metadata)
    if type(name)~='string' or type(rows)~='table' or type(metadata)~='table' then return nil,'Invalid collection response.' end
    local length,count=#rows,0
    for key in pairs(rows) do
        if type(key)~='number' or key<1 or key%1~=0 or key>length then return nil,'Expected an array of rows.' end
        count=count+1
    end
    if count~=length then return nil,'Expected an array of rows.' end
    local encoded,err=json.encode(rows)
    if not encoded then return nil,err end
    if length==0 then encoded='[]' end
    local keys={}
    for key in pairs(metadata) do
        if type(key)~='string' or key==name then return nil,'Invalid response metadata.' end
        keys[#keys+1]=key
    end
    table.sort(keys)
    local fields={json.encode(name)..':'..encoded}
    for _,key in ipairs(keys) do
        local value,message=json.encode(metadata[key])
        if not value then return nil,message end
        fields[#fields+1]=json.encode(key)..':'..value
    end
    return '{'..table.concat(fields,',')..'}'
end
return M
