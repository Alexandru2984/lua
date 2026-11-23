-- Read public certificate/session metadata from the SSL_SESSION returned by the
-- verified ngx.socket handshake. OpenSSL objects stay opaque; no Nginx structs,
-- key material, session serialization or additional network requests are used.
local M={}
local binding,unavailable
local function api()
    if binding then return binding end
    if unavailable then return nil,unavailable end
    local ok,result=pcall(function()
        local ffi=require 'ffi'
        ffi.cdef[[
            typedef struct ssl_session_st SSL_SESSION;
            typedef struct ssl_cipher_st SSL_CIPHER;
            typedef struct x509_st X509;
            typedef struct X509_name_st X509_NAME;
            typedef struct asn1_string_st ASN1_TIME;
            typedef struct evp_md_st EVP_MD;
            X509 *SSL_SESSION_get0_peer(SSL_SESSION *s);
            int SSL_SESSION_get_protocol_version(const SSL_SESSION *s);
            const SSL_CIPHER *SSL_SESSION_get0_cipher(const SSL_SESSION *s);
            const char *SSL_CIPHER_get_name(const SSL_CIPHER *c);
            int X509_up_ref(X509 *x);
            void X509_free(X509 *x);
            const X509_NAME *X509_get_subject_name(const X509 *x);
            const X509_NAME *X509_get_issuer_name(const X509 *x);
            int X509_NAME_get_text_by_NID(const X509_NAME *name,int nid,char *buf,int len);
            const ASN1_TIME *X509_get0_notBefore(const X509 *x);
            const ASN1_TIME *X509_get0_notAfter(const X509 *x);
            ASN1_TIME *ASN1_TIME_new(void);
            void ASN1_TIME_free(ASN1_TIME *t);
            int ASN1_TIME_set_string_X509(ASN1_TIME *t,const char *s);
            int ASN1_TIME_diff(int *days,int *seconds,const ASN1_TIME *from,const ASN1_TIME *to);
            const EVP_MD *EVP_sha256(void);
            int X509_digest(const X509 *x,const EVP_MD *type,unsigned char *md,unsigned int *len);
        ]]
        local C=ffi.C
        -- Resolve every required symbol before processing any peer object.
        local functions={C.SSL_SESSION_get0_peer,C.SSL_SESSION_get_protocol_version,
            C.SSL_SESSION_get0_cipher,C.SSL_CIPHER_get_name,C.X509_up_ref,C.X509_free,
            C.X509_get_subject_name,C.X509_get_issuer_name,C.X509_NAME_get_text_by_NID,
            C.X509_get0_notBefore,C.X509_get0_notAfter,C.ASN1_TIME_new,C.ASN1_TIME_free,
            C.ASN1_TIME_set_string_X509,C.ASN1_TIME_diff,C.EVP_sha256,C.X509_digest}
        local epoch=ffi.gc(C.ASN1_TIME_new(),C.ASN1_TIME_free)
        assert(epoch~=nil and C.ASN1_TIME_set_string_X509(epoch,'19700101000000Z')==1)
        return {ffi=ffi,C=C,epoch=epoch,functions=functions}
    end)
    if not ok then unavailable='Certificate metadata is not supported by this runtime.';return nil,unavailable end
    binding=result
    return binding
end
function M.clean_name(value)
    return (value:gsub('[%z\1-\31\127-\255]',function(c)return string.format('\\x%02X',c:byte())end)):sub(1,2048)
end
function M.validity(not_before,not_after,at)
    if type(not_before)~='number' or type(not_after)~='number' or type(at)~='number' or
        not_before~=not_before or not_after~=not_after or at~=at or
        math.abs(not_before)==math.huge or math.abs(not_after)==math.huge or math.abs(at)==math.huge or not_after<not_before then
        return 'unavailable',nil
    end
    local days=math.floor((not_after-at)/86400)
    if at<not_before then return 'not_yet_valid',days end
    if at>=not_after then return 'expired',days end
    if not_after-at<=7*86400 then return 'urgent',days end
    if not_after-at<=30*86400 then return 'soon',days end
    return 'valid',days
end
function M.inspect(session,at)
    if type(session)~='cdata' then return nil,'Certificate session metadata is unavailable.' end
    local b,err=api()
    if not b then return nil,err end
    local ffi,C=b.ffi,b.C
    if not ffi.istype('void *',session) or session==nil then return nil,'Certificate session metadata is unavailable.' end
    local cert=C.SSL_SESSION_get0_peer(ffi.cast('SSL_SESSION *',session))
    if cert==nil then return nil,'The TLS session did not expose a peer certificate.' end
    if C.X509_up_ref(cert)~=1 then return nil,'Could not retain the peer certificate.' end
    cert=ffi.gc(cert,C.X509_free)
    local function timestamp(value)
        if value==nil then return nil end
        local days,seconds=ffi.new('int[1]'),ffi.new('int[1]')
        if C.ASN1_TIME_diff(days,seconds,b.epoch,value)~=1 then return nil end
        return tonumber(days[0])*86400+tonumber(seconds[0])
    end
    local not_before=timestamp(C.X509_get0_notBefore(cert))
    local not_after=timestamp(C.X509_get0_notAfter(cert))
    local digest,length=ffi.new('unsigned char[64]'),ffi.new('unsigned int[1]')
    if not not_before or not not_after or C.X509_digest(cert,C.EVP_sha256(),digest,length)~=1 or length[0]~=32 then
        return nil,'Could not read the certificate dates or fingerprint.' end
    local function name(value)
        if value==nil then return nil end
        local buf=ffi.new('char[1024]')
        local size=C.X509_NAME_get_text_by_NID(value,13,buf,1024)
        if size<0 then return nil end
        return M.clean_name(ffi.string(buf,math.min(size,1023)))
    end
    local version=tonumber(C.SSL_SESSION_get_protocol_version(ffi.cast('SSL_SESSION *',session)))
    local protocol=({[771]='TLS 1.2',[772]='TLS 1.3'})[version] or string.format('0x%04x',version)
    local cipher=C.SSL_SESSION_get0_cipher(ffi.cast('SSL_SESSION *',session))
    local cipher_name=cipher~=nil and C.SSL_CIPHER_get_name(cipher) or nil
    local hex={}
    for i=0,31 do hex[#hex+1]=string.format('%02x',tonumber(digest[i])) end
    local state,days=M.validity(not_before,not_after,at)
    return {subject_cn=name(C.X509_get_subject_name(cert)),issuer_cn=name(C.X509_get_issuer_name(cert)),
        not_before=not_before,not_after=not_after,observed_at=at,
        fingerprint_sha256=table.concat(hex),protocol=protocol,
        cipher=cipher_name~=nil and ffi.string(cipher_name) or nil,
        validity_at_scan=state,days_remaining_at_scan=days}
end
return M
