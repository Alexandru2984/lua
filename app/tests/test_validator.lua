local validator = require("validator")

describe("Validator Module", function()
    
    it("extracts host from a full URL", function()
        local host, err = validator.sanitize_and_validate("https://example.com/path?test=1")
        assert.is_nil(err)
        assert.are.equal("example.com", host)
    end)
    
    it("allows valid public IPs", function()
        local host, err = validator.sanitize_and_validate("8.8.8.8")
        assert.is_nil(err)
        assert.are.equal("8.8.8.8", host)
    end)

    it("blocks private/internal IPs (SSRF protection)", function()
        local host, err = validator.sanitize_and_validate("127.0.0.1")
        assert.is_not_nil(err)
        assert.is_nil(host)
        
        host, err = validator.sanitize_and_validate("192.168.1.100")
        assert.is_not_nil(err)
        
        host, err = validator.sanitize_and_validate("10.0.0.5")
        assert.is_not_nil(err)
        
        host, err = validator.sanitize_and_validate("172.16.0.5")
        assert.is_not_nil(err)
    end)

    it("rejects invalid domains", function()
        local host, err = validator.sanitize_and_validate("invalid_domain")
        assert.is_not_nil(err)
        assert.are.equal("Invalid domain format", err)
    end)

    it("allows valid domains", function()
        local host, err = validator.sanitize_and_validate("lua.micutu.com")
        assert.is_nil(err)
        assert.are.equal("lua.micutu.com", host)
    end)
    
    it("rejects invalid IPv4 format", function()
        local host, err = validator.sanitize_and_validate("300.2.3.4")
        assert.is_not_nil(err)
        assert.are.equal("Invalid IPv4 format", err)
    end)

end)
