# TLS certificate snapshots

A successful HTTPS root request already verifies the certificate chain and the
requested hostname against the system CA bundle. LuaLens now captures the leaf
certificate exposed by that same session, before closing its socket. It records
subject and issuer common names, validity timestamps, SHA-256 fingerprint, the
observation timestamp, and the protocol/cipher negotiated for this connection.
Common names are display fields; hostname verification remains the TLS stack's
responsibility. No private keys, tickets or serialized sessions are stored.

The module uses LuaJIT FFI and public OpenSSL APIs on opaque objects. It resolves
required symbols before processing a session, increments the certificate's
reference count, bounds name buffers and computes validity via ASN.1 APIs without
platform-specific struct layouts. Unsupported runtime metadata remains explicitly
unavailable. No new network connection, native package or runtime subprocess is
introduced. The test runner uses the OpenSSL CLI only to create temporary local
test certificates, then removes them.

Relative warnings use the server time supplied by the bootstrap and a monotonic
browser clock: urgent at seven days or less, soon at 30 days or less. The recorded
expiry is a snapshot, including when it appears on a saved-domain card. A new
manual scan is required to observe renewal. Time passing does not create a new
scan, notification or scheduled job. The normal report retention applies.

Initial redirects are not followed. Different backend servers, certificate
choices or routes can produce a different snapshot on another connection. The
negotiated protocol/cipher does not enumerate everything the server supports.
Revocation, Certificate Transparency policy compliance, exhaustive TLS grading
and automated expiry alerts are outside this feature. Collection errors produce
partial reports, preserving independently known HTTPS verification.

## Native API references

- [SSL_SESSION_get0_peer](https://docs.openssl.org/3.6/man3/SSL_SESSION_get0_peer/)
- [SSL_SESSION_get_protocol_version](https://docs.openssl.org/3.6/man3/SSL_SESSION_get_protocol_version/)
- [ASN.1 time APIs](https://docs.openssl.org/3.6/man3/ASN1_TIME_set/)
- [X509 name accessors](https://docs.openssl.org/3.6/man3/X509_NAME_get_index_by_NID/)
