# DNS and email observations

LuaLens describes directly queried records. It does not authenticate a message,
probe mail servers, expand SPF includes/redirects, discover organizational-domain
policy, validate DKIM or calculate an email security score. Failed or skipped
queries remain unavailable; an empty answer or NXDOMAIN is a different outcome.

- SPF: distinguish one record, multiple competing records, explicit all
  qualifiers and redirects. Finding `-all` alone does not validate earlier terms.
- DMARC: inspect the direct DMARC1 record, requested policy, duplicate policy
  tags, modern `t=y` testing mode and legacy `pct` usage. Missing direct policy
  may be covered by a parent. RFC 9989's absent-p default is monitoring; a legacy
  percentage is not a promise about how every receiver handles mail.
- CAA: report direct records without inferring effective issuer restrictions.
  Parent records, CNAME traversal and CA-specific parameters are not assessed.
- MX: distinguish ordinary records, null MX, mixed null/ordinary MX and absence.
  No MX record does not preclude address-record fallback.

References: [SPF, RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.html),
[DMARC, RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html),
[CAA, RFC 8659](https://www.rfc-editor.org/rfc/rfc8659.html),
[Null MX, RFC 7505](https://www.rfc-editor.org/rfc/rfc7505.html).
