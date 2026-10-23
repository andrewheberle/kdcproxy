# MS-KKDCP conformance

This matrix records how the KKDCP server conforms to [MS-KKDCP] **revision 9.0 (2024-04-23)**, one row per normative statement. Terms follow [GLOSSARY.md](../GLOSSARY.md). The work to close the gaps is tracked in [#105](https://github.com/andrewheberle/kdcproxy/issues/105).

**Scope.** It covers §2 (messages), §3.2 (server details) and §5.1 (security considerations), and quotes §3.1 (client details) only where it explains what a KKDCP client sees. §1 and §4 are informative, except that §4.2 shows password change, which is listed as a capability. A SHOULD counts as required unless a row records a deviation.

**Statuses.**

| Status | Meaning |
|-|-|
| Conforms | Behaviour matches the clause. |
| Deviates (by design) | Deliberate difference, with the reason in the row or an ADR. |
| Defect | Behaviour doesn't match the clause, and an issue tracks the fix. |
| Not yet supported | Capability not implemented yet; an issue tracks it. |
| N/A | The clause doesn't constrain this server's observable behaviour. |

**Tests.** Subtests are named `<clause>/<case>`, for example `3.2.5.1-2/missing_target_domain`, so `go test -run '/3.2.5.1-2/'` runs one clause. Windows-client interop can't run in CI and is verified by hand.

## §2 Messages

| Clause | Required | Status | Notes | Tests |
|-|-|-|-|-|
| 2.1-1 | Proxy messages are carried in HTTP POST. | Conforms | Other methods get 405. | `TestHandlerRejects/2.1-1/get_not_allowed` |
| 2.1-2 | HTTPS by default. | Deviates (by design) | Plain HTTP by default, because TLS is usually terminated upstream. HTTPS with `--cert`/`--key`. | — |
| 2.1-3 | The URI uses `/KdcProxy` unless otherwise configured. | Conforms | The path is fixed at `/KdcProxy`. | — |
| 2.1-4 | The body is a DER-encoded proxy message. | Conforms | A body that isn't a DER-encoded proxy message is malformed, so the connection is dropped (3.2.5.1-1). | `TestHandlerRejects/2.1-4/`<br>`TestHandlerDrops/2.1-4/` |
| 2.2.2-1 | `kerb-message` includes the 4-octet length prefix (RFC 4120 §7.2.2). | Conforms | A `kerb-message` shorter than 4 octets, or whose prefix doesn't match its length, is treated as malformed (3.2.5.1-1). | `TestHandlerDrops/2.2.2-1/` |
| 2.2.2-2 | `target-domain` is required in client messages. | Conforms | Requests are routed to the realm in `target-domain`. | `TestHandlerForwards/2.2.2-2/routed_by_target_domain`<br>`TestKdcProxyMsgEncoding/2.2.2-2/` |
| 2.2.2-3 | `target-domain` is not case-sensitive. | Conforms | Matched case-insensitively against krb5.conf realms; DNS lookups are already case-insensitive. | `TestHandlerForwards/2.2.2-3/target_domain_located_as_sent`<br>`TestKrb5Locator/2.2.2-3/` |
| 2.2.2-4 | `target-domain` and `dclocator-hint` are not used in server messages. | Conforms | Replies carry only `kerb-message`. | `TestHandlerForwards` (every row checks the reply) |

## §3.1 Client details (client-visible behaviour only)

| Clause | Required | Status | Notes | Tests |
|-|-|-|-|-|
| 3.1.5.3-1 | Clients map HTTP 403 to STATUS_AUTHENTICATION_FIREWALL_FAILED, and every other error to STATUS_NO_LOGON_SERVERS. | Conforms | 403 is never returned (correct). Errors use 400, 405, 411, 413, 429 and 503, with `text/plain` bodies (`http.Error` sets the type). | `TestHandlerRejects` (every row checks status and Content-Type) |

## §3.2 Server details

| Clause | Required | Status | Notes | Tests |
|-|-|-|-|-|
| 3.2.3-1 | Open an HTTP/HTTPS endpoint before receiving requests. | Conforms | | — |
| 3.2.5.1-1 | Validate that `kerb-message` is a well-formed Kerberos message, otherwise drop the connection. | Conforms | The connection is dropped with no response and counted in `kdc_proxy_http_dropped_connections_total`. A missing or wrong length prefix is malformed (2.2.2-1). AS-REQ, TGS-REQ and password change requests (versions `0x0001` and `0xff80`, with every length checked) are recognised; anything else, including a bare AP-REQ, is malformed. | `TestHandlerDrops/3.2.5.1-1/`<br>`TestRecovery` (cmd/kdcproxy) |
| 3.2.5.1-2 | If `target-domain` is absent, return ERROR_BAD_FORMAT. | Conforms | Returns 400. | `TestHandlerRejects/3.2.5.1-2/missing_target_domain` |
| 3.2.5.1-3 | Locate the KDC via the equivalent of `DsrGetDcNameEx2`, with the DC locator hint as flags (G and H if absent, plus U if FAST-armored). | Deviates (by design) | KDCs are located via DNS SRV or krb5.conf; the DC locator hint is ignored. See [ADR-0002](adr/0002-dns-srv-instead-of-dc-locator.md). | `TestKrb5Locator/3.2.5.1-3/` |
| 3.2.5.1-4 | Use the address of the located DC. | Conforms | Uses the addresses returned by the lookup in 3.2.5.1-3. | `TestHandlerForwards/3.2.5.1-5/` |
| 3.2.5.1-5 | Send `kerb-message` to the KDC. | Conforms | UDP sends without the length prefix and TCP with it. A UDP reply is read as one datagram. If there is no UDP reply, the request is retried over TCP. Password change requests go to a kpasswd server, found through the AD `_kpasswd` SRV records or krb5.conf, with no fallback to the KDC list ([ADR-0003](adr/0003-active-directory-is-the-target-kdc.md)). | `TestHandlerForwards/3.2.5.1-5/`<br>`TestHandlerForwards/4.1/`<br>`TestHandlerForwards/4.2/` |
| 3.2.5.2-1 | Reply with a proxy message whose `kerb-message` is the Kerberos message response. | Conforms | AS-REP, TGS-REP and KRB-ERROR replies are relayed unchanged over UDP and TCP, and KRB-ERRORs are not retried against another KDC. KRB_ERR_RESPONSE_TOO_BIG over UDP moves on to the TCP KDCs (RFC 4120 §7.2.1). | `TestHandlerForwards/3.2.5.2-1/`<br>`TestHandlerForwards/4.1/` |
| 3.2.5.2-2 | Send the reply on the same HTTP connection. | Conforms | Sent as `application/kerberos`. | `TestHandlerForwards` (every row checks Content-Type) |

## §4 Capabilities shown in examples

| Clause | Required | Status | Notes | Tests |
|-|-|-|-|-|
| 4.1 | Obtain a service ticket. | Conforms | | `TestHandlerForwards/4.1/` |
| 4.2 | Obtain a service ticket with a password change (kpasswd). | Conforms | Password change requests are relayed to a kpasswd server over UDP or TCP. | `TestHandlerForwards/4.2/`<br>`TestKrb5Locator/3.2.5.1-3/kpasswd_from_krb5conf` |

## §5.1 Security considerations

| Clause | Required | Status | Notes | Tests |
|-|-|-|-|-|
| 5.1-1 | Relay only valid Kerberos messages. | Conforms | Requests are validated (3.2.5.1-1). Replies must be AS-REP, TGS-REP or KRB-ERROR, or, for a password change request, a framed password change reply or a bare KRB-ERROR. TCP replies over 128 KiB are refused before being read. An invalid reply moves on to the next server. | `TestHandlerDrops/3.2.5.1-1/`<br>`TestHandlerForwards/5.1-1/`<br>`TestGetResponseLengthLimit/5.1-1/` |
| 5.1-2 | Throttle messages. | Conforms | Token-bucket limit set by `--rate`; requests over it get 429. | `TestHandlerRejects/5.1-2/rate_limited` |
| 5.1-3 | TLS client authentication, if needed, to avoid opening unauthenticated KDC access. | N/A | Optional, and not offered. If it's ever added, it should use 403, the only status clients treat specially (3.1.5.3-1). | — |

[MS-KKDCP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5bcebb8d-b747-4ee5-9453-428aec1c5c38
