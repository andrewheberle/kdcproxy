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
| 2.1-1 | Proxy messages are carried in HTTP POST. | Conforms | Other methods get 405. | — |
| 2.1-2 | HTTPS by default. | Deviates (by design) | Plain HTTP by default, because TLS is usually terminated upstream. HTTPS with `--cert`/`--key`. | — |
| 2.1-3 | The URI uses `/KdcProxy` unless otherwise configured. | Conforms | The path is fixed at `/KdcProxy`. | — |
| 2.1-4 | The body is a DER-encoded proxy message. | Conforms | | — |
| 2.2.2-1 | `kerb-message` includes the 4-octet length prefix (RFC 4120 §7.2.2). | Defect | The prefix isn't checked, and fewer than 4 octets panics ([#96](https://github.com/andrewheberle/kdcproxy/issues/96)). | — |
| 2.2.2-2 | `target-domain` is required in client messages. | Defect | Ignored; the routing realm comes from inside the Kerberos message ([#99](https://github.com/andrewheberle/kdcproxy/issues/99)). | — |
| 2.2.2-3 | `target-domain` is not case-sensitive. | Defect | Not applied, because `target-domain` is unused ([#99](https://github.com/andrewheberle/kdcproxy/issues/99)). | — |
| 2.2.2-4 | `target-domain` and `dclocator-hint` are not used in server messages. | Conforms | Replies carry only `kerb-message`. | — |

## §3.1 Client details (client-visible behaviour only)

| Clause | Required | Status | Notes | Tests |
|-|-|-|-|-|
| 3.1.5.3-1 | Clients map HTTP 403 to STATUS_AUTHENTICATION_FIREWALL_FAILED, and every other error to STATUS_NO_LOGON_SERVERS. | Defect | 403 is never returned (correct). Error bodies are wrongly labelled `application/kerberos`, and the status mapping isn't pinned down yet ([#100](https://github.com/andrewheberle/kdcproxy/issues/100)). | — |

## §3.2 Server details

| Clause | Required | Status | Notes | Tests |
|-|-|-|-|-|
| 3.2.3-1 | Open an HTTP/HTTPS endpoint before receiving requests. | Conforms | | — |
| 3.2.5.1-1 | Validate that `kerb-message` is a well-formed Kerberos message, otherwise drop the connection. | Defect | Returns 400 instead of dropping ([#95](https://github.com/andrewheberle/kdcproxy/issues/95)). Fewer than 4 octets panics ([#96](https://github.com/andrewheberle/kdcproxy/issues/96)). Only AS-REQ, TGS-REQ and AP-REQ are recognised; KPASSWD-REQ isn't ([#101](https://github.com/andrewheberle/kdcproxy/issues/101)). | — |
| 3.2.5.1-2 | If `target-domain` is absent, return ERROR_BAD_FORMAT. | Defect | A missing `target-domain` is accepted ([#99](https://github.com/andrewheberle/kdcproxy/issues/99)). | — |
| 3.2.5.1-3 | Locate the KDC via the equivalent of `DsrGetDcNameEx2`, with the DC locator hint as flags (G and H if absent, plus U if FAST-armored). | Deviates (by design) | KDCs are located via DNS SRV or krb5.conf; the DC locator hint is ignored. See [ADR-0002](adr/0002-dns-srv-instead-of-dc-locator.md). | — |
| 3.2.5.1-4 | Use the address of the located DC. | Conforms | Uses the addresses returned by the lookup in 3.2.5.1-3. | — |
| 3.2.5.1-5 | Send `kerb-message` to the KDC. | Defect | UDP sends without the length prefix and TCP with it, which is correct. UDP replies probably always time out ([#97](https://github.com/andrewheberle/kdcproxy/issues/97)). KPASSWD-REQ goes to the KDC rather than the kpasswd service ([#101](https://github.com/andrewheberle/kdcproxy/issues/101)). | — |
| 3.2.5.2-1 | Reply with a proxy message whose `kerb-message` is the Kerberos message response. | Defect | KRB-ERROR replies are dropped on the UDP path ([#98](https://github.com/andrewheberle/kdcproxy/issues/98)). | — |
| 3.2.5.2-2 | Send the reply on the same HTTP connection. | Conforms | Sent as `application/kerberos`. | — |

## §4 Capabilities shown in examples

| Clause | Required | Status | Notes | Tests |
|-|-|-|-|-|
| 4.1 | Obtain a service ticket. | Conforms | | — |
| 4.2 | Obtain a service ticket with a password change (kpasswd). | Not yet supported | [#101](https://github.com/andrewheberle/kdcproxy/issues/101) | — |

## §5.1 Security considerations

| Clause | Required | Status | Notes | Tests |
|-|-|-|-|-|
| 5.1-1 | Relay only valid Kerberos messages. | Defect | Requests are validated. Replies are validated only on UDP, and that validation rejects KRB-ERROR ([#98](https://github.com/andrewheberle/kdcproxy/issues/98)). | — |
| 5.1-2 | Throttle messages. | Conforms | Token-bucket limit set by `--rate`; requests over it get 429. | — |
| 5.1-3 | TLS client authentication, if needed, to avoid opening unauthenticated KDC access. | N/A | Optional, and not offered. If it's ever added, it should use 403, the only status clients treat specially (3.1.5.3-1). | — |

[MS-KKDCP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5bcebb8d-b747-4ee5-9453-428aec1c5c38
