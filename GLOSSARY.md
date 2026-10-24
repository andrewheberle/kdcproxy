# kdcproxy

A KKDCP server implementing Microsoft's Kerberos Key Distribution Center Proxy Protocol (MS-KKDCP), letting Kerberos clients reach Active Directory KDCs over HTTPS.

## Language

### Parties

**KKDCP server**:
This service: the HTTP endpoint that receives proxy messages and relays the Kerberos messages inside them to a KDC.
_Avoid_: proxy (alone), gateway

**KKDCP client**:
The HTTP-side caller that wraps a Kerberos message in a proxy message, such as Windows or MIT krb5.
_Avoid_: user, browser

**KDC**:
The upstream Kerberos Key Distribution Center (an Active Directory domain controller) that the KKDCP server relays Kerberos messages to.
_Avoid_: DC (except when quoting MS-NRPC), backend

**Kpasswd server**:
The upstream server (port 464 on an Active Directory domain controller) that the KKDCP server relays password change requests to. It is located separately from the KDC.
_Avoid_: kadmin server, admin server

### Messages

**Proxy message**:
A `KDC_PROXY_MESSAGE`: the DER-encoded structure carried in the HTTP body in both directions.
_Avoid_: request, packet, envelope

**Kerberos message**:
The `kerb-message` payload of a proxy message: a Kerberos request or reply, including its 4-octet length prefix.
_Avoid_: ticket, payload

**KDC request**:
A Kerberos message asking a KDC for a ticket: an AS-REQ or TGS-REQ. Its answer is a **KDC reply**: an AS-REP, TGS-REP or KRB-ERROR.
_Avoid_: ticket request, Kerberos request

**Password change request**:
A Kerberos message asking to change or set a password (KPASSWD-REQ; the spec's KRB_CHG_PWD_REQ). Its answer is a **password change reply**.
_Avoid_: kadmin request, change password message

### Routing

**Realm**:
A Kerberos administrative domain, as defined in RFC 4120.
_Avoid_: domain (alone)

**Target domain**:
The realm a KKDCP client asks the KKDCP server to route a Kerberos message to, carried in the proxy message's `target-domain` field. It is compared case-insensitively.
_Avoid_: realm (when meaning this field)

**DC locator hint**:
The optional `dclocator-hint` field of a proxy message, which carries MS-NRPC DC locator flags.
_Avoid_: flags
