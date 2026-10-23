# latchset/kdcproxy fixtures

These proxy messages were captured by the [latchset/kdcproxy](https://github.com/latchset/kdcproxy) project and copied from the base64 blobs in its `tests.py`, decoded to raw DER. They are used under the MIT license in [COPYING](COPYING), Copyright (c) 2013 Red Hat, Inc.

All four carry the target domain `FREEIPA.LOCAL`.

| File | Kerberos message |
|-|-|
| `asreq1.der` | AS-REQ (169 octets) |
| `asreq2.der` | AS-REQ with pre-authentication (264 octets) |
| `tgsreq.der` | TGS-REQ (936 octets) |
| `kpasswdreq.der` | KPASSWD-REQ, version 0x0001 (603 octets) |
