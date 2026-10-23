# Windows interop checklist

Windows clients can't run in CI, so check them by hand before releasing a change to protocol behaviour. The [integration tests](../../test/integration/README.md) already cover MIT krb5 clients.

## Setup

- [ ] A test AD domain, and a domain-joined Windows client that **cannot** reach a domain controller directly. Block TCP/UDP 88 and 464 to the DCs, for example with the client firewall, so every Kerberos request goes through the KKDCP server.
- [ ] The KKDCP server, built from the release candidate, reachable from the client over HTTPS with a certificate the client trusts.
- [ ] The client configured to use it. Use either:
  - Group Policy: **Computer Configuration > Administrative Templates > System > Kerberos > Specify KDC proxy servers for Kerberos clients**, with value name `<realm>` and value `<https kdcproxy.example.com:443:KdcProxy />`; or
  - the registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\KdcProxy\ProxyServers`, a string value named after the realm, with the same data.
- [ ] Note the server's `/metrics` counters before testing, so you can confirm traffic went through it.

## Checks

- [ ] **Sign in** to the client as a domain user. `klist` shows a TGT for the realm.
- [ ] **Service ticket:** `klist get host/<server FQDN>` succeeds.
- [ ] **Password change:** change the password with Ctrl+Alt+Del > Change a password. It succeeds, and signing in with the new password works.
- [ ] **Expired password:** set "User must change password at next logon" on a test user. Signing in asks for a new password, the change succeeds, and the sign-in completes.
- [ ] **RD Gateway**, if used: an RD Gateway connection that relies on the KKDCP server signs in.
- [ ] **Metrics:** `kdc_proxy_http_responses_total{code="OK"}` and `kdc_proxy_kerberos_requests_total` increased, and `kdc_proxy_http_dropped_connections_total` did not.

Record the Windows build and the KKDCP server version tested in the release PR.
