# Integration tests

These tests check the KKDCP server end to end. Real MIT krb5 clients connect through it to a Samba AD DC, which stands in for Active Directory (see [ADR-0003](../../docs/adr/0003-active-directory-is-the-target-kdc.md)). The unit tests in `pkg/proxy` cover message handling in detail. These cover what fakes can't: real Kerberos exchanges, AD DNS discovery, TLS, and UDP/TCP framing towards the KDC and kpasswd server.

## Running

You need Docker with the Compose plugin.

```sh
go test -tags integration -timeout 15m -v ./test/integration/
```

The `integration` build tag keeps these tests out of `go test ./...`. CI runs them in the `integration` workflow.

The test builds the images, starts the environment, runs the scenarios and tears everything down. It writes a throwaway CA and server certificate to `.run/` (gitignored) and removes it afterwards. The directory is in the repository rather than `/tmp` because snap-packaged Docker can't bind mount from `/tmp`. If a test fails, the compose logs are printed.

To explore the environment by hand, run the test once so the images are built. Then generate certificates into `.run/` (`ca.pem`, `server.crt`, `server.key`) and run `docker compose up --wait` from this directory.

## Environment

| Service | What it is |
|-|-|
| `dc` | Samba AD DC for `EXAMPLE.TEST`, provisioned unprivileged on start (`samba.Dockerfile`) |
| `kdcproxy-udp` | The KKDCP server built from the working tree, finding the KDC and kpasswd server through the DC's DNS SRV records |
| `kdcproxy-tcp` | The same, with `udp_preference_limit = 1` so it only uses TCP |
| `client` | MIT krb5 with `krb5-k5tls`, whose `krb5.conf` lists only a proxy (`client/krb5-udp.conf`, `client/krb5-tcp.conf`) |

## Scenarios

Each scenario runs once per proxy (`TestIntegration/<clause>/<case>/{udp,tcp}`), as its own user:

- `4.1/kinit`: AS exchange.
- `4.1/kvno`: TGS exchange.
- `3.2.5.2-1/wrong_password`: the KDC's error reaches the client.
- `4.2/kpasswd`: change a password.
- `4.2/expired_password`: change a password at `kinit`.

`3.2.5.1-5/transport_used` then checks each proxy's `kdc_proxy_kerberos_requests_total`, to confirm it used the transport it was set up for.

Some behaviour is covered only by unit tests: KRB_ERR_RESPONSE_TOO_BIG, the `0xff80` set-password version (MIT only sends `0x0001`), and malformed messages.

Samba logs many `samba_dnsupdate ... WERR_DNS_ERROR_RECORD_ALREADY_EXISTS` errors on start. They're harmless.
