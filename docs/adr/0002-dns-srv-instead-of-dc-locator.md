# Locate KDCs by DNS SRV or krb5.conf, ignoring the DC locator hint

MS-KKDCP §3.2.5.1 says a KKDCP server SHOULD locate the KDC by calling the equivalent of `DsrGetDcNameEx2` (MS-NRPC), with the DC locator hint as its flags and bit U set for FAST-armored messages. This service runs off Windows and has no DC locator, so it finds KDCs for the target domain through DNS SRV records, or through krb5.conf when one is configured. It accepts the DC locator hint and then ignores it. This is a documented deviation in `docs/spec-conformance.md`, not a gap to fix.

## Considered Options

- **Use the hint to filter DNS SRV results** (for example, prefer `_kerberos._tcp.<site>._sites.dc._msdcs` for site-aware flags): this only approximates a few of the flags, and the result would quietly differ from the Windows DC locator.
- **Reject proxy messages that carry a hint**: this would break Windows clients that send flags other than G and H, for no gain.
