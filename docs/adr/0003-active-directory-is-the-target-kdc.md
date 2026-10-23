# Active Directory is the target KDC

This service is a drop-in KKDCP server for Microsoft environments, so Active Directory domain controllers are the only KDCs it is designed and tested against. Other realms (MIT, Heimdal, FreeIPA) may work, since the protocol is standard Kerberos, but nothing is added or changed for them. Where AD and other implementations behave differently, AD behaviour wins. For example, kpasswd servers are found through the `_kpasswd` SRV records every AD domain publishes or through krb5.conf, and the non-AD `_kerberos-adm` fallback that gokrb5 also tries is out of scope.

## Considered Options

- **General-purpose KDC proxy, like latchset/kdcproxy**: this means supporting and testing MIT/Heimdal discovery quirks and kadmin lookups, which is more surface for no gain in the target environment.

## Consequences

Integration tests run against a Samba AD DC ([#102](https://github.com/andrewheberle/kdcproxy/issues/102)), not an MIT KDC. Issues that only affect non-AD realms can be closed as out of scope.
