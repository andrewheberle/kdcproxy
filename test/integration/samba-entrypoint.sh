#!/bin/sh
# Provisions the EXAMPLE.TEST domain on first start, then runs the DC
set -eu

if [ ! -f /var/lib/samba/private/sam.ldb ]; then
	# store NT ACLs in a TDB instead of security.* xattrs, so the container
	# needs no extra capabilities
	samba-tool domain provision \
		--realm=EXAMPLE.TEST --domain=EXAMPLE \
		--server-role=dc --dns-backend=SAMBA_INTERNAL \
		--adminpass="$ADMINPASS" --use-rfc2307 \
		--option="vfs objects=dfs_samba4 acl_xattr xattr_tdb"

	# let each test change a password more than once, keeping complexity rules
	samba-tool domain passwordsettings set --min-pwd-age=0 --history-length=0

	# for the healthcheck: the container resolves through Docker's DNS, which
	# does not serve the realm's SRV records, so point at the local KDC
	cat > /etc/krb5.conf <<-KRB5
		[libdefaults]
			default_realm = EXAMPLE.TEST
			dns_lookup_kdc = false

		[realms]
			EXAMPLE.TEST = {
				kdc = 127.0.0.1
			}
	KRB5
fi

exec samba -F --debug-stdout
