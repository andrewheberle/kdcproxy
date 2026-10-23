# Samba AD DC standing in for Active Directory in the integration tests
FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision python3-samba winbind krb5-user dnsutils ldb-tools \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/samba/smb.conf /etc/krb5.conf
COPY samba-entrypoint.sh /usr/local/bin/samba-entrypoint.sh
EXPOSE 53/udp 53/tcp 88/udp 88/tcp 464/udp 464/tcp
ENTRYPOINT ["/usr/local/bin/samba-entrypoint.sh"]
