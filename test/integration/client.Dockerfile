# MIT krb5 KKDCP client; krb5-k5tls provides the HTTPS transport for kdc = https://...
FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      krb5-user krb5-k5tls \
 && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
