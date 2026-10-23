# kdcproxy

[![Godoc](https://img.shields.io/badge/go-documentation-blue.svg?style=flat)](https://godoc.org/github.com/andrewheberle/kdcproxy)
[![tag](https://img.shields.io/github/v/tag/andrewheberle/kdcproxy)](https://github.com/andrewheberle/kdcproxy/-/tags)
[![LICENSE](https://img.shields.io/badge/license-MIT-blue)](https://github.com/andrewheberle/kdcproxy/-/blob/main/LICENSE)
[![codecov](https://codecov.io/gh/andrewheberle/kdcproxy/graph/badge.svg?token=9KGUAZO4Q8)](https://codecov.io/gh/andrewheberle/kdcproxy)

This is a Go based KDC Proxy designed for use against Active Directory.

# Usage

## Command Line

```sh
go install github.com/andrewheberle/kdcproxy/cmd/kdcproxy@v1.5.0 # x-release-please-version
./kdcproxy --listen :8080
```

## Docker

```sh
docker run -p 8080:8080 ghcr.io/andrewheberle/kdcproxy:v1.5.0 # x-release-please-version
```

To run via HTTPS:

```sh
docker run -p 8443:8080 \
    -e KDC_PROXY_CERT=/ssl/server.crt \
    -e KDC_PROXY_KEY=/ssl/server.key \
    -v /path/to/certificates:/ssl:ro \
    ghcr.io/andrewheberle/kdcproxy:v1.5.0 # x-release-please-version
```

# Configuration

The application supports the following options:

| Command Line Option | Environment Variable | Default | Usage |
|-|-|-|-|
| --listen | KDC_PROXY_LISTEN | 127.0.0.1:8080[^1] | Service listen address |
| --cert | KDC_PROXY_CERT | | TLS Certificate (optional) |
| --key | KDC_PROXY_KEY | | TLS KEY (optional) |
| --krb5conf | KDC_PROXY_KRB5CONF | | Path to krb5.conf (optional) |
| --rate | KDC_PROXY_RATE | 10 | Requests per second to the KDC allowed (optional) |

[^1]: The default for the container is ":8080"

## Krb5.conf

It is optional to provide a MIT krb5.conf configuration file. Without this, the service defaults to using DNS to look up the KDC's for the realm to send requests.

In most cases, assuming DNS resolution is working and the required DNS SRV records are in place, this should not be required.

# Specifications

This service follows the MS-KKDCP specification that is published here:

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5bcebb8d-b747-4ee5-9453-428aec1c5c38

Conformance to the specification is tracked clause by clause in [docs/spec-conformance.md](docs/spec-conformance.md), including any deliberate deviations and known defects.

Clients must send the `target-domain` field in every proxy message, as the specification requires. It decides which realm the request is routed to, and requests without it are rejected with HTTP 400. Windows and MIT krb5 clients send it.

If a proxy message, or the Kerberos message inside it, is malformed, the connection is dropped without a response, as the specification says. A reverse proxy in front of the service will usually report these requests as HTTP 502.

# Metrics

Prometheus metrics are served at `/metrics`. Connections dropped without a response are counted in `kdc_proxy_http_dropped_connections_total`, labelled by `reason`. The only reason so far is `malformed_kerberos_message`. These requests are not counted in `kdc_proxy_http_responses_total`, because no response is sent.

# Credits

This was initially based on the KDC Proxy implementation here:

https://github.com/bolkedebruin/rdpgw

In addition a lot of the logic for the service to make things work came from:

https://github.com/latchset/kdcproxy
