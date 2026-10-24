# kdcproxy

[![Godoc](https://img.shields.io/badge/go-documentation-blue.svg?style=flat)](https://godoc.org/github.com/andrewheberle/kdcproxy)
[![tag](https://img.shields.io/github/v/tag/andrewheberle/kdcproxy)](https://github.com/andrewheberle/kdcproxy/-/tags)
[![LICENSE](https://img.shields.io/badge/license-MIT-blue)](https://github.com/andrewheberle/kdcproxy/-/blob/main/LICENSE)
[![codecov](https://codecov.io/gh/andrewheberle/kdcproxy/graph/badge.svg?token=9KGUAZO4Q8)](https://codecov.io/gh/andrewheberle/kdcproxy)

This is a Go based KDC Proxy designed for use against Active
Directory as an alternative for the Windows built-in KDC Proxy
Service (KPSSVC).

# Usage

## Command Line

```sh
go install github.com/andrewheberle/kdcproxy/cmd/kdcproxy@v1.7.0 # x-release-please-version
./kdcproxy --listen :8080
```

## Docker

```sh
docker run -p 8080:8080 ghcr.io/andrewheberle/kdcproxy:v1.7.0 # x-release-please-version
```

The MS-KKDCP specification requires access via HTTPS so the above example assumes
an upstream reverse proxy/load balancer is handling TLS termination.

To enable TLS directly:

```sh
docker run -p 8443:8080 \
    -e KDC_PROXY_CERT=/ssl/server.crt \
    -e KDC_PROXY_KEY=/ssl/server.key \
    -v /path/to/certificates:/ssl:ro \
    ghcr.io/andrewheberle/kdcproxy:v1.7.0 # x-release-please-version
```

The service will pick up certificate/key updates on disk.

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

In most cases, assuming DNS resolution is working and the required DNS SRV records are in place, providing a krb5.conf file should not be required.

# Specifications

This service follows the MS-KKDCP specification that is published here:

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5bcebb8d-b747-4ee5-9453-428aec1c5c38

Conformance to the specification is tracked clause by clause in [docs/spec-conformance.md](docs/spec-conformance.md), including any deliberate deviations and known defects.

Clients must send the `target-domain` field in every proxy message, as the specification requires. It decides which realm the request is routed to, and requests without it are rejected with HTTP 400. Windows and MIT krb5 clients send it.

Password change requests (kpasswd, for example when a password has expired) are relayed to the realm's kpasswd servers. These are found through the `_kpasswd._udp`/`_kpasswd._tcp` DNS SRV records that Active Directory publishes, or through `kpasswd_server`/`admin_server` in krb5.conf.

If a proxy message, or the Kerberos message inside it, is malformed, the connection is dropped without a response, as the specification says. A reverse proxy in front of the service will usually report these requests as HTTP 502. Each one is logged at WARN as `connection dropped` (see [Logging](#logging)).

# Logging

Each request is logged once, to stderr:

| Message | Level | When |
|-|-|-|
| `request` | INFO for 2xx/3xx, WARN for 4xx, ERROR for 5xx | A response was sent |
| `connection dropped` | WARN | The connection was dropped without a response |
| `panic recovered` | ERROR | The request caused an unexpected error, answered with HTTP 500. The line also has `error` and `stack` |

Every line has these attributes:

| Attribute | Value |
|-|-|
| `id` | The `X-Request-Id` header if the client or a reverse proxy sent one, otherwise a random 32 character hex id |
| `method`, `path` | The HTTP method and path |
| `status` | The HTTP status sent. Not logged for a dropped connection |
| `response_bytes` | The size of the response body. Not logged for a dropped connection |
| `request_bytes` | The size of the request body read |
| `duration` | How long the request took |
| `ip` | The client address, which is the reverse proxy's address when there is one |
| `forwarded_for` | The `X-Forwarded-For` header exactly as sent, when present. It is only logged, never trusted |
| `user_agent` | The `User-Agent` header |

# Metrics

Prometheus metrics are served at `/metrics`. Connections dropped without a response are counted in `kdc_proxy_http_dropped_connections_total`, labelled by `reason`. The only reason so far is `malformed_kerberos_message`. These requests are not counted in `kdc_proxy_http_responses_total`, because no response is sent.

# Testing

`go test ./...` runs the unit tests. Integration tests, which run MIT krb5 clients against a Samba AD DC through the service, are described in [test/integration](test/integration/README.md). Windows clients are checked by hand with the [Windows interop checklist](docs/testing/windows-interop.md).

# Credits

This was initially based on the KDC Proxy implementation here:

https://github.com/bolkedebruin/rdpgw

In addition a lot of the logic for the service to make things work came from:

https://github.com/latchset/kdcproxy
