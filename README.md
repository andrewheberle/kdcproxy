# kdcproxy

[![Go Report Card](https://goreportcard.com/badge/github.com/andrewheberle/kdcproxy?style=flat)](https://goreportcard.com/report/github.com/andrewheberle/kdcproxy)
[![Godoc](https://img.shields.io/badge/go-documentation-blue.svg?style=flat)](https://godoc.org/github.com/andrewheberle/kdcproxy)
[![tag](https://img.shields.io/github/v/tag/andrewheberle/kdcproxy)](https://github.com/andrewheberle/kdcproxy/-/tags)
[![LICENSE](https://img.shields.io/badge/license-MIT-blue)](https://github.com/andrewheberle/kdcproxy/-/blob/main/LICENSE)

This is a Go based KDC Proxy designed for use against Active Directory.

# Usage

## Command Line

```sh
go install github.com/andrewheberle/kdcproxy/cmd/kdcproxy@v1.3.0
./kdcproxy --listen :8080
```

## Docker

```sh
docker run -p 8080:8080 ghcr.io/andrewheberle/kdcproxy:v1.3.0
```

To run via HTTPS:

```sh
docker run -p 8443:8080 \
    -e KDC_PROXY_CERT=/ssl/server.crt \
    -e KDC_PROXY_KEY=/ssl/server.key \
    -v /path/to/certificates:/ssl:ro \
    ghcr.io/andrewheberle/kdcproxy:v1.3.0
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

# Credits

This was initially based on the KDC Proxy implementation here:

https://github.com/bolkedebruin/rdpgw

In addition a lot of the logic for the service to make things work came from:

https://github.com/latchset/kdcproxy
