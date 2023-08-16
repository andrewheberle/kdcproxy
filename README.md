# kdcproxy

[![Go Report Card](https://goreportcard.com/badge/github.com/andrewheberle/kdcproxy?style=flat)](https://goreportcard.com/report/github.com/andrewheberle/kdcproxy)
[![Godoc](https://img.shields.io/badge/go-documentation-blue.svg?style=flat)](https://godoc.org/github.com/andrewheberle/kdcproxy)
[![tag](https://img.shields.io/github/v/tag/andrewheberle/kdcproxy)](https://github.com/andrewheberle/kdcproxy/-/tags)
[![LICENSE](https://img.shields.io/badge/license-MIT-blue)](https://github.com/andrewheberle/kdcproxy/-/blob/main/LICENSE)

This is a Go based KDC Proxy designed for use against Active Directory.

# Usage

## Command Line

```sh
go build github.com/andrewheberle/kdcproxy/cmd/kdcproxy
./kdcproxy --listen :8080
```

## Docker

```sh
docker run -p 8080:8080 ghcr.io/andrewheberle/kdcproxy:v1.2.0
```

To run via HTTPS:

```sh
docker run -p 8443:8080 \
    -e KDC_PROXY_CERT=/ssl/server.crt \
    -e KDC_PROXY_KEY=/ssl/server.key \
    -v /path/to/certificates:/ssl:ro \
    ghcr.io/andrewheberle/kdcproxy:v1.2.0
```

# Configuration

The application supports the following options:


| Command Line Option | Environment Variable | Default | Usage |
|-|-|-|-|
| --listen | KDC_PROXY_LISTEN | 127.0.0.1:8080[^1] | Service listen address |
| --cert | KDC_PROXY_CERT | | TLS Certificate (optional) |
| --key | KDC_PROXY_KEY | | TLS KEY (optional) |
| --debug | KDC_PROXY_DEBUG | false | Enable debug logging |
| --krb5conf | KDC_PROXY_KRB5CONF | | Path to krb5.conf (optional) |

[^1]: The default for the container is ":8080"

# Specifications

This service follows the MS-KKDCP specification that is published here:

https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5bcebb8d-b747-4ee5-9453-428aec1c5c38

# Credits

This was initially based on the KDC Proxy implementation here:

https://github.com/bolkedebruin/rdpgw

In addition a lot of the logic for the service to make things work came from:

https://github.com/latchset/kdcproxy
