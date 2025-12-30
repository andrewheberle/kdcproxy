FROM golang:1.25@sha256:31c1e53dfc1cc2d269deec9c83f58729fa3c53dc9a576f6426109d1e319e9e9a AS builder

COPY . /build

RUN cd /build && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags '-w' ./cmd/kdcproxy

FROM gcr.io/distroless/base-debian12:nonroot@sha256:cd961bbef4ecc70d2b2ff41074dd1c932af3f141f2fc00e4d91a03a832e3a658

COPY --from=builder /build/kdcproxy /app/kdcproxy

ENV KDC_PROXY_LISTEN=:8080

EXPOSE 8080

ENTRYPOINT [ "/app/kdcproxy" ]
