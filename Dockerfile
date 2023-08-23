FROM golang:1.20-bullseye@sha256:d6e78e2618d6070f54c185bcf166500633888c01c4c96adf5e8188bca6303107 AS builder

COPY . /build

RUN cd /build && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags '-w' ./cmd/kdcproxy

FROM gcr.io/distroless/base-debian11:latest@sha256:73deaaf6a207c1a33850257ba74e0f196bc418636cada9943a03d7abea980d6d

COPY --from=builder /build/kdcproxy /app/kdcproxy

ENV KDC_PROXY_LISTEN=:8080

EXPOSE 8080

ENTRYPOINT [ "/app/kdcproxy" ]
