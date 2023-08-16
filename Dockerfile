FROM golang:1.21@sha256:a820bbba79cb17845f259d86b5342a4854b1f62b654172b68ba7446bd9c1319e AS builder

COPY . /build

RUN cd /build && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags '-w' ./cmd/kdcproxy

FROM gcr.io/distroless/base-debian11:latest@sha256:73deaaf6a207c1a33850257ba74e0f196bc418636cada9943a03d7abea980d6d

COPY --from=builder /build/kdcproxy /app/kdcproxy

ENV KDC_PROXY_LISTEN=:8080

EXPOSE 8080

ENTRYPOINT [ "/app/kdcproxy" ]
