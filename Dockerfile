FROM golang:1.23@sha256:613a108a4a4b1dfb6923305db791a19d088f77632317cfc3446825c54fb862cd AS builder

COPY . /build

RUN cd /build && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags '-w' ./cmd/kdcproxy

FROM gcr.io/distroless/base-debian12:nonroot@sha256:53745e95f227cd66e8058d52f64efbbeb6c6af2c193e3c16981137e5083e6a32

COPY --from=builder /build/kdcproxy /app/kdcproxy

ENV KDC_PROXY_LISTEN=:8080

EXPOSE 8080

ENTRYPOINT [ "/app/kdcproxy" ]
