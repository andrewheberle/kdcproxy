# Builds the KKDCP server from the working tree; the release image is built by goreleaser
FROM golang:1.26-trixie@sha256:909771fef53e3dcb0950255f0c9a8b4728c3b841e61509c7b29b098de7ee02d4 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /kdcproxy ./cmd/kdcproxy

FROM cgr.dev/chainguard/static:latest@sha256:17367e4d3ae2b46c3290858e483fac09be085c92b372360fe3bf6a6150848fde
COPY --from=build /kdcproxy /usr/bin/kdcproxy
USER 65532
ENTRYPOINT ["/usr/bin/kdcproxy"]
