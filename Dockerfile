# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=v0.2.0
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/dataproxy-hub ./cmd/dataproxy-hub && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/dataproxy-agent ./cmd/dataproxy-agent

# ---- Minimal Runtime Base ----
# alpine:3.21 already includes /etc/ssl/certs/ca-certificates.crt; zero apk fetches needed.
FROM alpine:3.21 AS runtime-base
RUN addgroup -S dataproxy && adduser -S -G dataproxy dataproxy && \
    mkdir -p /etc/dataproxy /var/lib/dataproxy && \
    chown -R dataproxy:dataproxy /etc/dataproxy /var/lib/dataproxy
USER dataproxy
WORKDIR /var/lib/dataproxy

# ---- Hub Target: docker build --target hub -t dataproxy-hub . ----
FROM runtime-base AS hub
COPY --from=builder /out/dataproxy-hub /usr/local/bin/dataproxy-hub
EXPOSE 8443/tcp 8443/udp 1080/tcp 8080/tcp 9090/tcp 13306/tcp 15432/tcp 16379/tcp 17017/tcp
ENTRYPOINT ["/usr/local/bin/dataproxy-hub"]
CMD ["-config", "/etc/dataproxy/hub.yaml"]

# ---- Agent Target: docker build --target agent -t dataproxy-agent . ----
FROM runtime-base AS agent
COPY --from=builder /out/dataproxy-agent /usr/local/bin/dataproxy-agent
ENTRYPOINT ["/usr/local/bin/dataproxy-agent"]
CMD ["-config", "/etc/dataproxy/agent.yaml"]

# ---- Default Combined Image (contains both hub & agent binaries) ----
FROM runtime-base AS all
COPY --from=builder /out/dataproxy-hub /usr/local/bin/dataproxy-hub
COPY --from=builder /out/dataproxy-agent /usr/local/bin/dataproxy-agent
ENTRYPOINT ["/usr/local/bin/dataproxy-agent"]
CMD ["-version"]
