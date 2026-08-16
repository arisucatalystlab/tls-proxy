# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache ca-certificates tzdata git

WORKDIR /src

# Cache module downloads
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/tls-proxy ./cmd/server

# ---- Runtime stage ----
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S tlsproxy && adduser -S -G tlsproxy tlsproxy

COPY --from=builder /out/tls-proxy /usr/local/bin/tls-proxy

USER tlsproxy

ENV TLS_PROXY_PORT=8080 \
    TLS_PROXY_LOG_LEVEL=info \
    TLS_PROXY_ENABLE_PROXY=true \
    TLS_PROXY_SOCKS5_ADDR=:1080

EXPOSE 8080 1080

ENTRYPOINT ["/usr/local/bin/tls-proxy"]
