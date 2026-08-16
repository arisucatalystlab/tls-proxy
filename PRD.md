# Product Requirement Document (PRD): TLS-Proxy

## 1. Executive Summary
**tls-proxy** is a lightweight HTTP service designed to bypass TLS
fingerprinting (such as JA3/JA4 and HTTP/2 frame signatures) using the
`tls-client` backend from
[bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client). The service
exposes a streaming reverse proxy (`/url/*`) and a JSON payload based API
endpoint (`POST /request`), and is compatible with Serverless environments
(Vercel) and Containerized environments (Docker, Railway, Heroku, Render,
Fly.io, and more).

---

## 2. Goals & Key Features
- **TLS Fingerprint Evasion**: Emulates modern browsers (Chrome, Firefox,
  Safari) to avoid bot/TLS fingerprinting detection.
- **Routing Modes**:
  1. Streaming reverse proxy via `/url/*` (target URL embedded in the path,
     binary-safe streaming, `x-proxy-` response header prefixing).
  2. Dynamic JSON REST API endpoint via `POST /request`.
  3. Fingerprint catalog via `GET /list-fingerprint`.
- **Multi-Platform Deployment**: Supports Vercel Serverless and any platform
  that can run the container image published to GHCR (Railway, Heroku, Render,
  Fly.io, Google Cloud Run, Azure Container Apps, Docker/Linux container, and
  more).
- **Stateless & Serverless-Ready**: Ready to run without any internal database
  dependency.

---

## 3. Architecture & Deployment Targets

### 3.1 Supported Platforms
1. **Docker / Container hosts**: Runs the standalone Go binary in a
   container. Supports all endpoints including the streaming `/url/*` proxy.
2. **Vercel**: Runs as a Serverless Function (the same binary as Docker).
   `/request`, `/url/*`, `/health`, and `/list-fingerprint` are fully
   functional.
3. **Other container platforms** (Railway, Heroku, Render, Fly.io, Koyeb,
   Google Cloud Run, Azure Container Apps, DigitalOcean App Platform, ECS/EKS,
   Kubernetes): run `ghcr.io/arisucatalystlab/tls-proxy` with a `$PORT`
   environment variable and the documented env vars.

---

## 4. Functional Requirements

### 4.1 Mode 1: Streaming Reverse Proxy (`/url/*`)
The target URL is embedded in the request path:

```
GET  /url/https://example.com/image.png
POST /url/https://api.example.com/v1/upload
```

The incoming method, headers, and body are forwarded as-is using a browser TLS
fingerprint (default profile). The response body is streamed back (binary-safe:
images, video, downloads, SSE). Standard entity headers pass through unchanged;
every other response header is exposed under an `x-proxy-` prefix.

### 4.2 Mode 2: Custom JSON Endpoint (`POST /request`)
A general purpose endpoint that accepts all HTTP request parameters in the
request body.

- **Endpoint**: `POST /request`
- **Content-Type**: `application/json`

#### Request Schema Example:
```json
{
  "tls_config": {
    "client_identifier": "chrome_120",
    "ja3_string": "771,4865-4866-4867...",
    "proxy_url": "http://user:pass@ip:port",
    "timeout": 30
  },
  "request": {
    "url": "https://api.targetsite.com/v1/data",
    "method": "POST",
    "headers": {
      "Content-Type": "application/json",
      "User-Agent": "Mozilla/5.0..."
    },
    "body": "{\"key\": \"value\"}"
  }
}
```
Response Schema Example:

```json
{
  "status_code": 200,
  "headers": {
    "Content-Type": "application/json",
    "Set-Cookie": "session=xyz..."
  },
  "cookies": {
    "session": "xyz"
  },
  "body": "{\"result\": \"success\"}"
}
```

### 4.3 Mode 3: Fingerprint Catalog (`GET /list-fingerprint`)
Returns the sorted list of all available `client_identifier` values plus a
count.

## 5. Non-Functional Requirements
- Performance: Proxy overhead latency `< 50ms` (excluding the target site's
  network latency).
- Security: Supports an Authentication Header / Secret Token option
  (X-API-Key) on the server to prevent open-proxy abuse; `/url/*` also accepts
  `Proxy-Authorization: Basic`.
- Logging: Minimal logging without storing sensitive user payload data.

## 6. Project Structure
```txt
tls-proxy/
├── api/                  # Vercel serverless entrypoint
│   └── index.go
├── cmd/server/           # Standalone binary entrypoint
├── src/core/             # Core logic & tls-client wrapper
├── Dockerfile            # Container build specification
├── docker-compose.yml
├── Procfile              # Heroku (Go buildpack) process definition
├── render.yaml           # Render blueprint
├── vercel.json           # Vercel configuration
├── .github/workflows/    # CI: lint, build, test, docker, GHCR publish
├── README.md
└── PRD.md
```

## 7. Development Milestones
1. Phase 1: Core Wrapper Integration `github.com/bogdanfinn/tls-client` &
   Standalone HTTP Server (/request endpoint).
2. Phase 2: Implement the streaming reverse proxy `/url/*`.
3. Phase 3: Build the Dockerfile & Optimize Image Size.
4. Phase 4: Adapt to Vercel Serverless Function; publish the image to GHCR via
   GitHub Actions for other container platforms.

## Addition
Do everything in order, then test the whole application and make sure it can
also run in the Dockerfile; also create the `.github/workflows` for building,
linting, and publishing the image to GHCR.
