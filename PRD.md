# Product Requirement Document (PRD): TLS-Proxy

## 1. Executive Summary
**tls-proxy** is a lightweight HTTP proxy service designed to bypass TLS
fingerprinting (such as JA3/JA4 and HTTP/2 frame signatures) using the
`tls-client` backend from
[bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client). The service
can act as a standard HTTP proxy or as a JSON payload based API endpoint
(`/request`), and is compatible with Serverless environments (Vercel,
Cloudflare Workers) and Containerized environments (Docker).

---

## 2. Goals & Key Features
- **TLS Fingerprint Evasion**: Emulates modern browsers (Chrome, Firefox,
  Safari) to avoid bot/TLS fingerprinting detection.
- **Dual Routing Mode**:
  1. Standard HTTP/HTTPS Proxy Agent.
  2. Dynamic JSON REST API endpoint via `POST /request`.
- **Multi-Platform Deployment**: Supports Vercel, Cloudflare Workers, and
  Docker (Linux/Unix container).
- **Stateless & Serverless-Ready**: Ready to run without any internal database
  dependency.

---

## 3. Architecture & Deployment Targets

### 3.1 Supported Platforms
1. **Docker / Self-Hosted**: Runs as a Go/CGO binary or a Python/Node wrapper
   (according to the `tls-client` binding) in a container. Supports both
   Standard HTTP Proxy and REST API modes.
2. **Vercel**: Runs as a Serverless Function. The `/request` API endpoint is
   fully functional.
3. **Cloudflare Workers**: Runs via a Wasm / API adapter where possible, or by
   routing the proxy to a `tls-client` backend instance.

---

## 4. Functional Requirements

### 4.1 Mode 1: Standard HTTP Proxy Agent
The system can be configured as a regular proxy URL
(`http://user:pass@proxy-ip:port`) that accepts incoming requests from
standard HTTP clients (for example `curl`, `requests`, `axios`) and forwards
them through `tls-client`.

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
    "url": "[https://api.targetsite.com/v1/data](https://api.targetsite.com/v1/data)",
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

## 5. Non-Functional Requirements
- Performance: Proxy overhead latency `< 50ms` (excluding the target site's
  network latency).
- Security: Supports an Authentication Header / Secret Token option
  (X-API-Key) on the proxy server to prevent open-proxy abuse.
- Logging: Minimal logging without storing sensitive user payload data.

## 6. Project Structure
```txt
tls-proxy/
├── api/                  # Vercel serverless entrypoint
│   └── index.go / index.js
├── src/                  # Core logic & tls-client wrapper
├── worker/               # Cloudflare Workers entrypoint
├── Dockerfile            # Container build specification
├── docker-compose.yml
├── vercel.json           # Vercel configuration
├── README.md
└── PRD.md
```

## 7. Development Milestones
1. Phase 1: Core Wrapper Integration `github.com/bogdanfinn/tls-client` &
   Standalone HTTP Server (/request endpoint).
2. Phase 2: Implement the Standard HTTP Proxy Agent.
3. Phase 3: Build the Dockerfile & Optimize Image Size.
4. Phase 4: Adapt to Vercel Serverless Function & Cloudflare Worker Wrapper.

## Addition
Do everything in order, then test the whole application and make sure it can
also run in the Dockerfile; also create the `.github/workflows` for building
and linting.

If any required tools are not installed yet, install them first.
