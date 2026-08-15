# tls-proxy

A lightweight HTTP proxy service designed to bypass TLS fingerprinting
(JA3/JA4, HTTP/2 frame signatures) using the
[`github.com/bogdanfinn/tls-client`](https://github.com/bogdanfinn/tls-client)
backend. It can act as a standard HTTP/HTTPS proxy or as a JSON REST API
(`POST /request`), and is ready to run on Docker, Vercel Serverless, and
Cloudflare Workers (as an adapter).

## Features

- **Modern browser TLS emulation**: Chrome, Firefox, Safari, Opera, okhttp,
  and more (via `client_identifier`)
- **Custom JA3 string**: manually specify a particular TLS fingerprint
- **Dual mode**:
  1. Standard HTTP/HTTPS proxy agent (absolute-form forwarding plus
     `CONNECT` tunnel)
  2. REST API `POST /request` with a JSON payload
- **Upstream proxy**: route through another proxy (http/https/socks5), e.g.
  a residential proxy
- **Auth**: `X-API-Key` for the API, `Proxy-Authorization: Basic` for proxy
  mode
- **Stateless and serverless-ready**: no internal database required

## Quick Start

### 1. Standalone (Go)

```bash
go build -o tls-proxy ./cmd/server
TLS_PROXY_API_KEY=secret ./tls-proxy
```

### 2. Docker

```bash
docker compose up -d --build
```

### 3. REST API (`POST /request`)

```bash
curl -X POST http://localhost:8080/request \
  -H "Content-Type: application/json" \
  -H "X-API-Key: secret" \
  -d '{
    "tls_config": {
      "client_identifier": "chrome_120",
      "proxy_url": "http://user:pass@proxy-ip:port",
      "timeout": 30
    },
    "request": {
      "url": "https://api.targetsite.com/v1/data",
      "method": "POST",
      "headers": {
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
      },
      "body": "{\"key\": \"value\"}"
    }
  }'
```

Response:

```json
{
  "status_code": 200,
  "headers": { "Content-Type": "application/json" },
  "cookies": { "session": "xyz" },
  "body": "{\"result\": \"success\"}"
}
```

### 4. Standard HTTP/HTTPS Proxy

```bash
# HTTP
curl -x http://localhost:8080 http://example.com/

# HTTPS (uses a CONNECT tunnel automatically)
curl -x http://localhost:8080 https://example.com/

# With auth
curl -x http://tls-proxy:secret@localhost:8080 https://example.com/
```

## Docker Usage (Detailed)

### Build and run the image

```bash
# Build locally
docker build -t arisucatalystlab/tls-proxy:latest .

# Run with default settings
docker run -d --name tls-proxy -p 8080:8080 arisucatalystlab/tls-proxy:latest

# Run with an API key (required in production to avoid open-proxy abuse)
docker run -d --name tls-proxy -p 8080:8080 \
  -e TLS_PROXY_API_KEY=super-secret \
  arisucatalystlab/tls-proxy:latest
```

### Using docker-compose (recommended)

The repository ships a `docker-compose.yml`. Start it with:

```bash
docker compose up -d --build
```

Then verify the service:

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

Send a fingerprinted request through the container:

```bash
curl -X POST http://localhost:8080/request \
  -H "Content-Type: application/json" \
  -d '{"tls_config":{"client_identifier":"firefox_148"},"request":{"url":"https://tls.peet.ws/api/all","method":"GET"}}'
```

Use it as a standard proxy from any HTTP client:

```bash
curl -x http://localhost:8080 https://example.com/
```

### Passing environment variables

| Variable | Example | Purpose |
|---|---|---|
| `TLS_PROXY_PORT` | `8080` | Listening port |
| `TLS_PROXY_API_KEY` | `secret1,secret2` | Comma-separated API keys. Empty means no auth (not recommended in production) |
| `TLS_PROXY_DEFAULT_PROFILE` | `chrome_120` | Default fingerprint profile for proxy mode |
| `TLS_PROXY_DEFAULT_TIMEOUT` | `30` | Request timeout in seconds |
| `TLS_PROXY_ENABLE_PROXY` | `true` | Enable standard proxy mode |
| `TLS_PROXY_MAX_BODY_SIZE` | `10485760` | Maximum request body size in bytes |
| `TLS_PROXY_MAX_RESPONSE_SIZE` | `20971520` | Maximum buffered response size in bytes |
| `TLS_PROXY_UPSTREAM_PROXY` | `http://user:pass@host:port` | Route through an upstream proxy (http/https/socks5) |
| `TLS_PROXY_LOG_LEVEL` | `info` | `info` or `none` |

Example with an upstream residential proxy:

```bash
docker run -d --name tls-proxy -p 8080:8080 \
  -e TLS_PROXY_API_KEY=super-secret \
  -e TLS_PROXY_UPSTREAM_PROXY=http://user:pass@residential.example.com:8080 \
  arisucatalystlab/tls-proxy:latest
```

## Vercel Setup (Detailed)

`api/index.go` is a Vercel Serverless Function and `vercel.json` configures the
routes. The `/request` endpoint and `/health` are fully functional on Vercel.
Standard proxy mode (CONNECT/absolute-form forwarding) is not available on
serverless functions; use `POST /request` instead.

### Deploy with the Vercel CLI

```bash
npm i -g vercel

# Login and link the project
vercel login
vercel link

# Deploy to preview
vercel

# Promote to production
vercel --prod
```

### Configure environment variables

Set these in the Vercel dashboard (Project Settings -> Environment
Variables) or via the CLI:

```bash
vercel env add TLS_PROXY_API_KEY production
vercel env add TLS_PROXY_DEFAULT_PROFILE production
vercel env add TLS_PROXY_DEFAULT_TIMEOUT production
```

### Test the deployed function

```bash
curl -X POST https://<your-project>.vercel.app/request \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <your-key>" \
  -d '{"tls_config":{"client_identifier":"chrome_120"},"request":{"url":"https://example.com/","method":"GET"}}'
```

## Cloudflare Workers Setup (Detailed)

Go with tls-client cannot run inside Cloudflare's runtime, so `worker/index.js`
is a thin routing adapter. It forwards requests to a self-hosted tls-proxy
backend (Docker, Vercel, or any other host).

### 1. Deploy the worker

```bash
# Requires wrangler
npm i -g wrangler

# Login
wrangler login

# Deploy
wrangler deploy
```

### 2. Configure the backend URL

Set the `TLS_PROXY_BACKEND` secret to your self-hosted tls-proxy instance and
optionally `TLS_PROXY_API_KEY`:

```bash
wrangler secret put TLS_PROXY_BACKEND
# Enter: https://tls-proxy.example.com

wrangler secret put TLS_PROXY_API_KEY
# Enter: your-api-key (optional)
```

### 3. Route traffic through the worker

```bash
# Forward a /request payload to the backend
curl -X POST https://<worker>.workers.dev/request \
  -H "Content-Type: application/json" \
  -d '{"tls_config":{"client_identifier":"chrome_120"},"request":{"url":"https://example.com/","method":"GET"}}'

# Health check
curl https://<worker>.workers.dev/health
```

Requests that are not `/request` or `/health` are relayed to the backend with
the same path and query string, so the worker can sit in front of your
deployed proxy.

## Environment Variables (Reference)

| Variable | Default | Description |
|---|---|---|
| `TLS_PROXY_PORT` | `8080` | Listening port |
| `TLS_PROXY_API_KEY` | empty | Comma-separated API keys; empty disables auth |
| `TLS_PROXY_DEFAULT_PROFILE` | `chrome_120` | Default profile for proxy mode |
| `TLS_PROXY_DEFAULT_TIMEOUT` | `30` | Timeout in seconds |
| `TLS_PROXY_ENABLE_PROXY` | `true` | Enable standard proxy mode |
| `TLS_PROXY_MAX_BODY_SIZE` | `10485760` | Max request body size (bytes) |
| `TLS_PROXY_MAX_RESPONSE_SIZE` | `20971520` | Max buffered response size (bytes) |
| `TLS_PROXY_UPSTREAM_PROXY` | empty | Upstream proxy `http(s)://...` or `socks5://...` |
| `TLS_PROXY_LOG_LEVEL` | `info` | `info` or `none` |

### Available Client Identifiers

`chrome_103` to `chrome_146`, `firefox_102` to `firefox_148`, `safari_15_6_1`,
`safari_16_0`, `safari_ios_17_0`, `opera_89` to `opera_91`,
`okhttp4_android_*`, and more. See the full list in
`profiles.MappedTLSClients`
([tls-client/profiles](https://github.com/bogdanfinn/tls-client/tree/master/profiles)).

## Testing

```bash
go test ./... -v
```

The test suite covers:

- **Fingerprint accuracy**: JA3 (ciphers, curves, version) verified against
  a fingerprint reader site (`tls.peet.ws/api/all`) for Chrome, Firefox, and
  Safari profiles
- **Cloudflare / anti-bot WAF bypass**: requests return a real 200, not a
  403 challenge
- **Custom `ja3_string`**
- **Standard proxy**: HTTP forwarding and HTTPS CONNECT tunnel
- **Auth**: `X-API-Key` and `Proxy-Authorization`

Network tests run as-is in CI and skip automatically when offline.

## Project Structure

```txt
tls-proxy/
├── api/                   # Vercel serverless entrypoint (api/index.go)
├── cmd/server/            # Standalone binary entrypoint
├── src/core/              # Core logic: client, request handler, proxy, server
├── worker/                # Cloudflare Workers adapter
├── Dockerfile
├── docker-compose.yml
├── vercel.json
├── .github/workflows/     # CI: lint, build, test, docker
├── README.md
└── PRD.md
```

## License

See the origin repository: [arisucatalystlab/tls-proxy](https://github.com/arisucatalystlab/tls-proxy)
