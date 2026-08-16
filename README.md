# tls-proxy

A lightweight HTTP service designed to bypass TLS fingerprinting (JA3/JA4,
HTTP/2 frame signatures) using the
[`github.com/bogdanfinn/tls-client`](https://github.com/bogdanfinn/tls-client)
backend. It exposes a streaming reverse proxy (`/url/*`), a JSON REST API
(`POST /request`), a health check (`/health`), a fingerprint catalog
(`/list-fingerprint`), and an optional HTTP + SOCKS5 forward proxy. It runs
on Vercel Serverless and on any platform that can run a container image
(Railway, Heroku, Render, Fly.io, and more).

## Features

- **Modern browser TLS emulation**: Chrome, Firefox, Safari, Opera, okhttp,
  and more (via `client_identifier`)
- **Custom JA3 string**: manually specify a particular TLS fingerprint
- **Streaming reverse proxy (`/url/*`)**: the target URL is embedded in the
  path; the incoming method, headers, and body are forwarded as-is using a
  browser TLS fingerprint. The response is streamed back (binary-safe:
  images, video, downloads, SSE). Standard entity headers pass through
  unchanged and every other response header is exposed under an `x-proxy-`
  prefix
- **REST API (`POST /request`)**: JSON payload API with string bodies and
  full response as JSON
- **Fingerprint catalog (`/list-fingerprint`)**: list all available
  `client_identifier` values
- **Upstream proxy**: route through another proxy (http/https/socks5), e.g.
  a residential proxy
- **Forward proxy (HTTP + SOCKS5, opt-in)**: standard HTTP forward proxy
  (absolute-form + CONNECT) and a SOCKS5 proxy so existing HTTP clients
  (axios `proxy: { host, port }`) and SOCKS5 clients
  (`socks-proxy-agent`) can use tls-proxy as a drop-in proxy. Disabled by
  default; enabled in the Docker image
- **Auth**: `X-API-Key` on all endpoints; `Proxy-Authorization: Basic` (or
  `Authorization`) is also accepted on `/url/*` and the proxy routes
- **Stateless and serverless-ready**: no internal database required

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check, returns `{"status":"ok"}` |
| `/list-fingerprint` | GET | Lists all available `client_identifier` values |
| `/request` | POST | JSON payload API (string body, JSON response) |
| `/url/<target>` | any | Streaming reverse proxy (binary-safe) |

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

### 3. GitHub Container Registry (GHCR)

The CI pipeline publishes an image to GHCR on every push to `main`:

```bash
docker pull ghcr.io/arisucatalystlab/tls-proxy:latest

# 8080 = HTTP API + HTTP forward proxy, 1080 = SOCKS5 proxy
docker run -d --name tls-proxy -p 8080:8080 -p 1080:1080 \
  -e TLS_PROXY_API_KEY=secret \
  ghcr.io/arisucatalystlab/tls-proxy:latest
```

If the package is private, log in first with a token that has
`read:packages` (or `write:packages` to also publish):

```bash
echo "$GITHUB_TOKEN" | docker login ghcr.io -u <username> --password-stdin
```

### 4. Streaming reverse proxy (`/url/*`)

The target URL is embedded directly in the path, so no proxy configuration is
needed on the client:

```bash
# Fetch a page with a Chrome TLS fingerprint
curl http://localhost:8080/url/https://example.com/

# Download a binary file (streamed, byte-for-byte)
curl -o image.png http://localhost:8080/url/https://example.com/image.png

# POST JSON to an API, method/body/headers forwarded as-is
curl -X POST http://localhost:8080/url/https://api.example.com/v1/upload \
  -H "Content-Type: application/json" \
  -d '{"name": "photo.jpg"}'

# Custom method and query string
curl -X PUT "http://localhost:8080/url/https://api.example.com/items/1?a=1&b=2"
```

Response headers: standard entity headers (`Content-Type`, `Content-Length`,
`Content-Disposition`, `Content-Range`, `Accept-Ranges`, `Content-Encoding`,
`ETag`, `Last-Modified`, `Cache-Control`, `Date`, `Vary`, `Location`, `Set-Cookie`,
...) pass through unchanged so binary rendering and range requests keep
working. Every other response header is prefixed with `x-proxy-`. For
example, if the target returns `X-Format-Google: Abcd`, the client sees:

```http
x-proxy-x-format-google: Abcd
```

### 5. JSON REST API (`POST /request`)

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

### 6. List available fingerprints

```bash
curl http://localhost:8080/list-fingerprint
```

```json
{
  "client_identifiers": ["chrome_103", "...", "chrome_120", "...", "firefox_148", "..."],
  "count": 42
}
```

### 7. Forward proxy (HTTP + SOCKS5, opt-in)

The Docker image ships with the forward proxy **enabled**: an HTTP forward
proxy on the main port (`8080`) and a SOCKS5 proxy on port `1080`. Outside
Docker it is **disabled by default** (serverless-safe) and can be turned on
with `TLS_PROXY_ENABLE_PROXY=true`.

```bash
docker run -d --name tls-proxy -p 8080:8080 -p 1080:1080 \
  -e TLS_PROXY_API_KEY=super-secret \
  ghcr.io/arisucatalystlab/tls-proxy:latest
```

#### axios (HTTP proxy)

Point axios at the server IP with `proxy: { host, port }`:

```js
import axios from "axios";

const res = await axios.get("https://httpbin.org/ip", {
  proxy: {
    host: "103.47.121.7", // your production IP (the Docker host)
    port: 8080,           // TLS_PROXY_PORT
    auth: { username: "tls-proxy", password: process.env.TLS_PROXY_API_KEY },
  },
  timeout: 10000,
});
console.log(res.data);
```

If no API key is set, the `auth` field can be omitted.

#### axios + socks-proxy-agent (SOCKS5)

```js
import axios from "axios";
import { SocksProxyAgent } from "socks-proxy-agent";

const agent = new SocksProxyAgent("socks5://tls-proxy:super-secret@103.47.121.7:1080");

const res = await axios.get("https://httpbin.org/ip", {
  httpsAgent: agent,
  timeout: 10000,
});
console.log(res.data);
```

#### curl

```bash
# HTTP proxy (CONNECT / absolute-form)
curl -x http://103.47.121.7:8080 https://httpbin.org/ip

# SOCKS5 proxy
curl --socks5 103.47.121.7:1080 https://httpbin.org/ip
```

When an API key is set, HTTP proxy requests authenticate with
`Proxy-Authorization: Basic` (`username: tls-proxy`) and SOCKS5 with
username/password (password = API key).

#### Upstream proxy

The forward proxy's outbound leg can route through another proxy, including a
SOCKS5 proxy (e.g. a residential SOCKS5 line), via
`TLS_PROXY_UPSTREAM_PROXY=socks5://user:pass@host:port`:

```bash
docker run -d --name tls-proxy -p 8080:8080 -p 1080:1080 \
  -e TLS_PROXY_API_KEY=super-secret \
  -e TLS_PROXY_UPSTREAM_PROXY=socks5://user:pass@residential.example.com:1080 \
  ghcr.io/arisucatalystlab/tls-proxy:latest
```

The same upstream proxy also applies to `/url/*` and `/request`.

## Client Examples

### Node.js / axios

```js
// /request: string JSON API
const res = await axios.post(
  "https://tls-proxy.example.com/request",
  {
    tls_config: { client_identifier: "chrome_120" },
    request: { url: "https://api.example.com/v1/data", method: "GET" },
  },
  { headers: { "x-api-key": process.env.TLS_PROXY_API_KEY } }
);
console.log(res.data.body);

// /url/*: streaming/binary proxy (download a file)
const target = encodeURIComponent("https://example.com/image.png");
const file = await axios.get(
  `https://tls-proxy.example.com/url/${target}`,
  { responseType: "stream" }
);
file.data.pipe(fs.createWriteStream("image.png"));
```

Note: `encodeURIComponent` is recommended for targets containing reserved
characters. On Vercel the target URL **must** be percent-encoded
(e.g. `/url/https%3A%2F%2Fexample.com%2F`); the raw
`/url/https://example.com/` form is only supported on full-container
platforms.

### Python (requests)

```python
import requests

base = "https://tls-proxy.example.com"
headers = {"x-api-key": "secret"}

# /request: string JSON API
resp = requests.post(
    f"{base}/request",
    headers={**headers, "content-type": "application/json"},
    json={
        "tls_config": {"client_identifier": "firefox_148"},
        "request": {"url": "https://example.com/", "method": "GET"},
    },
)
print(resp.json()["body"])

# /url/*: streaming/binary proxy (download a file)
with requests.get(f"{base}/url/https://example.com/image.png",
                  headers=headers, stream=True) as r:
    with open("image.png", "wb") as f:
        for chunk in r.iter_content(chunk_size=65536):
            f.write(chunk)
```

### Go

```go
// /request: string JSON API
payload := []byte(`{"tls_config":{"client_identifier":"chrome_120"},"request":{"url":"https://example.com/","method":"GET"}}`)
req, _ := http.NewRequest(http.MethodPost, "https://tls-proxy.example.com/request", bytes.NewReader(payload))
req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-API-Key", "secret")
resp, err := http.DefaultClient.Do(req)

// /url/*: streaming/binary proxy
req, _ = http.NewRequest(http.MethodGet, "https://tls-proxy.example.com/url/https://example.com/image.png", nil)
resp, err = http.DefaultClient.Do(req)
data, _ := io.ReadAll(resp.Body) // or copy to a file
```

### Rust (reqwest)

```rust
// /request: string JSON API
let res = reqwest::Client::new()
    .post("https://tls-proxy.example.com/request")
    .header("x-api-key", "secret")
    .json(&serde_json::json!({
        "tls_config": {"client_identifier": "chrome_120"},
        "request": {"url": "https://example.com/", "method": "GET"}
    }))
    .send().await?;

// /url/*: streaming/binary proxy
let bytes = reqwest::Client::new()
    .get("https://tls-proxy.example.com/url/https://example.com/image.png")
    .header("x-api-key", "secret")
    .send().await?
    .bytes().await?;
```

### PHP (cURL)

```php
<?php
$base = "https://tls-proxy.example.com";
$apiKey = "secret";

// /request: string JSON API
$ch = curl_init("$base/request");
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => ["Content-Type: application/json", "X-API-Key: $apiKey"],
    CURLOPT_POSTFIELDS => json_encode([
        "tls_config" => ["client_identifier" => "chrome_120"],
        "request" => ["url" => "https://example.com/", "method" => "GET"],
    ]),
]);
$resp = json_decode(curl_exec($ch), true);
echo $resp["body"];

// /url/*: streaming/binary proxy (download a file)
$ch = curl_init("$base/url/https://example.com/image.png");
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => ["X-API-Key: $apiKey"],
]);
$data = curl_exec($ch);
file_put_contents("image.png", $data);
```

## Docker Usage (Detailed)

### Build and run the image

```bash
# Build locally
docker build -t arisucatalystlab/tls-proxy:latest .

# Run with default settings (HTTP proxy + SOCKS5 proxy enabled in the image)
docker run -d --name tls-proxy -p 8080:8080 -p 1080:1080 arisucatalystlab/tls-proxy:latest

# Run with an API key (required in production to avoid open-proxy abuse)
docker run -d --name tls-proxy -p 8080:8080 -p 1080:1080 \
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

Fetch a URL through the streaming proxy:

```bash
curl http://localhost:8080/url/https://example.com/
```

### Passing environment variables

| Variable | Example | Purpose |
|---|---|---|
| `TLS_PROXY_PORT` | `8080` | Listening port; Vercel's `PORT` is used when unset |
| `TLS_PROXY_API_KEY` | `secret1,secret2` | Comma-separated API keys. Empty means no auth (not recommended in production) |
| `TLS_PROXY_DEFAULT_PROFILE` | `chrome_120` | Default fingerprint profile used by `/url/*` |
| `TLS_PROXY_DEFAULT_TIMEOUT` | `30` | Request timeout in seconds |
| `TLS_PROXY_MAX_BODY_SIZE` | `10485760` | Maximum request body size in bytes |
| `TLS_PROXY_MAX_RESPONSE_SIZE` | `20971520` | Maximum buffered response size in bytes |
| `TLS_PROXY_UPSTREAM_PROXY` | `http://user:pass@host:port` | Route through an upstream proxy (http/https/socks5) |
| `TLS_PROXY_LOG_LEVEL` | `info` | `info` or `none` |

Example with an upstream residential proxy:

```bash
docker run -d --name tls-proxy -p 8080:8080 -p 1080:1080 \
  -e TLS_PROXY_API_KEY=super-secret \
  -e TLS_PROXY_UPSTREAM_PROXY=http://user:pass@residential.example.com:8080 \
  arisucatalystlab/tls-proxy:latest
```

## Vercel Setup (Detailed)

Vercel detects `cmd/server/main.go` and runs the full standalone server (the
same binary used by Docker) behind its edge. `/request`, `/health`,
`/list-fingerprint`, and `/url/*` are all fully functional. The forward
proxy (HTTP CONNECT / SOCKS5) is **disabled by default** and cannot be
enabled on serverless, so use `/url/*` for the same streaming proxy
capability over plain HTTP.

The server listens on the `PORT` environment variable (set by Vercel),
falling back to `TLS_PROXY_PORT`, then `8080`.

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

# Streaming proxy
curl https://<your-project>.vercel.app/url/https://example.com/

# Fingerprint catalog
curl https://<your-project>.vercel.app/list-fingerprint
```

## Deploy on Other Platforms (Railway, Heroku, Render, Fly.io, and more)

The CI pipeline publishes a container image to GHCR
(`ghcr.io/arisucatalystlab/tls-proxy`) on every push to `main`. Any platform
that can run a container and inject a `PORT` environment variable can host the
full server (all endpoints including the streaming `/url/*` proxy).

All config is done through environment variables (see the
[reference](#environment-variables-reference)); no platform-specific code is
required.

### Railway

```bash
# In the Railway dashboard: New Project -> Deploy from Docker image
# Image:      ghcr.io/arisucatalystlab/tls-proxy:latest
# Railway injects $PORT automatically.
# Add TLS_PROXY_API_KEY to keep the service private.
```

### Heroku

Deploy the GHCR image via the Heroku Container Registry:

```bash
heroku login
heroku apps:create tls-proxy-example
heroku container:login
docker pull ghcr.io/arisucatalystlab/tls-proxy:latest
docker tag ghcr.io/arisucatalystlab/tls-proxy:latest registry.heroku.com/tls-proxy-example/web
docker push registry.heroku.com/tls-proxy-example/web
heroku container:release web --app tls-proxy-example

# Set configuration
heroku config:set TLS_PROXY_API_KEY=secret --app tls-proxy-example

# Heroku injects $PORT automatically.
```

The Go buildpack path also works: push the repo to Heroku and it builds
`cmd/server` from `go.mod` (requires Go 1.24+; see the
[`Procfile`](Procfile)).

### Render

Use the `render.yaml` blueprint in this repository (or the dashboard):

```bash
# New Web Service -> Deploy from Docker image
# Image: ghcr.io/arisucatalystlab/tls-proxy:latest
# Render injects $PORT automatically.
```

### Fly.io

```bash
flyctl launch --image ghcr.io/arisucatalystlab/tls-proxy:latest
flyctl secrets set TLS_PROXY_API_KEY=secret
# Fly.io injects $PORT automatically.
```

### Other platforms

Any container platform (Koyeb, Google Cloud Run, Azure Container Apps,
DigitalOcean App Platform, Amazon ECS/EKS, Kubernetes, a plain VPS with
Docker, ...) works the same way: run `ghcr.io/arisucatalystlab/tls-proxy` with
`$PORT` and your env vars. The Docker image enables the HTTP + SOCKS5
forward proxy by default, so existing HTTP clients (axios, curl, wget, ...)
and SOCKS5 clients can connect straight to the deployed host.

## Environment Variables (Reference)

| Variable | Default | Description |
|---|---|---|
| `TLS_PROXY_PORT` | `8080` | Listening port; Vercel's `PORT` is used when unset |
| `TLS_PROXY_API_KEY` | empty | Comma-separated API keys; empty disables auth |
| `TLS_PROXY_DEFAULT_PROFILE` | `chrome_120` | Default profile used by `/url/*` |
| `TLS_PROXY_DEFAULT_TIMEOUT` | `30` | Timeout in seconds |
| `TLS_PROXY_MAX_BODY_SIZE` | `10485760` | Max request body size (bytes) |
| `TLS_PROXY_MAX_RESPONSE_SIZE` | `20971520` | Max buffered response size (bytes) |
| `TLS_PROXY_UPSTREAM_PROXY` | empty | Upstream proxy `http(s)://...` or `socks5://...` |
| `TLS_PROXY_ENABLE_PROXY` | `false` | Enables the HTTP forward proxy and the SOCKS5 proxy (the Docker image sets `true`) |
| `TLS_PROXY_SOCKS5_ADDR` | `:1080` | SOCKS5 proxy listen address |
| `TLS_PROXY_LOG_LEVEL` | `info` | `info` or `none` |

### Available Client Identifiers

`chrome_103` to `chrome_146`, `firefox_102` to `firefox_148`, `safari_15_6_1`,
`safari_16_0`, `safari_ios_17_0`, `opera_89` to `opera_91`,
`okhttp4_android_*`, and more. See the full list in
`profiles.MappedTLSClients`
([tls-client/profiles](https://github.com/bogdanfinn/tls-client/tree/master/profiles))
or query the live service:

```bash
curl http://localhost:8080/list-fingerprint
```

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
- **Streaming proxy (`/url/*`)**: binary passthrough, method/header/body and
  query forwarding, `x-proxy-` header prefixing, auth header stripping,
  target validation
- **Fingerprint catalog**: `/list-fingerprint` returns a non-empty sorted
  list including `chrome_120` and `firefox_148`
- **Auth**: `X-API-Key` on all endpoints and basic auth on `/url/*`
- **Forward proxy**: HTTP absolute-form + CONNECT tunneling and SOCKS5
  (CONNECT, username/password auth), disabled-by-default behavior

Network tests run as-is in CI and skip automatically when offline.

## Project Structure

```txt
tls-proxy/
├── api/                   # Vercel serverless entrypoint (api/index.go)
├── cmd/server/            # Standalone binary entrypoint
├── src/core/              # Core logic: client, request handler, url proxy, server
├── Dockerfile
├── docker-compose.yml
├── Procfile               # Heroku (Go buildpack) process definition
├── render.yaml            # Render blueprint
├── vercel.json
├── .github/workflows/     # CI: lint, build, test, docker, GHCR publish
├── README.md
└── PRD.md
```

## License

See the origin repository: [arisucatalystlab/tls-proxy](https://github.com/arisucatalystlab/tls-proxy)
