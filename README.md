# tls-proxy

Layanan HTTP Proxy ringan untuk mem-bypass TLS fingerprinting (JA3/JA4, HTTP/2
signatures) berbasis [`github.com/bogdanfinn/tls-client`](https://github.com/bogdanfinn/tls-client).
Dapat bertindak sebagai **HTTP/HTTPS proxy standar** maupun **REST API** (`POST /request`),
dan siap dijalankan di Docker, Vercel Serverless, serta Cloudflare Workers (adapter).

## Fitur

- **Emulasi TLS browser modern** — Chrome, Firefox, Safari, Opera, dll. (via `client_identifier`)
- **Custom JA3 string** — gunakan fingerprint TLS tertentu secara manual
- **Dual mode**:
  1. Standard HTTP/HTTPS Proxy Agent (support `CONNECT` tunnel + absolute-form forwarding)
  2. REST API `POST /request` dengan payload JSON
- **Upstream proxy** — route lewat proxy lain (http/https/socks5), misal residential proxy
- **Auth** — `X-API-Key` untuk API, `Proxy-Authorization: Basic` untuk mode proxy
- **Stateless & serverless-ready** — tanpa database internal

## Cara Pakai

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

# HTTPS (otomatis pakai CONNECT tunnel)
curl -x http://localhost:8080 https://example.com/

# Dengan auth
curl -x http://tls-proxy:secret@localhost:8080 https://example.com/
```

## Konfigurasi Environment

| Variable                     | Default          | Keterangan                                         |
|------------------------------|------------------|----------------------------------------------------|
| `TLS_PROXY_PORT`             | `8080`           | Port listen                                        |
| `TLS_PROXY_API_KEY`          | *(kosong)*       | API key (comma-separated). Kosong = tanpa auth     |
| `TLS_PROXY_DEFAULT_PROFILE`  | `chrome_120`     | Profile default untuk mode proxy                   |
| `TLS_PROXY_DEFAULT_TIMEOUT`  | `30`             | Timeout (detik)                                    |
| `TLS_PROXY_ENABLE_PROXY`     | `true`           | Aktifkan standard proxy mode                       |
| `TLS_PROXY_MAX_BODY_SIZE`    | `10485760`       | Maks body request (bytes)                          |
| `TLS_PROXY_MAX_RESPONSE_SIZE`| `20971520`       | Maks body response yang dibuffer (bytes)           |
| `TLS_PROXY_UPSTREAM_PROXY`   | *(kosong)*       | Upstream proxy `http(s)://...` / `socks5://...`    |
| `TLS_PROXY_LOG_LEVEL`        | `info`           | `info` / `none`                                    |

### Client Identifier tersedia

`chrome_103`–`chrome_146`, `firefox_102`–`firefox_148`, `safari_15_6_1`,
`safari_16_0`, `safari_ios_17_0`, `opera_89`–`91`, `okhttp4_android_*`, dan
lainnya — lihat daftar lengkap di `profiles.MappedTLSClients`
([tls-client/profiles](https://github.com/bogdanfinn/tls-client/tree/master/profiles)).

## Deployment

### Vercel

Repository ini memiliki `api/index.go` (Serverless Function) dan `vercel.json`.
Set environment variable `TLS_PROXY_API_KEY` di dashboard Vercel.

### Cloudflare Workers

`worker/index.js` adalah adapter yang meneruskan `POST /request` (atau request
lainnya) ke instance tls-proxy backend. Set `TLS_PROXY_BACKEND` dan opsional
`TLS_PROXY_API_KEY` pada Worker.

## Testing

```bash
go test ./... -v
```

Test mencakup:
- Verifikasi **akurasi fingerprint** JA3 (cipher, curves, version) terhadap
  situs pembaca fingerprint (`tls.peet.ws/api/all`) untuk Chrome/Firefox/Safari
- Verifikasi **bypass Cloudflare / anti-bot WAF** (request 200, bukan 403 challenge)
- Custom `ja3_string`
- Standard proxy: HTTP forwarding & HTTPS CONNECT tunnel
- Autentikasi (`X-API-Key`, `Proxy-Authorization`)

Test jaringan di CI dijalankan apa adanya (skipped otomatis jika offline).

## Struktur Proyek

```txt
tls-proxy/
├── api/                   # Entrypoint Vercel serverless (api/index.go)
├── cmd/server/            # Entrypoint binary standalone
├── src/core/              # Core logic: client, request handler, proxy, server
├── worker/                # Cloudflare Workers adapter
├── Dockerfile
├── docker-compose.yml
├── vercel.json
├── .github/workflows/     # CI: lint, build, test, docker
├── README.md
└── PRD.md
```

## Lisensi

Lihat repository origin: [arisucatalystlab/tls-proxy](https://github.com/arisucatalystlab/tls-proxy)
