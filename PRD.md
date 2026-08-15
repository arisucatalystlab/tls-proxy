# Product Requirement Document (PRD): TLS-Proxy

## 1. Executive Summary
**tls-proxy** adalah layanan HTTP Proxy ringan yang dirancang untuk membypass TLS fingerprinting (seperti JA3/JA4, HTTP/2 frame signatures) dengan memanfaatkan backend `tls-client` dari [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client). Service ini dapat bertindak sebagai HTTP Proxy standar maupun API endpoint (`/request`) berbasis payload JSON, serta kompatibel untuk dijalankan di lingkungan Serverless (Vercel, Cloudflare Workers) dan Containerized (Docker).

---

## 2. Goals & Key Features
- **TLS Fingerprint Evasion**: Emulasi browser modern (Chrome, Firefox, Safari) untuk menghindari deteksi bot/TLS fingerprinting.
- **Dual Routing Mode**:
  1. Standard HTTP/HTTPS Proxy Agent.
  2. Dynamic JSON REST API endpoint via `POST /request`.
- **Multi-Platform Deployment**: Mendukung Vercel, Cloudflare Workers, dan Docker (Linux/Unix container).
- **Stateless & Serverless-Ready**: Siap dijalankan tanpa ketergantungan database internal.

---

## 3. Architecture & Deployment Targets

### 3.1 Supported Platforms
1. **Docker / Self-Hosted**: Dijalankan sebagai Go/CGO binary atau Python/Node wrapper (sesuai binding `tls-client`) dalam container. Support mode Standard HTTP Proxy dan REST API.
2. **Vercel**: Dijalankan sebagai Serverless Function. API endpoint `/request` berfungsi penuh.
3. **Cloudflare Workers**: Dijalankan via Wasm / API adapter jika memungkinkan, atau routing proxy ke instance `tls-client` backend.

---

## 4. Functional Requirements

### 4.1 Mode 1: Standard HTTP Proxy Agent
Sistem dapat dikonfigurasi sebagai URL proxy biasa (`http://user:pass@proxy-ip:port`) yang menerima request incoming dari HTTP Client standar (misal: `curl`, `requests`, `axios`) dan menyalurkannya via `tls-client`.

### 4.2 Mode 2: Custom JSON Endpoint (`POST /request`)
Endpoint serbaguna yang menerima seluruh parameter HTTP request di dalam request body.

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
- Performance: Latensi overhead proxy `< 50ms` (di luar network latency target site).
- Security: Mendukung opsi Authentication Header / Secret Token (X-API-Key) pada server proxy untuk mencegah penyalahgunaan open-proxy.
- Logging: Log minimalis tanpa menyimpan data sensitif payload user.

## 6. Project Structure
```txt
tls-proxy/
├── api/                  # Entrypoint Vercel serverless
│   └── index.go / index.js
├── src/                  # Core logic & tls-client wrapper
├── worker/               # Entrypoint Cloudflare Workers
├── Dockerfile            # Container build specification
├── docker-compose.yml
├── vercel.json           # Konfigurasi Vercel
├── README.md
└── PRD.md
```

## 7. Development Milestones
1. Phase 1: Core Wrapper Integration `github.com/bogdanfinn/tls-client` & Standalone HTTP Server (/request endpoint).
2. Phase 2: Implementasi Standard HTTP Proxy Agent.
3. Phase 3: Build Dockerfile & Optimasi Image Size.
4. Phase 4: Adaptasi ke Vercel Serverless Function & Cloudflare Worker Wrapper.


## Addition
Lakukan semuanya secara urut, lalu testing aplikasinya secara keseluruhan dan juga dapat berjalan di Dockerfile, buat juga pada .github/workflows untuk building & linting.

Jika ada tools yang belum terinstall, silahkan install terlebih dahulu.
