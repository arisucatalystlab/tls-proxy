/**
 * tls-proxy Cloudflare Worker adapter.
 *
 * The Go/tls-client core cannot run on Cloudflare's runtime, so this worker
 * acts as a thin routing adapter in front of a self-hosted tls-proxy backend.
 *
 * Configure via worker secret/environment variables:
 *   TLS_PROXY_BACKEND  (required) e.g. https://tls-proxy.example.com
 *   TLS_PROXY_API_KEY  (optional) sent as X-API-Key to the backend
 *
 * Routes:
 *   POST /request   -> forwards the JSON payload to the backend /request
 *   *               -> standard forward-proxy passthrough to the backend
 */

const BACKEND = TLS_PROXY_BACKEND;
const API_KEY = TLS_PROXY_API_KEY || "";

export default {
  async fetch(request, env, ctx) {
    const backend = env.TLS_PROXY_BACKEND || BACKEND;
    const apiKey = env.TLS_PROXY_API_KEY || API_KEY;

    if (!backend) {
      return new Response(JSON.stringify({ error: "TLS_PROXY_BACKEND is not configured" }), {
        status: 500,
        headers: { "content-type": "application/json" },
      });
    }

    const url = new URL(request.url);
    const backendUrl = new URL(backend);

    // /request endpoint: forward the payload as-is to the backend.
    if (url.pathname === "/request" || url.pathname === "/request/") {
      const headers = new Headers(request.headers);
      headers.delete("host");
      if (apiKey) headers.set("x-api-key", apiKey);
      return fetch(new URL("/request", backendUrl).toString(), {
        method: request.method,
        headers,
        body: request.body,
      });
    }

    if (url.pathname === "/health") {
      const res = await fetch(new URL("/health", backendUrl).toString());
      return res;
    }

    // Standard forward-proxy behavior: relay the absolute URL to the backend.
    const headers = new Headers(request.headers);
    headers.delete("host");
    headers.delete("proxy-authorization");
    if (apiKey) headers.set("x-api-key", apiKey);

    return fetch(backendUrl.origin + url.pathname + url.search, {
      method: request.method,
      headers,
      body: request.body,
    });
  },
};
