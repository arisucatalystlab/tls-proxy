package core

import (
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	fhttp "github.com/bogdanfinn/fhttp"
)

// hopByHopHeaders lists connection-specific headers that must not be
// forwarded upstream or copied back to the client.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Authentication-Info",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func isHopByHopHeader(name string) bool {
	for _, h := range hopByHopHeaders {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}

// isAuthHeader reports whether the given header carries credentials that must
// be stripped before forwarding the request upstream.
func isAuthHeader(name string) bool {
	switch {
	case strings.EqualFold(name, "X-API-Key"),
		strings.EqualFold(name, "Authorization"),
		strings.EqualFold(name, "Proxy-Authorization"):
		return true
	}
	return false
}

// passThroughHeaders are the standard entity/rendering headers that are
// forwarded unchanged so binary bodies (images, video, downloads, range
// requests, cacheable assets) work on the client. Every other upstream
// response header is exposed under an "x-proxy-" prefix.
var passThroughHeaders = map[string]bool{
	"accept-ranges":       true,
	"age":                 true,
	"cache-control":       true,
	"content-disposition": true,
	"content-encoding":    true,
	"content-language":    true,
	"content-length":      true,
	"content-location":    true,
	"content-range":       true,
	"content-type":        true,
	"date":                true,
	"etag":                true,
	"expires":             true,
	"last-modified":       true,
	"link":                true,
	"location":            true,
	"retry-after":         true,
	"set-cookie":          true,
	"vary":                true,
}

// DefaultUserAgent is a desktop Chrome UA used when the caller does not send
// one, so upstream servers see a realistic browser profile.
const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// URLProxyHandler is a streaming reverse proxy. The target URL is embedded in
// the request path:
//
//	GET  /url/https://example.com/image.png
//	POST /url/https://api.example.com/v1/upload
//
// The incoming method, headers, and body are forwarded as-is using a browser
// TLS fingerprint (default profile). The response body is streamed back
// (binary-safe: images, video, downloads, SSE), standard entity headers pass
// through unchanged, and every other response header is exposed as
// "x-proxy-<name>".
type URLProxyHandler struct {
	Factory        *ClientFactory
	DefaultTimeout int
	UpstreamProxy  string
}

func NewURLProxyHandler(factory *ClientFactory, cfg ServerConfig) *URLProxyHandler {
	return &URLProxyHandler{
		Factory:        factory,
		DefaultTimeout: cfg.DefaultTimeout,
		UpstreamProxy:  cfg.UpstreamProxy,
	}
}

func (h *URLProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := targetFromRequest(r)
	if target == "" {
		http.Error(w, "bad request: missing target URL (use /url/https://example.com)", http.StatusBadRequest)
		return
	}

	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		http.Error(w, "bad request: invalid target URL: "+target, http.StatusBadRequest)
		return
	}

	client, err := h.Factory.Get(&TLSConfig{
		ClientIdentifier: DefaultProfile,
		Timeout:          h.DefaultTimeout,
		ProxyURL:         h.UpstreamProxy,
	})
	if err != nil {
		http.Error(w, "failed to create client: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var body io.Reader
	if r.Body != nil && r.ContentLength != 0 {
		body = r.Body
	}

	req, err := fhttp.NewRequest(r.Method, target, body)
	if err != nil {
		http.Error(w, "failed to build request: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.ContentLength = r.ContentLength

	for k, vv := range r.Header {
		if isHopByHopHeader(k) || isAuthHeader(k) || strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", DefaultUserAgent)
	}

	fresp, err := client.Do(req)
	if err != nil {
		log.Printf("url proxy %s %s failed: %v", r.Method, target, err)
		http.Error(w, "upstream request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = fresp.Body.Close() }()

	for k, vv := range fresp.Header {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range vv {
			if passThroughHeaders[strings.ToLower(k)] {
				w.Header().Add(k, v)
			} else {
				w.Header().Add("x-proxy-"+k, v)
			}
		}
	}
	w.WriteHeader(fresp.StatusCode)
	_, _ = copyStream(w, fresp.Body)
}

// targetFromRequest extracts the embedded target URL from a /url/* request,
// preserving the query string.
func targetFromRequest(r *http.Request) string {
	if !strings.HasPrefix(r.URL.Path, "/url/") {
		return ""
	}
	target := strings.TrimPrefix(r.URL.Path, "/url/")
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	return target
}

// copyStream copies src to w in chunks, flushing after every chunk so
// streaming responses (large downloads, SSE) reach the client incrementally.
func copyStream(w http.ResponseWriter, src io.Reader) (int64, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return io.Copy(w, src)
	}
	buf := make([]byte, 32*1024)
	var written int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			nw, werr := w.Write(buf[:n])
			written += int64(nw)
			if werr != nil {
				return written, werr
			}
			flusher.Flush()
		}
		if rerr == io.EOF {
			return written, nil
		}
		if rerr != nil {
			return written, rerr
		}
	}
}
