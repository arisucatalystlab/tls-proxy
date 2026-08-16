package core

import (
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
)

// ProxyHandler implements a standard HTTP/HTTPS forward proxy (absolute-form
// requests and CONNECT tunneling), the way HTTP clients such as axios
// (proxy: { host, port }) talk to a proxy. It is opt-in
// (TLS_PROXY_ENABLE_PROXY) and disabled by default so serverless platforms
// (e.g. Vercel) do not accidentally expose an open proxy.
type ProxyHandler struct {
	Factory       *ClientFactory
	Timeout       int
	UpstreamProxy string
	MaxBodySize   int64
}

func NewProxyHandler(factory *ClientFactory, cfg ServerConfig) *ProxyHandler {
	return &ProxyHandler{
		Factory:       factory,
		Timeout:       cfg.DefaultTimeout,
		UpstreamProxy: cfg.UpstreamProxy,
		MaxBodySize:   cfg.MaxBodySize,
	}
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// handleHTTP forwards an absolute-form proxy request to the target using a
// fingerprinted tls-client connection.
func (p *ProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || r.URL.Scheme == "" || r.URL.Host == "" {
		http.Error(w, "bad request: missing absolute target URL", http.StatusBadRequest)
		return
	}
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		http.Error(w, "unsupported scheme: "+r.URL.Scheme, http.StatusBadRequest)
		return
	}

	client, err := p.Factory.Get(&TLSConfig{
		ClientIdentifier: DefaultProfile,
		Timeout:          p.Timeout,
		ProxyURL:         p.UpstreamProxy,
		DisableRedirects: true,
	})
	if err != nil {
		http.Error(w, "failed to create client: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var body io.Reader
	if r.Body != nil && r.ContentLength != 0 {
		body = r.Body
	}
	if p.MaxBodySize > 0 && body != nil {
		body = http.MaxBytesReader(w, r.Body, p.MaxBodySize)
	}

	req, err := fhttp.NewRequest(r.Method, r.URL.String(), body)
	if err != nil {
		http.Error(w, "failed to build request: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.ContentLength = r.ContentLength

	for k, vv := range r.Header {
		if isHopByHopHeader(k) || isAuthHeader(k) || strings.EqualFold(k, "Content-Length") {
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
		log.Printf("proxy %s %s failed: %v", r.Method, r.URL.String(), err)
		http.Error(w, "upstream request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = fresp.Body.Close() }()

	writeUpstreamResponse(w, fresp, false)
}

// handleConnect establishes a raw TCP tunnel for HTTPS (or any TLS) traffic.
// The outbound leg optionally routes through the configured upstream proxy
// (http/https or socks5/socks5h); TLS happens end-to-end between the client
// and the target, exactly like a standard forward proxy.
func (p *ProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Host
	if target == "" {
		http.Error(w, "bad request: missing CONNECT target", http.StatusBadRequest)
		return
	}
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	conn, err := dialTargetWith(r.Context(), target, p.UpstreamProxy, time.Duration(p.Timeout)*time.Second)
	if err != nil {
		log.Printf("CONNECT %q failed: %v", target, err)
		http.Error(w, "tunnel failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = conn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buf, err := hj.Hijack()
	if err != nil {
		_ = conn.Close()
		http.Error(w, "hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if _, err := buf.WriteString("HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		_ = conn.Close()
		_ = clientConn.Close()
		return
	}
	if err := buf.Flush(); err != nil {
		_ = conn.Close()
		_ = clientConn.Close()
		return
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(conn, clientConn)
		_ = conn.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, conn)
		_ = clientConn.Close()
		done <- struct{}{}
	}()
	<-done
}
