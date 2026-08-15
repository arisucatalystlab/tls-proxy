package core

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	"golang.org/x/net/proxy"
)

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

// handleHTTP forwards a proxy request (absolute-form request URI) to the
// target using a fingerprinted tls-client connection.
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

	body := r.Body
	if p.MaxBodySize > 0 {
		body = http.MaxBytesReader(w, r.Body, p.MaxBodySize)
	}
	req, err := fhttp.NewRequest(r.Method, r.URL.String(), body)
	if err != nil {
		http.Error(w, "failed to build request: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.ContentLength = r.ContentLength

	for k, vv := range r.Header {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	fresp, err := client.Do(req)
	if err != nil {
		http.Error(w, "upstream request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = fresp.Body.Close() }()

	for k, vv := range fresp.Header {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(fresp.StatusCode)
	_, _ = io.Copy(w, fresp.Body)
}

// handleConnect establishes a raw TCP tunnel for HTTPS (or any TLS) traffic.
// The outbound leg is a plain connection (optionally routed through the
// configured upstream proxy); TLS happens end-to-end between the client and
// the target, exactly like a standard forward proxy.
func (p *ProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Host
	if target == "" {
		http.Error(w, "bad request: missing CONNECT target", http.StatusBadRequest)
		return
	}
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	conn, err := p.dialTarget(r.Context(), target)
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

// dialTarget opens a raw TCP connection to the target, tunneling through the
// configured upstream proxy when one is set.
func (p *ProxyHandler) dialTarget(ctx context.Context, target string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: time.Duration(p.Timeout) * time.Second}

	if p.UpstreamProxy == "" {
		return dialer.DialContext(ctx, "tcp", target)
	}

	u, err := url.Parse(p.UpstreamProxy)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream proxy: %w", err)
	}

	switch u.Scheme {
	case "http", "https":
		return dialViaHTTPProxy(ctx, dialer, u, target)
	case "socks5", "socks5h":
		sd, err := proxy.SOCKS5("tcp", u.Host, authFromURL(u), dialer)
		if err != nil {
			return nil, err
		}
		return sd.Dial("tcp", target)
	default:
		return nil, fmt.Errorf("unsupported upstream proxy scheme: %s", u.Scheme)
	}
}

// dialViaHTTPProxy connects to an upstream HTTP proxy and issues CONNECT.
func dialViaHTTPProxy(ctx context.Context, dialer *net.Dialer, u *url.URL, target string) (net.Conn, error) {
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Host, "80")
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if u.User != nil {
		user := u.User.Username()
		pass, _ := u.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req += "Proxy-Authorization: Basic " + cred + "\r\n"
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("upstream proxy CONNECT failed: %s", resp.Status)
	}
	return conn, nil
}

func authFromURL(u *url.URL) *proxy.Auth {
	if u.User == nil {
		return nil
	}
	pass, _ := u.User.Password()
	return &proxy.Auth{User: u.User.Username(), Password: pass}
}

func isHopByHopHeader(name string) bool {
	for _, h := range hopByHopHeaders {
		if strings.EqualFold(name, h) {
			return true
		}
	}
	return false
}

// IsUpstreamProxy reports whether the given string looks like a proxy URL.
func IsUpstreamProxy(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme != "" && u.Host != ""
}
