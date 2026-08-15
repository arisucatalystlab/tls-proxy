package core

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type Server struct {
	Config  ServerConfig
	Factory *ClientFactory
	HTTP    *http.Server
}

func NewServer(cfg ServerConfig) *Server {
	factory := NewClientFactory()

	mux := http.NewServeMux()

	var proxyHandler http.Handler
	if cfg.EnableProxy {
		proxyHandler = &ProxyHandler{Factory: factory, Timeout: cfg.DefaultTimeout, UpstreamProxy: cfg.UpstreamProxy, MaxBodySize: cfg.MaxBodySize}
		mux.Handle("/", proxyHandler)
	}

	requestHandler := NewRequestHandler(factory, cfg.MaxBodySize, cfg.MaxResponseSize)
	mux.HandleFunc("/request", requestHandler.ServeHTTP)
	mux.HandleFunc("/request/", requestHandler.ServeHTTP)

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// CONNECT must be intercepted before the mux: Go's ServeMux 301-redirects
	// requests whose URL path is empty, which breaks HTTPS tunneling.
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			if proxyHandler == nil {
				http.Error(w, "CONNECT not supported", http.StatusMethodNotAllowed)
				return
			}
			proxyHandler.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
	handler = logMiddleware(handler, cfg.LogLevel)
	handler = authMiddleware(handler, cfg.APIKeys)

	return &Server{
		Config:  cfg,
		Factory: factory,
		HTTP: &http.Server{
			Addr:         ":" + cfg.Port,
			Handler:      handler,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
		},
	}
}

// NewHandler returns the raw http.Handler without starting a server. This is
// used by serverless adapters (e.g. Vercel) that own the HTTP lifecycle.
func NewHandler(cfg ServerConfig) http.Handler {
	s := NewServer(cfg)
	return s.HTTP.Handler
}

func (s *Server) ListenAndServe() error {
	log.Printf("tls-proxy listening on :%s (proxy=%v)", s.Config.Port, s.Config.EnableProxy)
	return s.HTTP.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.Factory.Close()
	return s.HTTP.Shutdown(ctx)
}

func authMiddleware(next http.Handler, keys []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(keys) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		provided := r.Header.Get("X-API-Key")
		ok := false
		for _, k := range keys {
			if subtle.ConstantTimeCompare([]byte(provided), []byte(k)) == 1 {
				ok = true
				break
			}
		}

		// Also accept basic-auth credentials on the proxy routes.
		if !ok && r.URL.Path != "/request" && r.URL.Path != "/request/" {
			authHeader := r.Header.Get("Proxy-Authorization")
			if authHeader == "" {
				authHeader = r.Header.Get("Authorization")
			}
			if user, pass, hasAuth := parseBasicAuth(authHeader); hasAuth {
				for _, k := range keys {
					if subtle.ConstantTimeCompare([]byte(user), []byte("tls-proxy")) == 1 &&
						subtle.ConstantTimeCompare([]byte(pass), []byte(k)) == 1 {
						ok = true
						break
					}
				}
			}
		}

		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="tls-proxy"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}

		next.ServeHTTP(w, r)
	})
}

func parseBasicAuth(header string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", "", false
	}
	idx := strings.IndexByte(string(decoded), ':')
	if idx < 0 {
		return "", "", false
	}
	return string(decoded[:idx]), string(decoded[idx+1:]), true
}

func logMiddleware(next http.Handler, level string) http.Handler {
	quiet := strings.EqualFold(level, "none") || strings.EqualFold(level, "error")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if quiet {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Printf("%s %q %d %s remote=%q", r.Method, r.URL.RequestURI(), sw.status, time.Since(start).Round(time.Microsecond), r.RemoteAddr)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("underlying ResponseWriter does not support hijacking")
	}
	return hj.Hijack()
}
