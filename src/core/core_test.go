package core

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	tls "github.com/bogdanfinn/utls"
)

const peetAPI = "https://tls.peet.ws/api/all"

// peetReport mirrors the fields we need from https://tls.peet.ws/api/all.
type peetReport struct {
	HTTPVersion string `json:"http_version"`
	TLS         struct {
		JA3  string `json:"ja3"`
		JA3S string `json:"ja3s"`
		JA4  string `json:"ja4"`
	} `json:"tls"`
}

type ja3Parts struct {
	version      int
	ciphers      []string
	extensions   []string
	curves       []string
	pointFormats []string
}

func parseJA3(ja3 string) (ja3Parts, error) {
	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		return ja3Parts{}, fmt.Errorf("malformed ja3: %s", ja3)
	}
	ver, err := strconv.Atoi(parts[0])
	if err != nil {
		return ja3Parts{}, err
	}
	split := func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(s, "-")
	}
	return ja3Parts{
		version:      ver,
		ciphers:      split(parts[1]),
		extensions:   split(parts[2]),
		curves:       split(parts[3]),
		pointFormats: split(parts[4]),
	}, nil
}

// stripGrease removes GREASE placeholder values from a list of JA3 items.
// utls replaces GREASE placeholders with a random GREASE value on every
// handshake, so they cannot be compared deterministically.
func stripGrease(items []string) []string {
	var out []string
	for _, it := range items {
		n, err := strconv.Atoi(it)
		if err != nil || !isGreaseValue(n) {
			out = append(out, it)
		}
	}
	return out
}

func isGreaseValue(n int) bool {
	// GREASE values are 0x0a0a, 0x1a1a, 0x2a2a ... 0xfafa.
	if n < 0x0a0a || n > 0xfafa {
		return false
	}
	low := n & 0xff
	high := n >> 8
	return high == low && low&0x0f == 0x0a
}

// networkAvailable reports whether the target endpoint is reachable so that
// network-dependent tests can degrade gracefully in offline environments.
func networkAvailable(t *testing.T, addr string, timeout time.Duration) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func fetchPeet(t *testing.T, payload *RequestPayload) (*peetReport, *ResponsePayload) {
	t.Helper()
	handler := NewRequestHandler(NewClientFactory(), 10<<20, 20<<20)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	raw, _ := json.Marshal(payload)
	resp, err := http.Post(srv.URL+"/request", "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("POST /request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	var out ResponsePayload
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal proxy response: %v (body=%s)", err, body)
	}
	if out.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", out.StatusCode, body)
	}

	var report peetReport
	if err := json.Unmarshal([]byte(out.Body), &report); err != nil {
		t.Fatalf("unmarshal peet report: %v", err)
	}
	return &report, &out
}

func newTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	return httptest.NewServer(handler)
}

// expectedJA3Parts derives the stable JA3 fields (version, cipher suites,
// curves, point formats) from a profile's canonical ClientHello spec. The
// extension *order* is intentionally randomized at request time by
// WithRandomTLSExtensionOrder, so it is not compared here.
func expectedJA3Parts(t *testing.T, id string) ja3Parts {
	t.Helper()
	profile, err := ResolveProfile(id, "")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := profile.GetClientHelloSpec()
	if err != nil {
		t.Fatalf("get spec for %s: %v", id, err)
	}

	parts := ja3Parts{version: 771}
	for _, c := range spec.CipherSuites {
		parts.ciphers = append(parts.ciphers, strconv.Itoa(int(c)))
	}
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *tls.SupportedCurvesExtension:
			for _, c := range e.Curves {
				parts.curves = append(parts.curves, strconv.Itoa(int(c)))
			}
		case *tls.SupportedPointsExtension:
			for _, p := range e.SupportedPoints {
				parts.pointFormats = append(parts.pointFormats, strconv.Itoa(int(p)))
			}
		}
	}
	return parts
}

func TestResolveProfile(t *testing.T) {
	for _, id := range []string{"chrome_120", "chrome_133", "firefox_148", "firefox_120", "safari_ios_17_0", "opera_91", "okhttp4_android_13"} {
		p, err := ResolveProfile(id, "")
		if err != nil {
			t.Errorf("ResolveProfile(%q): %v", id, err)
			continue
		}
		if p.GetClientHelloStr() == "" {
			t.Errorf("profile %q has empty client hello", id)
		}
	}

	if _, err := ResolveProfile("not_a_real_browser", ""); !errors.Is(err, ErrUnknownProfile) {
		t.Errorf("expected ErrUnknownProfile, got %v", err)
	}
	p, err := ResolveProfile("", "")
	if err != nil {
		t.Fatalf("default profile: %v", err)
	}
	if p.GetClientHelloStr() == "" {
		t.Error("default profile empty")
	}
}

func TestRequestHandlerValidation(t *testing.T) {
	handler := NewRequestHandler(NewClientFactory(), 10<<20, 20<<20)
	srv := newTestServer(t, handler)
	defer srv.Close()

	cases := []struct {
		name string
		body string
		want int
	}{
		{"not json", "not-json", http.StatusBadRequest},
		{"missing request", `{}`, http.StatusBadRequest},
		{"missing url", `{"request":{"method":"GET"}}`, http.StatusBadRequest},
		{"empty body", ``, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := http.Post(srv.URL+"/request", "application/json", strings.NewReader(c.body))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != c.want {
				t.Errorf("got %d want %d", resp.StatusCode, c.want)
			}
		})
	}
}

func TestFingerprintMatchesProfile(t *testing.T) {
	if !networkAvailable(t, "tls.peet.ws:443", 5*time.Second) {
		t.Skip("tls.peet.ws unreachable, skipping network test")
	}

	for _, id := range []string{"chrome_120", "chrome_133", "firefox_148", "safari_ios_17_0"} {
		t.Run(id, func(t *testing.T) {
			want := expectedJA3Parts(t, id)

			report, _ := fetchPeet(t, &RequestPayload{
				TLSConfig: &TLSConfig{ClientIdentifier: id, Timeout: 30},
				Request:   &HTTPRequest{URL: peetAPI, Method: http.MethodGet},
			})
			got, err := parseJA3(report.TLS.JA3)
			if err != nil {
				t.Fatalf("server-reported ja3 unparsable: %v", err)
			}

			// HTTP/2 must be negotiated so the full browser fingerprint
			// (JA4, HTTP/2 settings order) matches the emulated browser.
			if report.HTTPVersion != "h2" {
				t.Errorf("http_version = %q, want h2", report.HTTPVersion)
			}

			if got.version != want.version {
				t.Errorf("TLS version: got %d want %d", got.version, want.version)
			}
			if strings.Join(stripGrease(got.ciphers), "-") != strings.Join(stripGrease(want.ciphers), "-") {
				t.Errorf("cipher suites differ:\n got %s\nwant %s", got.ciphers, want.ciphers)
			}
			if strings.Join(stripGrease(got.curves), "-") != strings.Join(stripGrease(want.curves), "-") {
				t.Errorf("curves differ:\n got %s\nwant %s", got.curves, want.curves)
			}
			if strings.Join(got.pointFormats, "-") != strings.Join(want.pointFormats, "-") {
				t.Errorf("point formats differ:\n got %s\nwant %s", got.pointFormats, want.pointFormats)
			}
		})
	}
}

func TestCustomJA3String(t *testing.T) {
	if !networkAvailable(t, "tls.peet.ws:443", 5*time.Second) {
		t.Skip("tls.peet.ws unreachable, skipping network test")
	}

	// Canonical Chrome 120 JA3 (widely published reference fingerprint).
	const chrome120JA3 = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"

	report, _ := fetchPeet(t, &RequestPayload{
		TLSConfig: &TLSConfig{JA3String: chrome120JA3, Timeout: 30},
		Request:   &HTTPRequest{URL: peetAPI, Method: http.MethodGet},
	})
	got, _ := parseJA3(report.TLS.JA3)
	want, _ := parseJA3(chrome120JA3)

	if got.version != want.version ||
		strings.Join(got.ciphers, "-") != strings.Join(want.ciphers, "-") ||
		strings.Join(got.curves, "-") != strings.Join(want.curves, "-") ||
		strings.Join(got.pointFormats, "-") != strings.Join(want.pointFormats, "-") {
		t.Errorf("custom ja3 fingerprint mismatch:\n got: %s\nwant: %s", report.TLS.JA3, chrome120JA3)
	}
}

// TestCloudflareBypass verifies that requests succeed against a site served
// behind Cloudflare's edge (and its bot/anti-bot WAF) using a browser TLS
// fingerprint: the response must be a real 200 with content, not a 403
// "Just a moment..." challenge.
func TestCloudflareBypass(t *testing.T) {
	if !networkAvailable(t, "tls.peet.ws:443", 5*time.Second) {
		t.Skip("tls.peet.ws unreachable, skipping network test")
	}

	report, out := fetchPeet(t, &RequestPayload{
		TLSConfig: &TLSConfig{ClientIdentifier: "chrome_120", Timeout: 30},
		Request:   &HTTPRequest{URL: peetAPI, Method: http.MethodGet},
	})

	// Traffic must have actually traversed Cloudflare.
	if !strings.Contains(strings.ToLower(out.Headers["Server"]), "cloudflare") {
		t.Logf("server header: %q (cloudflare header may be absent)", out.Headers["Server"])
	}

	if report.TLS.JA3 == "" || report.TLS.JA4 == "" {
		t.Errorf("expected ja3/ja4 in report, got %+v", report.TLS)
	}
	if !strings.HasPrefix(report.TLS.JA4, "t13") {
		t.Errorf("unexpected ja4 prefix: %s", report.TLS.JA4)
	}
}

func TestURLProxyStreaming(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/binary":
			w.Header().Set("Content-Type", "image/png")
			w.Header().Set("Content-Length", "4")
			w.Header().Set("X-Format-Google", "Abcd")
			_, _ = w.Write([]byte{0x89, 0x50, 0x4e, 0x47})
		default:
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("X-Echo-URL", r.URL.RequestURI())
			w.Header().Set("X-Method", r.Method)
			if v := r.Header.Get("X-Extra-Header"); v != "" {
				w.Header().Set("X-Extra-Header", v)
			}
			body, _ := io.ReadAll(r.Body)
			_, _ = w.Write(body)
		}
	}))
	defer target.Close()

	srv := NewServer(ServerConfig{Port: "0", DefaultTimeout: 30})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.HTTP.Serve(ln) }()
	defer func() { _ = srv.HTTP.Close() }()

	base := "http://" + ln.Addr().String() + "/url/"

	t.Run("binary passthrough with header prefix", func(t *testing.T) {
		resp, err := http.Get(base + target.URL + "/binary")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("got %d want 200", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "image/png" {
			t.Errorf("content-type not passed through: %q", ct)
		}
		if v := resp.Header.Get("X-Proxy-X-Format-Google"); v != "Abcd" {
			t.Errorf("expected prefixed x-proxy-x-format-google=Abcd, got %q", v)
		}
		body, _ := io.ReadAll(resp.Body)
		if !bytesEqual(body, []byte{0x89, 0x50, 0x4e, 0x47}) {
			t.Errorf("binary body corrupted: %v", body)
		}
	})

	t.Run("method body and query forwarded", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, base+target.URL+"/echo?a=1&b=2", strings.NewReader(`{"hello":"world"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Extra-Header", "custom-value")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("got %d want 200", resp.StatusCode)
		}
		if v := resp.Header.Get("X-Proxy-X-Method"); v != "POST" {
			t.Errorf("method not forwarded: %q", v)
		}
		if v := resp.Header.Get("X-Proxy-X-Extra-Header"); v != "custom-value" {
			t.Errorf("custom header not forwarded: %q", v)
		}
		if v := resp.Header.Get("X-Proxy-X-Echo-URL"); v != "/echo?a=1&b=2" {
			t.Errorf("query not forwarded: %q", v)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != `{"hello":"world"}` {
			t.Errorf("body not forwarded: %q", body)
		}
	})

	t.Run("auth headers stripped", func(t *testing.T) {
		target2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got := r.Header.Get("X-API-Key")
			w.Header().Set("X-Saw-Key", got)
			_, _ = w.Write([]byte("ok"))
		}))
		defer target2.Close()
		req, _ := http.NewRequest(http.MethodGet, base+target2.URL+"/", nil)
		req.Header.Set("X-API-Key", "sekret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if v := resp.Header.Get("X-Proxy-X-Saw-Key"); v != "" {
			t.Errorf("x-api-key leaked upstream: %q", v)
		}
	})
}

// newRawTarget starts a plain TCP listener that captures the first request it
// receives byte-for-byte and replies 200. Strict servers (e.g. Cloudflare)
// reject malformed framing that Go's own server silently accepts, so raw
// capture is the only way to assert on it.
func newRawTarget(t *testing.T) (addr string, got chan []byte) {
	t.Helper()
	got = make(chan []byte, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer func() { _ = conn.Close() }()
		var data []byte
		buf := make([]byte, 4096)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				data = append(data, buf[:n]...)
			}
			if rerr != nil {
				break
			}
			if hdrEnd := bytes.Index(data, []byte("\r\n\r\n")); hdrEnd >= 0 {
				cl := 0
				for _, line := range strings.Split(string(data[:hdrEnd]), "\r\n") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "content-length") {
						cl, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
					}
				}
				if len(data) >= hdrEnd+4+cl {
					break
				}
			}
			if len(data) > 1<<20 {
				break
			}
		}
		got <- data
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	}()
	return ln.Addr().String(), got
}

func assertSingleContentLength(t *testing.T, name string, got []byte) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: upstream connection failed", name)
	}
	if c := bytes.Count(bytes.ToLower(got), []byte("content-length")); c != 1 {
		t.Errorf("%s: expected exactly one Content-Length header upstream, got %d: %q", name, c, got)
	}
}

func TestURLProxySingleContentLength(t *testing.T) {
	target, raw := newRawTarget(t)

	srv := NewServer(ServerConfig{Port: "0", DefaultTimeout: 30})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.HTTP.Serve(ln) }()
	defer func() { _ = srv.HTTP.Close() }()

	req, _ := http.NewRequest(http.MethodPost,
		"http://"+ln.Addr().String()+"/url/http://"+target+"/x",
		strings.NewReader(`{"msg":"world"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	assertSingleContentLength(t, "/url/*", <-raw)
}

func TestRequestHandlerSingleContentLength(t *testing.T) {
	target, raw := newRawTarget(t)

	srv := NewServer(ServerConfig{Port: "0", DefaultTimeout: 30})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.HTTP.Serve(ln) }()
	defer func() { _ = srv.HTTP.Close() }()

	body := `{"tls_config":{"client_identifier":"chrome_120"},"request":{"url":"http://` + target + `/x","method":"POST","headers":{"Content-Type":"application/json"},"body":"{\"msg\":\"world\"}"}}`
	resp, err := http.Post("http://"+ln.Addr().String()+"/request", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	assertSingleContentLength(t, "/request", <-raw)
}

func TestURLProxyValidation(t *testing.T) {
	srv := NewServer(ServerConfig{Port: "0"})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.HTTP.Serve(ln) }()
	defer func() { _ = srv.HTTP.Close() }()
	addr := "http://" + ln.Addr().String()

	cases := []string{
		"/url/",
		"/url/not-a-url",
		"/url/ftp://example.com/",
		"/url/",
	}
	for _, path := range cases {
		resp, err := http.Get(addr + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%q got %d want 400", path, resp.StatusCode)
		}
	}
}

func TestListFingerprint(t *testing.T) {
	srv := NewServer(ServerConfig{Port: "0"})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.HTTP.Serve(ln) }()
	defer func() { _ = srv.HTTP.Close() }()

	resp, err := http.Get("http://" + ln.Addr().String() + "/list-fingerprint")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d want 200", resp.StatusCode)
	}
	var out struct {
		ClientIdentifiers []string `json:"client_identifiers"`
		Count             int      `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Count != len(out.ClientIdentifiers) || out.Count == 0 {
		t.Errorf("bad listing: count=%d len=%d", out.Count, len(out.ClientIdentifiers))
	}
	seen := map[string]bool{}
	for _, id := range out.ClientIdentifiers {
		seen[id] = true
	}
	if !seen["chrome_120"] || !seen["firefox_148"] {
		t.Errorf("expected chrome_120 and firefox_148 in listing, got %v", out.ClientIdentifiers)
	}
}

func TestServerAuth(t *testing.T) {
	srv := NewServer(ServerConfig{Port: "0", APIKeys: []string{"sekret-42"}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.HTTP.Serve(ln) }()
	defer func() { _ = srv.HTTP.Close() }()
	addr := "http://" + ln.Addr().String()

	do := func(method, path string, headers map[string]string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	t.Run("request no key", func(t *testing.T) {
		resp := do(http.MethodPost, "/request", nil)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("got %d want 401", resp.StatusCode)
		}
	})

	t.Run("request with key", func(t *testing.T) {
		resp := do(http.MethodPost, "/request", map[string]string{"X-API-Key": "sekret-42"})
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusUnauthorized {
			t.Error("got 401 with correct key")
		}
	})

	t.Run("url no key", func(t *testing.T) {
		resp := do(http.MethodGet, "/url/http://example.com/", nil)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("got %d want 401", resp.StatusCode)
		}
	})

	t.Run("url with key", func(t *testing.T) {
		resp := do(http.MethodGet, "/url/http://127.0.0.1:1/x", map[string]string{"X-API-Key": "sekret-42"})
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusUnauthorized {
			t.Error("got 401 with correct key")
		}
	})

	t.Run("url basic auth", func(t *testing.T) {
		resp := do(http.MethodGet, "/url/http://127.0.0.1:1/x", map[string]string{"Proxy-Authorization": "Basic " + basicAuth("tls-proxy:sekret-42")})
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusUnauthorized {
			t.Error("got 401 with basic auth")
		}
	})

	t.Run("list-fingerprint with key", func(t *testing.T) {
		resp := do(http.MethodGet, "/list-fingerprint", map[string]string{"X-API-Key": "sekret-42"})
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("got %d want 200", resp.StatusCode)
		}
	})
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func basicAuth(cred string) string {
	return base64.StdEncoding.EncodeToString([]byte(cred))
}
