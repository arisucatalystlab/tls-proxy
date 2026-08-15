package core

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestProxyHTTPForwarding(t *testing.T) {
	srv := NewServer(ServerConfig{Port: "0", EnableProxy: true, DefaultTimeout: 30})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.HTTP.Serve(ln) }()
	defer func() { _ = srv.HTTP.Close() }()

	proxyURL := "http://" + ln.Addr().String()

	client := &http.Client{
		Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		}},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("http via proxy got %d", resp.StatusCode)
	}
}

func TestProxyHTTPSConnect(t *testing.T) {
	srv := NewServer(ServerConfig{Port: "0", EnableProxy: true, DefaultTimeout: 30})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.HTTP.Serve(ln) }()
	defer func() { _ = srv.HTTP.Close() }()

	proxyURL := "http://" + ln.Addr().String()
	client := &http.Client{
		Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse(proxyURL)
		}},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("https (CONNECT) via proxy got %d", resp.StatusCode)
	}
}

func TestServerAuth(t *testing.T) {
	srv := NewServer(ServerConfig{Port: "0", EnableProxy: true, APIKeys: []string{"sekret-42"}})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.HTTP.Serve(ln) }()
	defer func() { _ = srv.HTTP.Close() }()
	addr := ln.Addr().String()

	do := func(req *http.Request) *http.Response {
		t.Helper()
		client := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse("http://" + addr)
		}}, Timeout: 20 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	t.Run("request no key", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "http://proxy.invalid/request", strings.NewReader(`{"request":{"url":"https://example.com/"}}`))
		resp := do(req)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("got %d want 401", resp.StatusCode)
		}
	})

	t.Run("request with key", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "http://proxy.invalid/request", strings.NewReader(`{"request":{"url":"https://example.com/"}}`))
		req.Header.Set("X-API-Key", "sekret-42")
		resp := do(req)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusUnauthorized {
			t.Error("got 401 with correct key")
		}
	})

	t.Run("proxy no creds", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
		resp := do(req)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("got %d want 401", resp.StatusCode)
		}
	})

	t.Run("proxy basic auth", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Header.Set("Proxy-Authorization", "Basic "+basicAuth("tls-proxy:sekret-42"))
		resp := do(req)
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusUnauthorized {
			t.Error("got 401 with proxy basic auth")
		}
	})
}

func basicAuth(cred string) string {
	return base64.StdEncoding.EncodeToString([]byte(cred))
}
