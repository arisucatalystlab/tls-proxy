package core

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	fhttp "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/cookiejar"
	"github.com/bogdanfinn/fhttp/http2"
	tlsclient "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

const (
	DefaultProfile        = "chrome_120"
	DefaultTimeoutSeconds = 30
)

var (
	ErrUnknownProfile  = errors.New("unknown client_identifier profile")
	ErrInvalidJA3      = errors.New("invalid ja3_string")
	ErrInvalidProxyURL = errors.New("invalid proxy_url")
)

var pseudoHeaderOrder = []string{
	":method",
	":authority",
	":scheme",
	":path",
}

var chromeLikeSettings = map[http2.SettingID]uint32{
	http2.SettingHeaderTableSize:      65536,
	http2.SettingMaxConcurrentStreams: 1000,
	http2.SettingInitialWindowSize:    6291456,
	http2.SettingMaxHeaderListSize:    262144,
}

var chromeLikeSettingsOrder = []http2.SettingID{
	http2.SettingHeaderTableSize,
	http2.SettingMaxConcurrentStreams,
	http2.SettingInitialWindowSize,
	http2.SettingMaxHeaderListSize,
}

var connectionFlow = uint32(15663105)

// ClientFactory builds and caches tls-client instances so that repeated
// requests sharing the same TLS configuration reuse pooled connections.
type ClientFactory struct {
	mu      sync.Mutex
	clients map[string]tlsclient.HttpClient
}

func NewClientFactory() *ClientFactory {
	return &ClientFactory{clients: make(map[string]tlsclient.HttpClient)}
}

// ResolveProfile returns the emulated browser profile for a given
// client_identifier or a custom profile built from a JA3 string.
func ResolveProfile(identifier, ja3 string) (profiles.ClientProfile, error) {
	if ja3 != "" {
		return buildJA3Profile(ja3)
	}
	if identifier == "" {
		identifier = DefaultProfile
	}
	key := strings.ToLower(identifier)
	if p, ok := profiles.MappedTLSClients[key]; ok {
		return p, nil
	}
	return profiles.ClientProfile{}, fmt.Errorf("%w: %s", ErrUnknownProfile, identifier)
}

func buildJA3Profile(ja3 string) (profiles.ClientProfile, error) {
	if strings.Count(ja3, ",") < 4 {
		return profiles.ClientProfile{}, fmt.Errorf("%w: %s", ErrInvalidJA3, ja3)
	}
	specFactory, err := tlsclient.GetSpecFactoryFromJa3String(
		ja3,
		[]string{
			"ECDSAWithP256AndSHA256",
			"PSSWithSHA256",
			"PKCS1WithSHA256",
			"ECDSAWithP384AndSHA384",
			"PSSWithSHA384",
			"PKCS1WithSHA384",
			"PSSWithSHA512",
			"PKCS1WithSHA512",
		},
		nil,
		[]string{"GREASE", "1.3", "1.2"},
		[]string{"GREASE", "X25519", "P-256"},
		[]string{"h2", "http/1.1"},
		[]string{"h2"},
		[]tlsclient.CandidateCipherSuites{
			{KdfId: "HKDF_SHA256", AeadId: "AEAD_AES_128_GCM"},
			{KdfId: "HKDF_SHA256", AeadId: "AEAD_CHACHA20_POLY1305"},
		},
		[]uint16{128, 160, 192, 224},
		[]string{"brotli"},
		0,
	)
	if err != nil {
		return profiles.ClientProfile{}, fmt.Errorf("%w: %v", ErrInvalidJA3, err)
	}
	customID := tls.ClientHelloID{
		Client:      "tls-proxy",
		Version:     "custom-ja3",
		SpecFactory: specFactory,
	}
	return profiles.NewClientProfile(
		customID,
		chromeLikeSettings,
		chromeLikeSettingsOrder,
		pseudoHeaderOrder,
		connectionFlow,
		nil, nil, 0, false,
		nil, nil, 0, nil, false,
	), nil
}

// Get returns a cached (or newly created) tls-client matching the TLS config.
func (f *ClientFactory) Get(cfg *TLSConfig) (tlsclient.HttpClient, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	key := cacheKey(cfg)
	if c, ok := f.clients[key]; ok {
		return c, nil
	}

	c, err := newTLSClient(cfg)
	if err != nil {
		return nil, err
	}
	f.clients[key] = c
	return c, nil
}

func (f *ClientFactory) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.clients {
		c.CloseIdleConnections()
	}
	f.clients = make(map[string]tlsclient.HttpClient)
}

func newTLSClient(cfg *TLSConfig) (tlsclient.HttpClient, error) {
	if cfg == nil {
		cfg = &TLSConfig{}
	}

	profile, err := ResolveProfile(cfg.ClientIdentifier, cfg.JA3String)
	if err != nil {
		return nil, err
	}

	opts := []tlsclient.HttpClientOption{
		tlsclient.WithClientProfile(profile),
		tlsclient.WithRandomTLSExtensionOrder(),
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeoutSeconds
	}
	opts = append(opts, tlsclient.WithTimeoutSeconds(timeout))

	if cfg.ProxyURL != "" {
		if err := validateProxyURL(cfg.ProxyURL); err != nil {
			return nil, err
		}
		opts = append(opts, tlsclient.WithProxyUrl(cfg.ProxyURL))
	}

	if cfg.InsecureSkipVerify {
		opts = append(opts, tlsclient.WithInsecureSkipVerify())
	}

	if cfg.DisableRedirects {
		opts = append(opts, tlsclient.WithNotFollowRedirects())
	}

	if cfg.ForceHTTP1 {
		opts = append(opts, tlsclient.WithForceHttp1())
	}

	if cfg.DisableHTTP3 {
		opts = append(opts, tlsclient.WithDisableHttp3())
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}
	opts = append(opts, tlsclient.WithCookieJar(jar))

	return tlsclient.NewHttpClient(tlsclient.NewNoopLogger(), opts...)
}

func validateProxyURL(raw string) error {
	if !strings.Contains(raw, "://") {
		return fmt.Errorf("%w: %s", ErrInvalidProxyURL, raw)
	}
	return nil
}

func cacheKey(cfg *TLSConfig) string {
	if cfg == nil {
		cfg = &TLSConfig{}
	}
	return strings.Join([]string{
		cfg.ClientIdentifier,
		cfg.JA3String,
		cfg.ProxyURL,
		fmt.Sprintf("%d", cfg.Timeout),
		fmt.Sprintf("%t", cfg.InsecureSkipVerify),
		fmt.Sprintf("%t", cfg.DisableRedirects),
		fmt.Sprintf("%t", cfg.ForceHTTP1),
		fmt.Sprintf("%t", cfg.DisableHTTP3),
	}, "|")
}

// buildFHTTPRequest converts a JSON request payload into an fhttp request.
func buildFHTTPRequest(p *RequestPayload) (*fhttp.Request, error) {
	req, err := fhttp.NewRequest(p.Method(), p.Request.URL, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range p.Request.Headers {
		req.Header.Set(k, v)
	}

	if p.Request.Body != "" {
		req.Body = io.NopCloser(strings.NewReader(p.Request.Body))
		req.ContentLength = int64(len(p.Request.Body))
		if _, ok := p.Request.Headers["Content-Length"]; !ok {
			req.Header.Set("Content-Length", fmt.Sprintf("%d", len(p.Request.Body)))
		}
	}

	q := req.URL.Query()
	for k, v := range p.Request.QueryParams {
		q.Set(k, v)
	}
	req.URL.RawQuery = q.Encode()

	return req, nil
}

// DefaultClient returns a cached client built from the given identifier,
// used by the standard proxy mode when the caller does not supply a profile.
func (f *ClientFactory) DefaultClient(timeout int, proxyURL string) (tlsclient.HttpClient, error) {
	return f.Get(&TLSConfig{
		ClientIdentifier: DefaultProfile,
		Timeout:          timeout,
		ProxyURL:         proxyURL,
	})
}
