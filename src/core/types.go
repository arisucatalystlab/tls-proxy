package core

import (
	"errors"
	"net/http"
	"strings"
)

type TLSConfig struct {
	ClientIdentifier   string `json:"client_identifier"`
	JA3String          string `json:"ja3_string"`
	ProxyURL           string `json:"proxy_url"`
	Timeout            int    `json:"timeout"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
	DisableRedirects   bool   `json:"disable_redirects"`
	ForceHTTP1         bool   `json:"force_http1"`
	DisableHTTP3       bool   `json:"disable_http3"`
}

type RequestPayload struct {
	TLSConfig *TLSConfig   `json:"tls_config"`
	Request   *HTTPRequest `json:"request"`
}

type HTTPRequest struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	QueryParams map[string]string `json:"query_params"`
	Body        string            `json:"body"`
}

type ResponsePayload struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Cookies    map[string]string `json:"cookies"`
	Body       string            `json:"body"`
}

func (p *RequestPayload) Validate() error {
	if p == nil {
		return errors.New("missing request payload")
	}
	if p.Request == nil {
		return errors.New("missing request object")
	}
	if p.Request.URL == "" {
		return errors.New("missing request.url")
	}
	return nil
}

func (p *RequestPayload) Method() string {
	m := strings.ToUpper(strings.TrimSpace(p.Request.Method))
	if m == "" {
		return http.MethodGet
	}
	return m
}

func (p *RequestPayload) Timeout() int {
	if p.TLSConfig == nil || p.TLSConfig.Timeout <= 0 {
		return DefaultTimeoutSeconds
	}
	return p.TLSConfig.Timeout
}

func (p *RequestPayload) ClientIdentifier() string {
	if p.TLSConfig != nil && p.TLSConfig.ClientIdentifier != "" {
		return p.TLSConfig.ClientIdentifier
	}
	return DefaultProfile
}

func (p *RequestPayload) ProxyURL() string {
	if p.TLSConfig != nil {
		return p.TLSConfig.ProxyURL
	}
	return ""
}
