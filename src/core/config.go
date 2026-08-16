package core

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	EnvPort            = "TLS_PROXY_PORT"
	EnvAPIKey          = "TLS_PROXY_API_KEY" // #nosec G101 -- env var name, not a credential
	EnvDefaultProfile  = "TLS_PROXY_DEFAULT_PROFILE"
	EnvDefaultTimeout  = "TLS_PROXY_DEFAULT_TIMEOUT"
	EnvMaxBodySize     = "TLS_PROXY_MAX_BODY_SIZE"
	EnvMaxResponseSize = "TLS_PROXY_MAX_RESPONSE_SIZE"
	EnvLogLevel        = "TLS_PROXY_LOG_LEVEL"
	EnvReadTimeout     = "TLS_PROXY_READ_TIMEOUT"
	EnvWriteTimeout    = "TLS_PROXY_WRITE_TIMEOUT"
	EnvUpstreamProxy   = "TLS_PROXY_UPSTREAM_PROXY"
)

type ServerConfig struct {
	Port            string
	APIKeys         []string
	DefaultProfile  string
	DefaultTimeout  int
	MaxBodySize     int64
	MaxResponseSize int64
	LogLevel        string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	UpstreamProxy   string
}

func ConfigFromEnv() ServerConfig {
	return ServerConfig{
		Port:            envOr(EnvPort, envOr("PORT", "8080")),
		APIKeys:         splitComma(envOr(EnvAPIKey, "")),
		DefaultProfile:  envOr(EnvDefaultProfile, "chrome_120"),
		DefaultTimeout:  envIntOr(EnvDefaultTimeout, 30),
		MaxBodySize:     envInt64Or(EnvMaxBodySize, 10*1024*1024),
		MaxResponseSize: envInt64Or(EnvMaxResponseSize, 20*1024*1024),
		LogLevel:        envOr(EnvLogLevel, "info"),
		ReadTimeout:     time.Duration(envInt64Or(EnvReadTimeout, 30)) * time.Second,
		WriteTimeout:    time.Duration(envInt64Or(EnvWriteTimeout, 60)) * time.Second,
		UpstreamProxy:   envOr(EnvUpstreamProxy, ""),
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOr(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envInt64Or(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
