package handler

import (
	"net/http"

	"tls-proxy/src/core"
)

var handler http.Handler

func init() {
	cfg := core.ConfigFromEnv()
	handler = core.NewHandler(cfg)
}

func Handler(w http.ResponseWriter, r *http.Request) {
	handler.ServeHTTP(w, r)
}
