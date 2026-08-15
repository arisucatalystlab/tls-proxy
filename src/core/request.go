package core

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

type RequestHandler struct {
	Factory         *ClientFactory
	MaxBodySize     int64
	MaxResponseSize int64
}

func NewRequestHandler(factory *ClientFactory, maxBody, maxResponse int64) *RequestHandler {
	return &RequestHandler{
		Factory:         factory,
		MaxBodySize:     maxBody,
		MaxResponseSize: maxResponse,
	}
}

func (h *RequestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"error": "method not allowed, use POST",
		})
		return
	}

	body := r.Body
	if h.MaxBodySize > 0 {
		body = http.MaxBytesReader(w, r.Body, h.MaxBodySize)
	}
	raw, err := io.ReadAll(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "failed to read request body: " + err.Error(),
		})
		return
	}

	var payload RequestPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid JSON payload: " + err.Error(),
		})
		return
	}

	if err := payload.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	resp, err := h.execute(&payload)
	if err != nil {
		log.Printf("request failed url=%s err=%v", payload.Request.URL, err)
		writeJSON(w, http.StatusBadGateway, map[string]string{
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func (h *RequestHandler) execute(p *RequestPayload) (*ResponsePayload, error) {
	client, err := h.Factory.Get(p.TLSConfig)
	if err != nil {
		return nil, err
	}

	req, err := buildFHTTPRequest(p)
	if err != nil {
		return nil, err
	}

	fresp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fresp.Body.Close() }()

	var sb strings.Builder
	limited := io.LimitReader(fresp.Body, h.MaxResponseSize)
	buf := make([]byte, 32*1024)
	for {
		n, rerr := limited.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}

	headers := make(map[string]string, len(fresp.Header))
	for k, v := range fresp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	cookies := make(map[string]string)
	for _, sc := range fresp.Header.Values("Set-Cookie") {
		parts := strings.SplitN(sc, ";", 2)
		kv := strings.SplitN(parts[0], "=", 2)
		if len(kv) == 2 {
			cookies[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}

	return &ResponsePayload{
		StatusCode: fresp.StatusCode,
		Headers:    headers,
		Cookies:    cookies,
		Body:       sb.String(),
	}, nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
