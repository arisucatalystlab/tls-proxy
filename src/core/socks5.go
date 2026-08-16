package core

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// SOCKS5Proxy is an opt-in SOCKS5 proxy server. It lets standard SOCKS5
// clients (e.g. axios via socks-proxy-agent) route TCP traffic through the
// server; the outbound leg optionally tunnels through the configured upstream
// proxy (http/https or socks5/socks5h). Disabled by default so serverless
// platforms (e.g. Vercel) do not expose an open proxy.
type SOCKS5Proxy struct {
	Timeout       int
	UpstreamProxy string
	APIKeys       []string
	mu            sync.Mutex
	listener      net.Listener
}

func NewSOCKS5Proxy(cfg ServerConfig) *SOCKS5Proxy {
	return &SOCKS5Proxy{
		Timeout:       cfg.DefaultTimeout,
		UpstreamProxy: cfg.UpstreamProxy,
		APIKeys:       cfg.APIKeys,
	}
}

func (s *SOCKS5Proxy) Serve(laddr string) error {
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	log.Printf("socks5 proxy listening on %s", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *SOCKS5Proxy) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Addr returns the bound listener address once Serve is running.
func (s *SOCKS5Proxy) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

const (
	socks5Version     = 0x05
	socks5CmdConnect  = 0x01
	socks5AtypIPv4    = 0x01
	socks5AtypDomain  = 0x03
	socks5AtypIPv6    = 0x04
	socks5NoAuth      = 0x00
	socks5UserPass    = 0x02
	socks5NoMethods   = 0xff
	socks5AuthVersion = 0x01
)

var (
	errSOCKS5BadVersion = errors.New("socks5: unsupported version")
	errSOCKS5NoMethods  = errors.New("socks5: no acceptable authentication method")
	errSOCKS5AuthFailed = errors.New("socks5: authentication failed")
	errSOCKS5BadRequest = errors.New("socks5: malformed request")
)

// handle processes a single SOCKS5 client connection.
func (s *SOCKS5Proxy) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(time.Duration(s.Timeout) * time.Second))
	br := bufio.NewReader(conn)
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	if err := s.negotiateAuth(br, conn); err != nil {
		log.Printf("socks5 handshake failed from %s: %v", conn.RemoteAddr(), err)
		return
	}

	target, err := readSOCKS5Request(br)
	if err != nil {
		log.Printf("socks5 request failed from %s: %v", conn.RemoteAddr(), err)
		return
	}

	out, err := s.dialTarget(target)
	if err != nil {
		log.Printf("socks5 CONNECT %q from %s failed: %v", target, conn.RemoteAddr(), err)
		_, _ = writeSOCKS5Reply(conn, 0x05)
		return
	}
	defer func() { _ = out.Close() }()

	if _, err := writeSOCKS5Reply(conn, 0x00); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(out, conn)
		_ = out.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, out)
		_ = conn.Close()
		done <- struct{}{}
	}()
	<-done
}

// negotiateAuth performs the SOCKS5 greeting and (when API keys are set)
// username/password authentication. The password must match an API key.
func (s *SOCKS5Proxy) negotiateAuth(br *bufio.Reader, conn net.Conn) error {
	version, err := br.ReadByte()
	if err != nil {
		return err
	}
	if version != socks5Version {
		return errSOCKS5BadVersion
	}

	nmethods, err := br.ReadByte()
	if err != nil {
		return err
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}

	needAuth := len(s.APIKeys) > 0
	if !needAuth {
		for _, m := range methods {
			if m == socks5NoAuth {
				if _, err := conn.Write([]byte{socks5Version, socks5NoAuth}); err != nil {
					return err
				}
				return nil
			}
		}
		if _, err := conn.Write([]byte{socks5Version, socks5NoMethods}); err != nil {
			return err
		}
		return errSOCKS5NoMethods
	}

	for _, m := range methods {
		if m == socks5UserPass {
			if _, err := conn.Write([]byte{socks5Version, socks5UserPass}); err != nil {
				return err
			}
			if err := s.authenticateUserPass(br, conn); err != nil {
				return err
			}
			return nil
		}
	}
	if _, err := conn.Write([]byte{socks5Version, socks5NoMethods}); err != nil {
		return err
	}
	return errSOCKS5NoMethods
}

func (s *SOCKS5Proxy) authenticateUserPass(br *bufio.Reader, conn net.Conn) error {
	version, err := br.ReadByte()
	if err != nil {
		return err
	}
	if version != socks5AuthVersion {
		return errSOCKS5BadVersion
	}
	ulen, err := br.ReadByte()
	if err != nil {
		return err
	}
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(br, uname); err != nil {
		return err
	}
	plen, err := br.ReadByte()
	if err != nil {
		return err
	}
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(br, passwd); err != nil {
		return err
	}

	ok := false
	for _, k := range s.APIKeys {
		if subtle.ConstantTimeCompare(passwd, []byte(k)) == 1 {
			ok = true
			break
		}
	}
	if !ok {
		_, _ = conn.Write([]byte{socks5AuthVersion, 0x01})
		return errSOCKS5AuthFailed
	}
	_, err = conn.Write([]byte{socks5AuthVersion, 0x00})
	return err
}

// readSOCKS5Request parses a CONNECT request and returns the target host:port.
func readSOCKS5Request(br *bufio.Reader) (string, error) {
	version, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	if version != socks5Version {
		return "", errSOCKS5BadVersion
	}
	cmd, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	if cmd != socks5CmdConnect {
		return "", fmt.Errorf("socks5: unsupported command 0x%02x", cmd)
	}
	if _, err := br.ReadByte(); err != nil { // RSV
		return "", err
	}
	atyp, err := br.ReadByte()
	if err != nil {
		return "", err
	}

	var host string
	switch atyp {
	case socks5AtypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case socks5AtypDomain:
		n, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		host = string(buf)
	case socks5AtypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	default:
		return "", errSOCKS5BadRequest
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// writeSOCKS5Reply sends a CONNECT reply using an IPv4 zero address.
func writeSOCKS5Reply(conn net.Conn, rep byte) (int, error) {
	buf := []byte{socks5Version, rep, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}
	return conn.Write(buf)
}

// dialTarget opens a raw TCP connection to the target, tunneling through the
// configured upstream proxy when one is set (http/https or socks5/socks5h).
func (s *SOCKS5Proxy) dialTarget(target string) (net.Conn, error) {
	return dialTargetWith(context.Background(), target, s.UpstreamProxy, time.Duration(s.Timeout)*time.Second)
}

// dialTargetWith opens a raw TCP connection to target, optionally tunneling
// through an upstream proxy (http/https or socks5/socks5h).
func dialTargetWith(ctx context.Context, target, upstream string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}

	if upstream == "" {
		return dialer.DialContext(ctx, "tcp", target)
	}

	u, err := url.Parse(upstream)
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
		if cd, ok := sd.(proxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", target)
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

// IsUpstreamProxy reports whether the given string looks like a proxy URL.
func IsUpstreamProxy(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme != "" && u.Host != ""
}
