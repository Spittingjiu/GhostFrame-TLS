package client

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"ghostframe/internal/gft"
)

// HTTPProxyServer handles incoming HTTP and HTTPS (CONNECT) proxy requests.
type HTTPProxyServer struct {
	addr     string
	engine   *Engine
	listener net.Listener
	closed   chan struct{}
	mu       sync.Mutex
}

// NewHTTPProxyServer creates a new HTTP proxy server instance.
func NewHTTPProxyServer(addr string, eng *Engine) *HTTPProxyServer {
	return &HTTPProxyServer{
		addr:   addr,
		engine: eng,
		closed: make(chan struct{}),
	}
}

// Start begins listening and serving connections.
func (s *HTTPProxyServer) Start() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-s.closed:
					return
				default:
					time.Sleep(50 * time.Millisecond)
					continue
				}
			}
			go s.handleConn(c)
		}
	}()
	return nil
}

// Addr returns the listener address.
func (s *HTTPProxyServer) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Close stops the HTTP proxy server.
func (s *HTTPProxyServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:
		return nil
	default:
		close(s.closed)
	}
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *HTTPProxyServer) handleConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	sess := s.engine.ActiveSession()
	if sess == nil {
		s.engine.Logf("[HTTP Proxy] Rejecting %s %s: not connected", req.Method, req.Host)
		resp := "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nGhostFrame not connected to server\r\n"
		_, _ = c.Write([]byte(resp))
		return
	}

	if req.Method == http.MethodConnect {
		// HTTPS Tunnel: CONNECT host:port HTTP/1.1
		target := req.Host
		if !strings.Contains(target, ":") {
			target += ":443"
		}

		st, err := sess.OpenStream(target, nil)
		if err != nil {
			s.engine.Logf("[HTTP Proxy] CONNECT %s failed: %v", target, err)
			_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer st.Close()

		if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}

		_ = c.SetDeadline(time.Time{})
		s.engine.Logf("[HTTP Proxy] Tunneling HTTPS %s -> %s", c.RemoteAddr(), target)
		gft.Relay(st, c, 15*time.Minute)
		return
	}

	// Plain HTTP Request
	target := req.Host
	if !strings.Contains(target, ":") {
		target += ":80"
	}

	// Prepare request to write through stream
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	var reqBuf bytes.Buffer
	if err := req.Write(&reqBuf); err != nil {
		return
	}

	// 0-RTT: Send request header + initial body
	st, err := sess.OpenStream(target, reqBuf.Bytes())
	if err != nil {
		s.engine.Logf("[HTTP Proxy] %s %s failed: %v", req.Method, target, err)
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer st.Close()

	_ = c.SetDeadline(time.Time{})
	s.engine.Logf("[HTTP Proxy] Forwarding HTTP %s %s -> %s", req.Method, req.URL.Path, target)
	gft.Relay(st, c, 15*time.Minute)
}

var _ = fmt.Sprintf
var _ = io.Copy
