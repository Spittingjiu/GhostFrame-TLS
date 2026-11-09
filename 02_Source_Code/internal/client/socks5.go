package client

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"ghostframe/internal/gft"
)

// SOCKS5Server handles incoming SOCKS5 requests and tunnels them via GFT engine.
type SOCKS5Server struct {
	addr     string
	engine   *Engine
	listener net.Listener
	closed   chan struct{}
	mu       sync.Mutex
}

// NewSOCKS5Server creates a new SOCKS5 server instance.
func NewSOCKS5Server(addr string, eng *Engine) *SOCKS5Server {
	return &SOCKS5Server{
		addr:   addr,
		engine: eng,
		closed: make(chan struct{}),
	}
}

// Start begins listening and serving connections.
func (s *SOCKS5Server) Start() error {
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
func (s *SOCKS5Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Close stops the server.
func (s *SOCKS5Server) Close() error {
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

func (s *SOCKS5Server) handleConn(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	// 1. Negotiation
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return
	}
	if head[0] != 0x05 {
		return // Not SOCKS5
	}
	nmethods := int(head[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}

	// Accept NO AUTH (0x00)
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// 2. Request
	var reqHead [4]byte
	if _, err := io.ReadFull(c, reqHead[:]); err != nil {
		return
	}
	if reqHead[0] != 0x05 || reqHead[1] != 0x01 { // Only CMD 0x01 (CONNECT) supported
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch reqHead[3] {
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	case 0x03: // FQDN
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return
		}
		domain := make([]byte, l[0])
		if _, err := io.ReadFull(c, domain); err != nil {
			return
		}
		host = string(domain)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(c, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	// Check if active session is available
	sess := s.engine.ActiveSession()
	if sess == nil {
		s.engine.Logf("[SOCKS5] Error: Not connected to GFT server, rejecting %s", target)
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	st, err := sess.OpenStream(target, nil)
	if err != nil {
		s.engine.Logf("[SOCKS5] OpenStream to %s failed: %v", target, err)
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer st.Close()

	// Success response
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	_ = c.SetDeadline(time.Time{})
	s.engine.Logf("[SOCKS5] Tunneling %s -> %s", c.RemoteAddr(), target)
	gft.Relay(st, c, 15*time.Minute)
}

var errNoActiveSession = errors.New("no active GFT session")
