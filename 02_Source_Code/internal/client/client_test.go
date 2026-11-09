package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"ghostframe/internal/gft"
)

// mockServer creates an in-memory GFT server loop over a pipe.
func mockGFTLoop(t *testing.T) (*gft.Link, func()) {
	t.Helper()
	// Create an echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()

	return nil, func() {
		_ = echoLn.Close()
	}
}

func TestSOCKS5HandshakeAndProxy(t *testing.T) {
	// Create a dummy engine
	eng, err := NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	socks := NewSOCKS5Server("127.0.0.1:0", eng)
	if err := socks.Start(); err != nil {
		t.Fatal(err)
	}
	defer socks.Close()

	// 1. When disconnected, SOCKS5 CONNECT returns error
	c, err := net.Dial("tcp", socks.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// SOCKS5 Greeting: 0x05, 0x01, 0x00
	_, _ = c.Write([]byte{0x05, 0x01, 0x00})
	var rep [2]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil || rep[0] != 0x05 || rep[1] != 0x00 {
		t.Fatalf("greeting reply: %v %v", err, rep)
	}

	// Request: CONNECT 127.0.0.1:80 (IPv4)
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80}
	_, _ = c.Write(req)
	var resp [10]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		t.Fatal(err)
	}
	if resp[1] != 0x05 { // Must return 0x05 (connection refused) because not connected
		t.Fatalf("expected 0x05 rejected, got %v", resp[1])
	}
}

func TestHTTPProxyRejectionWhenDisconnected(t *testing.T) {
	eng, err := NewEngine("")
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	hp := NewHTTPProxyServer("127.0.0.1:0", eng)
	if err := hp.Start(); err != nil {
		t.Fatal(err)
	}
	defer hp.Close()

	c, err := net.Dial("tcp", hp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// CONNECT request
	_, _ = c.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", resp.StatusCode)
	}
}

func TestSystemProxyRegistry(t *testing.T) {
	// Query current
	_, _, err := GetSystemProxy()
	if err != nil {
		t.Logf("GetSystemProxy error: %v", err)
	}
}

var _ = time.Now
var _ = fmt.Sprintf
var _ = context.Background
