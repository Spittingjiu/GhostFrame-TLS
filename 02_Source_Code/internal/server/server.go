package server

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"ghostframe/internal/gft"
)

// Server is the GhostFrame-TLS server: one TCP port, TLS 1.3, knock -> proxy, otherwise -> web fallback.
type Server struct {
	cfg      *Config
	psk      []byte
	verifier *gft.KnockVerifier
	params   *gft.ParamStore
	audit    *Audit
	stats    *Stats
	panel    *Panel
	web      http.Handler
	fallback *chanListener
	started  time.Time

	smu      sync.Mutex
	sessions map[uint64]*sessEntry
	nextSess atomic.Uint64
	logger   *log.Logger
}

type sessEntry struct {
	ID    uint64
	IP    string
	Since time.Time
	Sess  *gft.Session
}

func New(cfg *Config, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	psk, err := base64.StdEncoding.DecodeString(cfg.PSK)
	if err != nil || len(psk) < 16 {
		return nil, errors.New("bad psk in config")
	}
	s := &Server{cfg: cfg, psk: psk, verifier: gft.NewKnockVerifier(psk), sessions: map[uint64]*sessEntry{},
		started: time.Now(), logger: logger}
	s.params = gft.NewParamStore(s.loadParams())
	s.audit = NewAudit(filepath.Join(cfg.StateDir, "audit.json"))
	s.stats = NewStats()
	s.fallback = newChanListener()
	s.panel = newPanel(s)
	s.web = s.buildRouter()
	return s, nil
}

func (s *Server) loadParams() gft.Params {
	p := gft.DefaultParams()
	if b, err := os.ReadFile(filepath.Join(s.cfg.StateDir, "params.json")); err == nil {
		var q gft.Params
		if json.Unmarshal(b, &q) == nil && q.Validate() == nil {
			p = q
		}
	}
	return p
}

func (s *Server) saveParams(p gft.Params) {
	b, _ := json.Marshal(p)
	_ = os.WriteFile(filepath.Join(s.cfg.StateDir, "params.json"), b, 0o600)
}

// Run serves until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
	if err != nil {
		return err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	s.logger.Printf("listening on %s (TLS1.3)", ln.Addr())

	var protos http.Protocols
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	hs := &http.Server{
		Handler:           s.web,
		Protocols:         &protos,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); _ = hs.Serve(s.fallback) }()
	go func() { // housekeeping
		defer wg.Done()
		t := time.NewTicker(time.Second)
		defer t.Stop()
		n := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.stats.Sample()
				n++
				if n%30 == 0 {
					s.verifier.Sweep(time.Now())
					s.audit.Flush()
					s.panel.sweep()
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = ln.Close()
		_ = hs.Close()
		s.fallback.Close()
		s.closeAllSessions()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			if errors.Is(err, net.ErrClosed) {
				break
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go s.handle(ctx, c, tlsCfg)
	}
	wg.Wait()
	s.audit.Flush()
	return nil
}

func (s *Server) closeAllSessions() {
	s.smu.Lock()
	for _, e := range s.sessions {
		e.Sess.Close()
	}
	s.smu.Unlock()
}

func remoteIP(c net.Conn) string {
	h, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return h
}

func isHTTP(b []byte) bool {
	methods := []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "TRACE ", "PATCH ", "CONNECT ", "PRI "}
	for _, m := range methods {
		if len(b) >= len(m) && strings.HasPrefix(string(b), m) {
			return true
		}
		if len(b) < len(m) && strings.HasPrefix(m, string(b)) {
			return true
		}
	}
	return false
}

func (s *Server) handle(ctx context.Context, raw net.Conn, tlsCfg *tls.Config) {
	ip := remoteIP(raw)
	if s.audit.IsBanned(ip) {
		_ = raw.Close()
		return
	}
	tc := tls.Server(raw, tlsCfg)
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		return
	}
	_ = tc.SetDeadline(time.Time{})
	rc := gft.NewRewindConn(tc)
	res := s.verifier.ServerKnock(rc)
	if res != gft.KnockOK {
		s.audit.Record(ip, res.String())
		s.logger.Printf("knock fail ip=%s reason=%s -> fallback", ip, res)
		_ = rc.SetReadDeadline(time.Time{})
		if isHTTP(rc.RecordedBytes()) {
			rc.Rewind()
		} else {
			if rc.Recorded() >= 16 {
				pad := gft.PadLenFor(rc.RecordedBytes()[:16])
				if pad > 0 {
					var junk [64]byte
					_ = tc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					_, _ = io.ReadFull(tc, junk[:pad])
					_ = tc.SetReadDeadline(time.Time{})
				}
			}
			rc.StopRecording()
		}
		if !s.fallback.push(rc) {
			_ = rc.Close()
		}
		return
	}
	rc.StopRecording()
	s.serveSession(ctx, tc, ip)
}

func (s *Server) serveSession(ctx context.Context, tc *tls.Conn, ip string) {
	sess := gft.NewSession(tc, false, s.params, s.handleConnect)
	sess.OnBytes = s.stats.Add
	id := s.nextSess.Add(1)
	s.smu.Lock()
	s.sessions[id] = &sessEntry{ID: id, IP: ip, Since: time.Now(), Sess: sess}
	s.smu.Unlock()
	s.logger.Printf("session %d opened from %s", id, ip)
	go func() { _ = sess.SendParams(s.params.Get()) }()
	_ = sess.Run()
	sess.Close()
	s.smu.Lock()
	delete(s.sessions, id)
	s.smu.Unlock()
	s.logger.Printf("session %d closed", id)
}

var errBlockedTarget = errors.New("blocked target")

// AllowPrivateTargets disables the loopback/private-address egress block (tests only).
var AllowPrivateTargets bool

func blockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast()
}

func (s *Server) handleConnect(st *gft.Stream, target string, first []byte) {
	d := net.Dialer{Timeout: 10 * time.Second, Control: func(network, address string, _ syscall.RawConn) error {
		h, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		if ip := net.ParseIP(h); ip == nil || (blockedIP(ip) && !AllowPrivateTargets) {
			return errBlockedTarget
		}
		return nil
	}}
	c, err := d.Dial("tcp", target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DEBUG DIAL FAILED: target=%s err=%v AllowPrivate=%v\n", target, err, AllowPrivateTargets)
		s.logger.Printf("handleConnect dial %s failed: %v", target, err)
		_ = st.Close()
		return
	}
	if len(first) > 0 {
		if _, err := c.Write(first); err != nil {
			_ = c.Close()
			_ = st.Close()
			return
		}
	}
	gft.Relay(st, c, 15*time.Minute)
}

// ---- fallback listener --------------------------------------------------------

type chanListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newChanListener() *chanListener {
	return &chanListener{ch: make(chan net.Conn, 256), done: make(chan struct{})}
}

func (l *chanListener) push(c net.Conn) bool {
	select {
	case l.ch <- c:
		return true
	default:
		return false
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error { l.once.Do(func() { close(l.done) }); return nil }
func (l *chanListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

// Handler exposes the fallback web handler (used by tests).
func (s *Server) Handler() http.Handler { return s.web }

// Verifier exposes the knock verifier (tests).
func (s *Server) Verifier() *gft.KnockVerifier { return s.verifier }
