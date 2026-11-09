package gft

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"time"
)

// TLSConfigFor builds a client TLS config that authenticates the server ONLY by
// SHA-256 fingerprint pinning of the leaf certificate (self-signed servers).
// A pin is mandatory: a link without a valid pin is rejected.
func TLSConfigFor(l *Link) (*tls.Config, error) {
	want, err := hex.DecodeString(l.Pin)
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("invalid pin")
	}
	sni := l.SNI
	if sni == "" && net.ParseIP(l.Host) == nil {
		sni = l.Host
	}
	return &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
		// Standard Go pattern for fingerprint pinning: chain verification is replaced by the
		// mandatory pin comparison in VerifyConnection below (the connection fails without a match).
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(sum[:], want) != 1 {
				return errors.New("certificate pin mismatch")
			}
			return nil
		},
	}, nil
}

// PinOf returns the hex SHA-256 pin of a certificate.
func PinOf(c *x509.Certificate) string { s := sha256.Sum256(c.Raw); return hex.EncodeToString(s[:]) }

// DialKnock performs TCP+TLS1.3 (pinned) and sends the Knock Frame.
// It returns the raw TLS conn and the time spent in the TLS handshake.
func DialKnock(ctx context.Context, l *Link, timeout time.Duration) (*tls.Conn, time.Duration, error) {
	psk, err := l.PSKBytes()
	if err != nil {
		return nil, 0, err
	}
	cfg, err := TLSConfigFor(l)
	if err != nil {
		return nil, 0, err
	}
	d := net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(l.Host, strconv.Itoa(l.Port)))
	if err != nil {
		return nil, 0, err
	}
	tc := tls.Client(raw, cfg)
	t0 := time.Now()
	_ = tc.SetDeadline(time.Now().Add(timeout))
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, 0, err
	}
	hs := time.Since(t0)
	if _, err := tc.Write(BuildKnock(psk, time.Now())); err != nil {
		_ = raw.Close()
		return nil, 0, err
	}
	_ = tc.SetDeadline(time.Time{})
	return tc, hs, nil
}

// DialSession connects and starts a client session (read loop running).
func DialSession(ctx context.Context, l *Link, ps *ParamStore, timeout time.Duration) (*Session, time.Duration, error) {
	tc, hs, err := DialKnock(ctx, l, timeout)
	if err != nil {
		return nil, 0, err
	}
	s := NewSession(tc, true, ps, nil)
	s.SetOnParam(func(p Params) { ps.Set(p) })
	go func() { _ = s.Run() }()
	return s, hs, nil
}

// PingResult holds real handshake + knock round-trip latencies.
type PingResult struct {
	Handshake time.Duration // TCP connect excluded; TLS 1.3 handshake time
	KnockRTT  time.Duration // knock sent -> echo response received
	Total     time.Duration
}

// Ping dials a fresh connection, knocks, and measures an echo round trip.
func Ping(ctx context.Context, l *Link, timeout time.Duration) (PingResult, error) {
	t0 := time.Now()
	ps := NewParamStore(DefaultParams())
	if l.Params != nil {
		ps.Set(*l.Params)
	}
	tc, hs, err := DialKnock(ctx, l, timeout)
	if err != nil {
		return PingResult{}, err
	}
	s := NewSession(tc, true, ps, nil)
	defer s.Close()
	got := make(chan time.Duration, 1)
	s.SetOnPing(func(d time.Duration) {
		select {
		case got <- d:
		default:
		}
	})
	go func() { _ = s.Run() }()
	if err := s.SendPingReq(); err != nil {
		return PingResult{}, err
	}
	select {
	case d := <-got:
		return PingResult{Handshake: hs, KnockRTT: d, Total: time.Since(t0)}, nil
	case <-time.After(timeout):
		return PingResult{}, errors.New("knock echo timeout")
	case <-ctx.Done():
		return PingResult{}, ctx.Err()
	}
}
