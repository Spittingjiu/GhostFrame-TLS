// Package gft implements the GhostFrame-TLS protocol primitives:
// Knock Frame, RewindConn, Ghost Data Frames and the stream multiplexer.
package gft

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	KnockLen       = 16 + 8 + 32 // nonce + timestamp + hmac
	KnockWindow    = 90 * time.Second
	KnockReplayTTL = 180 * time.Second
	KnockTimeout   = 3 * time.Second
	knockMaxCache  = 200000
)

// KnockResult is the outcome of knock verification.
type KnockResult int

const (
	KnockOK KnockResult = iota
	KnockBadHMAC
	KnockExpired
	KnockReplay
	KnockTimeoutFail
	KnockIncomplete
)

func (r KnockResult) String() string {
	switch r {
	case KnockOK:
		return "ok"
	case KnockBadHMAC:
		return "hmac"
	case KnockExpired:
		return "expired"
	case KnockReplay:
		return "replay"
	case KnockTimeoutFail:
		return "timeout"
	case KnockIncomplete:
		return "incomplete"
	}
	return "unknown"
}

func knockMAC(psk, nonceTs []byte) [32]byte {
	m := hmac.New(sha256.New, psk)
	m.Write(nonceTs)
	var out [32]byte
	m.Sum(out[:0])
	return out
}

// PadLenFor returns the padding length encoded by a nonce.
func PadLenFor(nonce []byte) int { return int(nonce[15]) % 64 }

// BuildKnock builds a complete Knock Frame (including padding).
func BuildKnock(psk []byte, now time.Time) []byte {
	var hdr [24]byte
	_, _ = io.ReadFull(rand.Reader, hdr[:16])
	binary.BigEndian.PutUint64(hdr[16:], uint64(now.Unix()))
	mac := knockMAC(psk, hdr[:])
	n := PadLenFor(hdr[:16])
	out := make([]byte, KnockLen+n)
	copy(out, hdr[:])
	copy(out[24:], mac[:])
	if n > 0 {
		_, _ = io.ReadFull(rand.Reader, out[KnockLen:])
	}
	return out
}

// KnockVerifier validates Knock Frames and maintains the nonce replay cache.
type KnockVerifier struct {
	psk  []byte
	mu   sync.Mutex
	seen map[[16]byte]int64 // nonce -> expiry (unix nano)
}

func NewKnockVerifier(psk []byte) *KnockVerifier {
	return &KnockVerifier{psk: append([]byte(nil), psk...), seen: make(map[[16]byte]int64, 1024)}
}

// Check performs steps 2-4 (HMAC, time window, replay) on the 56 knock bytes.
// It returns the padding length to discard when OK. All MAC comparisons are constant time.
func (v *KnockVerifier) Check(buf []byte, now time.Time) (int, KnockResult) {
	if len(buf) < KnockLen {
		return 0, KnockIncomplete
	}
	mac := knockMAC(v.psk, buf[:24])
	macOK := hmac.Equal(mac[:], buf[24:KnockLen])
	ts := int64(binary.BigEndian.Uint64(buf[16:24]))
	d := now.Unix() - ts
	if d < 0 {
		d = -d
	}
	timeOK := d <= int64(KnockWindow/time.Second)
	if !macOK {
		return 0, KnockBadHMAC
	}
	if !timeOK {
		return 0, KnockExpired
	}
	var nonce [16]byte
	copy(nonce[:], buf[:16])
	nowN := now.UnixNano()
	v.mu.Lock()
	defer v.mu.Unlock()
	if exp, ok := v.seen[nonce]; ok && exp > nowN {
		return 0, KnockReplay
	}
	if len(v.seen) >= knockMaxCache {
		v.sweepLocked(nowN)
		if len(v.seen) >= knockMaxCache {
			return 0, KnockReplay // cache saturated: refuse rather than lose replay protection
		}
	}
	v.seen[nonce] = nowN + int64(KnockReplayTTL)
	return PadLenFor(nonce[:]), KnockOK
}

func (v *KnockVerifier) sweepLocked(nowN int64) {
	for k, exp := range v.seen {
		if exp <= nowN {
			delete(v.seen, k)
		}
	}
}

// Sweep removes expired nonces (call periodically).
func (v *KnockVerifier) Sweep(now time.Time) {
	v.mu.Lock()
	v.sweepLocked(now.UnixNano())
	v.mu.Unlock()
}

// CacheSize returns the replay cache size (testing/metrics).
func (v *KnockVerifier) CacheSize() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.seen)
}

// ServerKnock reads and verifies a Knock Frame from c (which should be a RewindConn so the
// bytes can be replayed on failure). It never writes to c.
func (v *KnockVerifier) ServerKnock(c net.Conn) KnockResult {
	_ = c.SetReadDeadline(time.Now().Add(KnockTimeout))
	var buf [KnockLen]byte
	if _, err := io.ReadFull(c, buf[:]); err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return KnockTimeoutFail
		}
		return KnockIncomplete
	}
	pad, res := v.Check(buf[:], time.Now())
	if res != KnockOK {
		return res
	}
	if pad > 0 {
		var junk [64]byte
		if _, err := io.ReadFull(c, junk[:pad]); err != nil {
			return KnockTimeoutFail
		}
	}
	_ = c.SetReadDeadline(time.Time{})
	return KnockOK
}
