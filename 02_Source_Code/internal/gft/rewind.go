package gft

import "net"

// RewindConn wraps a net.Conn, recording every byte read so that, after a failed
// knock, the bytes can be replayed to the fallback web server before it continues
// reading from the original connection.
type RewindConn struct {
	net.Conn
	rec       []byte
	recording bool
	replaying bool
	pos       int
}

func NewRewindConn(c net.Conn) *RewindConn {
	return &RewindConn{Conn: c, recording: true}
}

func (r *RewindConn) Read(p []byte) (int, error) {
	if r.replaying {
		n := copy(p, r.rec[r.pos:])
		r.pos += n
		if r.pos >= len(r.rec) {
			r.rec, r.pos, r.replaying = nil, 0, false
		}
		return n, nil
	}
	n, err := r.Conn.Read(p)
	if r.recording && n > 0 {
		r.rec = append(r.rec, p[:n]...)
	}
	return n, err
}

// Rewind stops recording and arranges for the recorded bytes to be re-read first.
func (r *RewindConn) Rewind() {
	r.recording = false
	r.pos = 0
	r.replaying = len(r.rec) > 0
}

// StopRecording discards the recorded bytes (knock succeeded).
func (r *RewindConn) StopRecording() {
	r.recording = false
	r.rec = nil
	r.pos = 0
	r.replaying = false
}

// Recorded returns the number of recorded bytes (testing).
func (r *RewindConn) Recorded() int { return len(r.rec) }

// RecordedBytes returns a copy of the recorded bytes.
func (r *RewindConn) RecordedBytes() []byte { return r.rec }
