package gft

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Ghost frame commands.
const (
	CmdConnect byte = 0x01
	CmdData    byte = 0x02
	CmdClose   byte = 0x03
	CmdPing    byte = 0x04
	CmdParam   byte = 0x05
	CmdWindow  byte = 0x06 // implementation extension: per-stream flow-control credit

	HeaderLen     = 6
	MaxPayload    = 65535
	maxChunk      = 16384
	streamWindow  = 256 * 1024
	windowUpdateN = 64 * 1024
	forcedPadN    = 5
)

// Ping payload markers (first payload byte). Noise heartbeats always use 0x00.
const (
	PingNoise byte = 0x00
	PingReq   byte = 0x01
	PingResp  byte = 0x02
)

var (
	ErrSessionClosed = errors.New("gft: session closed")
	ErrStreamClosed  = errors.New("gft: stream closed")
	ErrProtocol      = errors.New("gft: protocol violation")
)

// ConnectHandler is invoked (in its own goroutine) for every incoming CONNECT.
type ConnectHandler func(s *Stream, target string, first []byte)

// Session multiplexes streams over a single established (post-knock) connection.
type Session struct {
	conn     net.Conn
	isClient bool
	params   *ParamStore
	onParam  func(Params)
	onPing   func(rtt time.Duration)
	handler  ConnectHandler

	mu      sync.Mutex
	streams map[uint16]*Stream
	nextID  uint16

	wmu  sync.Mutex
	sent int

	done      chan struct{}
	closeOnce sync.Once
	err       atomic.Value // error

	pingMu   sync.Mutex
	pingSent time.Time

	UpBytes   atomic.Uint64      // payload bytes sent to peer
	DownBytes atomic.Uint64      // payload bytes received from peer
	OnBytes   func(up, down int) // optional global accounting
}

// NewSession creates a session; call Run to start the read loop.
func NewSession(c net.Conn, isClient bool, ps *ParamStore, h ConnectHandler) *Session {
	return &Session{conn: c, isClient: isClient, params: ps, handler: h,
		streams: make(map[uint16]*Stream), nextID: 1, done: make(chan struct{})}
}

func (s *Session) SetOnParam(f func(Params))       { s.onParam = f }
func (s *Session) SetOnPing(f func(time.Duration)) { s.onPing = f }
func (s *Session) Done() <-chan struct{}           { return s.done }
func (s *Session) Err() error {
	if e, ok := s.err.Load().(error); ok {
		return e
	}
	return nil
}

// Close tears down the session and all streams.
func (s *Session) Close() { s.fail(ErrSessionClosed) }

func (s *Session) fail(err error) {
	s.closeOnce.Do(func() {
		s.err.Store(err)
		close(s.done)
		_ = s.conn.Close()
		s.mu.Lock()
		for id, st := range s.streams {
			delete(s.streams, id)
			st.abort(err)
		}
		s.mu.Unlock()
	})
}

// StreamInfo is a snapshot of a stream for monitoring.
type StreamInfo struct {
	ID     uint16
	Target string
	Up     uint64
	Down   uint64
}

func (s *Session) StreamInfos() []StreamInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]StreamInfo, 0, len(s.streams))
	for _, st := range s.streams {
		out = append(out, StreamInfo{st.id, st.Target, st.Up.Load(), st.Down.Load()})
	}
	return out
}

func (s *Session) NumStreams() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.streams) }

// writeFrame serialises one frame (header|payload|padding) into a pooled buffer and writes it.
func (s *Session) writeFrame(cmd byte, id uint16, payload []byte) error {
	if len(payload) > MaxPayload {
		return ErrProtocol
	}
	select {
	case <-s.done:
		return ErrSessionClosed
	default:
	}
	p := s.params.Get()
	bp := GetBuf()
	buf := *bp
	s.wmu.Lock()
	pad := 0
	if s.sent < forcedPadN || rand.IntN(100) < p.PadProb {
		pad = randRange(p.PadMin, p.PadMax)
	}
	s.sent++
	buf[0] = cmd
	buf[1] = byte(pad)
	binary.BigEndian.PutUint16(buf[2:], uint16(len(payload)))
	binary.BigEndian.PutUint16(buf[4:], id)
	n := HeaderLen + copy(buf[HeaderLen:], payload)
	if pad > 0 {
		fillRandom(buf[n : n+pad])
		n += pad
	}
	_, err := s.conn.Write(buf[:n])
	s.wmu.Unlock()
	PutBuf(bp)
	if err != nil {
		s.fail(err)
		return err
	}
	return nil
}

// Run processes frames until the connection fails; it also runs the noise heartbeat.
func (s *Session) Run() error {
	go s.heartbeat()
	br := bufio.NewReaderSize(s.conn, 32*1024)
	var hdr [HeaderLen]byte
	bp := GetBuf()
	defer PutBuf(bp)
	payload := (*bp)[:MaxPayload]
	for {
		p := s.params.Get()
		_ = s.conn.SetReadDeadline(time.Now().Add(time.Duration(4*p.HbMaxMs+30000) * time.Millisecond))
		if _, err := io.ReadFull(br, hdr[:]); err != nil {
			s.fail(err)
			return err
		}
		cmd, pad := hdr[0], int(hdr[1])
		plen := int(binary.BigEndian.Uint16(hdr[2:]))
		id := binary.BigEndian.Uint16(hdr[4:])
		if s.isClient {
			// fmt.Printf("[Client Session] recv cmd=%d id=%d plen=%d pad=%d\n", cmd, id, plen, pad)
		}
		if plen > 0 {
			if _, err := io.ReadFull(br, payload[:plen]); err != nil {
				s.fail(err)
				return err
			}
		}
		if pad > 0 {
			if _, err := br.Discard(pad); err != nil {
				s.fail(err)
				return err
			}
		}
		if err := s.dispatch(cmd, id, payload[:plen]); err != nil {
			s.fail(err)
			return err
		}
	}
}

func (s *Session) dispatch(cmd byte, id uint16, pl []byte) error {
	switch cmd {
	case CmdConnect:
		if s.handler == nil {
			return ErrProtocol
		}
		target, rest, err := DecodeAddr(pl)
		if err != nil {
			_ = s.writeFrame(CmdClose, id, nil)
			return nil
		}
		s.mu.Lock()
		if _, dup := s.streams[id]; dup {
			s.mu.Unlock()
			return ErrProtocol
		}
		st := newStream(s, id)
		st.Target = target
		s.streams[id] = st
		s.mu.Unlock()
		var first []byte
		if len(rest) > 0 {
			first = append([]byte(nil), rest...)
		}
		go s.handler(st, target, first)
	case CmdData:
		s.mu.Lock()
		st := s.streams[id]
		s.mu.Unlock()
		s.DownBytes.Add(uint64(len(pl)))
		if s.OnBytes != nil {
			s.OnBytes(0, len(pl))
		}
		if st != nil {
			return st.push(pl)
		}
	case CmdClose:
		s.mu.Lock()
		st := s.streams[id]
		s.mu.Unlock()
		if st != nil {
			st.remoteClose()
		}
	case CmdWindow:
		if len(pl) >= 4 {
			s.mu.Lock()
			st := s.streams[id]
			s.mu.Unlock()
			if st != nil {
				st.addWindow(int64(binary.BigEndian.Uint32(pl)))
			}
		}
	case CmdPing:
		if len(pl) > 0 {
			switch pl[0] {
			case PingReq:
				return s.writeFrame(CmdPing, 0, []byte{PingResp})
			case PingResp:
				s.pingMu.Lock()
				t := s.pingSent
				s.pingMu.Unlock()
				if s.onPing != nil && !t.IsZero() {
					s.onPing(time.Since(t))
				}
			}
		}
		// noise heartbeats are silently dropped
	case CmdParam:
		if s.onParam != nil {
			if p, err := UnmarshalParams(pl); err == nil && p.Validate() == nil {
				s.onParam(p)
			}
		}
	default:
		// unknown commands are ignored for forward compatibility
	}
	return nil
}

// SendParams pushes the given params to the peer (PARAM_UPDATE).
func (s *Session) SendParams(p Params) error { return s.writeFrame(CmdParam, 0, MarshalParams(p)) }

// SendPingReq sends an echo request; the response triggers the onPing callback.
func (s *Session) SendPingReq() error {
	s.pingMu.Lock()
	s.pingSent = time.Now()
	s.pingMu.Unlock()
	return s.writeFrame(CmdPing, 0, []byte{PingReq})
}

func (s *Session) heartbeat() {
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	var noise [65]byte
	for {
		p := s.params.Get()
		d := time.Duration(randRange(p.HbMinMs, p.HbMaxMs)) * time.Millisecond
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(d)
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		n := rand.IntN(64) + 1
		fillRandom(noise[1 : 1+n])
		noise[0] = PingNoise
		if s.writeFrame(CmdPing, 0, noise[:1+n]) != nil {
			return
		}
	}
}

// OpenStream (client side) sends CONNECT for target, optionally with first data (0-RTT).
func (s *Session) OpenStream(target string, first []byte) (*Stream, error) {
	addr, err := EncodeAddr(target)
	if err != nil {
		return nil, err
	}
	if len(first) > MaxPayload-len(addr) {
		first = first[:MaxPayload-len(addr)]
	}
	s.mu.Lock()
	select {
	case <-s.done:
		s.mu.Unlock()
		return nil, ErrSessionClosed
	default:
	}
	var id uint16
	for i := 0; i < 65535; i++ {
		c := s.nextID
		s.nextID++
		if s.nextID == 0 {
			s.nextID = 1
		}
		if c != 0 {
			if _, used := s.streams[c]; !used {
				id = c
				break
			}
		}
	}
	if id == 0 {
		s.mu.Unlock()
		return nil, errors.New("gft: no free stream id")
	}
	st := newStream(s, id)
	st.Target = target
	s.streams[id] = st
	s.mu.Unlock()
	pl := make([]byte, 0, len(addr)+len(first))
	pl = append(pl, addr...)
	pl = append(pl, first...)
	if err := s.writeFrame(CmdConnect, id, pl); err != nil {
		s.removeStream(id)
		return nil, err
	}
	st.Up.Add(uint64(len(first)))
	return st, nil
}

func (s *Session) removeStream(id uint16) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------

// Stream is one multiplexed bidirectional byte stream.
type Stream struct {
	s      *Session
	id     uint16
	Target string
	Up     atomic.Uint64
	Down   atomic.Uint64

	mu       sync.Mutex
	rcond    *sync.Cond
	wcond    *sync.Cond
	rbuf     []byte
	rpos     int
	consumed int
	rEOF     bool  // remote finished sending
	sendWin  int64 // remaining credit to send
	wClosed  bool  // local write side closed
	aborted  error
}

func newStream(s *Session, id uint16) *Stream {
	st := &Stream{s: s, id: id, sendWin: streamWindow}
	st.rcond = sync.NewCond(&st.mu)
	st.wcond = sync.NewCond(&st.mu)
	return st
}

func (st *Stream) push(p []byte) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.aborted != nil || st.rEOF {
		return nil
	}
	if len(st.rbuf)-st.rpos+len(p) > 2*streamWindow {
		return ErrProtocol // peer ignored flow control
	}
	if st.rpos > 0 && st.rpos == len(st.rbuf) {
		st.rbuf, st.rpos = st.rbuf[:0], 0
	} else if st.rpos > streamWindow {
		n := copy(st.rbuf, st.rbuf[st.rpos:])
		st.rbuf, st.rpos = st.rbuf[:n], 0
	}
	st.rbuf = append(st.rbuf, p...)
	st.Down.Add(uint64(len(p)))
	st.rcond.Broadcast()
	return nil
}

func (st *Stream) remoteClose() {
	st.mu.Lock()
	st.rEOF = true
	st.rcond.Broadcast()
	done := st.wClosed
	st.mu.Unlock()
	if done {
		st.s.removeStream(st.id)
	}
}

func (st *Stream) addWindow(n int64) {
	st.mu.Lock()
	st.sendWin += n
	st.wcond.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) abort(err error) {
	st.mu.Lock()
	if st.aborted == nil {
		st.aborted = err
	}
	st.rcond.Broadcast()
	st.wcond.Broadcast()
	st.mu.Unlock()
}

// Read implements io.Reader; returns io.EOF after the peer closes its write side.
func (st *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	st.mu.Lock()
	for st.rpos >= len(st.rbuf) {
		if st.aborted != nil {
			err := st.aborted
			st.mu.Unlock()
			return 0, err
		}
		if st.rEOF {
			st.mu.Unlock()
			return 0, io.EOF
		}
		st.rcond.Wait()
	}
	n := copy(p, st.rbuf[st.rpos:])
	st.rpos += n
	st.consumed += n
	var upd int
	if st.consumed >= windowUpdateN {
		upd, st.consumed = st.consumed, 0
	}
	st.mu.Unlock()
	if upd > 0 {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(upd))
		_ = st.s.writeFrame(CmdWindow, st.id, b[:])
	}
	return n, nil
}

// Write implements io.Writer with flow control.
func (st *Stream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		st.mu.Lock()
		for st.sendWin <= 0 && st.aborted == nil && !st.wClosed {
			st.wcond.Wait()
		}
		if st.aborted != nil {
			err := st.aborted
			st.mu.Unlock()
			return total, err
		}
		if st.wClosed {
			st.mu.Unlock()
			return total, ErrStreamClosed
		}
		n := len(p)
		if n > maxChunk {
			n = maxChunk
		}
		if int64(n) > st.sendWin {
			n = int(st.sendWin)
		}
		st.sendWin -= int64(n)
		st.mu.Unlock()
		if err := st.s.writeFrame(CmdData, st.id, p[:n]); err != nil {
			return total, err
		}
		st.Up.Add(uint64(n))
		st.s.UpBytes.Add(uint64(n))
		if st.s.OnBytes != nil {
			st.s.OnBytes(n, 0)
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

// CloseWrite signals that no more data will be sent (sends CLOSE).
func (st *Stream) CloseWrite() error {
	st.mu.Lock()
	if st.wClosed {
		st.mu.Unlock()
		return nil
	}
	st.wClosed = true
	st.wcond.Broadcast()
	done := st.rEOF
	st.mu.Unlock()
	err := st.s.writeFrame(CmdClose, st.id, nil)
	if done {
		st.s.removeStream(st.id)
	}
	return err
}

// Close fully closes the stream.
func (st *Stream) Close() error {
	_ = st.CloseWrite()
	st.mu.Lock()
	st.rEOF = true
	st.rcond.Broadcast()
	st.mu.Unlock()
	st.s.removeStream(st.id)
	return nil
}
