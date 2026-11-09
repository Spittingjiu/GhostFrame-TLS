package gft

import (
	"io"
	"net"
	"sync"
	"time"
)

// CopyBuf copies src to dst using a pooled buffer (no per-call allocation).
func CopyBuf(dst io.Writer, src io.Reader, onN func(int)) error {
	bp := GetBuf()
	defer PutBuf(bp)
	buf := (*bp)[:32*1024]
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if onN != nil {
				onN(n)
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

type deadliner struct {
	c    net.Conn
	idle time.Duration
}

func (d deadliner) Read(p []byte) (int, error) {
	_ = d.c.SetReadDeadline(time.Now().Add(d.idle))
	return d.c.Read(p)
}

// Relay pipes a stream and a TCP-like connection in both directions until both finish.
// idle is the per-read idle timeout applied on the TCP side.
func Relay(st *Stream, c net.Conn, idle time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // stream -> conn
		defer wg.Done()
		err := CopyBuf(c, st, nil)
		if cw, ok := c.(interface{ CloseWrite() error }); ok && err == nil {
			_ = cw.CloseWrite()
		} else {
			_ = c.Close()
		}
	}()
	go func() { // conn -> stream
		defer wg.Done()
		err := CopyBuf(st, deadliner{c, idle}, nil)
		if err == nil {
			_ = st.CloseWrite()
		} else {
			_ = st.Close()
		}
	}()
	wg.Wait()
	_ = c.Close()
	_ = st.Close()
}
