package server

import (
	"sync"
	"sync/atomic"
	"time"
)

const histLen = 120

// Stats tracks traffic counters and a rate history.
type Stats struct {
	up, down atomic.Uint64 // totals: up = from clients, down = to clients
	lastUp   uint64
	lastDown uint64
	mu       sync.Mutex
	upRate   uint64
	downRate uint64
	histUp   [histLen]uint64
	histDown [histLen]uint64
	histN    int
}

func NewStats() *Stats { return &Stats{} }

// Add is the session byte callback: sent = bytes written to the client (download),
// recv = bytes received from the client (upload).
func (s *Stats) Add(sent, recv int) {
	if sent > 0 {
		s.down.Add(uint64(sent))
	}
	if recv > 0 {
		s.up.Add(uint64(recv))
	}
}

// Sample is called once per second.
func (s *Stats) Sample() {
	u, d := s.up.Load(), s.down.Load()
	s.mu.Lock()
	s.upRate, s.downRate = u-s.lastUp, d-s.lastDown
	s.lastUp, s.lastDown = u, d
	s.histUp[s.histN%histLen] = s.upRate
	s.histDown[s.histN%histLen] = s.downRate
	s.histN++
	s.mu.Unlock()
}

type StatsSnapshot struct {
	UpRate    uint64   `json:"up_rate"`
	DownRate  uint64   `json:"down_rate"`
	UpTotal   uint64   `json:"up_total"`
	DownTotal uint64   `json:"down_total"`
	HistUp    []uint64 `json:"hist_up"`
	HistDown  []uint64 `json:"hist_down"`
}

func (s *Stats) Snapshot() StatsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.histN
	if n > histLen {
		n = histLen
	}
	hu := make([]uint64, n)
	hd := make([]uint64, n)
	for i := 0; i < n; i++ {
		idx := (s.histN - n + i) % histLen
		hu[i], hd[i] = s.histUp[idx], s.histDown[idx]
	}
	return StatsSnapshot{UpRate: s.upRate, DownRate: s.downRate, UpTotal: s.up.Load(), DownTotal: s.down.Load(), HistUp: hu, HistDown: hd}
}

var _ = time.Second
