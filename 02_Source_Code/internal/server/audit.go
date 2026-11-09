package server

import (
	"encoding/json"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

// AuditEntry aggregates failed probe/auth events for one IP.
type AuditEntry struct {
	IP      string         `json:"ip"`
	Count   int            `json:"count"`
	First   time.Time      `json:"first"`
	Last    time.Time      `json:"last"`
	Reasons map[string]int `json:"reasons"`
	Banned  bool           `json:"banned"`
}

type auditFile struct {
	Entries map[string]*AuditEntry `json:"entries"`
	Banned  []string               `json:"banned"`
}

// Audit stores failed knock/login records and the manual ban list.
type Audit struct {
	mu      sync.Mutex
	entries map[string]*AuditEntry
	banned  map[string]bool
	path    string
	dirty   bool
}

const auditMax = 5000

func NewAudit(path string) *Audit {
	a := &Audit{entries: map[string]*AuditEntry{}, banned: map[string]bool{}, path: path}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			var f auditFile
			if json.Unmarshal(b, &f) == nil {
				if f.Entries != nil {
					a.entries = f.Entries
				}
				for _, ip := range f.Banned {
					a.banned[ip] = true
				}
			}
		}
	}
	return a
}

func (a *Audit) Record(ip, reason string) {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	e := a.entries[ip]
	if e == nil {
		if len(a.entries) >= auditMax {
			a.evictLocked()
		}
		e = &AuditEntry{IP: ip, First: now, Reasons: map[string]int{}}
		a.entries[ip] = e
	}
	e.Count++
	e.Last = now
	e.Reasons[reason]++
	a.dirty = true
}

func (a *Audit) evictLocked() {
	var oldest string
	var ot time.Time
	for ip, e := range a.entries {
		if a.banned[ip] {
			continue
		}
		if oldest == "" || e.Last.Before(ot) {
			oldest, ot = ip, e.Last
		}
	}
	if oldest != "" {
		delete(a.entries, oldest)
	}
}

func (a *Audit) IsBanned(ip string) bool {
	a.mu.Lock()
	b := a.banned[ip]
	a.mu.Unlock()
	return b
}

func (a *Audit) SetBan(ip string, ban bool) bool {
	if net.ParseIP(ip) == nil {
		return false
	}
	a.mu.Lock()
	if ban {
		a.banned[ip] = true
	} else {
		delete(a.banned, ip)
	}
	a.dirty = true
	a.mu.Unlock()
	return true
}

func (a *Audit) List() []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditEntry, 0, len(a.entries)+len(a.banned))
	seen := map[string]bool{}
	for ip, e := range a.entries {
		c := *e
		c.Reasons = map[string]int{}
		for k, v := range e.Reasons {
			c.Reasons[k] = v
		}
		c.Banned = a.banned[ip]
		out = append(out, c)
		seen[ip] = true
	}
	for ip := range a.banned {
		if !seen[ip] {
			out = append(out, AuditEntry{IP: ip, Banned: true, Reasons: map[string]int{}})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out
}

func (a *Audit) Flush() {
	if a.path == "" {
		return
	}
	a.mu.Lock()
	if !a.dirty {
		a.mu.Unlock()
		return
	}
	f := auditFile{Entries: a.entries}
	for ip := range a.banned {
		f.Banned = append(f.Banned, ip)
	}
	b, _ := json.Marshal(f)
	a.dirty = false
	a.mu.Unlock()
	tmp := a.path + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, a.path)
	}
}
