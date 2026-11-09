package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"ghostframe/internal/gft"
)

const sessionCookieName = "gft_session"
const sessionTTL = 24 * time.Hour

type panelSession struct {
	token   string
	created time.Time
	expires time.Time
}

// Panel implements the hidden management web console and its REST APIs.
type Panel struct {
	srv      *Server
	mu       sync.Mutex
	sessions map[string]panelSession
	loginMu  sync.Mutex
	failures map[string]int // IP -> failure count
}

func newPanel(s *Server) *Panel {
	return &Panel{
		srv:      s,
		sessions: make(map[string]panelSession),
		failures: make(map[string]int),
	}
}

func (p *Panel) sweep() {
	p.mu.Lock()
	now := time.Now()
	for k, v := range p.sessions {
		if now.After(v.expires) {
			delete(p.sessions, k)
		}
	}
	p.mu.Unlock()

	p.loginMu.Lock()
	if len(p.failures) > 2000 {
		p.failures = make(map[string]int)
	}
	p.loginMu.Unlock()
}

func (p *Panel) isAuth(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	sess, ok := p.sessions[cookie.Value]
	if !ok || time.Now().After(sess.expires) {
		return false
	}
	return true
}

func (p *Panel) createSession() string {
	b := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, b)
	token := hex.EncodeToString(b)
	p.mu.Lock()
	p.sessions[token] = panelSession{
		token:   token,
		created: time.Now(),
		expires: time.Now().Add(sessionTTL),
	}
	p.mu.Unlock()
	return token
}

func (p *Panel) serve(w http.ResponseWriter, r *http.Request, sub string) {
	sub = strings.TrimPrefix(sub, "/")
	if sub == "" || sub == "index.html" {
		// Handle optional query key login: ?key=PASSWORD
		if key := r.URL.Query().Get("key"); key != "" {
			if err := bcrypt.CompareHashAndPassword([]byte(p.srv.cfg.PanelHash), []byte(key)); err == nil {
				token := p.createSession()
				http.SetCookie(w, &http.Cookie{
					Name:     sessionCookieName,
					Value:    token,
					Path:     p.srv.cfg.PanelPath,
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
					MaxAge:   int(sessionTTL / time.Second),
				})
				http.Redirect(w, r, p.srv.cfg.PanelPath+"/", http.StatusFound)
				return
			}
		}

		if !p.isAuth(r) {
			notFound(w)
			return
		}
		w.Header().Set("Server", serverHeader)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(panelHTML)
		return
	}

	// API Routing
	if strings.HasPrefix(sub, "api/") {
		p.serveAPI(w, r, strings.TrimPrefix(sub, "api/"))
		return
	}

	notFound(w)
}

func reqIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (p *Panel) serveAPI(w http.ResponseWriter, r *http.Request, action string) {
	w.Header().Set("Server", serverHeader)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	// Login is the only public API on the secret path
	if action == "login" && r.Method == http.MethodPost {
		p.handleLogin(w, r)
		return
	}

	// All other APIs require active session
	if !p.isAuth(r) {
		notFound(w)
		return
	}

	// CSRF validation on mutating methods
	if (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) && action != "login" {
		cookie, _ := r.Cookie(sessionCookieName)
		csrf := r.Header.Get("X-CSRF-Token")
		if csrf == "" || cookie == nil || csrf != cookie.Value {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "forbidden: missing or invalid csrf"})
			return
		}
	}

	switch action {
	case "logout":
		if r.Method == http.MethodPost {
			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    "",
				Path:     p.srv.cfg.PanelPath,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   -1,
			})
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
			return
		}
	case "stats":
		p.handleStats(w, r)
		return
	case "conns":
		p.handleConns(w, r)
		return
	case "audit":
		p.handleAudit(w, r)
		return
	case "ban":
		if r.Method == http.MethodPost {
			p.handleBan(w, r)
			return
		}
	case "params":
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			p.handleUpdateParams(w, r)
			return
		} else if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(p.srv.params.Get())
			return
		}
	case "link":
		p.handleLink(w, r)
		return
	}

	notFound(w)
}

func (p *Panel) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := reqIP(r)
	p.loginMu.Lock()
	fails := p.failures[ip]
	p.loginMu.Unlock()

	if fails >= 10 {
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "too many attempts"})
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid payload"})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(p.srv.cfg.PanelHash), []byte(req.Password))
	if err != nil {
		p.loginMu.Lock()
		p.failures[ip]++
		p.loginMu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "unauthorized"})
		return
	}

	// Login Success: Reset fail counter
	p.loginMu.Lock()
	delete(p.failures, ip)
	p.loginMu.Unlock()

	token := p.createSession()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     p.srv.cfg.PanelPath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL / time.Second),
	})

	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":    true,
		"token": token,
		"csrf":  token,
	})
}

func (p *Panel) handleStats(w http.ResponseWriter, r *http.Request) {
	p.srv.smu.Lock()
	activeCount := len(p.srv.sessions)
	p.srv.smu.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	snap := p.srv.stats.Snapshot()

	res := map[string]any{
		"uptime_sec": int64(time.Since(p.srv.started).Seconds()),
		"active":     activeCount,
		"traffic":    snap,
		"system": map[string]any{
			"alloc_mb":   m.Alloc / 1024 / 1024,
			"sys_mb":     m.Sys / 1024 / 1024,
			"goroutines": runtime.NumGoroutine(),
		},
	}
	_ = json.NewEncoder(w).Encode(res)
}

type connInfo struct {
	ID       uint64 `json:"id"`
	IP       string `json:"ip"`
	Duration int64  `json:"duration_sec"`
	UpBytes  uint64 `json:"up_bytes"`
	DownByte uint64 `json:"down_bytes"`
}

func (p *Panel) handleConns(w http.ResponseWriter, r *http.Request) {
	p.srv.smu.Lock()
	list := make([]connInfo, 0, len(p.srv.sessions))
	now := time.Now()
	for _, e := range p.srv.sessions {
		list = append(list, connInfo{
			ID:       e.ID,
			IP:       e.IP,
			Duration: int64(now.Sub(e.Since).Seconds()),
			UpBytes:  e.Sess.UpBytes.Load(),
			DownByte: e.Sess.DownBytes.Load(),
		})
	}
	p.srv.smu.Unlock()
	_ = json.NewEncoder(w).Encode(list)
}

func (p *Panel) handleAudit(w http.ResponseWriter, r *http.Request) {
	entries := p.srv.audit.List()
	_ = json.NewEncoder(w).Encode(entries)
}

func (p *Panel) handleBan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		Banned bool   `json:"banned"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid payload"})
		return
	}
	ok := p.srv.audit.SetBan(req.IP, req.Banned)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": ok})
}

func (p *Panel) handleUpdateParams(w http.ResponseWriter, r *http.Request) {
	var q gft.Params
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "bad json"})
		return
	}
	if err := q.Validate(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	p.srv.params.Set(q)
	p.srv.saveParams(q)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "params": q})
}

func (p *Panel) handleLink(w http.ResponseWriter, r *http.Request) {
	host, portStr, err := net.SplitHostPort(p.srv.cfg.Listen)
	port := 8443
	if err == nil {
		if p, e := net.LookupPort("tcp", portStr); e == nil {
			port = p
		}
	}
	if p.srv.cfg.PublicHost != "" {
		host = p.srv.cfg.PublicHost
	}

	curParams := p.srv.params.Get()
	linkObj := gft.Link{
		V:      1,
		Host:   host,
		Port:   port,
		SNI:    p.srv.cfg.SNI,
		PSK:    p.srv.cfg.PSK,
		Pin:    p.srv.cfg.Pin,
		Params: &curParams,
	}
	rawJSON, _ := json.Marshal(linkObj)
	encoded := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(rawJSON)
	uri := "gft://" + encoded + "#Japan-GhostFrame"

	_ = json.NewEncoder(w).Encode(map[string]any{
		"uri":     uri,
		"link":    linkObj,
		"raw_psk": p.srv.cfg.PSK,
		"pin":     p.srv.cfg.Pin,
	})
}

var _ = subtle.ConstantTimeCompare
