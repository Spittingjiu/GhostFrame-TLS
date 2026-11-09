package client

import (
	_ "embed"
	"encoding/json"
	"net/http"
)

//go:embed web/client.html
var clientHTML []byte

// WebServer provides the local GUI web server and control REST API.
type WebServer struct {
	engine *Engine
}

// NewWebServer creates a new WebServer.
func NewWebServer(e *Engine) *WebServer {
	return &WebServer{engine: e}
}

// Handler returns the HTTP handler for the local UI and API.
func (ws *WebServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", ws.handleIndex)
	mux.HandleFunc("/api/status", ws.handleStatus)
	mux.HandleFunc("/api/logs", ws.handleLogs)
	mux.HandleFunc("/api/connect", ws.handleConnect)
	mux.HandleFunc("/api/disconnect", ws.handleDisconnect)
	mux.HandleFunc("/api/sysproxy", ws.handleSysProxy)
	mux.HandleFunc("/api/clash", ws.handleClash)
	return mux
}

func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(clientHTML)
}

func (ws *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ws.engine.Status())
}

func (ws *WebServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ws.engine.Logs())
}

func (ws *WebServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	go func() {
		_ = ws.engine.Connect()
	}()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (ws *WebServer) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ws.engine.Disconnect()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (ws *WebServer) handleSysProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Enable bool `json:"enable"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	_ = ws.engine.SetSysProxyToggle(req.Enable)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "enable": req.Enable})
}

func (ws *WebServer) handleClash(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	_, _ = w.Write([]byte(ws.engine.ClashYAML()))
}
