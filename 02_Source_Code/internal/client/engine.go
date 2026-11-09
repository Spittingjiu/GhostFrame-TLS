package client

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"ghostframe/internal/gft"
)

type ConnState string

const (
	StateDisconnected ConnState = "disconnected"
	StateConnecting   ConnState = "connecting"
	StateConnected    ConnState = "connected"
	StateError        ConnState = "error"
)

// ClientConfig holds saved client preferences and current node.
type ClientConfig struct {
	Link      *gft.Link `json:"link"`
	SocksAddr string    `json:"socks_addr"`
	HTTPAddr  string    `json:"http_addr"`
	SysProxy  bool      `json:"sys_proxy"`
}

// LogEntry is a single line in the client rolling log.
type LogEntry struct {
	Time    string `json:"time"`
	Message string `json:"message"`
}

// TrafficPoint holds bandwidth at a specific time.
type TrafficPoint struct {
	Time int64  `json:"t"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// Engine coordinates client tunnels, GFT session, pinger, and system proxy.
type Engine struct {
	mu         sync.RWMutex
	cfgPath    string
	config     ClientConfig
	state      ConnState
	lastErr    string
	sess       *gft.Session
	paramStore *gft.ParamStore

	socksSrv *SOCKS5Server
	httpSrv  *HTTPProxyServer

	// Stats
	prevUp    uint64
	prevDown  uint64
	curUpBps  uint64
	curDownBps uint64
	pingMs    int64
	history   []TrafficPoint

	// Rolling log
	logMu sync.Mutex
	logs  []LogEntry

	stopPing chan struct{}
}

// NewEngine initializes the client engine with a config path.
func NewEngine(cfgPath string) (*Engine, error) {
	e := &Engine{
		cfgPath:    cfgPath,
		state:      StateDisconnected,
		paramStore: gft.NewParamStore(gft.DefaultParams()),
		history:    make([]TrafficPoint, 0, 60),
		logs:       make([]LogEntry, 0, 200),
		config: ClientConfig{
			SocksAddr: "127.0.0.1:10808",
			HTTPAddr:  "127.0.0.1:10809",
			SysProxy:  false,
		},
	}

	if cfgPath != "" {
		if data, err := os.ReadFile(cfgPath); err == nil {
			_ = json.Unmarshal(data, &e.config)
		}
	}

	if e.config.Link != nil && e.config.Link.Params != nil {
		e.paramStore.Set(*e.config.Link.Params)
	}

	e.socksSrv = NewSOCKS5Server(e.config.SocksAddr, e)
	e.httpSrv = NewHTTPProxyServer(e.config.HTTPAddr, e)

	return e, nil
}

// StartServers binds and listens on the local SOCKS5 and HTTP proxy ports.
func (e *Engine) StartServers() error {
	if err := e.socksSrv.Start(); err != nil {
		return fmt.Errorf("socks5 listen on %s: %w", e.config.SocksAddr, err)
	}
	e.Logf("SOCKS5 proxy listening on %s", e.config.SocksAddr)

	if err := e.httpSrv.Start(); err != nil {
		_ = e.socksSrv.Close()
		return fmt.Errorf("http proxy listen on %s: %w", e.config.HTTPAddr, err)
	}
	e.Logf("HTTP proxy listening on %s", e.config.HTTPAddr)

	go e.statsLoop()
	return nil
}

// SaveConfig writes the current configuration to disk.
func (e *Engine) SaveConfig() error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.cfgPath == "" {
		return nil
	}
	_ = os.MkdirAll(filepath.Dir(e.cfgPath), 0o755)
	b, err := json.MarshalIndent(e.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(e.cfgPath, b, 0o644)
}

// SetLink updates the node link.
func (e *Engine) SetLink(l *gft.Link) error {
	e.mu.Lock()
	e.config.Link = l
	if l != nil && l.Params != nil {
		e.paramStore.Set(*l.Params)
	}
	e.mu.Unlock()
	return e.SaveConfig()
}

// ActiveSession returns the current live GFT session if connected.
func (e *Engine) ActiveSession() *gft.Session {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.state == StateConnected {
		return e.sess
	}
	return nil
}

// Connect dials the GFT server and establishes the multiplexed tunnel.
func (e *Engine) Connect() error {
	e.mu.Lock()
	if e.state == StateConnected || e.state == StateConnecting {
		e.mu.Unlock()
		return nil
	}
	l := e.config.Link
	if l == nil {
		e.state = StateError
		e.lastErr = "no node configured"
		e.mu.Unlock()
		return fmt.Errorf("no node configured")
	}
	e.state = StateConnecting
	e.lastErr = ""
	e.mu.Unlock()

	e.Logf("Connecting to Japan node %s:%d via TLS 1.3 Knock...", l.Host, l.Port)

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	sess, hs, err := gft.DialSession(ctx, l, e.paramStore, 8*time.Second)
	if err != nil {
		e.mu.Lock()
		e.state = StateError
		e.lastErr = err.Error()
		e.mu.Unlock()
		e.Logf("Connection failed: %v", err)
		return err
	}

	e.mu.Lock()
	e.sess = sess
	e.state = StateConnected
	e.lastErr = ""
	e.pingMs = hs.Milliseconds()
	e.stopPing = make(chan struct{})
	e.mu.Unlock()

	e.Logf("Connected successfully! TLS 1.3 handshake: %v", hs)

	if e.config.SysProxy {
		if err := SetSystemProxy(e.config.HTTPAddr, true); err != nil {
			e.Logf("Failed to enable system proxy: %v", err)
		} else {
			e.Logf("System proxy enabled (%s)", e.config.HTTPAddr)
		}
	}

	go e.pingLoop(e.stopPing)
	go e.watchSession(sess)

	return nil
}

// Disconnect cleanly tears down the active tunnel.
func (e *Engine) Disconnect() {
	e.mu.Lock()
	if e.state != StateConnected && e.state != StateConnecting {
		e.mu.Unlock()
		return
	}
	e.state = StateDisconnected
	if e.stopPing != nil {
		select {
		case <-e.stopPing:
		default:
			close(e.stopPing)
		}
	}
	s := e.sess
	e.sess = nil
	e.mu.Unlock()

	if s != nil {
		s.Close()
	}
	if e.config.SysProxy {
		_ = SetSystemProxy("", false)
		e.Logf("System proxy disabled")
	}
	e.Logf("Disconnected from node")
}

func (e *Engine) watchSession(s *gft.Session) {
	// Session.Run() is running in a goroutine from DialSession.
	// When closed or errored, reset state.
	<-s.Done()
	e.mu.Lock()
	if e.sess == s {
		e.state = StateDisconnected
		e.sess = nil
		if e.stopPing != nil {
			select {
			case <-e.stopPing:
			default:
				close(e.stopPing)
			}
		}
		e.Logf("Session connection lost")
		if e.config.SysProxy {
			_ = SetSystemProxy("", false)
		}
	}
	e.mu.Unlock()
}

func (e *Engine) pingLoop(stop chan struct{}) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			e.mu.RLock()
			l := e.config.Link
			connected := e.state == StateConnected
			e.mu.RUnlock()
			if !connected || l == nil {
				return
			}

			pr, err := gft.Ping(context.Background(), l, 4*time.Second)
			if err == nil {
				e.mu.Lock()
				e.pingMs = pr.Total.Milliseconds()
				e.mu.Unlock()
			}
		}
	}
}

func (e *Engine) statsLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for range t.C {
		e.mu.Lock()
		var curUp, curDown uint64
		if e.sess != nil {
			curUp = e.sess.UpBytes.Load()
			curDown = e.sess.DownBytes.Load()
		}
		var upDelta, downDelta uint64
		if curUp >= e.prevUp {
			upDelta = curUp - e.prevUp
		}
		if curDown >= e.prevDown {
			downDelta = curDown - e.prevDown
		}
		e.prevUp = curUp
		e.prevDown = curDown
		e.curUpBps = upDelta
		e.curDownBps = downDelta

		pt := TrafficPoint{
			Time: time.Now().Unix(),
			Up:   upDelta,
			Down: downDelta,
		}
		if len(e.history) >= 60 {
			e.history = append(e.history[1:], pt)
		} else {
			e.history = append(e.history, pt)
		}
		e.mu.Unlock()
	}
}

// SetSysProxyToggle toggles the Windows system proxy setting.
func (e *Engine) SetSysProxyToggle(enable bool) error {
	e.mu.Lock()
	e.config.SysProxy = enable
	connected := e.state == StateConnected
	httpAddr := e.config.HTTPAddr
	e.mu.Unlock()

	_ = e.SaveConfig()

	if connected {
		if enable {
			if err := SetSystemProxy(httpAddr, true); err != nil {
				e.Logf("SetSystemProxy failed: %v", err)
				return err
			}
			e.Logf("System proxy enabled (%s)", httpAddr)
		} else {
			_ = SetSystemProxy("", false)
			e.Logf("System proxy disabled")
		}
	}
	return nil
}

// Logf records a log entry.
func (e *Engine) Logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	entry := LogEntry{
		Time:    time.Now().Format("15:04:05"),
		Message: msg,
	}
	e.logMu.Lock()
	if len(e.logs) >= 200 {
		e.logs = append(e.logs[1:], entry)
	} else {
		e.logs = append(e.logs, entry)
	}
	e.logMu.Unlock()
	fmt.Printf("[%s] %s\n", entry.Time, msg)
}

// Status returns the current engine state snapshot for the UI.
func (e *Engine) Status() map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var totalUp, totalDown uint64
	if e.sess != nil {
		totalUp = e.sess.UpBytes.Load()
		totalDown = e.sess.DownBytes.Load()
	}

	histCopy := make([]TrafficPoint, len(e.history))
	copy(histCopy, e.history)

	var nodeName, nodeHost string
	var nodePort int
	if e.config.Link != nil {
		nodeName = e.config.Link.Remark
		if nodeName == "" {
			nodeName = "Japan Tokyo VPS (GFT-TLS Pro)"
		}
		nodeHost = e.config.Link.Host
		nodePort = e.config.Link.Port
	}

	return map[string]any{
		"state":       string(e.state),
		"last_err":    e.lastErr,
		"ping_ms":     e.pingMs,
		"up_bps":      e.curUpBps,
		"down_bps":    e.curDownBps,
		"total_up":    totalUp,
		"total_down":  totalDown,
		"history":     histCopy,
		"sys_proxy":   e.config.SysProxy,
		"socks_addr":  e.config.SocksAddr,
		"http_addr":   e.config.HTTPAddr,
		"node_name":   nodeName,
		"node_host":   nodeHost,
		"node_port":   nodePort,
		"link_uri":    e.LinkURI(),
		"clash_yaml":  e.ClashYAML(),
	}
}

// Logs returns recent log lines.
func (e *Engine) Logs() []LogEntry {
	e.logMu.Lock()
	defer e.logMu.Unlock()
	cp := make([]LogEntry, len(e.logs))
	copy(cp, e.logs)
	return cp
}

// LinkURI returns the `gft://...` link representation.
func (e *Engine) LinkURI() string {
	if e.config.Link == nil {
		return ""
	}
	return e.config.Link.Encode()
}

// ClashYAML outputs Clash Verge / Clash Meta compatible node snippet.
func (e *Engine) ClashYAML() string {
	l := e.config.Link
	if l == nil {
		return "# No node configured"
	}
	return fmt.Sprintf(`- name: "%s"
  type: socks5
  server: 127.0.0.1
  port: 10808
  udp: true
# Note: GhostFrame-TLS handles high-entropy Knock, TLS 1.3 and zero-delay mux locally.
# Keep GhostFrame Client running on 127.0.0.1:10808.`, l.Remark)
}

// Close gracefully closes all servers and restores system proxy.
func (e *Engine) Close() {
	e.Disconnect()
	_ = e.socksSrv.Close()
	_ = e.httpSrv.Close()
	_ = SetSystemProxy("", false)
}

var _ = atomic.AddUint64
