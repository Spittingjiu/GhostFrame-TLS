package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"ghostframe/internal/gft"
)

func startTestServer(t *testing.T) (*Server, *gft.Link, string, context.CancelFunc) {
	t.Helper()
	dir := t.TempDir()
	// find free port
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()
	sec, err := Init(dir, dir, "127.0.0.1", "blog.example.test", addr)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(dir + "/server.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = s.Run(ctx) }()
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	link, err := gft.ParseLink(sec.Link)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Stdout
	cleanup := func() {
		cancel()
		time.Sleep(60 * time.Millisecond)
	}
	return s, link, sec.PanelPassword, cleanup
}

func pinnedHTTPClient(l *gft.Link, h2 bool) *http.Client {
	cfg, _ := gft.TLSConfigFor(l)
	if !h2 {
		cfg.NextProtos = []string{"http/1.1"}
	}
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 15 * time.Second,
		Transport:     &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: h2},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestFallbackBlogAndPanelSecrecy(t *testing.T) {
	s, link, pass, cancel := startTestServer(t)
	defer cancel()
	base := fmt.Sprintf("https://%s:%d", link.Host, link.Port)
	for _, h2 := range []bool{false, true} {
		c := pinnedHTTPClient(link, h2)
		resp, err := c.Get(base + "/")
		if err != nil {
			t.Fatalf("h2=%v GET /: %v", h2, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), "Quiet Compiler") {
			t.Fatalf("h2=%v blog index wrong: %d", h2, resp.StatusCode)
		}
		t.Logf("h2=%v proto=%s GET / -> %d Server=%q", h2, resp.Proto, resp.StatusCode, resp.Header.Get("Server"))
	}
	c := pinnedHTTPClient(link, false)
	get := func(path string) (int, string, http.Header) {
		resp, err := c.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b), resp.Header
	}
	c1, b1, h1 := get("/definitely-missing")
	c2, b2, h2 := get(s.cfg.PanelPath + "/api/stats")
	c3, b3, _ := get(s.cfg.PanelPath + "/")
	if c1 != 404 || c1 != c2 || c1 != c3 || b1 != b2 || b1 != b3 || h1.Get("Content-Type") != h2.Get("Content-Type") || h1.Get("Server") != h2.Get("Server") {
		t.Fatalf("panel 404 differs from normal 404: %d/%d/%d", c1, c2, c3)
	}
	for _, p := range []string{"/robots.txt", "/favicon.ico", "/static/style.css", "/posts/bbr-congestion-control.html"} {
		if code, _, _ := get(p); code != 200 {
			t.Fatalf("%s -> %d", p, code)
		}
	}
	// login flow
	lp := s.cfg.PanelPath
	post := func(path string, body any, csrf string) (*http.Response, []byte) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", base+path, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		rb, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, rb
	}
	if r, _ := post(lp+"/api/login", map[string]string{"password": "wrong"}, ""); r.StatusCode != 401 {
		t.Fatalf("wrong password: %d", r.StatusCode)
	}
	r, rb := post(lp+"/api/login", map[string]string{"password": pass}, "")
	if r.StatusCode != 200 {
		t.Fatalf("login: %d %s", r.StatusCode, rb)
	}
	var lr struct{ CSRF string }
	_ = json.Unmarshal(rb, &lr)
	ck := r.Header.Get("Set-Cookie")
	for _, a := range []string{"HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(ck, a) {
			t.Fatalf("cookie lacks %s: %s", a, ck)
		}
	}
	if code, _, _ := get(lp + "/api/stats"); code != 200 {
		t.Fatalf("stats after login: %d", code)
	}
	if r, _ := post(lp+"/api/logout", map[string]bool{}, ""); r.StatusCode != 403 {
		t.Fatalf("POST without csrf must be 403, got %d", r.StatusCode)
	}
	// params update
	req, _ := http.NewRequest("PUT", base+lp+"/api/params", strings.NewReader(`{"pmin":1,"pmax":20,"pprob":50,"hbmin":2000,"hbmax":5000}`))
	req.Header.Set("X-CSRF-Token", lr.CSRF)
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("put params: %v %v", err, resp)
	}
	resp.Body.Close()
	if s.params.Get().PadMax != 20 {
		t.Fatal("params not applied")
	}
	if code, body, _ := get(lp + "/api/link"); code != 200 || !strings.Contains(body, "gft://") {
		t.Fatalf("link api: %d %s", code, body)
	}
	if code, body, _ := get(lp + "/api/audit"); code != 200 || !strings.Contains(body, "127.0.0.1") {
		t.Fatalf("audit api: %d %s", code, body)
	}
	_ = url.Parse
	_ = cookiejar.New
}

func TestProbesFallbackAndAudit(t *testing.T) {
	s, link, _, cancel := startTestServer(t)
	defer cancel()
	addr := fmt.Sprintf("%s:%d", link.Host, link.Port)
	cfg, _ := gft.TLSConfigFor(link)

	// 1. wrong knock (valid-length garbage) followed by HTTP request: web server must see the full original bytes.
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	req := "GET / HTTP/1.1\r\nHost: probe\r\nUser-Agent: x\r\nAccept: */*\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\nConnection: close\r\n\r\n"
	_, _ = conn.Write([]byte(req))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("garbage probe: %v %v", err, resp)
	}
	conn.Close()

	// 2. wrong PSK knock
	bad := make([]byte, 32)
	conn, _ = tls.Dial("tcp", addr, cfg)
	_, _ = conn.Write(gft.BuildKnock(bad, time.Now()))
	_, _ = conn.Write([]byte(req))
	resp, err = http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("wrong-psk probe: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("wrong-psk probe status %d", resp.StatusCode)
	}
	conn.Close()

	// 3. replayed knock: first use ok-ish, second use treated as web client
	psk, _ := link.PSKBytes()
	k := gft.BuildKnock(psk, time.Now())
	c1, _ := tls.Dial("tcp", addr, cfg)
	_, _ = c1.Write(k)
	time.Sleep(200 * time.Millisecond)
	c1.Close()
	conn, _ = tls.Dial("tcp", addr, cfg)
	_, _ = conn.Write(k)
	_, _ = conn.Write([]byte(req))
	resp, err = http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("replay probe: %v %v", err, resp)
	}
	conn.Close()

	// 4. half knock (no more data): after timeout, fallback http server sees partial bytes and must not crash
	conn, _ = tls.Dial("tcp", addr, cfg)
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	_, _ = conn.Write([]byte("Host: x\r\n\r\n"))
	resp, err = http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("split request probe: %v %v", err, resp)
	}
	conn.Close()

	list := s.audit.List()
	if len(list) != 1 {
		t.Fatalf("audit entries: %+v", list)
	}
	e := list[0]
	for _, r := range []string{"hmac", "replay"} {
		if e.Reasons[r] == 0 {
			t.Fatalf("audit missing reason %s: %+v", r, e.Reasons)
		}
	}
	t.Logf("audit: %+v", e)
}

func TestProxyEndToEnd(t *testing.T) {
	AllowPrivateTargets = true
	defer func() { AllowPrivateTargets = false }()
	_, link, _, cancel := startTestServer(t)
	defer cancel()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	ps := gft.NewParamStore(gft.DefaultParams())
	sess, hs, err := gft.DialSession(context.Background(), link, ps, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	st, err := sess.OpenStream(echo.Addr().String(), []byte("hello-0rtt|"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	want := "hello-0rtt|world"
	got := make([]byte, len(want))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != want {
		t.Fatalf("echo got %q, want %q", got, want)
	}
	_ = st.Close()

	pr, err := gft.Ping(context.Background(), link, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("proxy echo OK %q; handshake=%v knockRTT=%v", got, hs, pr.KnockRTT)

	// bad PSK client must not get a session: it is served the blog
	l2 := *link
	l2.PSK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	_, err = gft.Ping(context.Background(), &l2, 4*time.Second)
	if err == nil {
		t.Fatal("bad psk ping must fail")
	}
	t.Logf("bad-PSK ping failed as expected: %v", err)
}
