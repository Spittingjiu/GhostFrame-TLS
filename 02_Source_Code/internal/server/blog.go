package server

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"strings"
	"time"
)

//go:embed web/static/*
var staticFS embed.FS

//go:embed web/panel.html
var panelHTML []byte

const serverHeader = "nginx/1.24.0"

// notFound writes THE one canonical 404 response. Panel and blog share it so they are indistinguishable.
func notFound(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Server", serverHeader)
	h.Set("Content-Type", "text/html")
	h.Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>"+serverHeader+"</center>\r\n</body>\r\n</html>\r\n")
}

func methodNotAllowed(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Server", serverHeader)
	h.Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = io.WriteString(w, "<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n<center><h1>405 Not Allowed</h1></center>\r\n<hr><center>"+serverHeader+"</center>\r\n</body>\r\n</html>\r\n")
}

type article struct {
	Slug, Title, Date, Summary string
	Body                       template.HTML
}

var buildTime = time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)

var articles = []article{
	{"bbr-congestion-control", "Why BBR changed how I think about throughput", "2026-08-21",
		"Loss-based congestion control treats every drop as a signal. BBR models the pipe instead.",
		`<p>For decades the default answer to "how fast can I send?" was "until something drops". Reno and CUBIC both treat packet loss as the congestion signal, which works well on wired links with shallow buffers and badly almost everywhere else.</p>
<p>BBR takes a different approach: it continuously estimates the bottleneck bandwidth and the minimum round-trip time, and paces packets at roughly their product. The result is a sender that keeps queues short instead of filling every buffer on the path.</p>
<h2>What I measured</h2>
<p>On a long-haul link with 0.5% random loss, CUBIC stalled around a tenth of the available bandwidth while BBR stayed close to line rate. On a clean datacenter link the two were practically identical. The lesson is that BBR is a fix for the lossy, long, fat networks that real users actually live on.</p>
<p>Enabling it on Linux is two lines of sysctl: select the <code>bbr</code> congestion control and the <code>fq</code> queueing discipline. Verify with <code>sysctl net.ipv4.tcp_congestion_control</code> before you believe it.</p>`},
	{"go-sync-pool", "A practical guide to sync.Pool in Go services", "2026-07-30",
		"Pools are not caches. Used correctly they remove most short-lived allocations from hot paths.",
		`<p>Garbage collection pauses are rarely the first thing you notice in a Go service, but at high request rates short-lived buffers add up. <code>sync.Pool</code> lets you reuse them across goroutines without writing your own free list.</p>
<h2>Rules of thumb</h2>
<p>Store pointers to slices rather than slices themselves so that <code>Put</code> does not allocate. Always reset length before reuse, and never keep a reference to a buffer after returning it. The pool may drop items at any garbage collection, so treat it purely as an optimisation.</p>
<p>Benchmark before and after: in our proxy the pooled version cut allocations per request from 14 to 2, and p99 latency dropped by a third.</p>`},
	{"sqlite-in-production", "SQLite in production: what actually bites you", "2026-06-12",
		"Write-ahead logging, busy timeouts and the one pragma everybody forgets.",
		`<p>SQLite is far more capable than its reputation suggests. A single file, no daemon, and transactions that are genuinely ACID. For read-heavy services with modest write rates it is hard to beat.</p>
<h2>Settings worth knowing</h2>
<p>Turn on <code>journal_mode=WAL</code> so readers never block the writer, set a generous <code>busy_timeout</code>, and keep write transactions short. Use <code>synchronous=NORMAL</code> with WAL for a good durability and speed balance.</p>
<p>The pragma people forget is <code>foreign_keys=ON</code>; it is a per-connection setting and defaults to off. Put it in your connection initialiser and add a test that asserts it.</p>`},
	{"tls13-handshake-notes", "Notes on the TLS 1.3 handshake", "2026-05-03",
		"One round trip, encrypted certificates, and fewer ways to get it wrong.",
		`<p>TLS 1.3 removed an entire generation of legacy: static RSA key exchange, CBC modes, renegotiation, compression. What remains is a handshake that completes in a single round trip and encrypts everything after the ServerHello.</p>
<h2>Practical consequences</h2>
<p>Because the certificate is now encrypted, passive observers see far less. Session resumption with pre-shared keys can even send application data in the first flight, though replay protection then becomes the application's job.</p>
<p>When debugging, <code>openssl s_client -tls1_3 -connect host:443</code> still tells you most of what you need: negotiated cipher, ALPN protocol and the certificate chain.</p>`},
	{"idempotent-deploys", "Writing deployment scripts you can run twice", "2026-03-18",
		"Idempotence turns deployment from a ritual into a routine.",
		`<p>A deploy script that only works on a clean machine is a liability. The goal is to be able to run it again after any failure, in any state, and end up in the same place.</p>
<h2>Patterns</h2>
<p>Check before you change: create users only if they are missing, write files only if their content differs, and restart services only when something actually changed. Take a backup of anything you overwrite and record where it went.</p>
<p>Finally, ship the uninstall path together with the install path. If you cannot cleanly remove it, you do not yet understand what you installed.</p>`},
}

var pageTmpl = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title><meta name="description" content="{{.Desc}}">
<link rel="stylesheet" href="/static/style.css"><link rel="icon" href="/favicon.ico"></head>
<body><header><div class="wrap"><a class="brand" href="/">Quiet Compiler</a><nav><a href="/">Posts</a><a href="/about.html">About</a></nav></div></header>
<main class="wrap">{{.Body}}</main>
<footer><div class="wrap">&copy; 2026 Quiet Compiler &middot; Notes on systems, networks and tooling.</div></footer></body></html>`))

type page struct {
	Title, Desc string
	Body        template.HTML
}

type blogPage struct {
	body []byte
}

func renderPage(p page) []byte {
	var b bytes.Buffer
	_ = pageTmpl.Execute(&b, p)
	return b.Bytes()
}

func makeFavicon() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	bg, fg := color.RGBA{0x1f, 0x29, 0x37, 255}, color.RGBA{0x34, 0xd3, 0x99, 255}
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			c := bg
			if (x >= 3 && x <= 12 && (y == 3 || y == 12)) || (x == 3 && y >= 3 && y <= 12) || (x == 12 && y >= 8 && y <= 12) || (y == 8 && x >= 8 && x <= 12) {
				c = fg
			}
			img.Set(x, y, c)
		}
	}
	var pb bytes.Buffer
	_ = png.Encode(&pb, img)
	var ico bytes.Buffer
	ico.Write([]byte{0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0})
	n := uint32(pb.Len())
	ico.Write([]byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24), 22, 0, 0, 0})
	ico.Write(pb.Bytes())
	return ico.Bytes()
}

type asset struct {
	data  []byte
	ctype string
	cache string
}

func (s *Server) buildRouter() http.Handler {
	assets := map[string]asset{}
	var idx strings.Builder
	idx.WriteString(`<h1>Latest posts</h1>`)
	for _, a := range articles {
		fmt.Fprintf(&idx, `<article class="card"><h2><a href="/posts/%s.html">%s</a></h2><time>%s</time><p>%s</p></article>`, a.Slug, template.HTMLEscapeString(a.Title), a.Date, template.HTMLEscapeString(a.Summary))
		body := fmt.Sprintf(`<article><h1>%s</h1><time>%s</time>%s<p><a href="/">&larr; All posts</a></p></article>`, template.HTMLEscapeString(a.Title), a.Date, a.Body)
		assets["/posts/"+a.Slug+".html"] = asset{renderPage(page{a.Title + " - Quiet Compiler", a.Summary, template.HTML(body)}), "text/html; charset=utf-8", "public, max-age=300"}
	}
	assets["/"] = asset{renderPage(page{"Quiet Compiler", "Notes on systems, networks and tooling.", template.HTML(idx.String())}), "text/html; charset=utf-8", "public, max-age=300"}
	assets["/index.html"] = assets["/"]
	assets["/about.html"] = asset{renderPage(page{"About - Quiet Compiler", "About this blog", template.HTML(`<h1>About</h1><p>Quiet Compiler is a small personal blog about systems programming, networking and the tools that make both bearable. Posts are written when there is something worth saying, which is less often than anyone would like.</p><p>No analytics, no cookies, no newsletter.</p>`)}), "text/html; charset=utf-8", "public, max-age=300"}
	css, _ := staticFS.ReadFile("web/static/style.css")
	robots, _ := staticFS.ReadFile("web/static/robots.txt")
	assets["/static/style.css"] = asset{css, "text/css; charset=utf-8", "public, max-age=86400"}
	assets["/robots.txt"] = asset{robots, "text/plain; charset=utf-8", "public, max-age=3600"}
	assets["/favicon.ico"] = asset{makeFavicon(), "image/x-icon", "public, max-age=86400"}

	prefix := s.cfg.PanelPath
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == prefix || strings.HasPrefix(r.URL.Path, prefix+"/") {
			s.panel.serve(w, r, strings.TrimPrefix(r.URL.Path, prefix))
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w)
			return
		}
		a, ok := assets[r.URL.Path]
		if !ok {
			notFound(w)
			return
		}
		h := w.Header()
		h.Set("Server", serverHeader)
		h.Set("Content-Type", a.ctype)
		h.Set("Cache-Control", a.cache)
		h.Set("X-Content-Type-Options", "nosniff")
		http.ServeContent(w, r, "", buildTime, bytes.NewReader(a.data))
	})
}
