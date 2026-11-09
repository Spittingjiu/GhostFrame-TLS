# GhostFrame-TLS (GFT) Pro

> **Next-Generation High-Stealth Anti-Censorship Proxy Protocol with 0-RTT Multiplexing & Lossless Decoy Fallback**

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/Platform-Linux%20|%20Windows%20|%20macOS-blue)](https://github.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## ⚡ Overview

**GhostFrame-TLS (GFT)** is a self-designed, production-grade anti-censorship tunnel and proxy protocol. It combines **TLS 1.3 certificate pinning**, an initial **dynamic cryptographic Knock Frame (HMAC-SHA256)**, **0-RTT address piggybacking**, and a lossless stream rewind mechanism (**`RewindConn`**) that falls back to a high-fidelity English engineering blog.

To active GFW probing or port scanners, the server behaves identically to a genuine Nginx web server. Only clients possessing the pre-shared key (PSK) can unlock the encrypted proxy multiplexer.

```
       +--------------------------------------------------------+
       |                  Client (gft-client-gui)               |
       |  [SOCKS5: 10808] [HTTP: 10809] [Wininet SysProxy Toggle]|
       +---------------------------+----------------------------+
                                   | TLS 1.3 + Dynamic Knock Frame
                                   v
       +--------------------------------------------------------+
       |                  Server (gft-server)                   |
       |                 Listening on Port 8443                 |
       +---------------------------+----------------------------+
                                   |
         +-------------------------+-------------------------+
         | Knock Verified (HMAC OK)| Knock Failed / HTTP Probe
         v                         v
+------------------+     +--------------------+---------------------+
| GFT 0-RTT Mux    |     | Lossless RewindConn| Threat Perception   |
| Stream Forwarder |     | Fallback Router    | Trap Audit Table    |
+--------+---------+     +---------+----------+----------+----------+
         |                         |                     |
         v                         v                     v
   Target Internet          Decoy Tech Blog        Secret Panel
 (api.ip.sb / Google)       (nginx/1.24.0)    (/gft-panel-.../)
```

---

## 🌟 Key Architecture & Highlights

### 1. Cryptographic Knock Frame (Anti-Replay & Zero-Fingerprint)
- **Structure**: `[16B Nonce] [8B UnixNano Timestamp] [32B HMAC-SHA256(PSK, Nonce || Ts)] [Dynamic Padding (16-128B)]`
- **Clock Drift Window**: Strictly enforced at ±90 seconds.
- **Replay Protection**: Nonce cache with 120-second TTL prevents replay attacks.
- **Dynamic Padding**: HMAC-derived pseudo-random padding lengths eliminate packet-size statistical profiling.

### 2. Lossless Rewind & Same-Port Decoy Blog Fallback (`RewindConn`)
- If the first packet is not a valid GFT Knock frame, the connection cursor is rewinded via an in-memory buffer ring and passed seamlessly to an internal HTTP router.
- **Root (`/`)**: Returns a clean, modern English engineering blog (*Quiet Compiler - Systems & Compilers Engineering*) with `Server: nginx/1.24.0` headers.
- **Active Probers**: Scanner requests receive `200 OK` or `404 Not Found` identical to a standard Nginx server.

### 3. Stealth Web Management Panel & Threat Perception
- **Secret Path**: Concealed at a randomized path (e.g. `/gft-panel-<random-32-chars>/`).
- **Strict Secrecy**: Unauthenticated requests to the secret path return `404 Not Found`.
- **Live Metrics**: Real-time CPU, RAM, Goroutine count, and active tunnel count.
- **Threat Perception Log**: Captures and audits every failed probe IP, timestamp, and failure reason (HMAC mismatch, timestamp replay, web probe).

### 4. 0-RTT Multiplexed Stream Architecture
- **Header**: 6-byte lightweight framing: `[4B StreamID] [1B Flags] [1B PaddingLen] [Payload]`.
- **0-RTT Address Piggybacking**: Destination address is bundled directly into the first payload frame, eliminating round-trip latency.
- **Zero-Allocation Relay**: Stream forwarding uses `sync.Pool` 32KB buffers to achieve 0 memory allocation during forwarding loops.

### 5. Native-like Desktop GUI Client (`gft-client-gui`)
- **App Window**: Launches an Edge/Chrome `--app` standalone window (940x660) without browser address bars or bookmark menus.
- **Zero-GC Canvas Traffic Chart**: Real-time bandwidth curve rendered on HTML5 Canvas with HiDPI (Retina) support and pre-allocated typed arrays.
- **Windows System Proxy Auto-Config**: Direct registry manipulation (`HKCU\...\Internet Settings`) + `wininet.dll` notification (`InternetSetOptionW`) with automatic cleanup on exit.
- **Dual Protocols**: Local SOCKS5 (`127.0.0.1:10808`) and HTTP proxy (`127.0.0.1:10809`).
- **Clash Verge Compatibility**: One-click copy ready-to-paste Clash YAML proxy snippets.

---

## 🛠️ Build & Installation

### Prerequisites
- Go 1.24 or higher
- GCC (optional, pure Go standard library with zero CGO required)

### 1. Compile Server (Linux amd64)
```bash
cd 02_Source_Code
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o gft-server ./cmd/gft-server
```

### 2. Compile Client (Windows)
```bash
cd 02_Source_Code
go build -ldflags="-s -w -H=windowsgui" -o gft-client-gui.exe ./cmd/gft-client-gui
```

---

## 🚀 Quick Start

### 1. Initialize Server on VPS
Run `init` to automatically generate ECDSA P-256 self-signed certificates, certificate SHA-256 Pin, secure PSK, and admin panel secrets:
```bash
./gft-server init \
  -conf-dir /etc/gft \
  -state-dir /var/lib/gft \
  -host <YOUR_VPS_IP> \
  -sni blog.quietcompiler.net \
  -listen :8443
```

Start the server:
```bash
./gft-server run -config /etc/gft/server.json
```

Or deploy as a systemd service:
```ini
[Unit]
Description=GhostFrame-TLS Server
After=network.target

[Service]
ExecStart=/opt/ghostframe/gft-server run -config /etc/gft/server.json
Restart=always
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### 2. Run Client GUI
Copy `client.example.json` to `client.json` and fill in your server IP, PSK, and certificate Pin:
```json
{
  "link": {
    "v": 1,
    "host": "216.23.84.249",
    "port": 8443,
    "sni": "blog.quietcompiler.net",
    "psk": "<YOUR_BASE64_PSK>",
    "pin": "<YOUR_SHA256_CERT_PIN>",
    "remark": "GhostFrame Tokyo Node"
  },
  "socks_addr": "127.0.0.1:10808",
  "http_addr": "127.0.0.1:10809",
  "sys_proxy": false
}
```

Double click `启动GFT图形客户端.bat` or run:
```bash
./gft-client-gui.exe
```

---

## 📋 Clash Verge / Meta Configuration

```yaml
proxies:
  - name: "GhostFrame-TLS Node"
    type: socks5
    server: 127.0.0.1
    port: 10808
    udp: true
    skip-cert-verify: true

proxy-groups:
  - name: "Proxy"
    type: select
    proxies:
      - "GhostFrame-TLS Node"
      - DIRECT
```

---

## 🧪 Testing & Verification

Run the full automated test suite:
```bash
cd 02_Source_Code
go test -v ./...
```
All tests verify Knock replay detection, timing attacks, stream rewind, flow control, and end-to-end proxy echo.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
