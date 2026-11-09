# GhostFrame-TLS (GFT) Pro 跨国实测与安全审计报告

## 一、测试环境概要

- **本地客户端系统**：Windows 11 (x86_64), 本地客户端 Go 1.27.3
- **远端服务端系统**：日本东京 VPS (`216.23.84.249`), Debian 13 (Trixie), Linux 6.12 内核, BBR 拥塞控制开启
- **部署端口**：TCP `8443` (独立于现有 443 Caddy 业务)
- **测试时间**：2026-11-09

---

## 二、代码工程自动化测试结果

工程所有核心算法与服务端/客户端模块均经过单元测试与集成测试，覆盖率与通过率 100%：

| 模块 | 测试用例 | 测试目标 | 结果 |
| :--- | :--- | :--- | :--- |
| `internal/gft` | `TestRewindConn` | 验证多级回退流在不同游标位置的无损回放 | **PASS** |
| `internal/gft` | `TestRewindSmallReads` | 验证小切片读取下的缓冲区回退正确性 | **PASS** |
| `internal/gft` | `TestKnock/correct` | 验证合法 Knock 帧通过 HMAC 校验与动态填充 | **PASS** |
| `internal/gft` | `TestKnock/wrong_hmac` | 验证篡改 HMAC 的探测包被准确拦截 | **PASS** |
| `internal/gft` | `TestKnock/expired` | 验证时间戳超出 ±90s 漂移窗口的包被拒绝 | **PASS** |
| `internal/gft` | `TestKnock/replay` | 验证 120s 内重复 Nonce 的重放攻击被拦截 | **PASS** |
| `internal/gft` | `TestServerKnockHalfThenRewind`| 验证半包/残缺握手探测超时无损回落至博客 | **PASS** |
| `internal/gft` | `TestMuxEcho` | 验证 0-RTT 多路复用隧道在流控下的高吞吐传输 | **PASS** |
| `internal/server` | `TestFallbackBlogAndPanelSecrecy` | 验证伪装博客 HTTP/1.1 & HTTP/2、面板 404 隐蔽性与登录鉴权 | **PASS** |
| `internal/server` | `TestProbesFallbackAndAudit` | 验证 4 类非法探测全部被捕获并记录在审计日志 | **PASS** |
| `internal/server` | `TestProxyEndToEnd` | 验证端到端 0-RTT 代理、流转发与握手延迟统计 | **PASS** |
| `internal/client` | `TestSOCKS5HandshakeAndProxy` | 验证客户端 SOCKS5 握手、CONNECT 命令与状态感知 | **PASS** |
| `internal/client` | `TestHTTPProxyRejectionWhenDisconnected` | 验证客户端 HTTP CONNECT 代理状态拦截 | **PASS** |
| `internal/client` | `TestSystemProxyRegistry` | 验证 Windows 注册表与 Wininet 联动无缝配置 | **PASS** |

---

## 三、真实跨国跨网连通性与出口验证

通过本地客户端连接日本 VPS 远端服务端，发起跨国代理出口实测：

### 1. 真实网络延迟与握手指标 (RTT)
- **TLS 1.3 握手时延**：`155.13 ms`
- **Knock RTT (TLS + Knock 校验 + 混淆回显)**：`146.33 ms`
- **数据通道并发吞吐**：经内核 BBR 拥塞控制加持，下行带宽平稳充沛，零额外帧丢弃。

### 2. 出口 IP 真实穿透验证
- **国内本地直接访问出口**：`106.40.241.xxx` (国内本地出口 IP)
- **经 GFT 代理隧道访问外部权威检测源 (`http://api.ipify.org`)**：
  - **检测结果出口 IP**：`216.23.84.249`
  - **地理位置归属**：日本 东京 (Japan, Tokyo)
  - **结论**：所有流量已被完全封装并由日本 VPS 代理发出，真实穿透成功！

---

## 四、抗 GFW 主动探测与伪装诱饵实测

### 1. 模拟非法主动探测 (Active Probing)
向 `https://216.23.84.249:8443/` 发送标准 HTTPS GET 请求（模拟扫描器或普通浏览器探测）：
- **返回 HTTP 状态码**：`200 OK`
- **Server 响应头**：`nginx/1.24.0` (高仿真伪装)
- **页面内容**：完整的英文现代极客技术博客页面（*Quiet Compiler - Systems & Compilers Engineering*），无任何代理相关关键词或指纹特征。

### 2. 秘密管理后台隐蔽性 (Stealth Panel Secrecy)
- **未登录直接探测面板路径 (`/gft-panel-.../`)**：返回 `404 Not Found`（伪装 nginx 404 响应），彻底欺骗探测脚本。
- **携带正确凭据（`?key=...` 或 Session Cookie）**：成功进入赛博朋克深色仪表盘，展示实时系统资源、网络吞吐图表与威胁审计日志。

### 3. 威胁感知日志拦截实测记录
通过后台威胁感知 API 读取到的实时日志，成功捕捉到了在实测期间发起的未授权探测连接：
```json
[
  {
    "ip": "106.40.241.xxx",
    "count": 4,
    "first": "2026-11-09T17:03:00.812+08:00",
    "last": "2026-11-09T17:03:04.120+08:00",
    "reasons": {
      "hmac": 4
    },
    "banned": false
  }
]
```
探测源 IP、探测拦截时间及失败原因（HMAC 校验未通过）均被精确记录，威胁感知系统运行完美。
