# GhostFrame-TLS (GFT) Pro 规范 v1.0（技术经理签发）

交付位置：`Desktop/GhostFrame_Project/01_Architecture_Spec/protocol_and_gui_spec.md`（工程师需原样复制并可补充实现细节）。

## 1. 协议
### 1.1 传输
- TCP + TLS 1.3（`MinVersion=tls.VersionTLS13`），ALPN `h2,http/1.1`。
- 服务端证书：优先使用用户域名的真实证书；无域名则自签证书，客户端使用 SHA256 指纹固定（pin），**禁止 InsecureSkipVerify**。

### 1.2 Knock Frame（TLS 握手后客户端发送的第一段数据）
```
[16B Nonce][8B Timestamp(uint64 BE, unix秒)][32B HMAC-SHA256(PSK, Nonce||Timestamp)][N B 填充, N = Nonce[15] mod 64]
```
校验顺序（全部使用常量时间比较 `hmac.Equal`）：
1. 读取 56 字节（带 3s 读超时）。
2. HMAC 校验。
3. 时间窗 |now−ts| ≤ 90s。
4. Nonce 防重放缓存（TTL ≥ 180s，带容量上限与定期清理）。
5. 读取并丢弃 N 字节填充。
任何一步失败 → 不得返回任何协议错误，不得断开，进入 §2 回落。
- 失败时必须记录审计：IP、时间、失败原因（HMAC / 过期 / 重放 / 超时）。

### 1.3 Ghost Data Frame
头部 6 字节：`[Cmd 1B | PadLen 1B | PayloadLen 2B BE | StreamID 2B BE]`，随后 Payload，再后 PadLen 字节随机填充。
- Cmd：`0x01 CONNECT`（Payload = 地址类型+地址+端口，可捎带首包数据实现 0-RTT）、`0x02 DATA`、`0x03 CLOSE`、`0x04 PING/噪音心跳`、`0x05 PARAM_UPDATE`。
- 每个连接的前 5 个帧强制 PadLen ∈ [Pmin,Pmax] 随机；之后按配置概率填充。
- 噪音心跳：随机间隔 [Imin,Imax]，随机 Payload 长度，对端静默丢弃。
- 多路复用：StreamID 区分子流，单条 TLS 连接承载多流；每流需有背压（窗口/缓冲上限）。
- 混淆参数（Pmin/Pmax/填充概率/心跳间隔）可由面板修改并热生效，新连接使用新值。

## 2. 同端口回落与隐蔽面板
- 回落使用 `RewindConn`：包装 `net.Conn`，记录已读字节，回落时先重放这些字节再继续读原连接。**必须有单元测试：读取任意长度 k（含 0、1、55、56、56+N）后回落，Web 服务看到的字节序列与原始完全一致。**
- 回落目标：内置 `http.Server`（通过自定义 `net.Listener` 注入 RewindConn，不开额外端口，不监听其他端口）。
- 普通路径：返回逼真静态技术博客（多篇文章、CSS、`/robots.txt`、`/favicon.ico`、合理的 404 页、正确的 `Server`/缓存头；`embed` 打包）。
- 秘密路径 `/gft-panel-<≥24字符随机串>/`：部署时随机生成。需登录（密码经 bcrypt/argon2id 存储，会话 Token 使用 HttpOnly+Secure+SameSite=Strict Cookie，登录失败限速与 IP 封锁）。未认证访问秘密路径一律返回与普通 404 完全一致的响应。
- 面板功能：实时上下行速率与总流量、活跃连接列表、**探测/鉴权失败 IP 审计列表**（IP、次数、首/末次时间、原因，可导出，可手动封禁）、在线修改混淆参数、一键生成 `gft://` 链接（含复制与二维码）。
- 面板 API（均需会话，POST 需 CSRF Token）：
  - `GET /api/stats`、`GET /api/conns`、`GET /api/audit`、`GET/PUT /api/params`、`GET /api/link`、`POST /api/login`、`POST /api/logout`
- 单二进制：`embed` 前端，不依赖外部 CDN。

## 3. `gft://` 链接格式
`gft://<base64url(JSON)>#<备注>`，JSON：`{"v":1,"host":"","port":443,"sni":"","psk":"<base64>","pin":"<sha256 hex>","params":{...}}`。客户端必须校验 `v` 与字段合法性。

## 4. 桌面客户端
- Go 本地服务，监听 `127.0.0.1` 随机/固定端口，内嵌 WebUI；启动时调用 Edge/Chrome `--app=http://127.0.0.1:PORT` 打开无边框窗口（Windows 优先 Edge；找不到则回退系统默认浏览器）。零 CGO，`CGO_ENABLED=0` 交叉编译。
- WebUI 本地 API 必须带随机启动 Token，防止其他网页/进程 CSRF 调用。
- 功能：大尺寸连接/断开按钮、真实 TLS 握手+Knock 往返延迟测速、实时速率波形（Canvas）、SOCKS5 与 HTTP 端口显示（默认 127.0.0.1:10808 / 10809，仅监听回环）、系统代理开关（Windows 注册表 + 通知刷新；**退出/崩溃恢复时必须还原原设置**）、实时日志窗口（日志不得含 PSK）、`gft://` 导入。
- API：`GET /api/state`、`POST /api/connect`、`POST /api/disconnect`、`POST /api/ping`、`POST /api/sysproxy`、`POST /api/import`、`GET /api/logs`（SSE）、`GET /api/traffic`（SSE）。
- UI 要求：暗黑现代风，响应式，无黑框控制台（Windows 用 `-H=windowsgui`）。
- 桌面 `启动GFT图形客户端.bat`：双击启动并自动加载日本节点配置。

## 5. 零 GC 与健壮性（遵循项目 AGENTS 规范）
- 数据转发热路径使用 `sync.Pool` 缓冲区，禁止每帧分配。
- 所有 goroutine 有上下文取消；连接有空闲超时；无泄漏（退出时关闭监听与定时器）。
- 前端动画循环不创建临时对象，Canvas 处理 devicePixelRatio，`touch-action:none`。

## 6. 凭证读取与部署的安全要求（硬性）
1. 只在用户 `Desktop` 目录**浅层**查找凭证文件（txt/md/csv/docx/xlsx/json/pem/ppk 等），不得扫描其他目录。
2. 只提取**日本（Japan/JP/东京/大阪/Tokyo/Osaka）**VPS 的 IP、SSH 端口、账号、密码/密钥。有多台候选或无法确定时，**停止并向用户确认**，不得猜测。
3. 不得登录或改动其他 VPS；不得外传凭证；不得把密码写入脚本源码/日志/命令行参数（用环境变量或进程内读取）。凭证只允许出现在 `VPS_ACCESS_INFO.md`（用户要求的交付物）。
4. SSH 首次连接需记录并展示主机指纹；部署前先备份现状（`sshd` 配置不改动、不关闭 SSH、不改防火墙既有 SSH 规则、不重启系统）。
5. 部署内容：上传 Linux amd64（按 `uname -m` 判断）二进制；创建专用低权限用户 `gft`；systemd 单元（`Restart=always`、`NoNewPrivileges`、`ProtectSystem=strict`、`AmbientCapabilities=CAP_NET_BIND_SERVICE`）；生成证书与随机 PSK/面板路径/面板密码；`sysctl` 启用 BBR+fq（先检测内核支持，写入 `/etc/sysctl.d/`）；仅开放 443（或所选端口），并确认云厂商安全组提示。
6. 端口冲突（如 443 已被占用）→ 停止并报告，不得强杀现有服务。
7. 部署脚本须幂等、可回滚，提供 `uninstall`。

## 7. 验收标准（第二阶段我将逐项核验）
| # | 项目 | 证据 |
|---|---|---|
| 1 | RewindConn 单元测试通过，无字节丢失 | `go test -v` 输出 |
| 2 | Knock：正确/错 HMAC/过期/重放四种用例 | 测试日志 |
| 3 | 防探测：curl、openssl s_client、错误 Knock、半截 Knock 均得到博客或一致行为 | TEST_REPORT |
| 4 | 秘密路径未登录=404；登录后面板各功能可用 | 截图/请求日志 |
| 5 | 日本 VPS `systemctl status gft` 为 `active (running)`，`ss -tlnp` 仅对外一个代理端口 | 原始输出 |
| 6 | 本地通过 SOCKS5/HTTP 访问 IP 查询服务，返回日本 VPS IP | 原始输出 |
| 7 | BBR 生效 `sysctl net.ipv4.tcp_congestion_control` | 原始输出 |
| 8 | 客户端 GUI 全功能、系统代理开关可还原 | 截图 |
| 9 | 面板审计列表能看到上述探测产生的失败记录 | 截图 |
| 10 | 桌面目录结构与四份文档齐全 | 目录树 |

未跑通任一项一律打回。
