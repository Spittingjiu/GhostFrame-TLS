# GhostFrame-TLS (GFT) VPS 访问与配置示例模板

> **说明**：此文件为部署后的访问凭据记录模板。生产部署后，请妥善保管实际生成的访问密钥与管理后台地址。

---

## 一、VPS 隐蔽管理后台示例

- **节点主机**：`<YOUR_VPS_IP>`
- **隐蔽监听端口**：`8443`
- **伪装 SNI**：`blog.quietcompiler.net`
- **秘密面板完整 URL**：
  ```text
  https://<YOUR_VPS_IP>:8443/gft-panel-<RANDOM_KEY>/?key=<ADMIN_PASSWORD>
  ```
- **管理员密码**：`<AUTO_GENERATED_PASSWORD>`
- **证书指纹 Pin (SHA-256)**：
  `<SHA256_FINGERPRINT_HEX>`

---

## 二、标准 GFT 导入链接 (URI) 示例

```text
gft://<BASE64_URL_ENCODED_LINK_JSON>#GhostFrame-Node
```

---

## 三、本地客户端使用说明

1. 拷贝 `client.example.json` 为 `client.json` 并填入 VPS 节点的 IP、端口、PSK 与证书 Pin。
2. 运行 `gft-client-gui.exe` 或双击 `启动GFT图形客户端.bat`。
3. 本地监听：SOCKS5 `127.0.0.1:10808`，HTTP 代理 `127.0.0.1:10809`。
