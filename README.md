# Intranet Penetration

工业级内网穿透平台。当前进度：**Access Client P2（SOCKS/TUN · 设备绑定 · 踢下线 · 本机面板 · Windows TUN）**。

## 架构

```
用户 App ──► SOCKS5 / 系统代理 / TUN(VIP) ──► cmd/client
                                              │ client_hello + dial
                                              ▼
                                           Edge ── AccessPolicy ──► Agent ──► 内网服务
```

## 快速开始

```bash
make ci
make run-demo && make run-server && make run-agent

# 填入用户 API Key（admin 登录 / Bootstrap key）
# configs/client.yaml → token: "..."
make run-client

# 应用走 SOCKS5
curl --socks5-hostname 127.0.0.1:1080 http://demo.default.tunnel.local/
# 或开启 system_proxy: true（macOS networksetup / Linux gsettings）
```

HTTP 资源也可继续浏览器直连：`http://127.0.0.1:8088/default/demo/`（`browser_url`）。

### TUN 模式（需管理员）

```bash
# configs/client.yaml → mode: tun 或 both
sudo ./bin/client -config configs/client.yaml
# 本机 DNS：127.0.0.1:1053 将 hostname 解析到 100.64.0.0/10 VIP
# 分割路由：仅 100.64.0.0/10 走 utun/ip0/Wintun，其余流量不受影响
# 本机面板：http://127.0.0.1:17890/
```

### 踢下线 / 设备绑定 / Client 证书

```bash
# 在线会话
curl -u admin@localhost:admin123 http://127.0.0.1:8088/api/v1/client/live-sessions
# 踢下线
curl -u admin@localhost:admin123 -X POST http://127.0.0.1:8088/api/v1/client/live-sessions/kick \
  -d '{"session_id":"...","reason":"policy"}'
# 设备列表 / 吊销
curl -u admin@localhost:admin123 http://127.0.0.1:8088/api/v1/client/devices
# 签发 Client mTLS 证书（配合 agent_mtls）
curl -u admin@localhost:admin123 -X POST http://127.0.0.1:8088/api/v1/client/certs \
  -d '{"device_id":"laptop-1"}'
```

## 用户 Client

| 项 | 说明 |
|----|------|
| 二进制 | `cmd/client` / `make run-client` |
| 协议 | v5 `client_hello` / `dial` / `kick` |
| 本地 | SOCKS5（默认 `127.0.0.1:1080`） |
| 系统代理 | `system_proxy: true`（darwin/linux）；面板可开关 |
| TUN | `mode: tun\|both`：wireguard-tun + gVisor（darwin/linux/windows） |
| DNS | `dns_listen` A 记录；可选 `write_hosts` |
| 面板 | `panel_listen`（默认 `127.0.0.1:17890`） |
| 设备绑定 | 服务端 `client_device_bind: off\|auto\|require` |
| mTLS | `mtls:` + `/api/v1/client/certs`；姿态走 PosturePolicy |
| API | bootstrap · resources · sessions · live-sessions · devices · certs |

## 跨 Edge / 观测 / HA

见先前提交：影子 TCP/UDP、穿透探针、`cluster.redis_url` 下 Resume 与控制面快照 HA。

## 角色

| 角色 | 命令 |
|------|------|
| all | `make run-server` |
| Control / Edge | `make run-control` / `make run-edge` |
| Agent | `make run-agent` |
| User Client | `make run-client` |
