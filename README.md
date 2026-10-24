# Intranet Penetration

工业级内网穿透平台。当前进度：**用户 Access Client（SOCKS5 / 系统代理）· 协议 v5 · TUN 预留**。

## 架构

```
用户 App ──► 本机 SOCKS5 / 系统代理 ──► cmd/client
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

## 用户 Client（P0）

| 项 | 说明 |
|----|------|
| 二进制 | `cmd/client` / `make run-client` |
| 协议 | v5 `client_hello` / `dial`（与 Agent 共用 Edge mux / WS） |
| 本地 | SOCKS5（默认 `127.0.0.1:1080`） |
| 系统代理 | `system_proxy: true`（darwin/linux） |
| TUN | `mode: tun\|both` 仅占位日志，P1 实现 VIP/DNS |
| API | `/api/v1/client/bootstrap` · `/resources` · `/sessions` |

## 跨 Edge / 观测 / HA

见先前提交：影子 TCP/UDP、穿透探针、`cluster.redis_url` 下 Resume 与控制面快照 HA。

## 角色

| 角色 | 命令 |
|------|------|
| all | `make run-server` |
| Control / Edge | `make run-control` / `make run-edge` |
| Agent | `make run-agent` |
| User Client | `make run-client` |
