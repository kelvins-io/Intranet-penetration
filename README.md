# Intranet Penetration

可私有化的工业级内网穿透 / 轻量 ZTNA 平台。

- **Connector（Agent）**：内网仅出站，把 HTTP/TCP/UDP 服务暴露到 Edge
- **Access Client**：用户设备经 SOCKS5 / 系统代理 / TUN 访问已授权资源
- **控制面**：多租户、Access/Traffic/Posture 策略、OIDC、Dashboard

协议版本：**v5**（`client_hello` / `dial` / `kick`）。

## 架构

```
用户 App ──► SOCKS5 / 系统代理 / TUN(VIP) ──► cmd/client
                                              │ client_hello + dial
公网用户 ──► Edge HTTP/TCP/UDP 网关 ──────────┤
                                              ▼
                                           Edge ── AccessPolicy ──► Agent ──► 内网服务
                                              ▲
Agent ── QUIC → TCP(+TLS) → WebSocket ────────┘
```

| 角色 | 命令 | 说明 |
|------|------|------|
| all | `make run-server` | 本地一体（Control + Edge） |
| Control | `make run-control` | API / Dashboard（默认 `:8090`） |
| Edge | `make run-edge` | 数据面网关（`:7700` / `:8088` / `:8443`） |
| Agent | `make run-agent` | 内网 Connector |
| User Client | `make run-client` | 用户侧 Access Client |

## 快速开始

```bash
make ci
make run-demo && make run-server && make run-agent

# Dashboard / Access 门户 / 指标
open http://127.0.0.1:8088/dashboard/
open http://127.0.0.1:8088/access/
curl  http://127.0.0.1:8088/default/demo/
curl  http://127.0.0.1:8088/metrics

# Access Client：填入用户 API Key（admin 登录或 Bootstrap）
# configs/client.yaml → token: "..."
make run-client
curl --socks5-hostname 127.0.0.1:1080 http://demo.default.tunnel.local/
```

默认管理员：`admin@localhost` / `admin123`。

### TUN 模式（需管理员）

```bash
# configs/client.yaml → mode: tun | both
sudo ./bin/client -config configs/client.yaml
# DNS：127.0.0.1:1053 → hostname → 100.64.0.0/10 VIP
# 分割路由：仅 VIP 段走 utun / ip0 / Wintun
# 本机面板：http://127.0.0.1:17890/
```

### 踢下线 / 设备绑定 / Client 证书

```bash
curl -u admin@localhost:admin123 http://127.0.0.1:8088/api/v1/client/live-sessions
curl -u admin@localhost:admin123 -X POST http://127.0.0.1:8088/api/v1/client/live-sessions/kick \
  -d '{"session_id":"...","reason":"policy"}'
curl -u admin@localhost:admin123 http://127.0.0.1:8088/api/v1/client/devices
curl -u admin@localhost:admin123 -X POST http://127.0.0.1:8088/api/v1/client/certs \
  -d '{"device_id":"laptop-1"}'
```

## 能力一览

| 域 | 能力 |
|----|------|
| 隧道 | HTTP / HTTPS / TCP / UDP；跨 Edge 影子端口 + peer WebSocket 中继 |
| 传输 | Agent/Client：`QUIC → TCP(+TLS) → WebSocket`；可选 E2E 回程加密 |
| 准入 | AccessPolicy、TrafficPolicy（RPS/并发/带宽）、PosturePolicy、Agent/Client mTLS |
| 身份 | 密码 / API Key / OIDC；Client 设备绑定 `off\|auto\|require` |
| Client | SOCKS5、系统代理（darwin/linux）、TUN+VIP+DNS（darwin/linux/windows）、本机面板、踢下线 |
| 调度 | `regions/discover` · `regions/recommend`（区域匹配 + 心跳 + 负载） |
| 观测 | Prometheus `/metrics`、穿透路径探针 `probe_path`、SLA 报表、`X-Request-ID` Trace |
| HA | `cluster.redis_url`：Registry / Resume Token / 控制面 snapshot |
| 交付 | `make ci`、GitHub Actions、Docker Compose、Helm、`make private-up` |

## Access Client

| 项 | 说明 |
|----|------|
| 二进制 | `cmd/client` / `make run-client` |
| 协议 | v5 `client_hello` / `dial` / `kick`（与 Agent 共用 Edge mux / WS） |
| 本地 | SOCKS5 默认 `127.0.0.1:1080` |
| 系统代理 | `system_proxy: true`；面板可开关 |
| TUN | `mode: tun\|both`：wireguard-tun + gVisor |
| DNS | `dns_listen` A 记录；可选 `write_hosts` |
| 面板 | `panel_listen` 默认 `127.0.0.1:17890`（`-` 关闭） |
| 设备绑定 | 服务端 `client_device_bind` |
| mTLS | Client `mtls:` + `/api/v1/client/certs`；姿态走 PosturePolicy |
| API | bootstrap · resources · sessions · live-sessions · devices · certs |

HTTP 资源也可浏览器直连 Edge：`http://127.0.0.1:8088/default/demo/`（`browser_url`）。

## 平台要点

**WebSocket 保底与带宽**

```yaml
# configs/agent.yaml
ws_addr: "ws://127.0.0.1:8088/agent/ws"
prefer_ws_fallback: true
discover_url: "http://127.0.0.1:8088/api/v1/regions/discover"
```

TrafficPolicy 支持 `max_bandwidth_bps`（字节/秒）。

**跨 Edge TCP/UDP**

Owning Edge 登记端口到 Registry；其他 Edge 影子监听后经 `/internal/stream/{tcp|udp}/...` 转发。

**探针与 SLA**

```yaml
# configs/server.yaml
probe_interval: 15s
probe_path: "/default/demo/"   # 优先于 healthz 计入可用性
```

**控制面 HA**

配置 `cluster.redis_url` 后共享 Tunnel Registry、Resume Token、控制面 `store` 快照；无 Redis 时退回内存/本地文件。

## 私有化部署

```bash
make private-up    # Compose：Redis + Control + Edge
# Dashboard: http://127.0.0.1:8090/dashboard/
# 可选 Agent：docker compose -f deploy/docker-compose.yml --profile with-agent up -d

helm upgrade --install ip deploy/helm/intranet-penetration
```

## 开发

```bash
make tidy && make ci   # vet + test + build（含 client）
```

主要目录：`cmd/` · `internal/{server,agent,client,tunnel,policy,posture,traffic,cluster,resume}` · `configs/` · `deploy/`。
