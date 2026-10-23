# Intranet Penetration

工业级内网穿透平台。当前进度：**流量策略 / 限流**。

## 架构

```
公网用户 ──► Edge(:8088/:8443)
              │  Access Policy → Traffic Policy (RPS/并发)
              ▼
         本机 Agent session / Peer Edge forward

Agent ──► Edge(:7700) ── /internal/v1/* ──► Control(:8090)
                                         store.json + CA + 策略权威
Redis ◄── Edge heartbeat / tunnel location
```

| 角色 | 二进制 | 职责 |
|------|--------|------|
| **Control** | `cmd/control` | API、Dashboard、OIDC、策略/证书/限流配置、内部 RPC |
| **Edge** | `cmd/edge` | Agent mux、公网网关、TCP、限流执行、Redis 位置 |
| **all** | `cmd/server` | 本地单体（默认） |

## 快速开始（本地单体）

```bash
go mod tidy
make run-demo && make run-server && make run-agent
curl http://127.0.0.1:8088/default/demo/
open http://127.0.0.1:8088/dashboard/
```

## 流量策略 / 限流

Access 通过后，按最高优先级 `TrafficPolicy` 在 Edge 本机限流（token bucket + 并发计数）。

| 字段 | 说明 |
|------|------|
| `rate_rps` / `burst` | 每秒请求/连接速率与突发（0=不限） |
| `max_concurrent` | 最大并发（0=不限） |
| `scope` | `ip` / `tunnel` / `ip+tunnel` |
| `tunnels` | 隧道名或 `*` |

```bash
# 单体时 API 在 :8088；拆分拓扑在 Control :8090
curl -H "Authorization: Bearer $KEY" -X POST http://127.0.0.1:8088/api/v1/traffic-policies \
  -d '{"name":"demo-limit","priority":100,"tunnels":["demo"],"scope":"ip+tunnel","rate_rps":20,"burst":40,"max_concurrent":100}'
```

超限：HTTP `429`（`Retry-After: 1`）；TCP 拒绝并审计 `traffic.deny`。

## 拆分拓扑

```bash
make run-control && make run-edge && make run-agent
open http://127.0.0.1:8090/dashboard/
```

## 私有化

```bash
./scripts/private-install.sh
helm upgrade --install ip deploy/helm/intranet-penetration
```

## API 摘录

```bash
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8088/api/v1/traffic-policies
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8088/api/v1/policies
```
