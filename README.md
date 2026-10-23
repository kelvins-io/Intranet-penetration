# Intranet Penetration

工业级内网穿透平台。当前进度：**CI 门禁 · 生产观测/真实 SLA · WebSocket 保底 · 带宽配额 · Access Client / 区域调度**。

## 架构

```
公网用户 ──► Edge HTTP/TCP/UDP 网关
              │ Access → Traffic(RPS/并发/带宽) → Agent session
Agent ── QUIC → TCP → WebSocket ──► Edge
      └── discover_url 区域自动调度
```

## 快速开始

```bash
make ci          # vet + test + build（与 GitHub Actions 一致）
make run-demo && make run-server && make run-agent
curl http://127.0.0.1:8088/default/demo/
open http://127.0.0.1:8088/dashboard/
open http://127.0.0.1:8088/access/    # 用户 Access Client
curl http://127.0.0.1:8088/metrics    # Prometheus
```

## 观测与 SLA

- `GET /metrics`：Prometheus 文本指标（请求、字节、探针、可用性）
- `GET /api/v1/sla/report`：基于合成探针滚动窗口的可用性（非单纯 uptime）
- 服务端 `probe_interval`（默认 15s）周期性探测本地 `/healthz`

## WebSocket 保底与带宽配额

Agent 拨号顺序：`QUIC → TCP(+TLS) → WebSocket`（`prefer_ws_fallback` + `ws_addr`）。

```yaml
# agent.yaml
ws_addr: "ws://127.0.0.1:8088/agent/ws"
prefer_ws_fallback: true
discover_url: "http://127.0.0.1:8088/api/v1/regions/discover"
```

TrafficPolicy 支持 `max_bandwidth_bps`（字节/秒）：

```bash
curl -H "Authorization: Bearer $KEY" -X POST http://127.0.0.1:8088/api/v1/traffic-policies \
  -d '{"name":"cap","tunnels":["demo"],"max_bandwidth_bps":1048576,"rate_rps":100}'
```

## Access Client / 区域调度

| 入口 | 说明 |
|------|------|
| `/access/` | 轻量门户：登录、隧道列表、打开 HTTP |
| `/api/v1/regions/discover` | Agent 无鉴权发现（按 prefer 区域打分） |
| `/api/v1/regions/recommend` | 已登录用户推荐 |

打分考虑：区域匹配、心跳新鲜度、隧道负载。

## 角色拆分

| 角色 | 二进制 |
|------|--------|
| Control | `make run-control`（:8090） |
| Edge | `make run-edge`（:7700/:8088） |
| all | `make run-server` |

## API 摘录

```bash
/api/v1/traffic-policies
/api/v1/regions/recommend
/api/v1/regions/discover
/api/v1/sla/report
/metrics
```
