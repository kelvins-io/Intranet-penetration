# Intranet Penetration

工业级内网穿透平台。当前进度：**真正的 Edge / Control 部署拓扑**。

## 架构

```
公网用户 ──► Edge(:8088/:8443) ── Access Policy ──► 本机 Agent session
                │ miss
                ▼
           Peer Edge (/internal/forward)

Agent ── mTLS? ──► Edge(:7700) ── POST /internal/v1/* ──► Control(:8090)
                                                      │
                                                 store.json + CA
Redis ◄── Edge heartbeat / tunnel location ───────────┘（Control 只读目录）
```

| 角色 | 二进制 | 职责 |
|------|--------|------|
| **Control** | `cmd/control` | API、Dashboard、OIDC、策略/证书、租户权威、内部 RPC |
| **Edge** | `cmd/edge` | Agent mux、公网网关、TCP 段、本机会话、Redis 位置 |
| **all** | `cmd/server` | 本地单体（默认），行为与拆分前一致 |

## 快速开始（本地单体）

```bash
go mod tidy
make run-demo && make run-server && make run-agent
curl http://127.0.0.1:8088/default/demo/
open http://127.0.0.1:8088/dashboard/
```

## 拆分拓扑（本地）

```bash
# 终端 1
make run-control
# 终端 2
make run-edge
# 终端 3
make run-agent

# API / Dashboard 在 Control
open http://127.0.0.1:8090/dashboard/
# 公网入口在 Edge
curl http://127.0.0.1:8088/default/demo/
```

配置见 [`configs/control.yaml`](configs/control.yaml)、[`configs/edge.yaml`](configs/edge.yaml)。多 Edge 时每个进程使用唯一 `edge_id`，并配置同一 `cluster.secret` + Redis。

## 私有化部署

```bash
chmod +x scripts/private-install.sh
./scripts/private-install.sh
# → redis + control(:8090) + edge(:7700/:8088/:8443)

helm upgrade --install ip deploy/helm/intranet-penetration
```

Helm：Control Deployment（PVC）+ Edge StatefulSet（每副本独立 `edge_id`）。需自备 Redis（`config.redisURL`）。

## 能力一览

| 阶段 | 能力 |
|------|------|
| P0–P3 | 隧道、多租户、HTTPS、QUIC、E2E、多区域、SLA/合规 |
| Access Policy + mTLS | 访问策略、Agent 证书签发/吊销 |
| **当前** | **Control / Edge 进程分离、内部 RPC、Compose/Helm 拓扑** |

## API 摘录

```bash
# Control
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8090/api/v1/policies
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8090/api/v1/certs
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8090/api/v1/cluster

# Edge 健康检查（无公开管理 API）
curl http://127.0.0.1:8088/healthz
```

## 路线图

- **P0–P3**：隧道平台 → 多租户 → 集群/QUIC → E2E/私有化
- **Access Policy + mTLS**
- **当前**：真正的 Edge / Control 部署拓扑
