# Intranet Penetration

工业级内网穿透平台。当前进度：**P2**（Edge 集群、QUIC、会话恢复、OIDC）。

## 架构

```
公网用户 ──► HTTP :8088 / HTTPS :8443
              │
              ├─ 本地 Agent 会话 ──mux(QUIC|TCP)──► Agent ──► 内网服务
              └─ 集群转发 /internal/forward ──► 其他 Edge
Agent     ──► :7700 TCP + UDP(QUIC) （优先 QUIC，失败回退 TCP）
管理面    ──► /dashboard + /api/v1/* + OIDC
会话表    ──► 内存 或 Redis（tunnel → edge 映射）
```

## 快速开始

```bash
go mod tidy
make run-demo      # 终端1
make run-server    # 终端2
make run-agent     # 终端3（prefer_quic: true）

curl http://127.0.0.1:8088/default/demo/
open http://127.0.0.1:8088/dashboard/
```

## P2 能力

| 能力 | 说明 |
|------|------|
| **QUIC** | Agent 默认优先 QUIC（`quic_listen` / `prefer_quic`），失败自动 TCP+yamux |
| **会话恢复** | HelloAck 下发 `resume_token`；断线后短时重连复用域名/端口 |
| **Edge 集群** | `edge_id` + 共享 Registry（内存/Redis）+ Peer HTTP 转发 |
| **OIDC** | `/api/v1/auth/oidc/login` → 回调签发 API Key，Dashboard 可一键登录 |

### 集群（多 Edge）

1. 各节点配置不同 `edge_id` / 端口，`cluster.advertise_http` 指向自身
2. 可选 `cluster.redis_url` 共享隧道位置；或静态 `cluster.peers`
3. 设置相同 `cluster.secret`，跨 Edge 经 `/internal/forward/...` 转发

### OIDC

在 `configs/server.yaml` 启用：

```yaml
oidc:
  enabled: true
  issuer: "https://your-idp.example.com"
  client_id: "..."
  client_secret: "..."
  redirect_url: "http://127.0.0.1:8088/api/v1/auth/oidc/callback"
```

## 配置要点

- `configs/server.yaml`：`quic_listen`、`edge_id`、`resume_ttl`、`cluster`、`oidc`
- `configs/agent.yaml`：`prefer_quic`、`quic_addr`、`resume_token_file`

## 路线图

- **P0**：单体 Server、Token、HTTP/TCP、yamux、重连
- **P1**：多租户、HTTPS/自定义域名、Dashboard、配额与审计
- **P2（当前）**：Edge 集群、QUIC、会话恢复、OIDC
- **P3**：E2E 加密、多区域、私有化套件
