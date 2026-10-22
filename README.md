# Intranet Penetration

工业级内网穿透平台。当前进度：**P3**（E2E 回程加密、多区域、私有化套件、SLA/合规导出）。

## 架构

```
公网用户 ──► Edge(HTTP/HTTPS/TCP)
              │  E2E AEAD（X25519 + ChaCha20-Poly1305）保护 Edge↔Agent 回程
              ▼
Agent ──► 内网服务   （QUIC 优先，TCP 回退；支持 resume）

多区域：region 标签 + regions 目录 + 集群转发
私有化：Docker Compose / Helm / scripts/private-install.sh
```

## 快速开始（本地）

```bash
go mod tidy
make run-demo && make run-server && make run-agent
curl http://127.0.0.1:8088/default/demo/
open http://127.0.0.1:8088/dashboard/
```

## 私有化部署

```bash
# Docker Compose（server + redis）
chmod +x scripts/private-install.sh
./scripts/private-install.sh

# Kubernetes
helm upgrade --install ip deploy/helm/intranet-penetration
```

## P3 能力

| 能力 | 说明 |
|------|------|
| **E2E 回程加密** | `enable_e2e` + Agent `prefer_e2e`；流级 ECDH，中间转发节点不可读明文 |
| **多区域** | `region` / `regions`；`/api/v1/regions`；Edge 心跳带区域 |
| **私有化套件** | `deploy/Dockerfile`、`docker-compose.yml`、Helm Chart、安装脚本 |
| **SLA / 合规** | `/api/v1/sla/report`、`/api/v1/compliance/export` |

> 说明：HTTP 网关仍在 Edge 终结；E2E 保护的是 **Edge↔Agent 数据面回程**（含跨 Edge 转发路径上的密文），不是浏览器到内网服务的端到端应用层加密。

## API 摘录

```bash
# SLA
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8088/api/v1/sla/report

# 合规导出
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8088/api/v1/compliance/export -o compliance.json

# 区域
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8088/api/v1/regions
```

## 路线图

- **P0**：单体 Server、Token、HTTP/TCP、yamux、重连
- **P1**：多租户、HTTPS/自定义域名、Dashboard、配额与审计
- **P2**：Edge 集群、QUIC、会话恢复、OIDC
- **P3（当前）**：E2E 回程加密、多区域、私有化套件、SLA/合规导出
