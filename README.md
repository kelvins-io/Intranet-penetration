# Intranet Penetration

工业级内网穿透平台。当前进度：**Access Policy + Agent mTLS**（在 P3 之上）。

## 架构

```
公网用户 ──► Edge(HTTP/HTTPS/TCP) ── Access Policy ──►
              │  E2E AEAD（X25519 + ChaCha20-Poly1305）
              ▼
Agent ── mTLS ──► Server   （QUIC 优先，TCP 回退；支持 resume）
```

## 快速开始（本地）

```bash
go mod tidy
make run-demo && make run-server && make run-agent
curl http://127.0.0.1:8088/default/demo/
open http://127.0.0.1:8088/dashboard/
```

## Access Policy

按租户配置允许/拒绝规则，匹配主体、隧道、动作与来源 CIDR。

| 字段 | 说明 |
|------|------|
| subjects | `anyone` / `authenticated` / `email:x` / `role:admin` |
| tunnels | 隧道名或 `*` |
| actions | `http.access` / `tcp.access` / `*` |
| effect | `allow` / `deny`（按 priority 降序，首条命中生效） |
| access_default_deny | 无命中时默认拒绝（server.yaml） |

```bash
# 创建策略：仅允许内网网段访问 demo 隧道
curl -H "Authorization: Bearer $KEY" -X POST http://127.0.0.1:8088/api/v1/policies \
  -d '{"name":"office","effect":"allow","priority":10,"subjects":["anyone"],"tunnels":["demo"],"actions":["http.access"],"source_cidrs":["10.0.0.0/8"]}'
```

## Agent mTLS

Server `agent_mtls`: `off` | `optional` | `require`。证书 CN = `agent_id`，吊销后拒绝握手。

```bash
# 签发（返回 cert_pem / key_pem / ca_pem）
curl -H "Authorization: Bearer $KEY" -X POST http://127.0.0.1:8088/api/v1/certs \
  -d '{"agent_id":"dev-agent","ttl_days":365}'

# Agent 配置 mtls.enabled=true 并指向证书文件后重连
```

## 私有化部署

```bash
chmod +x scripts/private-install.sh
./scripts/private-install.sh
helm upgrade --install ip deploy/helm/intranet-penetration
```

## 能力一览

| 阶段 | 能力 |
|------|------|
| P0–P2 | 隧道、多租户、HTTPS/域名、Dashboard、QUIC/集群/resume/OIDC |
| P3 | E2E 回程加密、多区域、私有化套件、SLA/合规导出 |
| **当前** | **Access Policy、Agent mTLS（签发/吊销/CN 校验）** |

## API 摘录

```bash
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8088/api/v1/policies
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8088/api/v1/certs
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8088/api/v1/certs/ca -o ca.crt
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8088/api/v1/sla/report
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8088/api/v1/compliance/export -o compliance.json
```

## 路线图

- **P0**：单体 Server、Token、HTTP/TCP、yamux、重连
- **P1**：多租户、HTTPS/自定义域名、Dashboard、配额与审计
- **P2**：Edge 集群、QUIC、会话恢复、OIDC
- **P3**：E2E 回程加密、多区域、私有化套件、SLA/合规导出
- **当前**：Access Policy + Agent mTLS
