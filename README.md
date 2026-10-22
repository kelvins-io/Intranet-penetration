# Intranet Penetration

工业级内网穿透平台。当前进度：**P1**（多租户、HTTPS、配额/审计、Dashboard）。

## 架构

```
公网用户 ──► HTTP :8088 / HTTPS :8443 ──mux──► Agent ──► 内网服务
公网用户 ──► TCP :20000+                 ──mux──► Agent ──► 内网服务
Agent     ──► Mux :7700  （yamux：控制流 + 数据流）
管理面    ──► /dashboard + /api/v1/*（Bearer API Key）
```

## 快速开始

```bash
go mod tidy

# 终端 1：内网示例 HTTP 服务
make run-demo

# 终端 2：Server
make run-server

# 终端 3：Agent
make run-agent

# HTTP 穿透（多租户路径：/{tenant_slug}/{tunnel}/）
curl http://127.0.0.1:8088/default/demo/

# Dashboard
open http://127.0.0.1:8088/dashboard/
# 默认账号 admin@localhost / admin123

# 控制面 API
curl -u '' -H "Authorization: Bearer <api_key>" http://127.0.0.1:8088/api/v1/stats
# api_key 见首次启动后的 data/store.json 或登录接口返回
```

HTTPS 默认开启（`:8443`，`auto_tls` 自动生成自签证书到 `data/`）。

## P1 能力

| 能力 | 说明 |
|------|------|
| 多租户 | Tenant / User / Agent Token，隧道按租户隔离 |
| 鉴权 | 密码登录 + API Key；Agent 使用租户 Token |
| HTTPS | `:8443`，可配置证书或自动自签 |
| 自定义域名 | Agent 声明 `domain`，或 Dashboard/API 绑定 |
| 配额 | 每租户 max_agents / max_tunnels / max_tcp |
| 审计 | 连接、访问、配置变更写入 `data/store.json` |
| Dashboard | `/dashboard/` 查看隧道、Token、审计 |

### 路由方式

1. 路径：`http://host/{tenant_slug}/{tunnel}/...`
2. 子域：`{tunnel}.{tenant}.{base_domain}`（默认 `*.default.tunnel.local`）
3. 自定义域名：Host 精确匹配

## 配置

- `configs/server.yaml`：监听、Token、TLS、管理员、数据目录
- `configs/agent.yaml`：Server 地址、租户 Agent Token、隧道列表

## 路线图

- **P0**：单体 Server、Token、HTTP/TCP、yamux、重连
- **P1（当前）**：多租户、HTTPS/自定义域名、Dashboard、配额与审计
- **P2**：Edge 集群、QUIC、会话恢复、OIDC
- **P3**：E2E 加密、多区域、私有化套件
