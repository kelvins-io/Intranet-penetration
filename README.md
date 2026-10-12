# Intranet Penetration

工业级内网穿透平台（P0）：Agent 出站建连，Server 提供控制面握手 + HTTP/TCP 数据面转发。

## 架构（P0）

```
公网用户 ──► Server HTTP Gateway (:8088) ──mux──► Agent ──► 内网服务
公网用户 ──► Server TCP Port (:20000+)   ──mux──► Agent ──► 内网服务
Agent     ──► Server Mux (:7700)  （yamux：控制流 + 数据流）
```

## 快速开始

```bash
# 依赖
go mod tidy

# 终端 1：内网示例 HTTP 服务
make run-demo

# 终端 2：Server
make run-server

# 终端 3：Agent
make run-agent

# 访问穿透后的 HTTP
curl http://127.0.0.1:8088/demo/

# 查看在线隧道
curl http://127.0.0.1:8088/api/tunnels
```

TCP 隧道启动后，Server 日志会打印分配的公网端口，例如 `127.0.0.1:20000`。

## 配置

- `configs/server.yaml`：监听地址、共享 Token、TCP 端口池
- `configs/agent.yaml`：Server 地址、Token、隧道列表（`http` / `tcp`）

## 路线图

- **P0（当前）**：单体 Server、Token 鉴权、HTTP/TCP、yamux 复用、自动重连
- **P1**：多租户、HTTPS/自定义域名、Dashboard、配额与审计
- **P2**：Edge 集群、QUIC、会话恢复、OIDC
- **P3**：E2E 加密、多区域、私有化套件
