# Intranet Penetration

工业级内网穿透平台。当前进度：**UDP 隧道 + 设备姿态**。

## 架构

```
公网用户 ──► Edge HTTP/TCP/UDP 网关
              │ Access → Traffic → 本机 Agent session
Agent ── Hello(+Posture) ──► Edge/Control 校验姿态策略后分配隧道
```

## 快速开始

```bash
make run-demo && make run-server && make run-agent
curl http://127.0.0.1:8088/default/demo/
open http://127.0.0.1:8088/dashboard/
```

## UDP 隧道

Agent 配置 `type: udp`，Edge 在公网端口收 UDP，经 yamux/QUIC 流以长度前缀帧中继到内网 UDP 服务。

```yaml
tunnels:
  - name: dns
    type: udp
    local_addr: "127.0.0.1:53"
```

握手成功后日志会打印 `public: host:port/udp`。Access Policy 动作可用 `udp.access`。

## 设备姿态

Agent 在 Hello 中上报 OS/Arch/Hostname/Version 及可选加密/防火墙/自定义 attrs。Control 按 `PosturePolicy` 校验，不通过则拒绝握手。

```bash
# 要求 linux/darwin 且 Agent >= 0.4.0
curl -H "Authorization: Bearer $KEY" -X POST http://127.0.0.1:8088/api/v1/posture-policies \
  -d '{"name":"corp","priority":100,"require_os":["linux","darwin"],"min_agent_version":"0.4.0","require_encrypted":true}'

# 查看最近上报
curl -H "Authorization: Bearer $KEY" http://127.0.0.1:8088/api/v1/postures
```

Agent 侧可在 `posture:` 下声明静态字段：

```yaml
posture:
  device_id: "laptop-001"
  encrypted: true
  firewall: true
  attrs:
    dept: eng
```

## 角色拆分

| 角色 | 二进制 |
|------|--------|
| Control | `make run-control`（:8090） |
| Edge | `make run-edge`（:7700/:8088） |
| all | `make run-server` |

## API 摘录

```bash
/api/v1/traffic-policies
/api/v1/posture-policies
/api/v1/postures
/api/v1/policies
```
