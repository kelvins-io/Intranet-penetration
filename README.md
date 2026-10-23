# Intranet Penetration

工业级内网穿透平台。当前进度：**跨 Edge TCP/UDP · 穿透探针/Trace · 控制面 HA + Resume 共享**。

## 架构

```
公网用户 ──► 任意 Edge（HTTP / 影子 TCP·UDP 端口）
              │ 本机 Agent → 直接开流
              │ 他机隧道 → /internal/stream WebSocket 中继到 Owning Edge
Agent ── QUIC → TCP → WebSocket ──► Edge
Resume / 控制面 Snapshot ──► Redis（可选 HA）
```

## 快速开始

```bash
make ci
make run-demo && make run-server && make run-agent
curl http://127.0.0.1:8088/default/demo/
curl http://127.0.0.1:8088/metrics
open http://127.0.0.1:8088/access/
```

## 跨 Edge TCP/UDP

- Owning Edge 在 `RemotePort` 上监听并登记到 Redis Registry。
- 其他 Edge 每 5s 同步「影子监听」，同端口接收流量后经 `ws://peer/internal/stream/{tcp|udp}/...` 转发。
- 本地 `OpenToAgent` 失败时也会按 cluster 位置主动 peer 中继。

## 穿透探针与 Trace

```yaml
probe_interval: 15s
probe_path: "/default/demo/"   # 可选；优先于 healthz 计入 SLA
```

- `/healthz` + `probe_path` 双探针；SLA `availability_source` 可为 `path_probe_window`
- HTTP 网关注入 `X-Request-ID`，结构化 `trace` 日志

## 控制面 HA + Resume 共享

配置 `cluster.redis_url` 后：

| 组件 | 行为 |
|------|------|
| Tunnel Registry | Redis（已有） |
| Resume Token | Redis 共享，Agent 可换 Edge 续接 |
| Control `store.json` | 双写 Redis `ip:store:snapshot`，启动 Hydrate |

无 Redis 时退回进程内存 / 本地文件。

## Access / 流量 / WS

见先前里程碑：Access Policy、Traffic（含带宽）、WebSocket 保底、`/access/` 门户、区域 discover。

## 角色拆分

| 角色 | 命令 |
|------|------|
| all | `make run-server` |
| Control | `make run-control` |
| Edge | `make run-edge` |
