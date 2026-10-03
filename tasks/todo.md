# 中心化边缘节点联邦

- [x] 增加 A 主控与 B/C/D 边缘节点的出站控制链路和 peer 租约同步
- [x] 转发跨节点 PunchHole/Relay 控制消息，保持客户端协议兼容
- [x] 增加跨节点 Relay 路由，边缘 hbbr 可级联到 A
- [x] 运行聚焦测试和构建验证；仓库级格式检查仍受既有未格式化文件阻断

影响范围：`src/rendezvous_server.rs`、`src/relay_server.rs`、新增联邦模块及配置文档。
完成标准：边缘节点可出站接入 A，A 能发现边缘客户端并建立跨节点 RustDesk 会话；本地会话行为保持可用。
