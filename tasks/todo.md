# 中心化边缘节点联邦

- [x] 增加 A 主控与 B/C/D 边缘节点的出站控制链路和 peer 租约同步
- [x] 转发跨节点 PunchHole/Relay 控制消息，保持客户端协议兼容
- [x] 增加跨节点 Relay 路由，边缘 hbbr 可级联到 A
- [x] 运行聚焦测试和构建验证；仓库级格式检查仍受既有未格式化文件阻断

影响范围：`src/rendezvous_server.rs`、`src/relay_server.rs`、新增联邦模块及配置文档。
完成标准：边缘节点可出站接入 A，A 能发现边缘客户端并建立跨节点 RustDesk 会话；本地会话行为保持可用。

# 跨节点 UDP 打洞回程修复

- [x] 仅对命中联邦路由的 UDP `PunchHoleSent`/`LocalAddr` 执行回程转发
- [x] 增加路由匹配回归测试并完成 Rust 检查
- [x] 构建并部署 A/B，完成 Windows(B) 到 Mac(A) 的真实连接验证

影响范围：`src/rendezvous_server.rs`、必要的测试与调试记录。
完成标准：跨节点连接成功；A 的 hbbr 记录同一 Relay UUID 的配对事件；无路由 UDP 回程仍被丢弃。

验证记录：H15 版本部署到 A/B 后，A 的 `hbbr.log` 在 2026-10-05 22:44:50
记录 Relay UUID `62786afd-d5d7-4f47-b913-1ec6645969a5` 的 `New relay request`、
`got paired` 和 `Both are raw`，22:44:53 关闭；22:44:56 的第二次请求
`17e8d6bb-4cff-4749-93cc-10c5697222ef` 也完成相同配对。用户确认 Windows(B) 到
Mac(A) 连接成功。B 的 `hbbr` 文件日志在 20:51 服务重启后未追加本次事件，A 端
记录的第二个端点地址为 B Relay 公网地址；最终抓包保存在 `/tmp/rustdesk-final-h15-A.pcap`
和 `/tmp/rustdesk-final-h15-B.pcap`。

# Linux Release 工作流

- [x] 移除本分支不需要的 Docker 构建和推送 jobs
- [x] 保留 Linux amd64 binary/DEB 构建，并汇总为单一 GitHub Release
- [x] 增加 tag/包版本校验、校验和以及手动 workflow_dispatch 发布入口
- [x] 通过 GitHub Actions 实际生成并核验 v1.1.17 Release 资产

影响范围：`.github/workflows/build.yaml`、Linux binary/DEB Release 资产。
完成标准：Release 至少包含 Linux amd64 binary 压缩包和 `rustdesk-server-*.deb`，且 workflow 不依赖 Docker secrets 或跨编译容器。
