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

# 修复 1.1.18 Release 版本一致性

- [x] 核对失败 Actions、所有发布版本来源及当前分支，复现锁文件不一致错误
- [x] 同步 Debian changelog、Cargo.lock 和安装器版本，去除手动发布表单的过期默认标签
- [x] 验证工作流版本校验、Debian 版本解析和 CI 同参数的 Linux release 构建
- [x] 完成详细中文提交并推送 master，由用户手动运行 Actions

影响范围：`Cargo.lock`、`debian/changelog`、`ui/setup.nsi`、`.github/workflows/build.yaml`。
完成标准：发布标签、Cargo 包、二进制与 Debian 包元数据均为 `1.1.18`，`--locked` 构建通过；不触发 Actions 或创建发布标签。

# 跟进上游 2026-10 修复

- [x] 合并上游 `5e37f45` 打洞请求内存上限与 peer ID 长度修复
- [x] 合并上游 `873230e` 密钥文件权限、原子公钥写入与错误传播修复
- [x] 解决 `src/relay_server.rs`、`src/rendezvous_server.rs` 冲突，保留本地联邦与 Relay 上游逻辑
- [x] 完成依赖、文档、回归测试和 release 构建验证
- [x] 创建中文合并提交并推送现有 `origin/master`

影响范围：`src/common.rs`、`src/peer.rs`、`src/rendezvous_server.rs`、`src/relay_server.rs`、`Cargo.toml`、`Cargo.lock`、`docs/environment-variables.md`、测试和本记录。
完成标准：上游两组修复进入自有 `master`；`1.1.18`、联邦、Relay 上游行为保留；锁定构建、库测试、协议回归测试和差异检查通过。

验证记录：`OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu OPENSSL_INCLUDE_DIR=/usr cargo test --locked --lib` 通过（17 passed）；同环境下 `cargo test --locked --test protobuf_recursion` 通过（1 passed）；`cargo build --locked --release --all-features --bin hbbs --bin hbbr --bin rustdesk-utils` 通过；`git diff --check` 通过。

# 准备 1.1.19 Release

- [x] 定位 workflow 版本校验失败并核对当前分支、远端和所有发布版本来源
- [x] 同步 Cargo、锁文件、Debian changelog 和 Windows 安装器到 `1.1.19`
- [x] 验证 workflow 版本校验、锁定元数据和 release 构建
- [x] 创建中文提交并推送 `master`，再运行 `v1.1.19` Release workflow

影响范围：`Cargo.toml`、`Cargo.lock`、`debian/changelog`、`ui/setup.nsi` 和本记录。
完成标准：workflow 输入 `v1.1.19` 时与 Cargo 和 Debian 首条版本记录一致；锁定构建继续通过；历史 `1.1.18` 记录保留。

验证记录：workflow 等价版本校验通过；`dpkg-parsechangelog --count 1 --show-field Version` 输出 `1.1.19`；`cargo metadata --locked --no-deps` 返回 `hbbs 1.1.19`；`OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu OPENSSL_INCLUDE_DIR=/usr cargo build --locked --release --all-features --bin hbbs --bin hbbr --bin rustdesk-utils` 通过；`git diff --check` 通过。

# 修复联邦过期本地 Peer 阻塞

BDD 验收场景：

- 当 B 从数据库载入的 Peer 已超过注册超时，随后收到 A 的有效租约时，B 将该 Peer owner 更新为 A，并能把它作为在线远端 Peer 路由。
- 当 B 的本地 Peer 仍在注册超时内，收到 A 的同 ID 租约时，B 保留本地 owner、地址和密钥，不被远端租约抢占。

- [x] 让远端租约仅覆盖已过期的本地 Peer，并统一在线判断使用的注册超时
- [x] 增加数据库过期记录和新鲜本地记录的回归测试
- [x] 运行聚焦测试、库测试、锁定构建和差异检查
- [ ] 创建中文提交并推送现有 `origin/master`

影响范围：`src/peer.rs`、`src/rendezvous_server.rs`、本记录。
完成标准：上述两个场景通过；联邦在线判断继续使用同一超时契约；不修改生产 A/B 配置或服务状态。

验证记录：`cargo test --locked --lib` 通过（19 passed）；`cargo test --locked --test protobuf_recursion` 通过（1 passed）；`OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu OPENSSL_INCLUDE_DIR=/usr cargo build --locked --release --all-features --bin hbbs --bin hbbr --bin rustdesk-utils` 通过；`git diff --check` 通过。未部署或重启 A/B。
