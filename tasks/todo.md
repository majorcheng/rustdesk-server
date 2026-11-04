# 准备 1.1.22 Release

- [x] 同步 Cargo、Cargo.lock、debian/changelog 和 Windows 安装器到 1.1.22。
- [x] 汇总联邦只读目录、跨节点 Relay 地址改写、过期租约修复和文档。
- [x] 运行锁定检查与聚焦测试；不做提交、打 tag 或触发发布，等待手动发布。

影响范围：`Cargo.toml`、`Cargo.lock`、`debian/changelog`、`ui/setup.nsi`、本记录。

# 联邦只读目录与跨节点 Relay 修复

目标：让 A 的管理 API 能读取本机 hbbs 的本地/联邦 peer 目录，并让 RustBot 跨节点 Relay
控制请求携带目标 edge 的本地 relay 地址。

- [x] hbbs 新增 loopback-only 只读目录：peer 快照分页、单 peer 身份查询、Bearer token。
- [x] 目标 edge hbbs 在 `handle_federated_to_peer` 中把 `RequestRelay.relay_server`
  改写为本地 relay；空配置返回 `RelayResponse.refuse_reason`。
- [x] `PeerMap::snapshot` 只发布仍可用的本地 peer；修复联邦重连补发过期租约后短暂复活的问题。
- [x] 目录快照包含 site、owner、online、source_ip、site 源地址和最后控制观察时间。
- [x] 补 peer 目录/远端优先/过期租约/relay 改写聚焦测试。
- [x] 更新 `docs/environment-variables.md` 的联邦、共享签名密钥和目录说明。

影响范围：`src/federation.rs`、`src/peer.rs`、`src/database.rs`、
`src/federation_directory.rs`、`src/rendezvous_server.rs`、`src/lib.rs`、
`docs/environment-variables.md`、本记录。

验证记录：`cargo check --lib` 通过；`cargo test --lib peer::tests` 通过（6 passed）；
`cargo test --lib rendezvous_server::tests` 通过（8 passed）。本机没有 Linux A/B 环境，
未跑真实三跳 RustNet E2E、真实目录 HTTP 和跨站点密钥验签；未部署、未重启服务。

# QUIC relay 传输

目标：RustBot 的 `RustBot(B) → relay(B) → relay(A) → RustBot(A)` 全链路可以走 QUIC/UDP，
复用现有 hbbr 的 UUID 配对，原版 RustDesk 继续走 TCP。

- [x] hbbr 新增 QUIC listener（`RELAY_QUIC`、`RELAY_QUIC_BIND`、`RELAY_QUIC_PORT`）
- [x] hbbr edge 新增 QUIC upstream（`RELAY_UPSTREAM_QUIC`）与 IPv6 优先
- [x] `RequestRelay.token` 做 bot/stock 分流，空 secret 时 fail closed
- [x] pin 模式证书校验（`sha256:<base64 SHA-256(DER)>`），认证失败不回落 TCP
- [x] `RELAY_ROLE` 校验，默认 `standalone` 保持既有部署行为
- [x] 启动日志输出证书 pin，便于向 Bot 下发
- [x] 同步 1.1.21 版本元数据

影响范围：`src/quic_relay.rs`（新增）、`src/relay_server.rs`、`src/hbbr.rs`、`Cargo.toml`、
`Cargo.lock`、`debian/changelog`、`ui/setup.nsi`、`docker-compose.yml`、`docker/Dockerfile`、
`docs/environment-variables.md`、`docs/rustbot-udp-relay-plan.md`、本记录。
完成标准：`v1.1.21` 版本校验通过；stock 客户端仍走原有 TCP 路径；开 QUIC 但缺 token secret 时启动失败。

验证记录：`cargo test --locked --offline --bin hbbr` 通过（13 passed）；`cargo test --locked --offline --lib` 通过（21 passed）；
`cargo build --locked --offline --release --bin hbbr` 通过；`dpkg-parsechangelog --count 1 --show-field Version` 输出 `1.1.21`；
`cargo metadata --locked --no-deps` 返回 `hbbs 1.1.21`；证书生成/复用与 pin 计算已在本机验证并部署到 A/B。
未跑真实三跳 E2E（需新版 hbbr 部署到 A/B 后验证）。

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
- [x] 创建中文提交并推送现有 `origin/master`

影响范围：`src/peer.rs`、`src/rendezvous_server.rs`、本记录。
完成标准：上述两个场景通过；联邦在线判断继续使用同一超时契约；不修改生产 A/B 配置或服务状态。

验证记录：`cargo test --locked --lib` 通过（19 passed）；`cargo test --locked --test protobuf_recursion` 通过（1 passed）；`OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu OPENSSL_INCLUDE_DIR=/usr cargo build --locked --release --all-features --bin hbbs --bin hbbr --bin rustdesk-utils` 通过；`git diff --check` 通过。修复提交 `ad39609` 已推送到 `origin/master`；未部署或重启 A/B。

# 修复 hbbs UDP 中继目标不可达

BDD 验收场景：

- 当数据库中的过期 Peer 没有可用的 UDP 地址时，客户端发起 RequestRelay，hbbs 不得把消息发往 `0.0.0.0:0`，而应返回带 `refuse_reason` 的 RelayResponse。
- 当 Peer 注册仍在超时内且地址可路由时，RequestRelay 继续按原路径转发，行为不变。
- 当联邦转发的目标 Peer 离线或不存在时，源节点收到 RelayResponse，而不是 PunchHoleResponse。
- 当单条 UDP 报文的响应发送失败时，日志记录目标与原因，重建监听以清空 tokio-util 保留的失败帧。

- [x] 为 Peer 增加“注册新鲜且地址可投递”的唯一判定，PunchHole 与 Relay 共用
- [x] 中继请求对未知/离线 Peer 返回显式拒绝，联邦失败按请求类型返回对应响应
- [x] 在 UDP 队列入队和发送前校验目标地址，区分单包错误与监听器错误
- [x] 增加可达性判定和拒绝消息的回归测试
- [x] 同步 1.1.20 版本元数据

影响范围：`src/peer.rs`、`src/rendezvous_server.rs`、`Cargo.toml`、`Cargo.lock`、`debian/changelog`、`ui/setup.nsi`、本记录。
完成标准：过期 Peer 不再产生 UDP 发送失败；单包失败不再触发周期性 UDP 重建；`v1.1.20` 版本校验通过；不修改生产配置或服务状态。

验证记录：`OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu OPENSSL_INCLUDE_DIR=/usr cargo test --locked --lib` 通过（21 passed，含新增 2 个用例）；同环境 `cargo test --locked --test protobuf_recursion` 通过（1 passed）；`cargo build --locked --release --all-features --bin hbbs --bin hbbr --bin rustdesk-utils` 通过；`cargo metadata --locked --no-deps` 返回 `hbbs 1.1.20`；`dpkg-parsechangelog --count 1 --show-field Version` 输出 `1.1.20`；按 workflow 逻辑模拟 `v1.1.20` 版本校验通过；`git diff --check` 通过。未部署或重启任何生产服务。
