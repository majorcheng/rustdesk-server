# 跨节点连接失败排查

## Observations

- 用户报告：Windows 客户端注册到 B、macOS 客户端注册到 A 时连接失败；两台客户端都注册到 A 或都注册到 B 时可以连接。
- A/B 都运行 RustDesk Server `1.1.17`，`rustdesk-hbbs.service` 和 `rustdesk-hbbr.service` 均为 active。
- A 与 B 的 NodeLink 已建立并持续保持：B 的 `hbbs` 到 A 的 `60.205.236.85:21200` 为 `ESTAB`。
- A 日志已记录 `federation connected: node=B relay=166.111.5.220:21117`；B 日志已记录 `federation connected: node=A`。
- A 使用 `FEDERATION_RELAY=60.205.236.85:21117`，B 使用 `FEDERATION_RELAY=166.111.5.220:21117`，B 使用 `RELAY_UPSTREAM=60.205.236.85:21117`。
- A/B 的现有 RustDesk server 公钥一致，客户端/Relay `KEY` 不是当前首要差异。
- 在最近一次服务启动后的已读取日志中，没有观察到对应失败会话的 PunchHole、RequestRelay 或 Relay upstream 数据事件；尚未取得一次带时间标记的现场复现。
- 同节点连接可用，说明各节点本地注册、单节点 rendezvous 和本地 Relay 基本工作；故障边界在跨节点 peer lease、跨节点控制消息回程或级联 Relay 路径。

## Hypotheses

### H1: 跨节点 Relay 控制消息/地址回程不完整（ROOT HYPOTHESIS）

- Supports: 同节点工作而跨节点失败；跨节点需要额外处理 `RequestRelay`、`RelayResponse` 和 route；B 的 Relay 还要把首个请求级联到 A。
- Conflicts: 当前尚未有一次失败连接对应的 Relay 日志，不能确认请求是否到达 hbbr。
- Test: 复现一次并同时检查 A/B hbbs、A/B hbbr 是否出现同一时间的 RequestRelay/配对日志；若 A/B hbbs 有控制消息但 A hbbr 没有配对，锁定 Relay 控制或地址回程。

### H2: B peer lease 没有在 A 上正确可用

- Supports: A 的远程 peer 目录是内存状态，跨节点依赖注册快照和 owner 路由；当前日志只证明 NodeLink 连接，不证明目标 peer lease 已同步。
- Conflicts: B 在 NodeLink 建立时会发送本地快照，代码路径存在；尚未知道目标 Windows peer 的 ID。
- Test: 在 B 客户端重新注册后复现，观察 A 是否进入对应的远程 peer lookup/转发路径；必要时增加短期诊断日志或使用目标 ID 做精确核对。

### H3: PunchHole 的 source address 在 NAT/IPv4 映射后无法匹配 route

- Supports: route key 使用 `source_addr|target_id`，跨节点回程依赖客户端上报的编码地址与 A/B 看到的地址完全一致；A/B 的服务存在 IPv4-mapped 地址和公网 NAT。
- Conflicts: 同一 RustDesk 协议在单节点可用；当前没有失败请求的具体地址记录。
- Test: 复现时检查 PunchHoleSent/LocalAddr 是否抵达 B/A，以及 route 是否命中；若请求到达而回程没有发送给源客户端，确认 key 不一致。

### H4: B hbbr 到 A hbbr 的上游连接或 Relay key 校验失败

- Supports: 跨节点 Relay 依赖 `RELAY_UPSTREAM`，单节点连接不经过该路径。
- Conflicts: B 到 A 的 `21117` TCP 探测已通过，A/B 的 server 公钥一致；但 TCP 可达不等于 RustDesk `RequestRelay` 配对成功。
- Test: 强制客户端使用 Relay 后复现，检查 B hbbr 是否记录 upstream connect/send error，A hbbr 是否记录对应 UUID 的 New relay request 和 paired。

## Experiments

### 2026-10-05 19:49:44-19:49:53 失败复现

- 用户确认 Mac(A) 到 Windows(B) 的连接再次失败。
- B 的抓包确认 Windows(B) 向 B 的 `166.111.5.220:21116` 和 `:21117` 发起连接；B 同时向 A 的 `60.205.236.85:21117` 建立 Relay upstream 连接。
- A 的 hbbr 在同一时间窗口收到来自 B Relay 的多个 `New relay request`，但没有出现对应 UUID 的 `got paired` 或 `Both are raw`。
- A 的抓包没有看到 Mac(A) 向 A 的 `60.205.236.85:21117` 发起匹配的 Relay 请求；A 的 hbbs 也没有新的客户端注册事件。
- 结论：B 到 A 的 Relay upstream 传输可达，但 A 没有收到源端对应的控制流，故障发生在跨节点 rendezvous 控制消息回程，而不是 Relay TCP 可达性或 Relay 密钥校验。

### 根因收敛

- A 收到 Mac(A) 的 `PunchHoleRequest` 后，经 NodeLink 把 `PunchHole` 转发给 B；B 的 `handle_federated_to_peer` 会记录 `source_addr|target_id` 路由。
- Windows(B) 可能通过 UDP 返回 `PunchHoleSent` 或 `LocalAddr`。当前 `handle_udp` 对这两种消息无条件丢弃，而 TCP handler 才调用 `handle_hole_sent`/`handle_local_addr`。
- 因此 B 无法用已记录的联邦路由把目标端响应转发回 A；Windows(B) 仍会尝试 Relay，形成 A hbbr 只有 B 侧 upstream 流、没有源端匹配流的现象。
- 最小修复：UDP 收到 `PunchHoleSent`/`LocalAddr` 时，先按编码后的源地址和目标 ID查询已建立的联邦路由；只有命中路由才调用现有回程处理器，没有路由时继续丢弃，保留原有反射/放大防护边界。
- 路由单元测试还发现：原 `route_for` 在传入非空但错误的目标 ID 时会退回到同一源地址的任意路由。修复后非空目标 ID 必须精确匹配；只有空 ID（例如部分 `RelayResponse` 只携带 `pk` 的情况）才保留按源地址回退。

### 2026-10-05 20:18 左右修复后复现

- A/B 已部署同一修复构建，服务均 active，B 到 A 的 NodeLink 已重新建立。
- A hbbr 收到 Mac(A) 侧的 Relay 请求：`36b0ad68-d5e4-4587-8847-7743134317fb`、`2f7d6e3f-8cb6-4e19-b7a8-8ced9c2a5773`、`eea9f3ac-d59e-49f9-a9ed-c0b15c2ec199`。
- 同一失败尝试后，A hbbr 又收到来自 B Relay upstream 的请求：`c6c3bdab-e717-45bb-94db-cafcce11e31a`、`3000d046-e7c9-4765-9268-b98831b7c980`、`439b1d5c-20b4-4a45-82d0-f31c3617a5f7`、`cc221c9a-00a4-4750-8b92-ab6820194af9`、`7737a966-ffde-4551-bf3c-53a4b1783fca`、`90279405-3c71-4004-a453-ef323ade5174`；没有任何 UUID 出现 `got paired`。
- 这说明 UDP 回程放行后，源端已经能尝试 Relay，但目标端通过 B upstream 发到 A 的 Relay 请求没有携带同一个 UUID，或源端与目标端请求并非同一联邦会话。

### H5: 跨节点 `RequestRelay` 的 UUID/目标端转发链路不一致

- Supports: A hbbr 同时看到两侧请求但 UUID 集合完全不相交；单节点正常配对；B hbbr upstream 会原样转发收到的 `RequestRelay` 帧。
- Test: 在 A `handle_remote_forward_request`、B `handle_federated_to_peer` 和 UDP 路由回程处记录目标 ID、`RequestRelay.uuid`、源地址与消息方向；对同一次复现逐跳比较 UUID。
- 预期：A 转发的 `RequestRelay.uuid` 应在 B 发送给 Windows(B) 后保持不变，并由 B hbbr upstream 原样带到 A。

### H9: `RelayResponse` 回程使用了错误的 route 地址（ROOT HYPOTHESIS）

- Supports: A 在 21:09:25.108469 收到 Mac(A) 到 `21116` 的 84 字节 TCP frame；去除 2 字节 `BytesCodec` 头后，protobuf 是 `RelayResponse`，其中 `socket_addr` 解码为 Windows(B) 的 `222.131.66.42:48937`，`id=428172967`。A 当前 `forward_relay_response` 却用 Mac TCP 源地址 `36.112.108.165:52874` 查询 route，而联邦 route 是按 Windows(B) 的 source address 和目标 Mac ID 建立的。
- Conflicts: 还没有把该地址修正部署到现场并看到 `federation to source RelayResponse`，因此当前只确认了路由键不一致，尚未确认修复后的真实 Relay 配对。
- Test: 让 `forward_relay_response` 用 `RelayResponse.socket_addr` 解码后的地址查询 route；复现同一连接时，预期 A 产生 ToSource `RelayResponse`，B 收到源端响应并向客户端返回 Relay 控制，A/B hbbr 最终出现同一 UUID 的配对事件。

### H9 实验结果（2026-10-05）

- 从 A 抓包提取的 TCP 应用 frame 为：`49 01`（长度头）+ `9a 01 4f ...`（`RelayResponse`），其中 `socket_addr` 字节为 `2c c5 06 0c b2 2e c3 13 37 83 01`。
- 按 `AddrMangle::decode` 解码后得到 `222.131.66.42:48937`；该地址与 B 抓包中 Windows(B) 发往 B:21116 的 `222.131.66.42:48937` 完全一致，而与 Mac(A) TCP 源地址不同。
- 结论：H9 的 route 查找地址错误已被原始协议字节确认；下一步可实施生产修复，并增加回归测试验证 RelayResponse 应以编码的 `socket_addr` 作为 route key。

### H10: H9 修复后 `RelayResponse` 仍未观察到 ToSource（ROOT HYPOTHESIS）

- Observation: 修复版 A 在 21:40:27.594915 已记录 ToPeer `PunchHole`，Mac 在 21:40:27.607208 返回 `RelayResponse`；其 `socket_addr` 解码为 `222.131.66.42:49659`，与 A 记录的 route 源地址和 B 的 TCP PunchHoleRequest 一致，但 A/B 日志没有 `federation to source`。
- H10a: `RelayResponse` 解析分支没有执行（例如 frame 解码或 protobuf 解析失败）。支持：当前解析失败分支静默丢弃；冲突：抓包 protobuf 外层是合法 `RelayResponse`。
- H10b (ROOT): `forward_relay_response` 执行了，但 route 查询仍未命中（route 生命周期、目标 ID 或地址规范化仍有差异）。支持：现场没有 ToSource 日志；冲突：ToPeer 日志显示同一地址和 ID 已建立 route。
- H10c: ToSource 已发送，但 B 的事件处理或客户端 TCP sink 没有记录；支持：当前 B 日志没有回程日志；冲突：A/B NodeLink 持续 ESTAB。
- Test: 在 RelayResponse 分支和 `forward_relay_response` route 查询各增加一条临时日志，记录客户端源地址、编码地址、ID 和 `route.is_some()`；复现一次后据此选择后续修复方向，并删除临时日志。

### H10 实验结果（2026-10-05）

- A 在 21:49:57.261455、21:50:00.260584、21:50:06.260397 均进入 `RelayResponse` 分支；解码出的 B 源地址为 `222.131.66.42:49858`，三次 `route=true`。
- H10a（解析分支未执行）和 H10b（route 未命中）均拒绝；H10c 保留：ToSource 可能未到达 B，或 B 收到后未进入 `handle_federated_to_source`。B 没有对应 `federation to source`，也没有 `federation event failed`。

### H11: ToSource Forward 在联邦边界丢失（ROOT HYPOTHESIS）

- Supports: A 已确认 route 命中并调用 `forward_response`，B 的客户端 TCP 请求仍只收到 ACK，没有 hbbs 返回数据；B 没有 Forward/ToSource 处理日志。
- Conflicts: B pcap 可见 A→B NodeLink 持续有数据，但尚未能从加密帧区分具体 Forward 类型。
- Test: 在 A `forward_response` 发送前记录目标节点/源节点，在 B `FederationEvent::Forward` 入口记录 kind/target/source；若 A 有 dispatch 而 B 无 receive，检查 `send_node`/链路；若 B 有 receive 而无 ToSource，检查 target/source 校验或消息解析。

### H11 实验结果（2026-10-05）

- A 在 21:59:07.770373、21:59:10.767265、21:59:16.768730 均记录 `federation to source dispatch ... target_node=B`。
- B 没有任何对应的 `federation forward received`，也没有事件失败日志；NodeLink TCP 仍 ESTAB 且持续有 A→B 数据。
- H11 的“Forward 未在 B 侧进入事件处理”得到确认；下一步检查 A 的 link channel/writer 是否静默丢弃该消息。

### H12: A 的 NodeLink 发送队列或 writer 静默失败（ROOT HYPOTHESIS）

- Supports: `send_node` 对 channel 发送结果调用 `.ok()`，writer 对 `send_wire` 错误直接 `break`；两处都没有日志。H11 中 dispatch 有记录而 B 无 receive，且小型 Forward 帧未在包长序列中明显出现。
- Conflicts: TCP 连接保持 ESTAB，A 仍发送大量 Peer/心跳帧，尚未证明 Forward 的 channel send 失败。
- Test: 记录 `send_node` 缺少 link/队列关闭和 writer `send_wire` 错误；复现时若出现任一日志，修复 link 生命周期/错误恢复；若无日志，继续检查 Forward 序列化与帧顺序。

### H12 实验结果（2026-10-05）

- A/B NodeLink 在 22:08 仍为 ESTAB；A 没有 `queue is closed` 或 `writer failed`，B 没有 `federation forward received`。
- A 记录的 `federation send node=A link is missing` 与当前 RelayResponse dispatch 的 `target_node=B` 不一致，不能作为该 Forward 丢失的直接证据；H12 未确认。

### H13: Forward 未进入实际 B writer（ROOT HYPOTHESIS）

- Supports: A 记录了 `dispatch target_node=B`，但 B 没有收到事件；当前没有 Forward 专用的 enqueue/dequeue 证据，且 NodeLink 中可见的约 180 字节帧符合 Ping/Pong，不像 RelayResponse Forward。
- Conflicts: A→B 大量 Peer 帧持续写出，说明同一 TCP writer 活跃；尚未证明 Forward 在 `send_node` 前后的具体状态。
- Test: 仅对 `Message::Forward` 记录 `send_node` 入队、writer 出队和 B 侧接收；不改变队列或 wire format。

### H13 实验结果（2026-10-05）

- B 的 ToPeer 路径记录 `send-first forward node=A link_id=0` 和 `writer forward node=A`，A 能收到并处理 ToPeer。
- A 的 RelayResponse dispatch 之后没有 `send forward node=B` 或 `writer forward node=B`，B 没有接收事件；A 同时出现与目标不一致的 `send node=A link is missing`。H13 将问题收敛到 `forward_response` 调用内部，或一条错误的 A 侧 send_node 路径。

### H14: `forward_response` 在调用 federation send 前失败（ROOT HYPOTHESIS）

- Supports: dispatch 日志位于 `forward_response` 调用前；其内部 `msg.write_to_bytes()?` 的错误被上层 `allow_err!` 以 debug 静默处理，之后不会出现 send/writer 日志。
- Conflicts: protobuf 消息通常可编码，尚未取得序列化结果。
- Test: 在 `forward_response` 入口、protobuf 编码成功/失败和调用 `send_forward` 前记录日志；若编码失败，保留显式错误传播并修复消息构造；若成功，继续追踪 send_forward。

### H14 实验结果（2026-10-05）

- A 的 `forward_response` 编码成功：`payload=181`，因此 H14（protobuf 编码失败）被拒绝。
- 日志同时显示：上层 route dispatch 为 `target_node=B source_node=A`，进入 `forward_response` 后却发送 `target_node=A`，并出现 `federation send node=A link is missing`；B 只记录了 ToPeer writer，没有收到 ToSource。

## Root Cause

`forward_response` 把 `ForwardMessage.source_node` 当成下一跳节点，导致 A 将所有 ToSource 回程发送给 A 自己；正确的下一跳是 route 的 `target_node`。RelayResponse 之前因 route 地址取错而未暴露这一方向错误，修复地址后该错误成为实际阻断点。

## Fix

- `forward_response` 使用 `route.target_node` 发送 Forward；PunchHoleResponse、LocalAddr、RelayResponse 和失败响应共用该修复。
- 保留 route 地址规范化、精确目标 ID 和 HelloAck relay 同步修复；临时现场日志在最终提交前删除。

### 2026-10-05 20:42 反向复现与 H6 根因

- Windows(B) 连接 Mac(A) 时，B hbbs 明确收到 `PunchHoleRequest id=428172967 source=[::ffff:222.131.66.42]:48401 remote_owner=Some("A")`，说明 B 的远程 owner 租约和 NodeLink 路由均可用。
- B 的联邦连接日志仍为 `federation connected: node=A relay=`；A 的主节点 Relay 地址没有同步到 B。
- 抓包确认 B 客户端访问 B 的 `21116`，B 通过已建立的 NodeLink 向 A 发送控制帧；A hbbr 只看到 Mac(A) 侧的 Relay 请求，没有看到 B upstream 的配对请求。
- 源码确认：`run_server_connection` 收到 B 的 Hello 时知道 A 自己的 Relay 地址，但发送的 `HelloAck` 只有 `node_id`；`run_client_connection` 也只解析 `node_id` 并把空字符串传给 `run_link`。因此 B 的 `relays[A]` 为空，`federation.relay_for("A")` 返回空地址。
- 根因：联邦握手没有把对端 Relay 地址同步给 edge 节点。反向请求时 B 无法为 Windows(B) 生成可用的 A Relay/级联信息，导致 Relay 控制流无法完成配对。
- 修复方向：内部 `HelloAck` 增加 `relay_server` 字段；发送端填入本节点 Relay，接收端把它传给 `run_link`。字段使用 serde 默认值，允许旧节点发送不带该字段的握手帧继续连接，但旧节点无法提供跨节点级联 Relay 能力。

### 2026-10-05 20:52 H6 后复现

- H6 已生效，B 日志确认 `federation connected: node=A relay=60.205.236.85:21117`。
- Windows(B) 的 `PunchHoleRequest id=428172967` 已在 B 命中 `remote_owner=Some("A")`，但 B 在同一尝试中没有进入 `RequestRelay` 诊断日志；A hbbr 只看到 Mac(A) 侧的 `New relay request`。
- A/B 在 H6 重启后的日志中没有出现目标 Mac/Windows 的新 `update_pk`。联邦 PeerMap 是内存状态，服务重启后若客户端尚未重新注册，目标的 socket/lease 可能尚未恢复。
- 下一实验：记录 RegisterPeer、联邦 ToPeer 消息及 UDP `PunchHoleSent`/`LocalAddr` 的 route 命中，确认是否为注册恢复时序或仍有控制回程缺口。

### H15 实验结果：最终回程修复（2026-10-05 22:44）

- `forward_response` 已改为使用 `ForwardMessage.target_node` 作为下一跳。原实现错误地再次使用 `source_node`，导致 A 收到 Mac(A) 的 `RelayResponse` 后把 ToSource Forward 发回 A 自身；H14 的 `federation send node=A link is missing` 日志直接证明了这个方向错误。
- H15 构建已部署到 A/B，A/B 的 `hbbs` SHA256 均为 `6694592484a829fe7da77ccd985bb8fbe0998570183df2c35b640c85f6f8fce9`，服务均为 active，NodeLink 日志显示 A/B 互相记录对端 Relay 地址。
- A 的 `hbbr.log` 在 22:44:50 记录 `New relay request 62786afd-d5d7-4f47-b913-1ec6645969a5`，随后以相同 UUID 记录来自 `166.111.5.220` 的 `got paired` 和 `Both are raw`，22:44:53 关闭。22:44:56 的第二次请求 `17e8d6bb-4cff-4749-93cc-10c5697222ef` 也以相同顺序完成配对并在 22:44:58 关闭。
- 用户最终确认从 Windows(B) 连接 Mac(A) 成功；A/B 最终现场抓包已复制为 `/tmp/rustdesk-final-h15-A.pcap` 和 `/tmp/rustdesk-final-h15-B.pcap`。
- B 的 `/var/log/rustdesk-server/hbbr.log` 在 20:51 服务重启后没有追加这两次事件，因此最终 Relay 配对证据以 A 端同一 UUID 的两端配对记录和用户 E2E 结果为准，不把缺失的 B 文件日志描述为已观测。

### 最终限制

- 本次实现是 hbbs 控制面联邦、在线 peer 租约同步、跨节点 PunchHole/Relay 控制消息转发和 Relay 级联，客户端协议保持兼容。
- 它不是 tinc 式 TUN/TAP、二层 Ethernet、MAC 学习或广播复制网络；RustDesk `PeerDiscovery` 的局域网 UDP 广播也不会自动跨独立 hbbs 节点传播。
- 服务重启会清空进程内在线租约；客户端需要重新注册才能恢复跨节点在线状态。
