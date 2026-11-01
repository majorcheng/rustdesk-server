# RustBot Relay QUIC 方案（quic-preferred，v1 pin）

- 状态：v0.5（2026-11-01）
- 目标仓库：`rustdesk-server`（`hbbr`）+ `rustbot`（S100 headless peer transport）
- 目标路径：`RustBot(B) → relay(B) → relay(A) → RustBot(A)`
- 传输策略：**QUIC 优先，网络不可用时回落 TCP**
- 服务端认证：**v1 只做 pin**；ca/accept_any/Vault relay role/mTLS 后置
- IPv6 范围：**仅 relay(B) → relay(A) 的 upstream 腿优先 IPv6**
- 兼容约束：原版 RustDesk、`hbbs`、现有联邦控制面继续工作；stock RustDesk 仍走 TCP

> RustBot 不是 stock RustDesk 兼容客户端。它只复用 RustDesk 的 hbbs/hbbr 注册、发现、
> 打洞和 relay 配对，peer 层是自己的 length-frame + signed handshake + secretbox。
> 本方案不承诺 RustBot ↔ stock RustDesk。

- 实现状态（2026-11-01）：v1 pin 的 hbbr QUIC listener/upstream、RustBot `PeerIo::Quic`、pin、data-plane token、IPv6 upstream 和聚焦测试已实现；真实 hbbs+B/A+两个 RustBot 的跨节点 E2E 尚未验证。`ca`/`accept_any`/Vault relay role/mTLS/node token 尚未实现。

---

## 0. 修订说明（v0.1 → v0.5）

v0.5 收窄 v1 范围，并补齐 pin 的密码学契约和失败语义。

| 评审项 | 结论 | 处理 |
|---|---|---|
| quic-required | 不符合需求 | **quic-preferred**；网络失败回落 TCP，认证失败不回落 |
| IPv6 全链路 | 不符合需求 | 只保留 **relay(B)→relay(A)** 的 IPv6 优先 |
| RustBot ↔ stock RustDesk | 不是兼容目标 | 删除该矩阵；只保留 stock↔stock 的 TCP 回归 |
| RustBot 使用 `hbb_common`/`FramedStream` | 与代码不符 | 改为 RustBot 自己的 `PeerIo` / `protocol.rs` / `QuicIo` |
| token 放在 control-plane `RequestRelay` | 会被 Agent 拒绝 | token 只放在 **hbbr data-plane open**；control-plane 继续为空 |
| S100/Vault robot 证书直接给 QUIC 用 | 不适合作为 relay TLS 证书 | 不复用 robot role；v1 用 relay server cert + pin |
| mTLS 必须 | 不必须 | v1 不做 mTLS，不需要 client cert |
| relay server auth 必须 | 可简化，但不能默认关闭 | v1 默认并只实现 **pin**；accept_any 仅后续实验模式 |
| pin 契约缺失 | 需要定义 | `sha256:<base64(SHA-256(DER cert))>` + 有效期/签名/ALPN 校验 |
| pin 失败回落 TCP | 会绕过 pin | **认证失败不回落**；只有网络失败才回落 |
| A 为 master | 需要明确 | `RELAY_ROLE=standalone` 默认；master/edge 显式配置 |
| RustBot 配置未传播 | `ClientConfig`/`AgentConfig`/`client_config()` 需要扩展 | 加入配置字段和校验，见 6.3 |
| 代码骨架不能编译 | `make_pair_` 返回 `()` | 拆成返回 `ResultType` 的 upstream helper |
| tcpdump 看 uuid | 不可行 | 日志 uuid + QUIC connection ID + 五元组关联 |

---

## 1. 结论

1. Relay 仍然是“鉴权 + 按 uuid 配对 + 透明字节泵”；QUIC 只替换传输。
2. 三条腿分别选择传输：
   - ① `RustBot(B) → relay(B)`：QUIC 优先，网络失败回落 TCP；
   - ② `relay(B) → relay(A)`：QUIC 优先，**IPv6 优先**；网络失败再试 IPv4 QUIC，最后 TCP；
   - ③ `relay(A) → RustBot(A)`：QUIC 优先，网络失败回落 TCP。
3. 两个 Bot 各连自己的本地 relay；B 的 hbbr 通过 QUIC upstream 级联到 A；A 的 hbbr 完成跨节点配对。
4. **quic-preferred 的回落只针对网络不可用**：pin/证书/ALPN 认证失败必须让当前连接失败，不能回落 TCP；否则 pin 可以被主动中间人降级绕过。
5. IPv6 只用于 ②：B 的 upstream 客户端优先解析/连接 A 的 IPv6 QUIC endpoint；①③ 可以是 IPv4 QUIC 或 TCP。
6. **v1 只实现 pin**：
   - relay 使用持久化 server cert；
   - B/Bot 校验 `sha256:<standard base64(SHA-256(DER end-entity certificate))>`；
   - pin 模式忽略 hostname/SAN，但必须校验证书有效期、TLS 签名和 ALPN；
   - 不做 CA、不做 accept_any、不做 mTLS、不做 client cert。
7. 每个 relay 一个 pin：`pin(B)`、`pin(A)` 不同；B→A upstream 使用 `pin(A)`。v1 是单 pin；轮换需要协调更新并重启；双 pin 后置。
8. Bot 的 relay 授权用 **data-plane `RequestRelay.token`**（HMAC）；QUIC listener 只接受 bot token；stock 的 TCP 路径继续接受空 token。
9. E2E：RustBot 已有的 signed handshake + secretbox 在配对后的原始字节流上继续使用；QUIC TLS 只保护逐跳。
10. v1 范围只包含：pin、QUIC client legs、B→A QUIC upstream、IPv6 ②、TCP 网络回落、data-plane token、stock TCP 回归。`ca`/`accept_any`/Vault relay role/mTLS/node token 全部后置。

---

## 2. 现状与代码事实

### 2.1 RustBot

| 事实 | 位置 |
|---|---|
| `Route` 只有 `DirectTcp` / `DirectKcp` / `Relay` | `src/lib.rs:34-39` |
| `Relay` 当前通过 TCP 连 hbbr | `src/client.rs:324-370`、`src/agent.rs:405-425` |
| hbbr 首包是 `RequestRelay`（id/uuid/licence_key/conn_type），当前**无 token** | `src/transport.rs:15-30` |
| Agent 校验 hbbs 转发的 control-plane `RequestRelay`，**拒绝非空 token** | `src/agent.rs:382-403` |
| `PeerIo` 当前只有 `Tcp` / `Kcp`，`SecurePeer` 在其上做 framing + secretbox | `src/peer.rs:20-90` |
| `KcpIo` 是 UDP 上的可靠流，带 `KcpGuard` 管理生命周期 | `src/kcp.rs:20-190` |
| 网络连接解析是 IPv4-only（`resolve_ipv4`） | `src/protocol.rs:16-70` |
| `ClientConfig` 只有 hbbs/hbbr/server_key/connect_timeout_secs | `src/config.rs:29-34` |
| `AgentConfig` 没有 QUIC/pin/token 字段；`client_config()` 只复制四个字段 | `src/config.rs:76-132` |
| 注册身份是 Ed25519，`RegisterPk`/`RegisterPeer` | `src/identity.rs`、`src/agent.rs` |
| 已有 `rustls 0.23.46`、`sodiumoxide`、`kcp-sys`，无 `hbb_common` | `Cargo.toml` |
| `DirectKcp` 是 peer-to-peer KCP；relay 只用于协商/兜底 | `src/client.rs:476-545`、`src/agent.rs:437-501` |

关键结论：

- 给 RustBot 加 QUIC 的正确切入点是 `PeerIo` 增加 `Quic(QuicIo)`，不是引入 `hbb_common::FramedStream`。
- `QuicIo` 应模仿 `KcpIo`：实现 `AsyncRead`/`AsyncWrite`，并持有连接 guard。
- Bot 腿保持 IPv4；不需要给 RustBot 的 `resolve_ipv4` 增加 IPv6。IPv6 只发生在 hbbr B→A upstream。
- `Agent::validate_relay_request` 会拒绝 control-plane `RequestRelay.token`；token 只能加到 `send_hbbr_open` 发出的 data-plane 请求。
- v1 配置传播必须同时修改 `ClientConfig`、`AgentConfig` 和 `AgentConfig::client_config()`；只改其中一个会导致 Agent 拿不到 pin/token 配置。

### 2.2 hbbr

| 事实 | 位置 |
|---|---|
| TCP `21117`、WebSocket `21119` | `src/relay_server.rs:87-89` |
| 首包 `RequestRelay`，校验 `licence_key` | `src/relay_server.rs:470-483` |
| upstream 分支无条件优先于 uuid 本地配对 | `src/relay_server.rs:485-507` |
| `PEERS` 按 uuid 配对，先到者最多等 30s | `src/relay_server.rs:510-531` |
| 配对后 `set_raw()`，`relay()` 只搬字节 | `src/relay_server.rs:516-518, 539` |
| `RequestRelay.token` 已存在（field 8） | `libs/hbb_common/protos/rendezvous.proto:145-157` |
| 会话层 secretbox nonce 递增，要求可靠有序 | `libs/hbb_common/src/tcp.rs:296-321` |
| B→A 控制面是 TCP 联邦 | `src/federation.rs:342-356` |

### 2.3 S100 / Vault / ragateway 证书

| 事实 | 位置/证据 |
|---|---|
| ragateway 调用 Vault `sign-verbatim/yubiKey-vault-robot` 签发 S100 robot/device 证书 | `ragateway/README.md`、`config.example.json` |
| robot 证书 CN 为 `robot-<soc_uid>.dexteleop.com`，私钥在 TEE（P-384），RA 不接触私钥 | `ragateway/README.md`、`provisioning-ra-gateway-requirements.md` |
| YubiKey 9c signer 证书是 `DigitalSignature` + `CodeSigning`，无 SAN；它是授权 signer，不是 TLS 证书 | `ragateway/provision_yubikey_9c.sh`、`DEBUG.md` |
| 现场 robot 叶证书没有 Basic Constraints、EKU 或 SAN（至少已核验的 production 样本） | `ragateway/DEBUG.md:272` |

结论：S100/Vault 的 robot 证书是**设备身份**，不是 relay 的 TLS serverAuth 证书。它没有 relay SAN/serverAuth，私钥在 TEE，RustBot 也没有现成的 PKCS#11 TLS 集成。v1 不复用它；relay 使用独立 server cert + pin。

---

## 3. 目标拓扑与数据流

### 3.1 路径

```
RustBot(B) ──①QUIC(优先)/TCP──> hbbr(B) ──②QUIC(IPv6 优先)/TCP──> hbbr(A) ──③QUIC(优先)/TCP──> RustBot(A)
```

- ①：RustBot(B) 连本地 hbbr(B)；QUIC 走 IPv4，网络失败回落 TCP。
- ②：hbbr(B) 作为 QUIC 客户端连 hbbr(A)；优先 A 的 IPv6 地址，网络失败再试 IPv4 QUIC，最后 TCP。
- ③：RustBot(A) 连本地 hbbr(A)；QUIC 走 IPv4，网络失败回落 TCP。
- A 的 `PEERS[uuid]` 配对 ② 和 ③；B 的 `make_pair_` upstream 分支把 ① 和 ② 直接对接。
- 两个 Bot 在配对后的原始字节流上做 RustBot signed handshake + secretbox；两个 relay 只看到密文。

### 3.2 会话建立时序（Bot(B) 发起）

1. `RustBot(B)` 向 `hbbs(B)` 发 `PunchHoleRequest`；`hbbs(B)` 按现有联邦逻辑转发到 `hbbs(A)`。
2. `hbbs(A)` 通知 `RustBot(A)`；控制面交换 `RequestRelay`/`RelayResponse`，两边拿到同一个 uuid 和各自的本地 relay 地址。
   - 控制面的 `RequestRelay` **不带 token**；`Agent::validate_relay_request` 仍然拒绝非空 token。
3. `RustBot(B)` 连接 `hbbr(B)`：
   - 先尝试 QUIC（IPv4，`hbbr(B)` 的 QUIC 监听），发送 data-plane `RequestRelay { id, uuid, licence_key, token, conn_type }`；
   - 网络失败则回落 TCP；**pin 失败不回落**。
4. `hbbr(B)` 校验 key 和 bot token；因为配置了 `RELAY_UPSTREAM_QUIC`，B 打开到 A 的 QUIC upstream（IPv6 优先），发送同样的 `RequestRelay`，然后 raw pump。
5. `RustBot(A)` 连接 `hbbr(A)`（QUIC 优先/TCP 回落），发送同样的 data-plane `RequestRelay`；A 校验后与 B 的 upstream 按 uuid 配对，raw pump。
6. 两个 Bot 在原始字节流上执行 RustBot signed handshake + secretbox，开始会话。
7. 任一端关闭 → 对应 relay 的 `relay()` 结束 → 另一侧链路关闭；`QuicIo` 释放 QUIC connection。

### 3.3 quic-preferred 语义

- 每条腿独立尝试 QUIC；成功即用，**网络失败**按顺序回落。
- ② 的顺序：A 的 IPv6 QUIC → A 的 IPv4 QUIC → TCP `RELAY_UPSTREAM`。
- ①③ 的顺序：本地 relay 的 QUIC（IPv4）→ TCP。
- **认证失败不回落**：
  - pin mismatch；
  - 证书过期/无法解析；
  - TLS 签名失败；
  - ALPN 不匹配；
  - token 被 relay 拒绝。
- 回落必须记录：`transport=quic|tcp`、`family=v4|v6`、`fallback_reason=network|auth|token|config`。
- 验收时：
  - “全 QUIC 会话”要求三条腿 `transport=quic`；
  - “quic-preferred 正常”允许网络回落，但回落次数必须可见；
  - 认证失败必须计入错误/告警，不能算作正常回落。

### 3.4 与 DirectKcp 的关系

- `DirectKcp` 是 peer-to-peer KCP，通过 secure relay 交换 UDP mapping 后升级；它不是 relay(B)→relay(A) 的链式 relay。
- 本方案只改 `Relay` route 的 hbbr 连接和 hbbr B→A 的 upstream；`DirectTcp`/`DirectKcp` 逻辑不动。
- 若测试目标是“必须经过 relay 链”，需要让 DirectTcp/DirectKcp 失败或用测试配置禁用；否则 RustBot 可能优先选中直连/KCP。

---

## 4. 协议与鉴权设计

### 4.1 hbbr QUIC 连接

- ALPN：`rustdesk-relay/1`（不兼容变更时递增）。
- 每个 relay 会话一条 QUIC 连接 + 一条 bidi stream；首版不 multiplex。
- bidi stream 第一条消息是 RustBot 的 length-frame `RendezvousMessage::RequestRelay`（`protocol::write_message`，与 TCP 完全一致）。
- relay 解析 `RequestRelay` 后配对；配对成功后两边 `set_raw()`，QUIC stream 变成透明字节管道。
- `QuicIo` 在 Bot 侧保持 framed 模式；relay 侧 `FramedStream` 进入 raw 模式。
- 连接生命周期：
  - `QuicIo`/`QuicSession` 同时持有 `quinn::Connection`；
  - 会话结束显式 `connection.close(0u32.into(), b"relay closed")`；
  - 每连接只允许一个 bidi stream，额外 stream 直接 reset/拒绝；
  - `accept_bi`、首帧读取、token 校验都要有超时；
  - 使用 quinn 默认的 QUIC anti-amplification 保护；显式 QUIC Retry/地址验证后置；
  - 连接数用 semaphore/计数器限制，并支持 per-IP 上限；

### 4.2 Bot 鉴权：data-plane token

- 只放在 `send_hbbr_open` 发出的 **hbbr data-plane `RequestRelay`**：
  - 格式：`rustbot-quic-v1:<base64(HMAC-SHA256(SHA-256(secret), uuid))>`；
  - RustBot(B) 和 RustBot(A) 对同一个 uuid 计算出相同 token；
  - `secret` 来自 `RELAY_BOT_TOKEN_SECRET`，B、A、两个 Bot 使用同一个值。
- **control-plane 不放 token**：
  - `Client::connect_relay` 发给 hbbs 的 `RequestRelay` 保持 `token` 空；
  - `Agent::validate_relay_request` 仍要求 `request.token.is_empty()`；
  - `hbbs` 不需要任何改动。
- hbbr 校验规则：
  - TCP/WS listener：空 token 放行（stock），`rustbot-quic-v1:` token 校验，未知非空 token 拒绝；
  - QUIC listener：只接受合法 `rustbot-quic-v1:` token，空 token 拒绝。
- 常量时间比较；token 不写日志。
- HMAC 用 `sodiumoxide::crypto::auth::hmacsha256`（RustBot/hbbr 都已有 sodiumoxide）。
- `RELAY_BOT_TOKEN_SECRET` 为空时，QUIC listener 和 `relay_quic=true` 的 Bot 都必须 fail closed；v1 不允许“空 secret 但开 QUIC”。

### 4.3 E2E

- RustBot 已有 signed handshake（Ed25519 SignedId + X25519/secretbox）和逐帧 secretbox；配对后继续使用，relay 只搬密文。
- QUIC TLS 只保护 Bot↔relay / relay↔relay 的逐跳；不能把它当 E2E。
- stock RustDesk 的 secure handshake 与 RustBot 不同；两者不互通，本文不涉及。

### 4.4 pin 契约（v1）

**pin 输入**：

```text
pin = "sha256:" + standard_base64(SHA-256(DER end-entity certificate))
```

- hash 输入是 TLS handshake 中服务器发送的 **end-entity 证书 DER**，不是 PEM、不是 SPKI、不是 chain。
- 使用标准 Base64（无换行），前缀固定 `sha256:`。
- 比较使用常量时间比较。
- v1 pin 期望 relay server cert 为自签（issuer 自身）；CA 签发的证书留给后续 `ca` 模式。
- pin 模式**不做 CA 链校验**，但必须：
  - 解析证书；
  - 校验 `notBefore <= now <= notAfter`；
  - 校验 TLS 1.2/1.3 handshake signature；
  - 校验 ALPN 为 `rustdesk-relay/1`；
  - 不校验 hostname/SAN（pin 已经固定证书身份）。
- pin 拓扑两种都支持，二选一：
  - 每节点独立证书：RustBot(B) 校验 `pin(B)`，RustBot(A) 与 hbbr(B) upstream 校验 `pin(A)`；
    泄露面按节点隔离，可逐节点轮换。
  - 集群共用一份证书：`pin(A) == pin(B) == pin`，Bot 只需内置一个 pin，适合通过 deb 统一
    下发配置的车队；代价是私钥泄露可冒充全部 relay，且无法按节点吊销。
- 本部署采用集群共用证书：同一份 cert/key 部署在 A、B 的
  `/var/lib/rustdesk-server/relay-quic.{crt,key}.pem`，即 systemd `WorkingDirectory` 下的
  默认文件名，无需额外配置路径。
- v1 是单 pin。证书轮换需要协调更新客户端/边缘配置并重启；双 pin 重叠期后置。
- pin 缺失、格式错误、为空字符串：配置错误，启动失败；不能静默退化为 accept_any。
- 证书必须持久化；私钥 0600；日志只打印 fingerprint 前缀，不打印完整 pin/私钥。

### 4.5 rustls / quinn 实现约束

- pin 通过 rustls 0.23 的 `ServerCertVerifier` 实现：
  - `verify_server_cert`：计算 DER SHA-256、比较 pin、校验证书有效期；失败时返回 `InvalidCertificate` 并记录 auth failure。
  - `verify_tls12_signature` / `verify_tls13_signature`：使用 rustls 的 `rustls::crypto::verify_tls12_signature` / `verify_tls13_signature` 和默认 `signature_verification_algorithms`，不能跳过。
  - `supported_verify_schemes`：返回默认 provider 的 schemes。
  - `requires_raw_public_keys`：false。
- 用 `rustls::ClientConfig` 的 `dangerous().with_custom_certificate_verifier(...)` 构造，再 `QuicClientConfig::try_from` 转成 quinn client config；不要用 `accept_any` 代替 pin。
- **错误分类**：
  - `quinn::Endpoint::connect` 返回的 `ConnectError` 只覆盖参数/端点错误，不覆盖握手证书失败；
  - 握手失败从 `Connecting` future 返回 `ConnectionError`；证书错误通常是 `ConnectionError::TransportError` + `TransportErrorCode::crypto(alert)`；
  - 为可靠区分 auth failure，verifier 持有 `Arc<AtomicBool>`/错误槽，pin 失败时置位；`connect` 返回错误后先查该标记，再决定是否网络回落。
- **SNI**：
  - `quinn::Endpoint::connect(addr, server_name)` 需要 `&str`；
  - pin 模式忽略 hostname，但仍需要合法 `server_name`；
  - IPv6/IPv4 字面量时使用 `relay_quic_sni`/`RELAY_UPSTREAM_QUIC_SNI` 指定的名字；未配置时用配置的主机名；两者都没有则配置错误。
- ALPN 在 `rustls::ClientConfig.alpn_protocols` 设置；服务端 `ServerConfig` 同样设置。

### 4.6 回落策略

| 失败类型 | 例子 | 行为 |
|---|---|---|
| 网络失败 | timeout、connection refused、UDP 不可达、地址族不可用 | 按顺序回落：IPv6 QUIC → IPv4 QUIC → TCP |
| 认证失败 | pin mismatch、证书过期、签名失败、ALPN 不匹配 | **当前连接失败，不回落 TCP**；告警 |
| token 失败 | relay 拒绝 token / 关闭连接 | **不回落 TCP**；告警 |
| 配置错误 | pin 缺失、secret 缺失、SNI 无法确定 | 启动/建连前失败；不回落 |

- 配置：
  - `RELAY_UPSTREAM_QUIC_FALLBACK_ON_AUTH_ERROR=N`（默认）
  - `relay_quic_fallback_on_auth_error=false`（默认）
  - `strict` 仅作为“任何错误都不回落”的诊断开关，默认关闭。
- 认证失败不回落的原因：TCP 路径没有 pin/server auth，回落会让主动中间人通过“让 QUIC 证书失败”降级到 TCP 并读取 token。
- 网络回落时 token 走 TCP 明文（E2E 之前）；这是 quic-preferred 的可用性取舍，必须记录。

### 4.7 空闲、保活、流控

- `quinn` 默认 idle 10s；调到 60s；keepalive 15s。
- relay 的 `relay()` 仍有 30s 无数据判死；QUIC keepalive 不算业务数据，Bot 需要应用层心跳。
- stream/connection receive window 调到 MB 级；首版 `max_concurrent_bidi_streams = 1`。

### 4.8 后续模式（不属于 v1）

- `ca`：relay CA / Vault relay server role，适合多 relay/集中轮换。
- `accept_any`：显式关闭 server auth，仅私网/实验；active MITM 可读 token。
- `mTLS`：relay client cert；v1 不做。
- `node token`：A 对 B 的节点级认证；v1 不做。
- 这些模式不得混入 v1 的配置默认值、测试矩阵或交付验收。

---

## 5. 服务端实现（hbbr）

### 5.1 新增配置

| 变量 | 作用域 | 默认 | 说明 |
|---|---|---|---|
| `RELAY_ROLE` | hbbr | `standalone` | `standalone` / `master` / `edge`；未设置保持现有行为 |
| `RELAY_QUIC` | hbbr | off | 启用 QUIC 监听 |
| `RELAY_QUIC_BIND` | hbbr | `[::]` 双栈或 `0.0.0.0` | Bot 腿 v4 + upstream v6 时建议双栈 |
| `RELAY_QUIC_PORT` | hbbr | relay 端口 | 默认与 TCP 同号 |
| `RELAY_QUIC_CERT` / `RELAY_QUIC_KEY` | hbbr | `WorkingDirectory` 下 `relay-quic.{crt,key}.pem` | relay server cert/key；缺失时自动生成并持久化（私钥 0600），启动日志打印 pin |
| `RELAY_UPSTREAM` | edge hbbr | 空 | TCP upstream/网络回落 |
| `RELAY_UPSTREAM_QUIC` | edge hbbr | 空 | A 的 QUIC upstream，如 `[2001:db8::a]:21117` |
| `RELAY_UPSTREAM_IPV6` | edge hbbr | `prefer` | `prefer` / `only` / `off` |
| `RELAY_UPSTREAM_QUIC_AUTH` | edge hbbr | `pin` | v1 只接受 `pin` |
| `RELAY_UPSTREAM_QUIC_PIN` | edge hbbr | 空 | pin(A)；v1 必填 |
| `RELAY_UPSTREAM_QUIC_SNI` | edge hbbr | 空 | IP 字面量时的 SNI |
| `RELAY_UPSTREAM_QUIC_FALLBACK_ON_AUTH_ERROR` | edge hbbr | `N` | 认证失败是否回落；v1 固定 N |
| `RELAY_UPSTREAM_BIND` | edge hbbr | 按地址族 | QUIC 客户端源地址 |
| `RELAY_BOT_TOKEN_SECRET` | hbbr | 空 | bot token HMAC secret；开 QUIC 时必填 |
| `RELAY_QUIC_MAX_CONN` / `_PER_IP` | hbbr | 例如 10000 / 64 | QUIC 连接限制 |

- `RELAY_UPSTREAM_QUIC_AUTH` 的 `ca`/`accept_any` 是保留值，v1 遇到必须启动失败，不能静默接受。
- `RELAY_BOT_TOKEN_SECRET` 为空且 `RELAY_QUIC=Y`：启动失败（v1 fail closed）。

### 5.2 `src/quic_relay.rs`（新增）

- `QuicSession { connection: quinn::Connection, send: SendStream, recv: RecvStream }`
  - 用 `QuicDuplex`/`impl AsyncRead+AsyncWrite` 包装给 `FramedStream::from`；
  - `Drop` 或会话结束时 `connection.close(...)`。
- `start_listener(...)`：
  - 绑定 UDP；`[::]` 显式 `only_v6(false)`（双栈）；
  - 构建 `quinn::ServerConfig`：ALPN、证书、transport 参数；v1 不配置 client CA；
  - accept 前检查 `BLOCKLIST`、连接数、per-IP 上限；
  - `accept_bi()` 后调用 `make_pair_(..., Transport::Quic)`；
  - 记录 `transport=quic`、`family`、`peer`、`uuid`（从 `RequestRelay` 取）。
- `connect_upstream(...)`：
  - 解析 A 地址，v6 优先；
  - 按地址族创建/复用 `quinn::Endpoint`；
  - ALPN、SNI、pin verifier、5s 超时；v1 不发 client cert；
  - `open_bi()`，返回 `FramedStream`；
  - 返回 `ResultType`，并区分 `AuthFailed` / `Unavailable` / `TokenRejected`，由调用方决定是否回落。
- 证书加载/生成、fingerprint 日志。
- 连接计数、握手失败计数、基础日志。

### 5.3 `src/relay_server.rs` 改动

1. **配置读取**：`start_with_bind` 读取 QUIC/upstream/token/cert 配置；不打印 secret。
2. **Limiter 上提**：`check_params()` / `Limiter::new(TOTAL_BANDWIDTH)` 移到 `start_with_bind`，TCP/QUIC 共享总带宽 limiter。
3. **`make_pair_` 签名**：增加 `Transport`（Tcp/WebSocket/Quic）；QUIC 也用 `FramedStream`；现有调用传 `Tcp`。
4. **token 校验**：
   - 在解析 `RequestRelay` 后、upstream 选择前执行；
   - TCP/WS：空 token 放行（stock）；`rustbot-quic-v1:` 校验；
   - QUIC：只接受合法 `rustbot-quic-v1:` token，空 token 拒绝；
   - token 失败时 QUIC session 以固定 application error/reason `AUTH_FAILED` 关闭；Bot 将匹配的 `ApplicationClosed` 视为 token 失败，不回落 TCP；
   - 失败记录日志，不打印 token。
5. **upstream 选择**：
   - 进入条件：`!RELAY_UPSTREAM.is_empty() || (is_bot && !RELAY_UPSTREAM_QUIC.is_empty())`；
   - `is_bot = token.starts_with("rustbot-quic-v1:")`；
   - ② 顺序：`connect_upstream`（v6 优先）→ IPv4 QUIC → `FramedStream::new(RELAY_UPSTREAM)`；
   - **auth failure（pin/token）不进入 TCP 回落**；B 侧 bot 会话以 `AUTH_FAILED` 关闭，不得用 `RELAY_UPSTREAM` TCP 绕过 pin(A)；
   - stock（空 token）继续原 TCP upstream；
   - `RELAY_UPSTREAM` 为空时 stock 仍走本地配对；bot 的 QUIC 失败没有 TCP 回落。
   - 拆成 `async fn connect_upstream(...) -> ResultType<Box<dyn StreamTrait>>`，不要在 `make_pair_` 里用 `?`。
6. **启动 QUIC 监听**：`RELAY_QUIC=Y` 时 spawn `quic_relay::start_listener`；监听异常需要监督/重启；启动日志带地址族。
7. **USAGE/日志**：
   - QUIC 客户端腿的 key 用 `addr:port`；
   - B 的 upstream 分支沿用现有 `USAGE`（bot 的 addr）；
   - A 的 `USAGE` 只记录后到的一侧（现有行为）；
   - 日志增加 `transport`、`family`、`upstream=quic|tcp`、`fallback_reason`。
8. **角色校验**：
   - `RELAY_ROLE` 未设置：保持现有 hbbr 行为（standalone，无强制 upstream）；
   - `RELAY_ROLE=master`：`RELAY_UPSTREAM`/`RELAY_UPSTREAM_QUIC` 必须为空；
   - `RELAY_ROLE=edge`：显式要求 upstream；没有 upstream 时启动失败；
   - upstream 目标不能等于自身地址（简单自环检查）。
9. **`handle_connection` 不变**：TCP/WS 路径零改动；loopback console 逻辑不影响 QUIC 监听。

### 5.4 依赖

- `quinn = { version = "0.11", default-features = false, features = ["runtime-tokio", "rustls", "ring", "log"] }`
- `rcgen = "0.13"`（仅自签证书生成；使用外部证书可去掉）
- `rustls 0.23` 已在依赖树；`sodiumoxide` 用于 HMAC。
- 确认 `quinn`/`rustls` 版本与现有 `tokio-rustls 0.26`/`rustls 0.23` 兼容；更新 `Cargo.lock` 并跑 `--locked` 构建。
- Debian 打包/交叉编译确认 ring/rustls 目标支持。

### 5.5 兼容性

- `RELAY_QUIC` 默认 off；关闭时 hbbr 行为与现在完全一致。
- `RELAY_ROLE` 未设置时保持 standalone；现有无 upstream 的 hbbr 不受影响。
- stock RustDesk：只走 TCP；B 的 upstream 仍 TCP；无行为变化。
- RustBot：QUIC 优先；网络失败回落 TCP；认证失败不回落。
- 旧 hbbr + 新 RustBot：QUIC 失败 → 网络回落 TCP；会话仍可用。

---

## 6. RustBot 实现

### 6.1 `PeerIo::Quic`

- 新增 `PeerIo::Quic(QuicIo)`，与 `Tcp`/`Kcp` 并列，实现 `AsyncRead`/`AsyncWrite`。
- `QuicIo`：
  - 持有 `quinn::Connection` + `SendStream` + `RecvStream`；
  - `Drop`/结束显式 `connection.close(...)`；
  - 可以像 `KcpIo` 一样带 guard，确保 UDP socket/endpoint 生命周期正确。
- `SecurePeer`、`client_handshake`/`server_handshake`、`bridge_tcp`、KCP upgrade 都不需要改，它们只依赖 `PeerIo: AsyncRead + AsyncWrite`。

### 6.2 relay 连接

- 新增 `connect_hbbr`：
  1. 解析 `config.hbbr`（**IPv4 即可**，Bot 腿不要求 IPv6）；
  2. 尝试 `quinn` 连接 hbbr 的 QUIC（同 host:port，ALPN `rustdesk-relay/1`）；
  3. 用 `relay_quic_pin` 校验 hbbr server cert；pin 模式忽略 hostname，但校验有效期/签名/ALPN；
  4. `open_bi()`，得到 `QuicIo`；
  5. 用 `QuicIo` 作为 `impl AsyncWrite` 发送 `send_hbbr_open`；
  6. 包成 `PeerIo::Quic(quic)`，继续 `client_handshake`/`server_handshake`；
  7. **网络失败**回落现有 TCP：`connect_tcp` + `PeerIo::Tcp`；
  8. **pin/证书/ALPN/token 失败不回落**，返回错误并告警。
- `transport::send_hbbr_open` 的签名从 `&mut TcpStream` 改为 `&mut (impl AsyncWrite + Unpin)`。
- data-plane `RequestRelay` 增加 token：
  - `request.token = bot_token(&uuid, &config.relay_token_secret)`；
  - control-plane `RequestRelay` 保持 `token` 空，`Agent::validate_relay_request` 不改。
- `Client::connect_relay` 和 `Agent::handle_relay` 都走 `connect_hbbr`；其他逻辑不变。
- quic-preferred：网络失败记录 `fallback_reason=network`；认证失败记录 `auth` 并返回错误。
- `relay_quic_strict=Y` 仅用于诊断（任何错误都不回落）；默认 N。

### 6.3 配置传播

v1 必须同时扩展以下位置，不能只改文档：

| 位置 | 需要变化 |
|---|---|
| `ClientConfig` | 新增 `relay_quic`、`relay_quic_port`、`relay_quic_server_auth`、`relay_quic_pin`、`relay_quic_sni`、`relay_token_secret`、`relay_quic_fallback_on_auth_error`、`relay_quic_strict` |
| `AgentConfig` | 同上字段（或复用同一组 common 配置） |
| `AgentConfig::client_config()` | 复制所有新增字段，不能只复制 hbbs/hbbr/server_key/timeout |
| `ClientConfig::validate` | `relay_quic=true` 时要求 pin 格式正确、token secret 非空；`server_auth` v1 只允许 `pin` |
| `AgentConfig::load` | 复用上述校验；`deny_unknown_fields` 下旧配置必须仍可加载（`relay_quic` 默认 false） |
| `packaging/*.toml` | 增加注释示例；默认不开启 QUIC，避免旧配置启动失败 |
| 测试 | 配置解析、pin 缺失、secret 缺失、旧配置兼容 |

默认值：

```text
relay_quic = false
relay_quic_port = 21117
relay_quic_server_auth = "pin"
relay_quic_pin = ""
relay_quic_sni = ""
relay_token_secret = ""
relay_quic_fallback_on_auth_error = false
relay_quic_strict = false
```

- `relay_quic=false` 时，pin/secret 可以为空，保持旧配置可启动。
- `relay_quic=true` 时，pin 缺失、pin 格式错误、secret 为空都是配置错误。
- `relay_quic_server_auth` 不是 `pin` 时，v1 配置错误（ca/accept_any 后置）。

### 6.4 与 DirectKcp / DirectTcp 的关系

- `DirectTcp`/`DirectKcp` 不动；它们仍可能先于 Relay 被选中。
- `connect_relay` 改为 QUIC 优先后，`finish_relay` 的 KCP upgrade 仍可在 QUIC relay 上运行；KCP 协商帧走 QUIC stream，然后升级为 peer-to-peer KCP。
- 测试“relay 链全 QUIC”时需要禁用直连或构造直连失败场景。

---

## 7. IPv6（仅 relay(B) → relay(A)）

### 7.1 范围

- 只有 ②：hbbr(B) → hbbr(A) 的 QUIC upstream 优先 IPv6。
- ①③ 不要求 IPv6：RustBot 继续 IPv4；本地 relay 的 QUIC 监听可以在 IPv4 上。
- 不需要改 RustBot 的 `resolve_ipv4`，也不需要 bot 侧 v6 地址/DNS/防火墙。

### 7.2 监听与连接

- A 的 QUIC 监听建议 dual-stack `[::]`（显式 `only_v6(false)`）：
  - B 的 upstream 走 v6；
  - A 侧 Bot 走 v4（v4-mapped）。
- 如果 A 的平台不支持 dual-stack，使用两个监听：
  - `0.0.0.0:21117` 给 Bot；
  - `[2001:db8::a]:21117` 给 upstream（v6-only）。
- B 的 QUIC 监听只需 IPv4（给 Bot）；B 的 upstream 客户端单独解析 A 的 v6 地址。
- `RELAY_UPSTREAM_QUIC=[2001:db8::a]:21117`；B 的客户端 endpoint bind `[::]:0`，可用 `RELAY_UPSTREAM_BIND` 固定源地址。
- 解析顺序：v6 优先；网络失败 → v4 QUIC → TCP `RELAY_UPSTREAM`；认证失败不回落。
- 日志记录 `family=v6|v4` 和 `fallback_reason`；可选 `RELAY_UPSTREAM_IPV6=only` 在 v6 失败时直接失败。

### 7.3 防火墙 / Docker / 证书

- A 放行 UDP `21117` 的 v6 入站；B 放行出站；Bot 只走 v4。
- `network_mode: host` 最省事；bridge 需启用 IPv6 并发布 `21117/udp`。
- 云安全组单独配置 IPv6 规则。
- pin 模式不校验 SAN；但如果以后切 CA，relay server cert 的 SAN 需包含 v6 地址或 hostname。
- B 的 v6 前缀变化时，现有 QUIC 连接可依赖 connection migration；新连接使用新地址。

### 7.4 控制面

- hbbs B→A 联邦链路仍是 TCP；如果也要 v6，配 `FEDERATION_MASTER=[2001:db8::a]:21200`、`FEDERATION_BIND=[::]:21200`。
- 控制面与数据面独立：可以控制面 v4、数据面 v6。
- 如果 B→A 的 TCP 控制面被阻断，会话无法建立；QUIC relay 救不了。

---

## 8. 安全

- **不要开开放 relay**：hbbr 设置 `-k`，并设置 `RELAY_BOT_TOKEN_SECRET`；v1 开 QUIC 时 secret 必填。
- `licence_key` 在 OSS 里是公钥，不是秘密；bot token 才是 bot 通道授权。
- v1 server auth 只做 pin：
  - 防止主动 MITM 用假 relay 读取 token；
  - pin 失败不回落 TCP，避免降级绕过；
  - pin 缺失/格式错误 fail closed。
- pin 模式忽略 hostname/SAN，但必须校验证书有效期、TLS 签名和 ALPN。
- 没有 mTLS 时，A 不能密码学区分 B 与其他持有 bot token 的客户端；v1 用 token 保密、网络 ACL、per-IP/连接数限制缓解；需要更强节点认证时再加 node token 或 mTLS（后置）。
- 每 IP 连接数、全局连接数、握手速率限制；`BLOCKLIST` 在 QUIC 握手前检查。
- QUIC Retry/地址校验；`max_concurrent_bidi_streams`、流控窗口、`SINGLE_BANDWIDTH`/`TOTAL_BANDWIDTH` 防滥用。
- token 在 TCP 网络回落时是明文（E2E 之前）；这是可用性取舍，必须记录。
- E2E 必需；relay 只应看到密文。
- 私钥/secret 权限 0600；不写日志；配置文件不入库。
- 关闭 QUIC 0-RTT；连接迁移只用于地址变化，不作为认证。

---

## 9. 可观测性与运维

- 日志字段：`transport=quic|tcp`、`family=v4|v6`、`peer`、`uuid`、`role=bot|stock`、`upstream=quic|tcp`、`fallback_reason=network|auth|token|config`。
- 启动日志：`Listening on quic [::]:21117`、`QUIC upstream: [2001:db8::a]:21117`、`relay role=standalone|master|edge`。
- 配对日志：
  - B：`Relay upstream (quic) of <bot> opened/closed`；
  - A：`Relayrequest <uuid> from <B> got paired`、`Both are raw`。
- `USAGE` 限制：A 只记录后到的一侧；跨节点端到端计费需要额外协议/日志关联。
- 指标（可选）：QUIC 连接数、pin/auth 失败、网络回落次数、按 family/transport 的字节数、每 IP 连接数。
- 告警：QUIC 监听异常、pin 失败率、网络回落率、A 的 QUIC CPU、连接数逼近上限。
- 回滚：
  - `RELAY_QUIC=off` / `relay_quic=false` → 全部回落 TCP，stock 不受影响；
  - 证书/pin 轮换：协调更新配置并重启；v1 没有双 pin 热切换。

---

## 10. 实施计划

### 10.1 阶段

| 阶段 | 内容 | 产物 | 验收 |
|---|---|---|---|
| P0 | 基线与前置 | TCP relay 基线；A/B v6 可达性；pin/证书方案定稿；stock 回归基线 | 基线数据、pin 清单 |
| P1 | hbbr QUIC 监听 + RustBot `PeerIo::Quic` | Bot↔relay QUIC（①③），网络失败回落 TCP | RustBot↔RustBot 单 relay 会话；stock TCP 不变 |
| P2 | B→A QUIC upstream（IPv6 优先） | ② QUIC；v6→v4→TCP 网络回落；A 的 dual-stack 监听 | RustBot(B)↔RustBot(A) 三腿 QUIC；v6 日志可见 |
| P3 | pin + token + 配置传播 + 角色校验 | pin verifier；data-plane token；ClientConfig/AgentConfig/client_config；standalone 兼容 | pin 错误/过期不回落；旧配置可启动；stock 无感 |
| P4 | 加固/测试/灰度 | 限额、日志/指标、压测、回滚 | 生产灰度通过；网络回落率可见；auth 失败告警 |

### 10.2 任务清单

- [ ] `Cargo.toml`（hbbr + rustbot）增加 `quinn`/`rcgen`，确认 `--locked` 构建。
- [ ] hbbr `QuicSession`/`QuicDuplex` + `src/quic_relay.rs`。
- [ ] hbbr `make_pair_` Transport/token/upstream 选择；Limiter 上提。
- [ ] RustBot `PeerIo::Quic`/`QuicIo`；`connect_hbbr` QUIC 优先/TCP 网络回落。
- [ ] RustBot data-plane token；control-plane 保持空；`send_hbbr_open` 泛化。
- [ ] RustBot `ClientConfig`/`AgentConfig`/`client_config()` 增加 pin/token/QUIC 字段和校验。
- [ ] pin verifier（SHA-256 DER、有效期、签名、ALPN）和 auth failure 标记。
- [ ] A 的 dual-stack QUIC 监听；B 的 v6 upstream 解析/网络回落。
- [ ] `RELAY_ROLE=standalone` 默认，master/edge 显式校验；现有 hbbr 回归。
- [ ] 单元/集成：`PeerIo::Quic`、pin 正确/错误/过期、token、网络回落、auth 不回落、v6、连接释放。
- [ ] 压测/安全：连接洪泛、并发、CPU/内存、QUIC 连接数。
- [ ] 文档/Docker/防火墙/pin 轮换/回滚。
- [ ] 灰度：A → B → Bot 车队；观察网络回落率和 pin 失败率。

粗略估算：P1–P3 MVP 约 3–5 周；P4 生产加固再 2–3 周。

### 10.3 文件影响

- `rustdesk-server`：`Cargo.toml`、`src/quic_relay.rs`（新增）、`src/relay_server.rs`、`src/hbbr.rs`、`docs/environment-variables.md`、`docker-compose.yml`、`tests/relay_quic.rs`。
- `rustbot`：`Cargo.toml`、`src/peer.rs`、`src/kcp.rs`（参考）、`src/transport.rs`、`src/client.rs`、`src/agent.rs`、`src/config.rs`、`packaging/*.toml`、测试。
- 证书：relay server cert + pin；不需要 CA/Vault/mTLS。

---

## 11. 测试与验收

### 11.1 测试矩阵（v1）

| 用例 | 步骤 | 期望 |
|---|---|---|
| pin 正常 | RustBot(B)↔RustBot(A)，A/B QUIC 开，pin 正确 | ①③ QUIC；② QUIC IPv6；日志 `transport=quic` |
| 网络回落 | 关 A 的 QUIC / 断 UDP | ② 网络回落 TCP；日志 `fallback_reason=network`；会话可用 |
| pin 错误 | 配错 pin | QUIC 失败；**不回落 TCP**；当前会话失败；告警 |
| pin 过期 | 使用过期 relay cert | QUIC 失败；**不回落 TCP**；告警 |
| pin 缺失 | 开 QUIC 但未配 pin | 配置/启动失败；不建连 |
| token 错误 | 错误 HMAC | QUIC 拒绝；不回落；无未授权会话 |
| token 缺失 | 空 token 打 QUIC | QUIC 拒绝；不回落 |
| pin 拓扑 | 每节点独立证书：B→A 用 pin(A)、Bot(B) 用 pin(B)；或共用一份证书统一 pin | 各自校验所连 relay 的证书；不混用 |
| B→A pin 错误 | 配错 upstream pin | ② QUIC auth 失败；不回落 TCP；B 关闭 bot 会话；告警 |
| stock↔stock | 现有客户端 | 仍 TCP；无行为变化 |
| standalone hbbr | 不配 `RELAY_ROLE`/upstream | 行为与改动前一致 |
| ② v6 回落 v4 | 断 A 的 v6 | 先 v6 失败，再 v4 QUIC；日志 `family=v4`、`network` |
| QUIC 连接释放 | 会话结束/异常断开 | 连接/stream 释放，无泄漏 |
| 并发/洪泛 | N 会话/握手洪泛 | 限额生效；stock TCP 不受影响 |

### 11.2 验收标准

1. pin 正常路径：`RustBot(B)→relay(B)→relay(A)→RustBot(A)` 三条腿日志均为 `transport=quic`；② 为 `family=v6`（网络支持时）。
2. 网络回落路径可见：关闭 QUIC/v6 后，日志/指标记录 `fallback_reason=network`；会话仍可用。
3. **pin 错误/过期不回落 TCP**；当前会话失败并告警。
4. stock↔stock 仍走 TCP，行为与改动前一致；不要求 RustBot↔stock。
5. data-plane token 校验生效；control-plane token 仍为空；`Agent::validate_relay_request` 不受影响。
6. `relay_quic=false` 或旧配置可正常启动；`RELAY_ROLE` 未设置时 standalone hbbr 行为不变。
7. QUIC 连接在会话结束后释放；无连接/stream 泄漏。
8. IPv6 只出现在 ②；①③ 不要求 v6。
9. 并发/洪泛测试通过；CPU/内存/连接数在预算内。
10. 文档、部署、pin 轮换、回滚步骤齐全。

### 11.3 验证命令/方法

```bash
# 构建
cargo test --locked --lib
cargo test --locked --test relay_quic
cargo build --locked --release --bin hbbr

# 监听/抓包（按五元组关联，不依赖 uuid）
ss -lunp | grep 21117
ss -6 -lunp | grep 21117
tcpdump -ni any 'ip6 and udp port 21117'
tcpdump -ni any 'tcp port 21117'

# v6 / DNS
ping6 -c 3 2001:db8::a
nslookup -type=AAAA relay-a.example.com

# 弱网
tc qdisc add dev eth0 root netem delay 80ms loss 2%
tc qdisc del dev eth0 root
```

- QUIC 应用数据被 TLS 加密，`tcpdump` 看不到 uuid；用 hbbr 日志的 `uuid + remote addr + connection ID` 或五元组关联抓包。
- pin 错误/过期场景用 `tcpdump` 确认没有后续 TCP 21117 数据。

---

## 12. 风险与开放问题

### 12.1 风险

1. **pin 轮换**：v1 单 pin，轮换需要协调更新/重启；没有双 pin 热切换。
2. **认证失败不回落**：pin 配错/证书轮换期间会话直接失败；这是安全换可用性的取舍，需要告警和运维流程。
3. **网络回落率**：如果大量会话网络回落 TCP，方案名义上线但实际未走 UDP；必须监控。
4. **错误分类**：`quinn::Endpoint::connect` 的 `ConnectError` 不覆盖握手证书失败；必须用 verifier 的 auth 标记区分，否则可能误回落。
5. **RustBot 配置传播**：只改 `ClientConfig` 不改 `AgentConfig::client_config()` 会导致 Agent 没有 pin/token；必须一并修改。
6. **standalone hbbr**：`RELAY_ROLE=edge` 强制 upstream 会破坏现有 standalone 部署；默认必须保持 standalone。
7. **IPv6 仅 ②**：A 的 QUIC 监听需要 dual-stack 或第二监听；否则 A 侧 Bot 无法用 v4 QUIC。
8. **B 的 `RELAY_UPSTREAM` 无条件**：所有 B 侧请求都会 chain 到 A；bot/stock 分流必须在 B 的 upstream 选择处做。
9. **同边会话 hairpin**：两个 Bot 都在 B 时会 B→A→B；quic-preferred 下仍走 WAN。
10. **QUIC 生命周期**：只丢 `SendStream/RecvStream` 不 close connection 会泄漏；必须用 `QuicSession` + close。
11. **A 只看到 B 的 IP**：`USAGE`/黑名单/限额按 B 聚合；端到端 per-bot 计费不在本方案。
12. **relay 30s 空闲判死**：Bot 需要应用层心跳；QUIC keepalive 不算业务数据。
13. **依赖/打包**：`quinn`/`rustls`/`rcgen` 版本、Debian/交叉编译、ring 目标支持。
14. **Docker IPv6/UDP**：bridge 可能不通；优先 host network。
15. **RustBot 直连竞争**：DirectTcp/DirectKcp 可能先选中；测试 relay 链要禁用直连或构造失败。

### 12.2 开放问题

- v1 单 pin 是否足够？双 pin/热轮换是否列为 v2？
- pin 按 relay 分发的方式：bot 配置、部署系统还是配置中心？
- ② 的 v6 失败时允许网络回落 v4/TCP，还是某些环境要求 `only`？
- A 的 QUIC 监听用 dual-stack 还是双监听？
- 是否需要 QUIC upstream multiplex（一条连接多流）降低 A 的连接数？
- 同边 Bot hairpin 是否可接受？是否需要本地 bot relay？
- `RELAY_QUIC` 默认 off 还是 on？取决于灰度策略。
- ca/accept_any/Vault relay role/mTLS/node token 的后续优先级？
- 控制面是否也需要 IPv6/是否可能被 TCP 阻断？
- 是否需要在 hbbs 广告中标记 relay 的 QUIC 能力？当前 Bot 本地配置即可。

---

## 13. 附录

### 13.1 配置示例

**A（master hbbr）**

```ini
RELAY_ROLE=master
RELAY_QUIC=Y
RELAY_QUIC_BIND=[::]:21117        # dual-stack；Bot 走 v4-mapped，B upstream 走 v6
RELAY_QUIC_CERT=/var/lib/rustdesk-server/relay-quic.crt.pem
RELAY_QUIC_KEY=/var/lib/rustdesk-server/relay-quic.key.pem
RELAY_BOT_TOKEN_SECRET=<cluster-secret>
RELAY_QUIC_MAX_CONN=10000
RELAY_QUIC_MAX_CONN_PER_IP=64
# TCP relay 仍是 0.0.0.0:21117，stock 走 v4
```

**B（edge hbbr）**

```ini
RELAY_ROLE=edge
RELAY_QUIC=Y
RELAY_QUIC_BIND=0.0.0.0:21117     # Bot 腿 IPv4 即可
RELAY_QUIC_CERT=/var/lib/rustdesk-server/relay-quic.crt.pem
RELAY_QUIC_KEY=/var/lib/rustdesk-server/relay-quic.key.pem
RELAY_UPSTREAM=relay-a.example.com:21117          # TCP 网络回落/stock
RELAY_UPSTREAM_QUIC=[2001:db8::a]:21117           # ② QUIC，IPv6 优先
RELAY_UPSTREAM_IPV6=prefer
RELAY_UPSTREAM_QUIC_AUTH=pin                      # v1 只接受 pin
RELAY_UPSTREAM_QUIC_PIN=sha256:<cluster-pin>   # 共用证书时与 Bot 侧同一个 pin
RELAY_UPSTREAM_QUIC_SNI=relay-a.example.com       # 如用 IP 字面量
RELAY_UPSTREAM_QUIC_FALLBACK_ON_AUTH_ERROR=N
RELAY_BOT_TOKEN_SECRET=<cluster-secret>
# 可选：RELAY_UPSTREAM_BIND=[2001:db8::b]:0
```

**RustBot(B)**

```ini
hbbs = "rustbot.dexteleop.com:21116"
hbbr = "relay-b.dexteleop.com:21117"
server_key = "<Ed25519 public key>"
relay_quic = true
relay_quic_port = 21117
relay_quic_server_auth = "pin"          # v1 只接受 pin
relay_quic_pin = "sha256:<cluster-pin>"
relay_quic_sni = "relay-b.dexteleop.com" # 如 hbbr 是 IP 字面量
relay_token_secret = "<cluster-secret>"
relay_quic_fallback_on_auth_error = false
relay_quic_strict = false
```

**RustBot(A)**

```ini
hbbs = "rustbot.dexteleop.com:21116"
hbbr = "relay-a.dexteleop.com:21117"
server_key = "<Ed25519 public key>"
relay_quic = true
relay_quic_port = 21117
relay_quic_server_auth = "pin"
relay_quic_pin = "sha256:<cluster-pin>"
relay_quic_sni = "relay-a.dexteleop.com"
relay_token_secret = "<cluster-secret>"
relay_quic_fallback_on_auth_error = false
relay_quic_strict = false
```

### 13.2 代码骨架

**pin verifier**

```rust
struct PinVerifier {
    pin: [u8; 32],
    auth_failed: Arc<AtomicBool>,
    supported: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual = Sha256::digest(end_entity.as_ref());
        if !constant_time_eq(&actual, &self.pin) {
            self.auth_failed.store(true, Ordering::SeqCst);
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        // 继续校验证书有效期；失败同样置 auth_failed。
        // 具体解析可用 rustls-webpki / x509 解析器。
        let _ = now;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}
```

**hbbr upstream 选择（区分 auth/network）**

```rust
async fn connect_upstream(
    quic_upstream: &str,
    tcp_upstream: &str,
    cfg: &QuicClientConfig,
) -> ResultType<Box<dyn StreamTrait>> {
    match quic_relay::connect_upstream(quic_upstream, cfg).await {
        Ok(s) => Ok(Box::new(s)),
        Err(e) if e.is_auth_failure() => Err(e.into()), // 不回落
        Err(e) if !tcp_upstream.is_empty() => {
            log::warn!("quic upstream network failure: {e}; falling back to tcp");
            Ok(Box::new(FramedStream::new(tcp_upstream, None, 5_000).await?))
        }
        Err(e) => Err(e.into()),
    }
}
```

**RustBot `QuicIo`**

```rust
pub(crate) struct QuicIo {
    connection: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl Drop for QuicIo {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"rustbot closed");
    }
}

impl AsyncRead for QuicIo { /* recv */ }
impl AsyncWrite for QuicIo { /* send */ }
```

**RustBot data-plane token**

```rust
pub(crate) async fn send_hbbr_open(
    stream: &mut (impl AsyncWrite + Unpin),
    config: &ClientConfig,
    peer_id: &str,
    uuid: &str,
) -> Result<()> {
    let mut request = RequestRelay::new();
    request.id = peer_id.to_owned();
    request.uuid = uuid.to_owned();
    request.licence_key = config.server_key.clone();
    request.token = bot_token(uuid, &config.relay_token_secret);
    request.conn_type = ConnType::PORT_FORWARD.into();
    let mut message = RendezvousMessage::new();
    message.set_request_relay(request);
    protocol::write_message(stream, &message).await
}
```

### 13.3 抓包/验证要点

- 三条腿的 QUIC 会话通过 hbbr 日志的 `uuid + remote addr + connection ID` 关联；`tcpdump` 只用于确认五元组是 UDP/QUIC。
- ② IPv6：A 侧 `ss -6 -lunp` 看到 `[::]:21117`；B 侧日志 `upstream family=v6`；抓包 `ip6 and udp port 21117`。
- 网络回落：关闭 A 的 QUIC 后，B 日志 `fallback_reason=network`；抓包转为 TCP。
- pin 错误：B/Bot 日志 `fallback_reason=auth`，且**没有**后续 TCP 21117 数据。
- stock：只看到 TCP 21117；没有 QUIC。

### 13.4 参考资料

- RustBot：`src/transport.rs`、`src/client.rs`、`src/agent.rs`、`src/peer.rs`、`src/kcp.rs`、`src/protocol.rs`、`src/config.rs`
- hbbr：`src/relay_server.rs`、`libs/hbb_common/src/tcp.rs`、`libs/hbb_common/protos/rendezvous.proto`
- ragateway/S100：`ragateway/README.md`、`provisioning-ra-gateway-requirements.md`、`provision_yubikey_9c.sh`、`DEBUG.md`
- `quinn` 0.11 / `rustls` 0.23：`ServerCertVerifier`、`QuicClientConfig::try_from`、`ConnectError`/`ConnectionError`、`TransportErrorCode::crypto`
- 现有联邦验证记录：`tasks/todo.md`（A/B 级联、Relay UUID 配对）
