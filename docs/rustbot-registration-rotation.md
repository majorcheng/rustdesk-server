# RustBot 注册：刷机后的公钥轮换

- 状态：已实现（2026-11-07），未部署
- 涉及仓库：`rustdesk-server`（hbbs）、`rustnet`（S100 Agent）
- 相关文档：`rustnet/docs/rustnet_reflash_reregistration.md`

## 1. 问题

RustBot 的 peer ID 与 registration UUID 由 SOC_UID 稳定派生，但 Ed25519 keypair 是首次启动
随机生成、只保存在设备本地。刷机清空根分区后重新生成 keypair，设备会以同一 ID、同一 UUID、
新公钥重新注册。

库存逻辑在 `rendezvous_server.rs` 里只在“来源 IP 未变”时允许换公钥，否则返回
`UUID_MISMATCH`。刷机后既换公钥又可能换出口 IP，注册被永久拒绝：设备连不上，
`rustbot-api` 也就看不到在线状态。

同时，叶子租约与本地注册混在同一张 peer map，过期租约里的来源地址是叶子看到的局域网地址，
与直接注册时的来源地址根本不可比，会额外把注册挡死。

## 2. 恢复密钥

设备由板载 SOC_UID 派生一把恢复密钥，不落盘、不上报、不写日志：

```text
seed = SHA256("rustbot-recovery-key-v1\n" || lower(trim(SOC_UID)))
(pk_r, sk_r) = ed25519_keypair_from_seed(seed)
```

`sk_r` 只用于签署公钥轮换声明。日常身份仍是随机主密钥，恢复密钥不能用于 peer 握手。
刷机后 `sk_r` 可以重算，因此“同一块板子”永远能重新证明自己。

## 3. 传输载体

`libs/hbb_common` 固定在上游 submodule，不能给 `RegisterPk` 增加字段。本仓库的注册分支
完全不使用 `RegisterPk.old_id`，RustBot Agent 用它承载轮换载荷：

```text
old_id = "rustnet-rotation-v1:" || base64( recovery_pk(32) || binding_sig(64) || rotation_sig(64) )
```

- 只有 RustBot peer ID（`rb-` + 32 位十六进制）才解析该载荷；其他 ID 一律按“没有载荷”处理。
- stock RustDesk 客户端不发送该前缀，行为不变。
- 前缀、域分隔字符串与字段顺序由两侧的固定向量用例锁定：
  `rustdesk-server/src/registration.rs` 与 `rustnet/src/registration.rs`。

签名域：

```text
bind   = "rustbot-recovery-bind-v1\n"   || id || "\n" || uuid || "\n" || recovery_pk   (主密钥签名)
rotate = "rustbot-recovery-rotate-v1\n" || id || "\n" || uuid || "\n" || pk            (恢复密钥签名)
```

`bind` 让当前主密钥持有者声明“这把恢复公钥归我”；`rotate` 让恢复密钥持有者声明
“换用这把新主密钥”。两者都在每次 `RegisterPk` 中携带，服务端按需使用。

## 4. 服务端判定

判定只使用本地注册记录或本地 DB 行。叶子租约只提供 `uuid`/`pk` 视图，**不提供来源 IP**。

| 已有身份 | 条件 | 结果 |
| --- | --- | --- |
| 无记录 | — | 接受；登记载荷里的恢复公钥（首次注册先到先得） |
| 有记录但 UUID 为空 | — | 接受；登记恢复公钥（与上游“尚未注册”语义一致） |
| UUID 不同 | — | 拒绝 `UUID_MISMATCH` |
| UUID 相同 | 主密钥相同 | 接受；`bind` 验签通过则登记或刷新恢复公钥 |
| UUID 相同 | 主密钥不同，`rotate` 用已登记恢复公钥验签通过 | 接受；更新主密钥并刷新恢复公钥 |
| UUID 相同 | 主密钥不同，来源 IP 与本地记录相同 | 接受；不登记恢复公钥（兼容旧 Agent） |
| 其余 | — | 拒绝 `UUID_MISMATCH`，日志写明原因 |

两个必须保持的点：

- 登记恢复公钥必须验 `bind`。公钥是公开数据（客户端按 hbbs 签名取回），只比主密钥相等
  等于让任何人登记自己的恢复公钥。
- 兼容路径只用本地记录里的 IP。终端的局域网地址、叶子看到的地址都不能参与比较。

接受之后：更新 `peer` 行（uuid、pk、ip、owner、socket 地址），并广播租约。

## 5. 恢复公钥的存储与传播

- 新表 `peer_recovery(id, recovery_pk, updated_at)`，独立于 `peer` 行：
  它属于设备身份，不属于本地注册，注册清理不删除它。
- 写入时机：注册接受时（见判定表）与收到联邦租约时。
- `PeerLease` 增加 `recovery_pk`（`serde(default)`，旧节点缺省为空）。这样任意节点都能
  在本地验证后续轮换，不必回源。

## 6. 兼容与上线顺序

| hbbs | Agent | 行为 |
| --- | --- | --- |
| 旧 | 旧 | 原行为 |
| 旧 | 新 | 旧 hbbs 忽略 `old_id`，与原行为一致 |
| 新 | 旧 | 租约不再挡注册；换公钥仍只用“同 IP”放行；不登记恢复公钥 |
| 新 | 新 | 首次注册登记恢复公钥；之后换公钥自动通过 |

因此上线顺序是：先升级 A 与所有叶子的 hbbs，再升级在线设备的 Agent（完成恢复公钥登记），
最后才安排刷机。升级 Agent 之前已经刷坏、没有登记恢复公钥的设备，需要一次性重置注册
（停 hbbs 删 `peer` 行后重启，或重启对端叶子让租约失效）。

## 7. 残余风险

- 知道 SOC_UID 的人可以轮换该设备的主密钥。SOC_UID 只存在于板载分区和 `rustbot-api`
  的元数据中，不进日志、不对外返回。
- 网络侧只能看到恢复公钥和两个签名；捕获的 `rotate` 只能把主密钥换成同一把。
- 旧 Agent 的“同 IP 放行”保留为兼容路径，等全部设备升级后可另行收紧。
