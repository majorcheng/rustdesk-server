//! RustNet 控制面信封协议。
//!
//! 规范见 `docs/rustnet_control_plane_encryption.md` 第 4 节。本 crate 是契约的唯一实现，
//! 服务端（hbbs）与端点（rustnet Agent/客户端）都引用它，测试向量在 `tests/` 下。
//!
//! 组成：
//!
//! - `key`：服务器静态密钥、`mac1` 与它的派生密钥。
//! - `frame`：内层帧（版本、序号、时间、确认、消息体、填充）。
//! - `handshake`：`Noise_NK_25519_ChaChaPoly_SHA256` 请求/应答与推送会话密钥。
//! - `session`：最近 3 个推送会话的环形队列与确认语义。
//! - `limits`：`mac1` 之后的每源限速与全局并发闸门。

mod error;
mod frame;
mod handshake;
mod key;
mod limits;
mod rng;
mod session;

pub use error::{Error, Result};
pub use frame::{plaintext_cap, Frame, FLAG_TIME_CORRECTION, HEADER_LEN, VERSION};
pub use handshake::{verify_request, Client, Keys, PushReader, PushWriter, ServerHandshake};
pub use key::{mac1, mac1_key, verify_mac1, DeviceKey, MAC1_LEN};
pub use limits::{Inflight, RateLimiter, PER_IP_PER_SEC};
pub use rng::{OsRng, Rng};
pub use session::{Entry, Ring, RING_CAP};

/// 握手 prologue。只进入握手哈希，不上网。
pub const PROLOGUE: &[u8] = b"rn-seal/1";

/// 单个数据报上限，避免 IP 分片。
pub const MAX_DATAGRAM: usize = 1200;

/// 内层填充下限与上限。
pub const PAD_MIN: usize = 96;
pub const PAD_MAX: usize = 320;

/// 密钥长度。
pub const KEY_LEN: usize = 32;
