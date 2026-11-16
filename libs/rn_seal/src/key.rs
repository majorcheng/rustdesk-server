use crate::{Error, Result, Rng, KEY_LEN};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

/// `mac1` 长度，与 WireGuard 一致。
pub const MAC1_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// 服务器静态密钥对。私钥以 32 字节原始形式保存，公钥由它推导。
#[derive(Clone)]
pub struct DeviceKey {
    secret: [u8; 32],
    public: [u8; 32],
}

impl DeviceKey {
    /// 从 32 字节原始私钥构造。curve25519 的钳位由 `StaticSecret` 处理。
    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        let key = StaticSecret::from(secret);
        let public = PublicKey::from(&key).to_bytes();
        Self { secret, public }
    }

    pub fn generate(rng: &mut impl Rng) -> Result<Self> {
        let mut secret = [0u8; KEY_LEN];
        rng.fill(&mut secret)?;
        Ok(Self::from_secret_bytes(secret))
    }

    pub fn from_secret_b64(text: &str) -> Result<Self> {
        let raw = B64.decode(text.trim()).map_err(|_| Error::KeyEncoding)?;
        let bytes: [u8; KEY_LEN] = raw.as_slice().try_into().map_err(|_| Error::KeyEncoding)?;
        Ok(Self::from_secret_bytes(bytes))
    }

    pub fn secret_b64(&self) -> String {
        B64.encode(self.secret)
    }

    pub fn public_b64(&self) -> String {
        B64.encode(self.public)
    }

    pub fn public_bytes(&self) -> [u8; KEY_LEN] {
        self.public
    }

    pub(crate) fn secret_bytes(&self) -> [u8; KEY_LEN] {
        self.secret
    }

    pub fn mac1_key(&self) -> [u8; 32] {
        mac1_key(&self.public)
    }
}

/// `mac1` 的密钥：`SHA256("mac1" ‖ 服务器公钥)`。它由公钥派生，因此不是认证手段，
/// 只过滤不知道服务器公钥的随机垃圾包。
pub fn mac1_key(server_public: &[u8; KEY_LEN]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"mac1");
    hasher.update(server_public);
    hasher.finalize().into()
}

/// `mac1`：`HMAC-SHA256(key, data)` 的前 16 字节。
pub fn mac1(key: &[u8; 32], data: &[u8]) -> [u8; MAC1_LEN] {
    let mut out = [0u8; MAC1_LEN];
    // HMAC 接受任意长度密钥，构造不会失败；失败时返回全 0，调用方按不匹配处理。
    if let Ok(mut hmac) = HmacSha256::new_from_slice(key) {
        hmac.update(data);
        let tag = hmac.finalize().into_bytes();
        out.copy_from_slice(&tag[..MAC1_LEN]);
    }
    out
}

/// 校验带 `mac1` 尾部的数据报。`tag` 区域必须是最后 16 字节。
pub fn verify_mac1(key: &[u8; 32], datagram: &[u8]) -> Result<()> {
    let split = datagram
        .len()
        .checked_sub(MAC1_LEN)
        .ok_or(Error::Malformed("short datagram"))?;
    let (body, tag) = datagram.split_at(split);
    let expected = mac1(key, body);
    if expected.ct_eq(tag).into() {
        Ok(())
    } else {
        Err(Error::Auth)
    }
}
