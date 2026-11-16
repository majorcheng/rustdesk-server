use crate::key::{mac1, mac1_key, DeviceKey};
use crate::{Error, Result, Rng, KEY_LEN, MAC1_LEN, MAX_DATAGRAM, PROLOGUE};
use sha2::{Digest, Sha256};
use snow::{HandshakeState, StatelessTransportState};
use std::collections::VecDeque;

const PATTERN: &str = "Noise_NK_25519_ChaChaPoly_SHA256";
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 8;
/// 每个推送会话记住的 nonce 数量。推送间隔 10 秒，64 个足够覆盖乱序与重放窗口。
const SEEN_CAP: usize = 64;

fn params() -> Result<snow::params::NoiseParams> {
    PATTERN
        .parse()
        .map_err(|_| Error::Malformed("noise params"))
}

/// 一次交换完成后的推送会话材料。
pub struct Keys {
    pub ack: [u8; 8],
    pub hash: [u8; 32],
    state: StatelessTransportState,
}

impl Keys {
    fn new(hash: &[u8], state: StatelessTransportState) -> Result<Self> {
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| Error::Malformed("handshake hash"))?;
        // 确认标识与推送密钥分离，避免把传输密钥派生的短值暴露在线上。
        let mut hasher = Sha256::new();
        hasher.update(b"ack");
        hasher.update(hash);
        let digest = hasher.finalize();
        let mut ack = [0u8; 8];
        ack.copy_from_slice(&digest[..8]);
        Ok(Self { ack, hash, state })
    }

    pub fn into_writer(self) -> PushWriter {
        PushWriter { state: self.state }
    }

    pub fn into_reader(self) -> PushReader {
        PushReader {
            state: self.state,
            seen: VecDeque::with_capacity(SEEN_CAP),
        }
    }
}

/// 发起方（端点）。一次请求换一个实例。
pub struct Client {
    hs: Option<HandshakeState>,
}

impl Client {
    /// 生成请求数据报。`inner` 是已编码的内层帧。
    pub fn start(server_public: &[u8; KEY_LEN], inner: &[u8]) -> Result<(Vec<u8>, Self)> {
        let mut hs = snow::Builder::new(params()?)
            .prologue(PROLOGUE)?
            .remote_public_key(server_public)?
            .build_initiator()?;
        let mut wire = vec![0u8; MAX_DATAGRAM];
        let len = hs.write_message(inner, &mut wire)?;
        wire.truncate(len);
        let tag = mac1(&mac1_key(server_public), &wire);
        wire.extend_from_slice(&tag);
        Ok((wire, Self { hs: Some(hs) }))
    }

    /// 读应答，返回内层帧明文与会话材料。
    pub fn finish(self, response: &[u8]) -> Result<(Vec<u8>, Keys)> {
        let mut hs = self.hs.ok_or(Error::Malformed("client finished twice"))?;
        if response.len() < KEY_LEN + TAG_LEN {
            return Err(Error::Malformed("short response"));
        }
        let mut plain = vec![0u8; MAX_DATAGRAM];
        let len = hs.read_message(response, &mut plain)?;
        plain.truncate(len);
        let hash = hs.get_handshake_hash().to_vec();
        let state = hs.into_stateless_transport_mode()?;
        Ok((plain, Keys::new(&hash, state)?))
    }
}

/// 响应方（hbbs）的两段式处理：先读到请求，处理完再写应答。
pub struct ServerHandshake {
    hs: HandshakeState,
}

impl ServerHandshake {
    /// 校验 `mac1`、解密请求，返回内层帧明文与后续阶段。
    pub fn read(key: &DeviceKey, datagram: &[u8]) -> Result<(Vec<u8>, Self)> {
        verify_request(key, datagram)?;
        let body_len = datagram.len() - MAC1_LEN;
        let secret = key.secret_bytes();
        let mut hs = snow::Builder::new(params()?)
            .prologue(PROLOGUE)?
            .local_private_key(&secret)?
            .build_responder()?;
        let mut plain = vec![0u8; MAX_DATAGRAM];
        let len = hs.read_message(&datagram[..body_len], &mut plain)?;
        plain.truncate(len);
        Ok((plain, Self { hs }))
    }

    /// 写入应答内层帧，返回应答数据报与会话材料。
    pub fn respond(mut self, inner: &[u8]) -> Result<(Vec<u8>, Keys)> {
        let mut reply = vec![0u8; MAX_DATAGRAM];
        let len = self.hs.write_message(inner, &mut reply)?;
        reply.truncate(len);
        let hash = self.hs.get_handshake_hash().to_vec();
        let state = self.hs.into_stateless_transport_mode()?;
        Ok((reply, Keys::new(&hash, state)?))
    }
}

/// `mac1` 校验与最小长度检查。`mac1` 必须先于任何 DH 计算。
pub fn verify_request(key: &DeviceKey, datagram: &[u8]) -> Result<()> {
    if datagram.len() > MAX_DATAGRAM {
        return Err(Error::Malformed("datagram too large"));
    }
    crate::key::verify_mac1(&key.mac1_key(), datagram)?;
    if datagram.len() < MAC1_LEN + KEY_LEN + TAG_LEN {
        return Err(Error::Malformed("short request"));
    }
    Ok(())
}

/// 推送加密。服务器每次心跳后用它封包。
pub struct PushWriter {
    state: StatelessTransportState,
}

impl PushWriter {
    /// `nonce` 随机，避免计数器高位固定形成线上特征。
    pub fn seal(&mut self, inner: &[u8], rng: &mut impl Rng) -> Result<Vec<u8>> {
        let nonce = rng.u64()?;
        if NONCE_LEN + inner.len() + TAG_LEN > MAX_DATAGRAM {
            return Err(Error::TooLarge);
        }
        let mut out = vec![0u8; NONCE_LEN + inner.len() + TAG_LEN];
        self.state
            .write_message(nonce, inner, &mut out[NONCE_LEN..])?;
        out[..NONCE_LEN].copy_from_slice(&nonce.to_le_bytes());
        Ok(out)
    }
}

/// 推送解密。端点按会话实例保存已见 nonce。
pub struct PushReader {
    state: StatelessTransportState,
    seen: VecDeque<u64>,
}

impl PushReader {
    pub fn open(&mut self, datagram: &[u8]) -> Result<Vec<u8>> {
        if datagram.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::Malformed("short push"));
        }
        if datagram.len() > MAX_DATAGRAM {
            return Err(Error::Malformed("datagram too large"));
        }
        let mut nonce_bytes = [0u8; NONCE_LEN];
        nonce_bytes.copy_from_slice(&datagram[..NONCE_LEN]);
        let nonce = u64::from_le_bytes(nonce_bytes);
        if self.seen.contains(&nonce) {
            return Err(Error::Replay);
        }
        let mut plain = vec![0u8; datagram.len() - NONCE_LEN - TAG_LEN];
        let len = self
            .state
            .read_message(nonce, &datagram[NONCE_LEN..], &mut plain)?;
        plain.truncate(len);
        if self.seen.len() >= SEEN_CAP {
            self.seen.pop_front();
        }
        self.seen.push_back(nonce);
        Ok(plain)
    }
}
