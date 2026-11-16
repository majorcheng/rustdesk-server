use crate::{Error, Result, Rng, MAX_DATAGRAM, PAD_MAX, PAD_MIN};

/// 内层格式版本。
pub const VERSION: u8 = 1;

/// 应答携带时间校正。
pub const FLAG_TIME_CORRECTION: u8 = 0x01;

/// 内层头长度：版本 1、标志 1、请求序号 4、时间 8、确认 8、消息体长度 2。
pub const HEADER_LEN: usize = 24;

/// 内层帧。线上形态：`ver(1) ‖ flags(1) ‖ req_seq(4) ‖ ts_ms(8) ‖ ack(8) ‖ body_len(2) ‖ body ‖ pad`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub flags: u8,
    pub req_seq: u32,
    pub ts_ms: u64,
    pub ack: [u8; 8],
    pub body: Vec<u8>,
}

impl Frame {
    pub fn new(req_seq: u32, ts_ms: u64, body: Vec<u8>) -> Self {
        Self {
            flags: 0,
            req_seq,
            ts_ms,
            ack: [0u8; 8],
            body,
        }
    }

    /// 编码并填充到 `PAD_MIN..=PAD_MAX` 的随机长度。
    ///
    /// 参数 `cap` 是加密前的明文上限，保证加上头部与 AEAD 标签后不超过单个数据报。
    pub fn encode(&self, rng: &mut impl Rng, cap: usize) -> Result<Vec<u8>> {
        let body_len: u16 = self.body.len().try_into().map_err(|_| Error::TooLarge)?;
        let raw = HEADER_LEN + self.body.len();
        if raw > cap.max(HEADER_LEN) {
            return Err(Error::TooLarge);
        }
        let target = pad_target(raw, rng)?;
        if target > cap {
            return Err(Error::TooLarge);
        }
        let mut out = Vec::with_capacity(target);
        out.push(VERSION);
        out.push(self.flags);
        out.extend_from_slice(&self.req_seq.to_be_bytes());
        out.extend_from_slice(&self.ts_ms.to_be_bytes());
        out.extend_from_slice(&self.ack);
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(&self.body);
        out.resize(target, 0);
        Ok(out)
    }

    /// 解析内层帧。填充必须全 0，长度必须正好等于头加消息体加填充。
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Malformed("short inner frame"));
        }
        if bytes[0] != VERSION {
            return Err(Error::Malformed("inner version"));
        }
        let flags = bytes[1];
        let req_seq = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let ts_ms = u64::from_be_bytes([
            bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],
        ]);
        let mut ack = [0u8; 8];
        ack.copy_from_slice(&bytes[14..22]);
        let body_len = u16::from_be_bytes([bytes[22], bytes[23]]) as usize;
        let end = HEADER_LEN
            .checked_add(body_len)
            .ok_or(Error::Malformed("inner length"))?;
        if end > bytes.len() {
            return Err(Error::Malformed("inner body length"));
        }
        if bytes[end..].iter().any(|byte| *byte != 0) {
            return Err(Error::Malformed("padding is not zero"));
        }
        Ok(Self {
            flags,
            req_seq,
            ts_ms,
            ack,
            body: bytes[HEADER_LEN..end].to_vec(),
        })
    }
}

/// 内层帧的上限：数据报上限减去握手/推送开销、`mac1` 与 AEAD 标签。
pub fn plaintext_cap(mac1: bool) -> usize {
    let fixed = crate::KEY_LEN + 16 + if mac1 { crate::MAC1_LEN } else { 0 };
    MAX_DATAGRAM.saturating_sub(fixed)
}

fn pad_target(raw: usize, rng: &mut impl Rng) -> Result<usize> {
    if raw >= PAD_MAX {
        return Ok(raw);
    }
    let low = raw.max(PAD_MIN);
    let span = PAD_MAX - low + 1;
    let mut bytes = [0u8; 2];
    rng.fill(&mut bytes)?;
    Ok(low + (u16::from_le_bytes(bytes) as usize) % span)
}
