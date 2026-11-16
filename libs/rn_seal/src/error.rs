use std::fmt;

/// 信封协议的错误类型。所有失败都不携带对端可观察的信息。
#[derive(Debug)]
pub enum Error {
    /// Noise 状态机或 AEAD 失败。
    Crypto(snow::Error),
    /// 系统随机数失败。
    Random(getrandom::Error),
    /// 数据报长度、版本或填充不合法。
    Malformed(&'static str),
    /// `mac1` 不匹配。
    Auth,
    /// 推送 nonce 重复。
    Replay,
    /// 明文超过允许的帧长。
    TooLarge,
    /// 密钥不是 32 字节的 base64。
    KeyEncoding,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Crypto(err) => write!(f, "crypto: {err}"),
            Error::Random(err) => write!(f, "random: {err}"),
            Error::Malformed(what) => write!(f, "malformed: {what}"),
            Error::Auth => write!(f, "auth failed"),
            Error::Replay => write!(f, "replayed nonce"),
            Error::TooLarge => write!(f, "frame too large"),
            Error::KeyEncoding => write!(f, "key is not 32 base64 bytes"),
        }
    }
}

impl std::error::Error for Error {}

impl From<snow::Error> for Error {
    fn from(err: snow::Error) -> Self {
        Error::Crypto(err)
    }
}

impl From<getrandom::Error> for Error {
    fn from(err: getrandom::Error) -> Self {
        Error::Random(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
