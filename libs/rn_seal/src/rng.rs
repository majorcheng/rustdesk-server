use crate::{Error, Result};

/// 随机源。测试用它注入确定字节。
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;
    fn u64(&mut self) -> Result<u64> {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }
}

/// 系统随机数。
pub struct OsRng;

impl Rng for OsRng {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        getrandom::getrandom(buf).map_err(Error::from)
    }
}

impl<T: Rng + ?Sized> Rng for &mut T {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        (**self).fill(buf)
    }
}
