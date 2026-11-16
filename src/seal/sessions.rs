use hbb_common::ResultType;
use rn_seal::{Keys, OsRng, Ring};
use std::collections::HashMap;
use std::net::SocketAddr;

/// 时间戳允许的偏差。请求与应答的时钟都按此窗口校验。
pub const TS_WINDOW_MS: u64 = 120_000;
/// 会话空闲上限。超过后丢弃，避免旧地址被新使用者继承。
pub const SESSION_TTL_MS: u64 = 600_000;

/// 推送发出口的处理结果。
pub enum Seal {
    /// 该地址没有信封会话，按明文发送。
    Plaintext,
    /// 会话尚未被对端确认，本次推送丢弃。
    Pending,
    /// 已封装的推送数据报。
    Datagram(Vec<u8>),
}

pub struct Slot {
    peer_id: String,
    ring: Ring,
    last_ts: u64,
}

/// 已建立的推送会话，按地址与节点 id 双向索引。
#[derive(Default)]
pub struct Sessions {
    by_addr: HashMap<SocketAddr, Slot>,
    by_peer: HashMap<String, SocketAddr>,
}

impl Sessions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn install(&mut self, peer_id: String, addr: SocketAddr, seq: u32, ts: u64, keys: Keys) {
        if let Some(old) = self.by_peer.get(&peer_id).copied() {
            if old != addr {
                self.by_addr.remove(&old);
            }
        }
        if let Some(previous) = self.by_addr.get(&addr) {
            if previous.peer_id != peer_id {
                self.by_peer.remove(&previous.peer_id);
            }
        }
        let slot = self.by_addr.entry(addr).or_insert(Slot {
            peer_id: peer_id.clone(),
            ring: Ring::new(),
            last_ts: ts,
        });
        slot.ring.push(seq, keys);
        slot.last_ts = ts;
        self.by_peer.insert(peer_id, addr);
    }

    /// 按确认标签把对应会话升为当前。
    pub fn confirm(&mut self, addr: SocketAddr, ack: &[u8; 8]) -> bool {
        match self.by_addr.get_mut(&addr) {
            Some(slot) => slot.ring.confirm(ack),
            None => false,
        }
    }

    /// 丢弃该地址的信封会话。明文注册走到同一地址时调用。
    pub fn remove_addr(&mut self, addr: SocketAddr) {
        if let Some(slot) = self.by_addr.remove(&addr) {
            if self.by_peer.get(&slot.peer_id) == Some(&addr) {
                self.by_peer.remove(&slot.peer_id);
            }
        }
    }

    /// 丢弃空闲过久的会话。
    pub fn expire(&mut self, now: u64) {
        let ttl = SESSION_TTL_MS;
        self.by_addr
            .retain(|_, slot| now.saturating_sub(slot.last_ts) <= ttl);
        self.by_peer
            .retain(|_, addr| self.by_addr.contains_key(addr));
    }

    /// 时间窗与单调性检查。没有会话的节点只检查窗口。
    pub fn advance_ts(&mut self, peer_id: &str, ts: u64, now: u64) -> bool {
        if ts.saturating_add(TS_WINDOW_MS) < now || ts > now.saturating_add(TS_WINDOW_MS) {
            return false;
        }
        let addr = match self.by_peer.get(peer_id).copied() {
            Some(addr) => addr,
            None => return true,
        };
        let slot = match self.by_addr.get_mut(&addr) {
            Some(slot) => slot,
            None => return true,
        };
        if ts <= slot.last_ts {
            return false;
        }
        slot.last_ts = ts;
        true
    }

    /// 用已确认的会话封装一条推送。
    ///
    /// 没有会话时返回 `Plaintext`，调用方退回明文路径；
    /// 会话还没被对端确认时返回 `Pending`，本次推送直接丢弃。
    pub fn seal(&mut self, addr: SocketAddr, inner: &[u8]) -> ResultType<Seal> {
        let slot = match self.by_addr.get_mut(&addr) {
            Some(slot) => slot,
            None => return Ok(Seal::Plaintext),
        };
        let entry = match slot.ring.current_mut() {
            Some(entry) => entry,
            None => return Ok(Seal::Pending),
        };
        let mut rng = OsRng;
        Ok(Seal::Datagram(entry.writer.seal(inner, &mut rng)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rn_seal::{Client, DeviceKey, Frame, OsRng, ServerHandshake};

    const PEER: &str = "rb-00112233445566778899aabbccddeeff";

    fn pair(seed: u8) -> (Keys, Keys) {
        let device = DeviceKey::from_secret_bytes([seed; 32]);
        let (request, client) = Client::start(&device.public_bytes(), b"inner").expect("start");
        let (_, stage) = ServerHandshake::read(&device, &request).expect("read");
        let (reply, server) = stage.respond(b"inner").expect("respond");
        let (_, client) = client.finish(&reply).expect("finish");
        (server, client)
    }

    fn inner_frame() -> Vec<u8> {
        Frame::new(0, 1, b"push".to_vec())
            .encode(&mut OsRng, rn_seal::plaintext_cap(false))
            .expect("encode")
    }

    #[test]
    fn push_waits_for_confirmation() {
        let addr: SocketAddr = "10.0.0.7:5000".parse().unwrap();
        let (server, client) = pair(9);
        let ack = client.ack;
        let inner = inner_frame();
        let mut sessions = Sessions::new();
        sessions.install(PEER.to_owned(), addr, 1, 1_000, server);
        // 对端确认之前没有解密状态，推送必须等待。
        assert!(matches!(
            sessions.seal(addr, &inner).unwrap(),
            Seal::Pending
        ));
        assert!(sessions.confirm(addr, &ack));
        let datagram = match sessions.seal(addr, &inner).unwrap() {
            Seal::Datagram(datagram) => datagram,
            _ => panic!("确认后必须走信封"),
        };
        let mut reader = client.into_reader();
        assert_eq!(reader.open(&datagram).expect("open"), inner);
    }

    #[test]
    fn unknown_addr_uses_plaintext() {
        let addr: SocketAddr = "10.0.0.8:5000".parse().unwrap();
        let mut sessions = Sessions::new();
        assert!(matches!(
            sessions.seal(addr, &inner_frame()).unwrap(),
            Seal::Plaintext
        ));
    }

    #[test]
    fn expire_and_remove_drop_session() {
        let addr: SocketAddr = "10.0.0.9:5000".parse().unwrap();
        let (server, client) = pair(5);
        let mut sessions = Sessions::new();
        sessions.install(PEER.to_owned(), addr, 1, 1_000, server);
        assert!(sessions.confirm(addr, &client.ack));
        sessions.expire(1_000 + SESSION_TTL_MS + 1);
        assert!(matches!(
            sessions.seal(addr, &inner_frame()).unwrap(),
            Seal::Plaintext
        ));

        let (server, client) = pair(6);
        sessions.install(PEER.to_owned(), addr, 2, 2_000, server);
        assert!(sessions.confirm(addr, &client.ack));
        sessions.remove_addr(addr);
        assert!(matches!(
            sessions.seal(addr, &inner_frame()).unwrap(),
            Seal::Plaintext
        ));
    }
}
