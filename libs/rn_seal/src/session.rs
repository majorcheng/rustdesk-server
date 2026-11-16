use crate::handshake::{Keys, PushWriter};
use std::collections::VecDeque;

/// 每个对端保留的推送会话数量。当前、待确认、刚退出的各一个。
pub const RING_CAP: usize = 3;

/// 一个推送会话。`seq` 是该会话对应的请求序号。
pub struct Entry {
    pub seq: u32,
    pub ack: [u8; 8],
    pub writer: PushWriter,
}

/// 推送会话环。索引 0 是最新的会话，`active` 指向对端已确认的那个。
pub struct Ring {
    entries: VecDeque<Entry>,
    active: Option<u32>,
}

impl Default for Ring {
    fn default() -> Self {
        Self::new()
    }
}

impl Ring {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(RING_CAP),
            active: None,
        }
    }

    /// 压入新会话。相同 `seq` 的旧条目先移除，避免重排应答留下重复会话。
    ///
    /// 新会话先记为待确认：对端在收到本次应答之前没有它的解密状态，
    /// 因此确认之前不能用于推送。
    pub fn push(&mut self, seq: u32, keys: Keys) {
        let ack = keys.ack;
        self.entries.retain(|entry| entry.seq != seq);
        self.entries.push_front(Entry {
            seq,
            ack,
            writer: keys.into_writer(),
        });
        self.trim();
    }

    /// 超出容量时从最旧的开始丢弃，已确认会话始终保留。
    fn trim(&mut self) {
        let active = self.active;
        while self.entries.len() > RING_CAP {
            match self
                .entries
                .iter()
                .rposition(|entry| Some(entry.seq) != active)
            {
                Some(index) => {
                    self.entries.remove(index);
                }
                None => break,
            }
        }
    }

    /// 收到 `ack` 时把对应会话提升为当前。
    pub fn confirm(&mut self, ack: &[u8; 8]) -> bool {
        let index = match self.entries.iter().position(|entry| &entry.ack == ack) {
            Some(index) => index,
            None => return false,
        };
        self.active = Some(self.entries[index].seq);
        if index > 0 {
            if let Some(entry) = self.entries.remove(index) {
                self.entries.push_front(entry);
            }
        }
        true
    }

    /// 已确认会话的序号。对端确认之前为 `None`。
    pub fn current_seq(&self) -> Option<u32> {
        self.active
    }

    /// 已确认的会话。确认之前返回 `None`，调用方不得用它发送推送。
    pub fn current_mut(&mut self) -> Option<&mut Entry> {
        let seq = self.active?;
        let index = self.entries.iter().position(|entry| entry.seq == seq)?;
        self.entries.get_mut(index)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Entry> {
        self.entries.iter_mut()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Client, DeviceKey, ServerHandshake};

    /// 真实握手产生一份会话材料；返回材料与它的确认标签。
    fn session(seed: u8) -> (Keys, [u8; 8]) {
        let server = DeviceKey::from_secret_bytes([seed; 32]);
        let (request, client) = Client::start(&server.public_bytes(), b"inner").expect("start");
        let (_, stage) = ServerHandshake::read(&server, &request).expect("read");
        let (reply, _) = stage.respond(b"inner").expect("respond");
        let (_, keys) = client.finish(&reply).expect("finish");
        let ack = keys.ack;
        (keys, ack)
    }

    #[test]
    fn pending_session_is_not_used_for_push() {
        let mut ring = Ring::new();
        let (keys, ack) = session(1);
        ring.push(1, keys);
        assert!(ring.current_mut().is_none());
        assert!(ring.confirm(&ack));
        assert_eq!(ring.current_seq(), Some(1));
        assert!(ring.current_mut().is_some());
    }

    #[test]
    fn confirm_keeps_previous_session_pushable() {
        let mut ring = Ring::new();
        let (first, first_ack) = session(1);
        ring.push(1, first);
        assert!(ring.confirm(&first_ack));
        let (second, second_ack) = session(2);
        ring.push(2, second);
        // 新会话尚未确认，推送继续使用旧会话。
        assert_eq!(ring.current_seq(), Some(1));
        assert!(ring.confirm(&second_ack));
        assert_eq!(ring.current_seq(), Some(2));
    }

    #[test]
    fn unknown_ack_does_not_change_current() {
        let mut ring = Ring::new();
        let (keys, _) = session(1);
        ring.push(1, keys);
        assert!(!ring.confirm(&[9u8; 8]));
        assert_eq!(ring.current_seq(), None);
    }

    #[test]
    fn trim_keeps_confirmed_session() {
        let mut ring = Ring::new();
        let (first, first_ack) = session(1);
        ring.push(1, first);
        assert!(ring.confirm(&first_ack));
        for seq in 2..=(RING_CAP as u32 + 1) {
            let (keys, _) = session(seq as u8);
            ring.push(seq, keys);
        }
        assert_eq!(ring.len(), RING_CAP);
        assert_eq!(ring.current_seq(), Some(1));
    }
}
