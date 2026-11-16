use super::sessions::{Seal, Sessions};
use super::{now_ms, SealedOutput};
use hbb_common::{
    log,
    protobuf::Message as _,
    rendezvous_proto::RendezvousMessage,
    tokio::sync::{mpsc, Mutex},
    udp::FramedSocket,
    ResultType,
};
use rn_seal::{plaintext_cap, Frame, OsRng};
use std::{net::SocketAddr, sync::Arc};

/// 应答出口。
///
/// 明文路径直接写 UDP；目标地址已有推送会话时自动改走信封路径。
/// 处理信封请求期间只缓存应答，由 `handle_sealed` 用握手状态封装。
pub struct Reply<'a> {
    udp: Option<&'a mut FramedSocket>,
    buffered: Vec<RendezvousMessage>,
    sealed_request: bool,
    peer_id: Option<String>,
    sessions: Arc<Mutex<Sessions>>,
    out: mpsc::UnboundedSender<SealedOutput>,
}

impl<'a> Reply<'a> {
    pub fn udp(
        socket: &'a mut FramedSocket,
        sessions: Arc<Mutex<Sessions>>,
        out: mpsc::UnboundedSender<SealedOutput>,
    ) -> Self {
        Self {
            udp: Some(socket),
            buffered: Vec::new(),
            sealed_request: false,
            peer_id: None,
            sessions,
            out,
        }
    }

    pub fn sealed(
        sessions: Arc<Mutex<Sessions>>,
        out: mpsc::UnboundedSender<SealedOutput>,
    ) -> Self {
        Self {
            udp: None,
            buffered: Vec::new(),
            sealed_request: true,
            peer_id: None,
            sessions,
            out,
        }
    }

    pub async fn send(&mut self, msg: &RendezvousMessage, addr: SocketAddr) -> ResultType<()> {
        if self.sealed_request {
            self.buffered.push(msg.clone());
            return Ok(());
        }
        let body = msg.write_to_bytes()?;
        let sealed = {
            let mut sessions = self.sessions.lock().await;
            let mut rng = OsRng;
            let frame = Frame::new(0, now_ms(), body);
            let inner = frame.encode(&mut rng, plaintext_cap(false))?;
            sessions.seal(addr, &inner)?
        };
        match sealed {
            Seal::Datagram(datagram) => {
                if let Err(err) = self.out.send(SealedOutput { addr, datagram }) {
                    log::warn!("seal output channel closed for {}: {}", addr, err);
                }
                return Ok(());
            }
            // 会话还没被对端确认：对端没有解密状态，发出去只能被丢弃。
            Seal::Pending => {
                log::debug!("sealed session for {} is not confirmed yet", addr);
                return Ok(());
            }
            Seal::Plaintext => {}
        }
        match self.udp.as_mut() {
            Some(socket) => socket.send(msg, addr).await,
            None => Ok(()),
        }
    }

    pub fn is_sealed(&self) -> bool {
        self.sealed_request
    }

    pub fn take_buffered(&mut self) -> Vec<RendezvousMessage> {
        std::mem::take(&mut self.buffered)
    }

    pub fn set_peer(&mut self, id: &str) {
        if self.sealed_request {
            self.peer_id = Some(id.to_owned());
        }
    }
}
