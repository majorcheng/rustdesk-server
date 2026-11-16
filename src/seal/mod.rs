mod reply;
mod sessions;

pub use reply::Reply;
pub use sessions::{Seal, Sessions};

use crate::common::{get_arg, get_arg_or};
use hbb_common::{
    log,
    tokio::{
        self,
        net::UdpSocket,
        sync::{mpsc, Mutex},
        time::Duration,
    },
    ResultType,
};
use rn_seal::{
    verify_request, DeviceKey, Frame, Inflight, OsRng, RateLimiter, ServerHandshake, MAX_DATAGRAM,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// 信封路径的默认 UDP 端口。
pub const DEFAULT_SEAL_PORT: u16 = 4443;
/// 接收缓冲区。比数据报上限大，便于发现超长包并拒绝。
const RECV_BUF: usize = 2048;
/// 已完成解密、等待分发的请求队列上限。超过后丢弃新请求。
const QUEUE_CAP: usize = 1024;

/// 信封路径收到的一次请求。内层帧已经解密，握手停在“待写应答”阶段。
pub struct SealedRequest {
    pub addr: SocketAddr,
    pub frame: Frame,
    pub stage: ServerHandshake,
}

/// 信封路径要发出的数据报。
pub struct SealedOutput {
    pub addr: SocketAddr,
    pub datagram: Vec<u8>,
}

pub struct SealConfig {
    pub port: u16,
    pub key: DeviceKey,
    /// 换钥期间同时接受的新密钥。代理切到新密钥后再把它提升为 `key`。
    pub next_key: Option<DeviceKey>,
}

impl SealConfig {
    /// 未配置 `SEAL-KEY` 时返回 `None`，信封路径关闭。
    pub fn from_env() -> ResultType<Option<Self>> {
        let secret = get_arg("SEAL_KEY");
        if secret.trim().is_empty() {
            return Ok(None);
        }
        let port_text = get_arg_or("SEAL_PORT", DEFAULT_SEAL_PORT.to_string());
        let port: u16 = port_text
            .trim()
            .parse()
            .map_err(|_| hbb_common::anyhow::anyhow!("invalid SEAL-PORT: {port_text}"))?;
        let key = load_key(&secret)?;
        let next_secret = get_arg("SEAL_KEY_NEXT");
        let next_key = if next_secret.trim().is_empty() {
            None
        } else {
            Some(load_key(&next_secret)?)
        };
        log::info!(
            "seal path enabled on udp/{} public_key={} (rotation key: {})",
            port,
            key.public_b64(),
            if next_key.is_some() { "set" } else { "none" }
        );
        Ok(Some(Self {
            port,
            key,
            next_key,
        }))
    }
}

/// 从 `SEAL-KEY` 指向的文件读取 32 字节私钥。文件内容是原始私钥的 base64，权限 0600。
fn load_key(path: &str) -> ResultType<DeviceKey> {
    let path = path.trim();
    let text = std::fs::read_to_string(path)
        .map_err(|err| hbb_common::anyhow::anyhow!("SEAL-KEY {path} is not readable: {err}"))?;
    DeviceKey::from_secret_b64(text.trim())
        .map_err(|err| hbb_common::anyhow::anyhow!("invalid SEAL-KEY {path}: {err}"))
}

struct SealState {
    key: DeviceKey,
    next_key: Option<DeviceKey>,
    rate: Mutex<RateLimiter>,
    inflight: Mutex<Inflight>,
}

impl SealState {
    fn new(key: DeviceKey, next_key: Option<DeviceKey>) -> Self {
        let workers = std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(4);
        Self {
            key,
            next_key,
            rate: Mutex::new(RateLimiter::new()),
            inflight: Mutex::new(Inflight::new(workers)),
        }
    }

    /// `mac1` 校验、限速、并发闸门，最后在阻塞线程里做 DH。
    async fn handle(
        self: Arc<Self>,
        datagram: Vec<u8>,
        addr: SocketAddr,
        req_tx: mpsc::Sender<SealedRequest>,
    ) {
        if datagram.len() > MAX_DATAGRAM {
            return;
        }
        let accepted = verify_request(&self.key, &datagram).is_ok()
            || self
                .next_key
                .as_ref()
                .map(|key| verify_request(key, &datagram).is_ok())
                .unwrap_or(false);
        if !accepted {
            return;
        }
        if !self.rate.lock().await.allow(addr.ip()) {
            return;
        }
        {
            let mut inflight = self.inflight.lock().await;
            if !inflight.try_acquire() {
                return;
            }
        }
        let key = self.key.clone();
        let next_key = self.next_key.clone();
        let result = tokio::task::spawn_blocking(move || {
            let read = match ServerHandshake::read(&key, &datagram) {
                Ok(pair) => Ok(pair),
                Err(rn_seal::Error::Auth) => match next_key {
                    Some(next) => ServerHandshake::read(&next, &datagram),
                    None => Err(rn_seal::Error::Auth),
                },
                Err(err) => Err(err),
            };
            let (inner, stage) = read?;
            let frame = Frame::decode(&inner)?;
            Ok::<_, rn_seal::Error>((frame, stage))
        })
        .await;
        self.inflight.lock().await.release();
        match result {
            Ok(Ok((frame, stage))) => match req_tx.try_send(SealedRequest { addr, frame, stage }) {
                Ok(()) => {}
                Err(err) => log::debug!("seal request from {} dropped: {}", addr, err),
            },
            Ok(Err(err)) => log::debug!("seal request from {} dropped: {}", addr, err),
            Err(err) => log::error!("seal worker failed: {}", err),
        }
    }
}

/// 绑定信封监听 socket。未指定地址时优先双栈，失败再退回 IPv4。
async fn bind(bind_addr: Option<IpAddr>, port: u16) -> ResultType<UdpSocket> {
    if let Some(ip) = bind_addr {
        return Ok(UdpSocket::bind(SocketAddr::new(ip, port)).await?);
    }
    match bind_dual_stack(port) {
        Ok(socket) => Ok(socket),
        Err(err) => {
            log::warn!(
                "sealed udp dual-stack bind failed, falling back to IPv4: {}",
                err
            );
            Ok(UdpSocket::bind(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                port,
            ))
            .await?)
        }
    }
}

fn bind_dual_stack(port: u16) -> ResultType<UdpSocket> {
    use std::net::Ipv6Addr;
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_only_v6(false)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}

/// 启动信封监听。返回（请求接收端、发送端）；调用方在 `io_loop` 中消费。
pub async fn start(
    bind_addr: Option<IpAddr>,
    config: SealConfig,
) -> ResultType<(
    mpsc::Receiver<SealedRequest>,
    mpsc::UnboundedSender<SealedOutput>,
)> {
    let socket = bind(bind_addr, config.port).await?;
    log::info!("Listening on sealed udp {}", socket.local_addr()?);
    let socket = Arc::new(socket);
    let state = Arc::new(SealState::new(config.key, config.next_key));
    let (req_tx, req_rx) = mpsc::channel::<SealedRequest>(QUEUE_CAP);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<SealedOutput>();
    tokio::spawn(async move {
        let mut buf = vec![0u8; RECV_BUF];
        loop {
            tokio::select! {
                received = socket.recv_from(&mut buf) => {
                    match received {
                        Ok((len, addr)) => {
                            if len > MAX_DATAGRAM {
                                continue;
                            }
                            let datagram = buf[..len].to_vec();
                            let state = state.clone();
                            let req_tx = req_tx.clone();
                            tokio::spawn(async move { state.handle(datagram, addr, req_tx).await; });
                        }
                        Err(err) => {
                            log::warn!("seal recv failed: {}", err);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
                Some(output) = out_rx.recv() => {
                    if let Err(err) = socket.send_to(&output.datagram, output.addr).await {
                        log::warn!("seal send to {} failed: {}", output.addr, err);
                    }
                }
            }
        }
    });
    Ok((req_rx, out_tx))
}

/// 当前时间，毫秒。
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as u64)
        .unwrap_or(0)
}

/// 封装一次应答。
pub fn seal_reply(
    stage: ServerHandshake,
    frame: &Frame,
    body: &[u8],
) -> ResultType<(Vec<u8>, rn_seal::Keys)> {
    let mut rng = OsRng;
    let mut reply = Frame::new(frame.req_seq, now_ms(), body.to_vec());
    reply.flags = 0;
    let inner = reply.encode(&mut rng, rn_seal::plaintext_cap(false))?;
    let (datagram, keys) = stage.respond(&inner)?;
    Ok((datagram, keys))
}
