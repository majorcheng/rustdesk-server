use hbb_common::sha2::{Digest, Sha256};
use hbb_common::{
    base64::{engine::general_purpose, Engine as _},
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    futures_util::{SinkExt, StreamExt},
    log,
    sodiumoxide::crypto::secretbox,
    tokio::{
        self,
        net::{TcpListener, TcpStream},
        sync::{mpsc, RwLock},
        time::{sleep, Duration},
    },
    tokio_util::codec::Framed,
    try_into_v4, ResultType,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

const CONNECT_TIMEOUT_MS: u64 = 5_000;
const RETRY_DELAY: Duration = Duration::from_secs(3);
const HEARTBEAT_DELAY: Duration = Duration::from_secs(10);
const MAX_CONTROL_FRAME: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PeerLease {
    pub(crate) id: String,
    pub(crate) uuid: Vec<u8>,
    pub(crate) pk: Vec<u8>,
    pub(crate) ip: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum ForwardKind {
    ToPeer,
    ToSource,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ForwardMessage {
    pub(crate) kind: ForwardKind,
    pub(crate) source_node: String,
    pub(crate) target_node: String,
    pub(crate) source_addr: String,
    pub(crate) target_id: String,
    pub(crate) source_relay: String,
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Message {
    Hello {
        node_id: String,
        proof: String,
        relay_server: String,
    },
    Challenge {
        node_id: String,
        nonce: String,
    },
    HelloAck {
        node_id: String,
        #[serde(default)]
        relay_server: String,
    },
    Peer(PeerLease),
    PeerRemove {
        owner: String,
        id: String,
    },
    Forward(ForwardMessage),
    Ping,
    Pong,
    Encrypted(Vec<u8>),
}

#[derive(Debug)]
pub(crate) enum Event {
    Connected {
        node_id: String,
        relay_server: String,
    },
    Disconnected {
        node_id: String,
    },
    Peer {
        from_node: String,
        lease: PeerLease,
    },
    PeerRemove {
        from_node: String,
        owner: String,
        id: String,
    },
    Forward {
        from_node: String,
        message: ForwardMessage,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct RemoteRoute {
    pub(crate) source_node: String,
    pub(crate) source_addr: SocketAddr,
    pub(crate) target_id: String,
    pub(crate) source_relay: String,
    pub(crate) expires_at: Instant,
}

struct Link {
    tx: mpsc::UnboundedSender<Message>,
    id: u64,
}

#[derive(Clone)]
pub(crate) struct Federation {
    node_id: Arc<String>,
    master: Arc<String>,
    is_master: bool,
    relay_server: Arc<String>,
    key: Arc<String>,
    links: Arc<RwLock<HashMap<String, Link>>>,
    relays: Arc<RwLock<HashMap<String, String>>>,
    routes: Arc<RwLock<HashMap<String, RemoteRoute>>>,
    next_link_id: Arc<AtomicU64>,
    crypto_key: Arc<secretbox::Key>,
    events: mpsc::UnboundedSender<Event>,
}

impl Federation {
    pub(crate) async fn start(
        node_id: String,
        master: String,
        bind: String,
        key: String,
        relay_server: String,
    ) -> ResultType<(Self, mpsc::UnboundedReceiver<Event>)> {
        let enabled = !node_id.is_empty() || !master.is_empty() || !bind.is_empty();
        if enabled && key.is_empty() {
            return Err(hbb_common::anyhow::anyhow!(
                "FEDERATION_KEY is required when federation is enabled"
            ));
        }
        if enabled {
            hbb_common::sodiumoxide::init()
                .map_err(|_| hbb_common::anyhow::anyhow!("failed to initialize sodiumoxide"))?;
        }
        let crypto_key = derive_key(&key);
        let (events, rx) = mpsc::unbounded_channel();
        let is_master = !bind.is_empty() && master.is_empty();
        let federation = Self {
            node_id: Arc::new(node_id),
            master: Arc::new(master),
            is_master,
            relay_server: Arc::new(relay_server),
            key: Arc::new(key),
            links: Default::default(),
            relays: Default::default(),
            routes: Default::default(),
            next_link_id: Arc::new(AtomicU64::new(0)),
            crypto_key: Arc::new(crypto_key),
            events,
        };

        if !bind.is_empty() {
            let listener = hbb_common::tcp::new_listener(&bind, true).await?;
            let cloned = federation.clone();
            tokio::spawn(async move { cloned.accept_loop(listener).await });
            log::info!("federation listener: {}", bind);
        }
        if !federation.master.is_empty() {
            let cloned = federation.clone();
            tokio::spawn(async move { cloned.connect_loop().await });
            log::info!("federation master: {}", federation.master);
        }
        if enabled {
            log::info!(
                "federation node={} role={} relay={}",
                federation.node_id,
                if federation.is_master {
                    "master"
                } else {
                    "edge"
                },
                federation.relay_server
            );
        }
        Ok((federation, rx))
    }

    pub(crate) fn disabled() -> (Self, mpsc::UnboundedReceiver<Event>) {
        let (events, rx) = mpsc::unbounded_channel();
        (
            Self {
                node_id: Arc::new(String::new()),
                master: Arc::new(String::new()),
                is_master: false,
                relay_server: Arc::new(String::new()),
                key: Arc::new(String::new()),
                links: Default::default(),
                relays: Default::default(),
                routes: Default::default(),
                next_link_id: Arc::new(AtomicU64::new(0)),
                crypto_key: Arc::new(secretbox::Key([0; secretbox::KEYBYTES])),
                events,
            },
            rx,
        )
    }

    pub(crate) fn enabled(&self) -> bool {
        !self.node_id.is_empty()
    }

    pub(crate) fn is_master(&self) -> bool {
        self.is_master
    }

    pub(crate) fn node_id(&self) -> &str {
        self.node_id.as_str()
    }

    pub(crate) async fn relay_for(&self, node_id: &str) -> Option<String> {
        self.relays.read().await.get(node_id).cloned()
    }

    pub(crate) async fn publish_peer(&self, lease: PeerLease) {
        if !self.enabled() {
            return;
        }
        let msg = Message::Peer(lease);
        if self.is_master {
            self.broadcast(msg, None).await;
        } else {
            self.send_first(msg).await;
        }
    }

    pub(crate) async fn send_peer_to(&self, node_id: &str, lease: PeerLease) {
        self.send_node(node_id, Message::Peer(lease)).await;
    }

    pub(crate) async fn broadcast_peer(&self, lease: PeerLease, skip: Option<&str>) {
        if self.is_master {
            self.broadcast(Message::Peer(lease), skip).await;
        }
    }

    pub(crate) async fn broadcast_remove(&self, owner: String, id: String, skip: Option<&str>) {
        if self.is_master {
            self.broadcast(Message::PeerRemove { owner, id }, skip)
                .await;
        }
    }

    pub(crate) async fn publish_remove(&self, owner: String, id: String) {
        if !self.enabled() {
            return;
        }
        let msg = Message::PeerRemove { owner, id };
        if self.is_master {
            self.broadcast(msg, None).await;
        } else {
            self.send_first(msg).await;
        }
    }

    pub(crate) async fn send_forward(&self, message: ForwardMessage) {
        if !self.enabled() {
            return;
        }
        if self.is_master {
            let target_node = message.target_node.clone();
            self.send_node(&target_node, Message::Forward(message))
                .await;
        } else {
            self.send_first(Message::Forward(message)).await;
        }
    }

    pub(crate) async fn send_forward_to(&self, node_id: &str, message: ForwardMessage) {
        self.send_node(node_id, Message::Forward(message)).await;
    }

    pub(crate) async fn route_for(
        &self,
        source_addr: SocketAddr,
        target_id: Option<&str>,
    ) -> Option<RemoteRoute> {
        let source_addr = try_into_v4(source_addr);
        let key = source_addr.to_string();
        let mut routes = self.routes.write().await;
        routes.retain(|_, route| route.expires_at > Instant::now());
        if let Some(target_id) = target_id.filter(|target_id| !target_id.is_empty()) {
            return routes.get(&format!("{key}|{target_id}")).cloned();
        }
        routes.iter().find_map(|(route_key, route)| {
            if route_key.starts_with(&format!("{key}|")) {
                Some(route.clone())
            } else {
                None
            }
        })
    }

    pub(crate) async fn remember_route(&self, route: RemoteRoute) {
        let mut route = route;
        route.source_addr = try_into_v4(route.source_addr);
        let key = format!("{}|{}", route.source_addr, route.target_id);
        self.routes.write().await.insert(key, route);
    }

    async fn accept_loop(self, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    stream.set_nodelay(true).ok();
                    let cloned = self.clone();
                    tokio::spawn(async move {
                        if let Err(err) = cloned.run_server_connection(stream).await {
                            log::warn!("federation connection from {} failed: {}", addr, err);
                        }
                    });
                }
                Err(err) => {
                    log::error!("federation listener failed: {}", err);
                    break;
                }
            }
        }
    }

    async fn connect_loop(self) {
        loop {
            match TcpStream::connect(self.master.as_str()).await {
                Ok(stream) => {
                    stream.set_nodelay(true).ok();
                    if let Err(err) = self.run_client_connection(stream).await {
                        log::warn!("federation connection to {} failed: {}", self.master, err);
                    }
                }
                Err(err) => {
                    log::debug!("federation connect to {} failed: {}", self.master, err);
                }
            }
            sleep(RETRY_DELAY).await;
        }
    }

    async fn run_server_connection(&self, stream: TcpStream) -> ResultType<()> {
        let framed = new_framed(stream);
        let (mut sink, mut source) = framed.split();
        let nonce = uuid::Uuid::new_v4().to_string();
        send_plain(
            &mut sink,
            &Message::Challenge {
                node_id: self.node_id.as_str().to_owned(),
                nonce: nonce.clone(),
            },
        )
        .await?;
        let second = hbb_common::timeout(CONNECT_TIMEOUT_MS, source.next())
            .await?
            .ok_or_else(|| hbb_common::anyhow::anyhow!("federation handshake closed"))??;
        let hello = decode_plain(&second)?;
        let (node_id, relay_server) = match hello {
            Message::Hello {
                node_id,
                proof,
                relay_server,
            } if !node_id.is_empty()
                && proof == make_proof(self.key.as_str(), &nonce, self.node_id.as_str()) =>
            {
                (node_id, relay_server)
            }
            _ => return Err(hbb_common::anyhow::anyhow!("invalid federation handshake")),
        };
        send_plain(
            &mut sink,
            &Message::HelloAck {
                node_id: self.node_id.as_str().to_owned(),
                relay_server: self.relay_server.as_str().to_owned(),
            },
        )
        .await?;
        self.run_link(node_id, relay_server, sink, source).await
    }

    async fn run_client_connection(&self, stream: TcpStream) -> ResultType<()> {
        let framed = new_framed(stream);
        let (mut sink, mut source) = framed.split();
        let first = hbb_common::timeout(CONNECT_TIMEOUT_MS, source.next())
            .await?
            .ok_or_else(|| hbb_common::anyhow::anyhow!("federation handshake closed"))??;
        let (server_node, nonce) = match decode_plain(&first)? {
            Message::Challenge { node_id, nonce } if !node_id.is_empty() => (node_id, nonce),
            _ => return Err(hbb_common::anyhow::anyhow!("invalid federation challenge")),
        };
        send_plain(
            &mut sink,
            &Message::Hello {
                node_id: self.node_id.as_str().to_owned(),
                proof: make_proof(self.key.as_str(), &nonce, &server_node),
                relay_server: self.relay_server.as_str().to_owned(),
            },
        )
        .await?;
        let second = hbb_common::timeout(CONNECT_TIMEOUT_MS, source.next())
            .await?
            .ok_or_else(|| hbb_common::anyhow::anyhow!("federation handshake closed"))??;
        let (node_id, relay_server) = match decode_plain(&second)? {
            Message::HelloAck {
                node_id,
                relay_server,
            } if !node_id.is_empty() => (node_id, relay_server),
            _ => {
                return Err(hbb_common::anyhow::anyhow!(
                    "invalid federation acknowledgement"
                ))
            }
        };
        self.run_link(node_id, relay_server, sink, source).await
    }

    async fn run_link<S, R>(
        &self,
        node_id: String,
        relay_server: String,
        mut sink: S,
        mut source: R,
    ) -> ResultType<()>
    where
        S: SinkExt<Bytes> + Unpin + Send + 'static,
        S::Error: std::error::Error + Send + Sync + 'static,
        R: StreamExt<Item = Result<BytesMut, std::io::Error>> + Unpin,
    {
        let link_id = self.next_link_id.fetch_add(1, Ordering::SeqCst);
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        self.links.write().await.insert(
            node_id.clone(),
            Link {
                tx: tx.clone(),
                id: link_id,
            },
        );
        self.relays
            .write()
            .await
            .insert(node_id.clone(), relay_server.clone());
        self.events
            .send(Event::Connected {
                node_id: node_id.clone(),
                relay_server,
            })
            .ok();

        let crypto_key = self.crypto_key.clone();
        let writer = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if send_wire(&mut sink, &message, &crypto_key).await.is_err() {
                    break;
                }
            }
        });
        let heartbeat = tokio::spawn({
            let tx = tx.clone();
            async move {
                loop {
                    sleep(HEARTBEAT_DELAY).await;
                    if tx.send(Message::Ping).is_err() {
                        break;
                    }
                }
            }
        });

        while let Some(bytes) = source.next().await {
            let bytes = bytes?;
            match decode_wire(&bytes, &self.crypto_key)? {
                Message::Ping => {
                    tx.send(Message::Pong).ok();
                }
                Message::Pong => {}
                Message::Hello { .. }
                | Message::HelloAck { .. }
                | Message::Challenge { .. }
                | Message::Encrypted(_) => {
                    return Err(hbb_common::anyhow::anyhow!(
                        "unexpected federation handshake message"
                    ));
                }
                Message::Peer(lease) => {
                    self.events
                        .send(Event::Peer {
                            from_node: node_id.clone(),
                            lease,
                        })
                        .ok();
                }
                Message::PeerRemove { owner, id } => {
                    self.events
                        .send(Event::PeerRemove {
                            from_node: node_id.clone(),
                            owner,
                            id,
                        })
                        .ok();
                }
                Message::Forward(message) => {
                    self.events
                        .send(Event::Forward {
                            from_node: node_id.clone(),
                            message,
                        })
                        .ok();
                }
            }
        }
        heartbeat.abort();
        writer.abort();
        self.remove_link(&node_id, link_id).await;
        self.events.send(Event::Disconnected { node_id }).ok();
        Ok(())
    }

    async fn remove_link(&self, node_id: &str, link_id: u64) {
        let mut links = self.links.write().await;
        if links.get(node_id).map(|link| link.id) == Some(link_id) {
            links.remove(node_id);
            self.relays.write().await.remove(node_id);
        }
    }

    async fn send_node(&self, node_id: &str, message: Message) {
        if let Some(link) = self.links.read().await.get(node_id) {
            link.tx.send(message).ok();
        }
    }

    async fn send_first(&self, message: Message) {
        if let Some(link) = self.links.read().await.values().next() {
            link.tx.send(message).ok();
        }
    }

    async fn broadcast(&self, message: Message, skip: Option<&str>) {
        let links = self.links.read().await;
        for (node_id, link) in links.iter() {
            if skip == Some(node_id.as_str()) {
                continue;
            }
            link.tx.send(message.clone()).ok();
        }
    }
}

fn new_framed(stream: TcpStream) -> Framed<TcpStream, BytesCodec> {
    let mut codec = BytesCodec::new();
    codec.set_max_packet_length(MAX_CONTROL_FRAME);
    Framed::new(stream, codec)
}

async fn send_plain<S>(sink: &mut S, message: &Message) -> ResultType<()>
where
    S: SinkExt<Bytes> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let bytes = serde_json::to_vec(message)?;
    if bytes.len() > MAX_CONTROL_FRAME {
        return Err(hbb_common::anyhow::anyhow!("federation frame is too large"));
    }
    sink.send(Bytes::from(bytes)).await?;
    Ok(())
}

async fn send_wire<S>(sink: &mut S, message: &Message, key: &secretbox::Key) -> ResultType<()>
where
    S: SinkExt<Bytes> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let plaintext = serde_json::to_vec(message)?;
    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(&plaintext, &nonce, key);
    let mut payload = nonce.0.to_vec();
    payload.extend(ciphertext);
    send_plain(sink, &Message::Encrypted(payload)).await
}

fn derive_key(value: &str) -> secretbox::Key {
    let digest = Sha256::digest(value.as_bytes());
    let mut key = [0u8; secretbox::KEYBYTES];
    key.copy_from_slice(&digest);
    secretbox::Key(key)
}

fn make_proof(key: &str, nonce: &str, node_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(key.as_bytes());
    digest.update([0]);
    digest.update(nonce.as_bytes());
    digest.update([0]);
    digest.update(node_id.as_bytes());
    general_purpose::STANDARD.encode(digest.finalize())
}

fn decode_plain(bytes: &[u8]) -> ResultType<Message> {
    if bytes.len() > MAX_CONTROL_FRAME {
        return Err(hbb_common::anyhow::anyhow!("federation frame is too large"));
    }
    let message: Message = serde_json::from_slice(bytes)?;
    if matches!(message, Message::Encrypted(_)) {
        return Err(hbb_common::anyhow::anyhow!(
            "encrypted message before federation handshake"
        ));
    }
    Ok(message)
}

fn decode_wire(bytes: &[u8], key: &secretbox::Key) -> ResultType<Message> {
    if bytes.len() > MAX_CONTROL_FRAME {
        return Err(hbb_common::anyhow::anyhow!("federation frame is too large"));
    }
    let message: Message = serde_json::from_slice(bytes)?;
    let Message::Encrypted(payload) = message else {
        return Err(hbb_common::anyhow::anyhow!(
            "unencrypted message after federation handshake"
        ));
    };
    if payload.len() < secretbox::NONCEBYTES + secretbox::MACBYTES {
        return Err(hbb_common::anyhow::anyhow!(
            "invalid encrypted federation frame"
        ));
    }
    let mut nonce = [0u8; secretbox::NONCEBYTES];
    nonce.copy_from_slice(&payload[..secretbox::NONCEBYTES]);
    let plaintext = secretbox::open(
        &payload[secretbox::NONCEBYTES..],
        &secretbox::Nonce(nonce),
        key,
    )
    .map_err(|_| hbb_common::anyhow::anyhow!("invalid federation frame authentication"))?;
    let message: Message = serde_json::from_slice(&plaintext)?;
    if matches!(message, Message::Encrypted(_)) {
        return Err(hbb_common::anyhow::anyhow!(
            "nested encrypted federation frame"
        ));
    }
    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_message_round_trip() {
        let message = Message::Forward(ForwardMessage {
            kind: ForwardKind::ToPeer,
            source_node: "A".to_owned(),
            target_node: "B".to_owned(),
            source_addr: "192.0.2.10:4000".to_owned(),
            target_id: "123456789".to_owned(),
            source_relay: "relay-a:21117".to_owned(),
            payload: vec![1, 2, 3, 4],
        });
        let encoded = serde_json::to_vec(&message).unwrap();
        let decoded = decode_plain(&encoded).unwrap();
        match decoded {
            Message::Forward(message) => {
                assert_eq!(message.source_node, "A");
                assert_eq!(message.target_node, "B");
                assert_eq!(message.payload, vec![1, 2, 3, 4]);
            }
            _ => panic!("unexpected federation message"),
        }
    }

    #[test]
    fn oversized_frame_is_rejected() {
        let bytes = vec![b' '; MAX_CONTROL_FRAME + 1];
        assert!(decode_plain(&bytes).is_err());
    }

    #[test]
    fn encrypted_frame_round_trip() {
        hbb_common::sodiumoxide::init().unwrap();
        let key = derive_key("test-key");
        let inner = Message::Ping;
        let plaintext = serde_json::to_vec(&inner).unwrap();
        let nonce = secretbox::gen_nonce();
        let ciphertext = secretbox::seal(&plaintext, &nonce, &key);
        let mut payload = nonce.0.to_vec();
        payload.extend(ciphertext);
        let outer = serde_json::to_vec(&Message::Encrypted(payload)).unwrap();
        assert!(matches!(decode_wire(&outer, &key).unwrap(), Message::Ping));
    }

    #[hbb_common::tokio::test]
    async fn route_for_matches_ipv4_mapped_source_address() {
        let (federation, _rx) = Federation::disabled();
        let source_addr = "192.0.2.10:4000".parse().unwrap();
        federation
            .remember_route(RemoteRoute {
                source_node: "A".to_owned(),
                source_addr,
                target_id: "123456789".to_owned(),
                source_relay: "relay-a:21117".to_owned(),
                expires_at: Instant::now() + std::time::Duration::from_secs(60),
            })
            .await;

        assert!(federation
            .route_for(
                "[::ffff:192.0.2.10]:4000".parse().unwrap(),
                Some("123456789"),
            )
            .await
            .is_some());
        assert!(federation
            .route_for("192.0.2.10:4000".parse().unwrap(), Some("987654321"))
            .await
            .is_none());
        assert!(federation
            .route_for("192.0.2.10:4000".parse().unwrap(), Some(""))
            .await
            .is_some());
    }

    #[test]
    fn hello_ack_without_relay_server_is_backward_compatible() {
        let encoded = br#"{"HelloAck":{"node_id":"A"}}"#;
        assert!(matches!(
            decode_plain(encoded).unwrap(),
            Message::HelloAck {
                node_id,
                relay_server
            } if node_id == "A" && relay_server.is_empty()
        ));
    }
}
