use async_speed_limit::Limiter;
use async_trait::async_trait;
use hbb_common::{
    anyhow,
    base64::{engine::general_purpose::STANDARD, Engine as _},
    bytes::{Bytes, BytesMut},
    log,
    sha2::{Digest, Sha256},
    sodiumoxide::{self, crypto::auth::hmacsha256},
    tcp::FramedStream,
    tokio::{
        self,
        io::{AsyncRead, AsyncWrite, ReadBuf},
        net::lookup_host,
        sync::Mutex,
        time::Duration,
    },
    ResultType,
};
use quinn::{
    congestion::BbrConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    ClientConfig, Connection, ConnectionError, Endpoint, EndpointConfig, RecvStream,
    SendDatagramError, SendStream, ServerConfig, TokioRuntime, TransportConfig,
};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
    CertificateError, DigitallySignedStruct, SignatureScheme,
};
use std::{
    collections::HashMap,
    fmt, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use crate::relay_server::{is_blocked, make_pair_, RelayOptions, Transport};

pub(crate) const ALPN: &[u8] = b"rustdesk-relay/1";
pub(crate) const BOT_TOKEN_PREFIX: &str = "rustbot-quic-v1:";
const AUTH_ERROR_CODE: u32 = 0x10;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const KEEP_ALIVE: Duration = Duration::from_secs(15);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IpPreference {
    Prefer,
    Only,
    Off,
}

impl IpPreference {
    pub(crate) fn from_arg(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "only" => Self::Only,
            "off" => Self::Off,
            _ => Self::Prefer,
        }
    }
}

pub(crate) async fn start_listener(
    bind: Option<IpAddr>,
    port: u16,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    options: Arc<RelayOptions>,
    limiter: Limiter,
) -> ResultType<()> {
    let (certs, key) = load_or_generate_cert(cert_path.as_deref(), key_path.as_deref())?;
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = QuicServerConfig::try_from(crypto)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(IDLE_TIMEOUT.try_into()?));
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
    transport.max_concurrent_bidi_streams(1u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport.datagram_receive_buffer_size(Some(DATAGRAM_RECV_BUFFER));
    server_config.transport_config(Arc::new(transport));

    let socket = bind_udp_socket(bind, port)?;
    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(TokioRuntime),
    )?;
    log::info!("Listening on quic {:?}", endpoint.local_addr()?);

    let limits = Arc::new(ConnectionLimits::new());
    while let Some(incoming) = endpoint.accept().await {
        let addr = incoming.remote_address();
        if is_blocked(addr.ip()).await {
            log::info!("{} blocked (quic)", addr);
            incoming.refuse();
            continue;
        }
        if !limits.acquire(addr.ip()).await {
            log::warn!("quic connection limit reached for {}", addr);
            incoming.refuse();
            continue;
        }
        let options = options.clone();
        let limiter = limiter.clone();
        let limits = limits.clone();
        tokio::spawn(async move {
            let result = handle_incoming(incoming, addr, options, limiter).await;
            if let Err(err) = result {
                log::debug!("quic connection {} closed: {}", addr, err);
            }
            limits.release(addr.ip()).await;
        });
    }
    Ok(())
}

async fn handle_incoming(
    incoming: quinn::Incoming,
    addr: SocketAddr,
    options: Arc<RelayOptions>,
    limiter: Limiter,
) -> ResultType<()> {
    let connection = incoming.await?;
    let (send, recv) = connection.accept_bi().await?;
    let io = QuicIo {
        connection: connection.clone(),
        send,
        recv,
    };
    let framed = FramedStream::from(io, addr);
    let stream = QuicRelayStream { framed, connection };
    make_pair_(stream, addr, &options, limiter, Transport::Quic).await;
    Ok(())
}

pub(crate) async fn connect_upstream(
    addr: &str,
    sni: &str,
    pin: [u8; 32],
    preference: IpPreference,
) -> Result<FramedStream, UpstreamError> {
    let mut addresses = lookup_host(addr)
        .await
        .map_err(|err| UpstreamError::Unavailable(err.into()))?
        .collect::<Vec<_>>();
    sort_addresses(&mut addresses, preference);
    if addresses.is_empty() {
        return Err(UpstreamError::Unavailable(anyhow::anyhow!(
            "no address for {addr}"
        )));
    }
    if preference == IpPreference::Only {
        addresses.retain(|addr| addr.is_ipv6());
        if addresses.is_empty() {
            return Err(UpstreamError::Unavailable(anyhow::anyhow!(
                "no IPv6 address for {addr}"
            )));
        }
    }

    let mut last_error = None;
    for remote in addresses {
        let bind = if remote.is_ipv6() {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let endpoint = match Endpoint::client(bind) {
            Ok(endpoint) => endpoint,
            Err(err) => {
                last_error = Some(err.into());
                continue;
            }
        };
        let auth_failed = Arc::new(AtomicBool::new(false));
        let client_config = match client_config(pin, auth_failed.clone()) {
            Ok(config) => config,
            Err(err) => return Err(UpstreamError::Unavailable(err)),
        };
        let server_name = if sni.trim().is_empty() { "relay" } else { sni };
        let connecting = match endpoint.connect_with(client_config, remote, server_name) {
            Ok(connecting) => connecting,
            Err(err) => {
                last_error = Some(err.into());
                continue;
            }
        };
        let connection = match tokio::time::timeout(CONNECT_TIMEOUT, connecting).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(err)) => {
                if auth_failed.load(Ordering::SeqCst) || is_auth_connection_error(&err) {
                    return Err(UpstreamError::Auth(err.into()));
                }
                last_error = Some(err.into());
                continue;
            }
            Err(err) => {
                last_error = Some(err.into());
                continue;
            }
        };
        let (send, recv) = match tokio::time::timeout(CONNECT_TIMEOUT, connection.open_bi()).await {
            Ok(Ok(streams)) => streams,
            Ok(Err(err)) => {
                if auth_failed.load(Ordering::SeqCst) || is_auth_connection_error(&err) {
                    return Err(UpstreamError::Auth(err.into()));
                }
                last_error = Some(err.into());
                continue;
            }
            Err(err) => {
                last_error = Some(err.into());
                continue;
            }
        };
        let io = QuicIo {
            connection,
            send,
            recv,
        };
        return Ok(FramedStream::from(io, remote));
    }
    Err(UpstreamError::Unavailable(last_error.unwrap_or_else(
        || anyhow::anyhow!("failed to connect {addr}"),
    )))
}

fn is_auth_connection_error(error: &ConnectionError) -> bool {
    matches!(
        error,
        ConnectionError::TransportError(error)
            if error.code
                == quinn::TransportErrorCode::crypto(
                    u8::from(rustls::AlertDescription::NoApplicationProtocol)
                )
    )
}

fn sort_addresses(addresses: &mut [SocketAddr], preference: IpPreference) {
    match preference {
        IpPreference::Prefer => addresses.sort_by_key(|addr| !addr.is_ipv6()),
        IpPreference::Only => addresses.sort_by_key(|addr| !addr.is_ipv6()),
        IpPreference::Off => addresses.sort_by_key(|addr| addr.is_ipv6()),
    }
}

fn client_config(
    pin: [u8; 32],
    auth_failed: Arc<AtomicBool>,
) -> std::result::Result<ClientConfig, anyhow::Error> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier::new(pin, auth_failed)))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic = QuicClientConfig::try_from(crypto)?;
    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(IDLE_TIMEOUT.try_into()?));
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    transport.congestion_controller_factory(Arc::new(BbrConfig::default()));
    transport.datagram_receive_buffer_size(Some(DATAGRAM_RECV_BUFFER));
    let mut config = ClientConfig::new(Arc::new(quic));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// relay datagram 的接收缓冲。
///
/// 显式设置而不是依赖 quinn 默认值：默认值随版本变化，一旦退化成 0 个包，
/// QUIC stream 仍然正常，只有 datagram 静默丢失。
const DATAGRAM_RECV_BUFFER: usize = 1024 * 1024;

/// relay 转发 datagram 用的独立句柄。
///
/// 与 `QuicRelayStream` 分离持有同一个 `Connection`，这样 relay 可以同时轮询
/// 两个方向的 stream 与 datagram，而不需要同时可变借用同一个对象。
#[derive(Clone)]
pub(crate) struct DatagramHandle {
    connection: Connection,
}

impl DatagramHandle {
    /// 读一条 datagram。错误保留类型：调用方需要区分连接结束与可恢复错误。
    pub(crate) async fn recv(&self) -> Result<BytesMut, ConnectionError> {
        self.connection
            .read_datagram()
            .await
            .map(|bytes| BytesMut::from(&bytes[..]))
    }

    /// 发一条 datagram。`TooLarge` 表示协商出的 MTU 与实际不符。
    pub(crate) fn send(&self, bytes: Bytes) -> Result<(), SendDatagramError> {
        self.connection.send_datagram(bytes)
    }
}

pub(crate) struct QuicIo {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
}

/// 连接关闭前留给已写入流数据的交付时间。
const CLOSE_GRACE: Duration = Duration::from_millis(500);

impl Drop for QuicIo {
    fn drop(&mut self) {
        // 直接 CONNECTION_CLOSE 会丢弃尚未送达的流数据，短请求-响应最先命中（例如服务
        // 结果、管理元数据回执）。先结束发送流让对端读到尾部数据，再延迟关闭连接。
        let _ = self.send.finish();
        let connection = self.connection.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                tokio::time::sleep(CLOSE_GRACE).await;
                connection.close(0u32.into(), b"relay closed");
            });
        }
    }
}

impl AsyncRead for QuicIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(size)) => Poll::Ready(Ok(size)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

struct QuicRelayStream {
    framed: FramedStream,
    connection: Connection,
}

impl QuicRelayStream {
    fn close_auth_failed(&mut self) {
        self.connection
            .close(AUTH_ERROR_CODE.into(), b"AUTH_FAILED");
    }
}

#[async_trait]
impl crate::relay_server::StreamTrait for QuicRelayStream {
    async fn recv(
        &mut self,
    ) -> Option<std::result::Result<hbb_common::bytes::BytesMut, io::Error>> {
        self.framed.next().await
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        self.framed.send_bytes(bytes).await
    }

    fn is_ws(&self) -> bool {
        false
    }

    fn set_raw(&mut self) {
        self.framed.set_raw();
    }

    fn close_auth_failed(&mut self) {
        self.close_auth_failed();
    }

    fn datagram_handle(&self) -> Option<DatagramHandle> {
        Some(DatagramHandle {
            connection: self.connection.clone(),
        })
    }
}

#[derive(Debug)]
pub(crate) enum UpstreamError {
    Auth(anyhow::Error),
    Unavailable(anyhow::Error),
}

impl UpstreamError {
    pub(crate) fn is_auth(&self) -> bool {
        matches!(self, Self::Auth(_))
    }
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth(err) | Self::Unavailable(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for UpstreamError {}

struct PinVerifier {
    pin: [u8; 32],
    auth_failed: Arc<AtomicBool>,
    supported: WebPkiSupportedAlgorithms,
}

impl PinVerifier {
    fn new(pin: [u8; 32], auth_failed: Arc<AtomicBool>) -> Self {
        Self {
            pin,
            auth_failed,
            supported: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }

    fn fail(&self, error: CertificateError) -> rustls::Error {
        self.auth_failed.store(true, Ordering::SeqCst);
        rustls::Error::InvalidCertificate(error)
    }
}

impl fmt::Debug for PinVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinVerifier").finish_non_exhaustive()
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if !sodiumoxide::utils::memcmp(&actual, &self.pin) {
            return Err(self.fail(CertificateError::ApplicationVerificationFailure));
        }
        let cert = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| self.fail(CertificateError::ApplicationVerificationFailure))?;
        let anchor = webpki::anchor_from_trusted_cert(end_entity)
            .map_err(|_| self.fail(CertificateError::ApplicationVerificationFailure))?;
        cert.verify_for_usage(
            self.supported.all,
            &[anchor],
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|_| self.fail(CertificateError::ApplicationVerificationFailure))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        match verify_tls12_signature(message, cert, dss, &self.supported) {
            Ok(value) => Ok(value),
            Err(err) => {
                self.auth_failed.store(true, Ordering::SeqCst);
                Err(err)
            }
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        match verify_tls13_signature(message, cert, dss, &self.supported) {
            Ok(value) => Ok(value),
            Err(err) => {
                self.auth_failed.store(true, Ordering::SeqCst);
                Err(err)
            }
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

struct ConnectionLimits {
    total: AtomicUsize,
    per_ip: Mutex<HashMap<IpAddr, usize>>,
    max_total: usize,
    max_per_ip: usize,
}

impl ConnectionLimits {
    fn new() -> Self {
        Self {
            total: AtomicUsize::new(0),
            per_ip: Mutex::new(HashMap::new()),
            max_total: parse_usize("RELAY_QUIC_MAX_CONN", 10_000),
            max_per_ip: parse_usize("RELAY_QUIC_MAX_CONN_PER_IP", 64),
        }
    }

    async fn acquire(&self, ip: IpAddr) -> bool {
        if self.total.fetch_add(1, Ordering::SeqCst) >= self.max_total {
            self.total.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        let mut per_ip = self.per_ip.lock().await;
        let count = per_ip.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            drop(per_ip);
            self.total.fetch_sub(1, Ordering::SeqCst);
            return false;
        }
        *count += 1;
        true
    }

    async fn release(&self, ip: IpAddr) {
        self.total.fetch_sub(1, Ordering::SeqCst);
        let mut per_ip = self.per_ip.lock().await;
        if let Some(count) = per_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                per_ip.remove(&ip);
            }
        }
    }
}

fn parse_usize(name: &str, default: usize) -> usize {
    crate::common::get_arg(name).parse().unwrap_or(default)
}

fn bind_udp_socket(bind: Option<IpAddr>, port: u16) -> ResultType<std::net::UdpSocket> {
    let ip = bind.unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    let domain = if ip.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, None)?;
    if ip.is_ipv6() && ip.is_unspecified() {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(ip, port).into())?;
    Ok(socket.into())
}

fn load_or_generate_cert(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
) -> ResultType<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let (cert_path, key_path) = match (cert_path, key_path) {
        (Some(cert), Some(key)) => (cert.to_path_buf(), key.to_path_buf()),
        (None, None) => {
            let cert = PathBuf::from("relay-quic.crt.pem");
            let key = PathBuf::from("relay-quic.key.pem");
            if !cert.exists() || !key.exists() {
                generate_cert(&cert, &key)?;
            }
            (cert, key)
        }
        _ => {
            return Err(anyhow::anyhow!(
                "RELAY_QUIC_CERT and RELAY_QUIC_KEY must be set together"
            ))
        }
    };
    let certs = load_certs(&cert_path)?;
    let key = load_key(&key_path)?;
    if let Some(cert) = certs.first() {
        log::info!(
            "QUIC relay certificate {} (pin: {})",
            cert_path.display(),
            cert_pin(cert.as_ref())
        );
    }
    Ok((certs, key))
}

fn generate_cert(cert_path: &Path, key_path: &Path) -> ResultType<()> {
    let cert = rcgen::generate_simple_self_signed(vec!["relay.local".to_owned()])?;
    write_private(key_path, cert.key_pair.serialize_pem().as_bytes())?;
    std::fs::write(cert_path, cert.cert.pem())?;
    log::info!(
        "Generated QUIC relay certificate {} (pin: {})",
        cert_path.display(),
        cert_pin(cert.cert.der().as_ref())
    );
    Ok(())
}

fn load_certs(path: &Path) -> ResultType<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(anyhow::anyhow!("no certificate in {}", path.display()));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> ResultType<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(std::fs::File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key in {}", path.display()))
}

fn write_private(path: &Path, bytes: &[u8]) -> ResultType<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn cert_pin(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    format!("sha256:{}", STANDARD.encode(digest))
}

pub(crate) fn verify_bot_token(token: &str, uuid: &str, secret: &str) -> bool {
    let Some(rest) = token.strip_prefix("rustbot-quic-v1:") else {
        return false;
    };
    let Ok(decoded) = STANDARD.decode(rest) else {
        return false;
    };
    let digest = Sha256::digest(secret.as_bytes());
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&digest);
    let key = hmacsha256::Key(key_bytes);
    let tag = hmacsha256::authenticate(uuid.as_bytes(), &key);
    sodiumoxide::utils::memcmp(&decoded, &tag.0)
}

pub(crate) fn parse_pin(value: &str) -> ResultType<Option<[u8; 32]>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let Some(rest) = value.strip_prefix("sha256:") else {
        return Err(anyhow::anyhow!("pin must start with sha256:"));
    };
    let decoded = STANDARD
        .decode(rest)
        .map_err(|_| anyhow::anyhow!("pin is not valid base64"))?;
    let pin: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("pin must be a 32-byte SHA-256 digest"))?;
    Ok(Some(pin))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 关闭 QUIC 中继连接时，已经写入的流数据必须送达对端。
    ///
    /// 回归背景：服务结果/管理回执这类短请求-响应在 edge 的 QUIC 入站路径上丢失，
    /// 客户端只看到 `relay closed (code 0)`。
    #[tokio::test]
    async fn drop_delivers_pending_stream_data() -> ResultType<()> {
        use hbb_common::tokio::io::{AsyncReadExt, AsyncWriteExt};

        let certified = rcgen::generate_simple_self_signed(vec!["relay.local".to_owned()])?;
        let cert = certified.cert.der().clone();
        let pin: [u8; 32] = Sha256::digest(cert.as_ref()).into();
        let key = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;
        crypto.alpn_protocols = vec![ALPN.to_vec()];
        let quic_crypto = QuicServerConfig::try_from(crypto)?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(IDLE_TIMEOUT.try_into()?));
        server_config.transport_config(Arc::new(transport));

        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            std::net::UdpSocket::bind("127.0.0.1:0")?,
            Arc::new(TokioRuntime),
        )?;
        let addr = endpoint.local_addr()?;
        let server = tokio::spawn(async move {
            let incoming = endpoint.accept().await.expect("incoming");
            let connection = incoming.await.expect("handshake");
            let (send, recv) = connection.accept_bi().await.expect("stream");
            let mut io = QuicIo {
                connection: connection.clone(),
                send,
                recv,
            };
            let mut request = [0u8; 4];
            io.read_exact(&mut request).await.expect("read request");
            io.write_all(b"reply").await.expect("write reply");
            drop(io);
            tokio::time::sleep(Duration::from_millis(800)).await;
        });

        let client = Endpoint::new(
            EndpointConfig::default(),
            None,
            std::net::UdpSocket::bind("127.0.0.1:0")?,
            Arc::new(TokioRuntime),
        )?;
        let client_cfg = client_config(pin, Arc::new(AtomicBool::new(false)))?;
        let connection = client
            .connect_with(client_cfg, addr, "relay.local")?
            .await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(b"ping").await?;
        send.finish()?;
        let reply = recv
            .read_to_end(1024)
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        server.await.expect("server task");
        assert_eq!(reply, b"reply");
        Ok(())
    }

    /// 起 QUIC relay 服务端，返回 endpoint、监听地址与证书 pin。
    ///
    /// endpoint 必须由调用方持有：丢弃它等于关闭 relay。
    async fn quic_relay_endpoint() -> ResultType<(Endpoint, SocketAddr, [u8; 32])> {
        let certified = rcgen::generate_simple_self_signed(vec!["relay.local".to_owned()])?;
        let cert = certified.cert.der().clone();
        let pin: [u8; 32] = Sha256::digest(cert.as_ref()).into();
        let key = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let mut crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;
        crypto.alpn_protocols = vec![ALPN.to_vec()];
        let quic_crypto = QuicServerConfig::try_from(crypto)?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(Some(IDLE_TIMEOUT.try_into()?));
        transport.datagram_receive_buffer_size(Some(DATAGRAM_RECV_BUFFER));
        server_config.transport_config(Arc::new(transport));
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(server_config),
            std::net::UdpSocket::bind("127.0.0.1:0")?,
            Arc::new(TokioRuntime),
        )?;
        let addr = endpoint.local_addr()?;
        Ok((endpoint, addr, pin))
    }

    /// 客户端建连。返回的 endpoint 同样必须由调用方持有。
    async fn connect_quic_client(
        addr: SocketAddr,
        pin: [u8; 32],
    ) -> ResultType<(Endpoint, Connection)> {
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            None,
            std::net::UdpSocket::bind("127.0.0.1:0")?,
            Arc::new(TokioRuntime),
        )?;
        let connection = endpoint
            .connect_with(
                client_config(pin, Arc::new(AtomicBool::new(false)))?,
                addr,
                "relay.local",
            )?
            .await?;
        Ok((endpoint, connection))
    }

    /// 服务端接受一条 bidi 流并组装成 relay 用的 stream。
    async fn accept_relay_stream(
        connection: Connection,
        addr: SocketAddr,
    ) -> ResultType<QuicRelayStream> {
        let (send, recv) = connection.accept_bi().await?;
        let io = QuicIo {
            connection: connection.clone(),
            send,
            recv,
        };
        Ok(QuicRelayStream {
            framed: FramedStream::from(io, addr),
            connection,
        })
    }

    /// relay 必须把一侧的 QUIC datagram 原样转发到另一侧，与 stream 互不影响。
    #[tokio::test]
    async fn datagram_is_forwarded_between_paired_peers() -> ResultType<()> {
        let (endpoint, addr, pin) = quic_relay_endpoint().await?;
        let relay_task = tokio::spawn({
            let endpoint = endpoint.clone();
            async move {
                // 先把两条连接都握完，再取流：QUIC 的 bidi 流要等首帧发出才对端可见，
                // 边接边等会与客户端的建连顺序互相卡住。
                let mut connections = Vec::new();
                for _ in 0..2 {
                    let incoming = endpoint.accept().await.expect("incoming");
                    connections.push(incoming.await.expect("handshake"));
                }
                let mut streams = Vec::new();
                for connection in connections {
                    streams.push(accept_relay_stream(connection, addr).await.expect("stream"));
                }
                let peer_stream = streams.pop().expect("peer");
                let inbound = streams.pop().expect("inbound");
                let mut peer: Box<dyn crate::relay_server::StreamTrait> = Box::new(peer_stream);
                crate::relay_server::relay_pair(
                    inbound,
                    &mut peer,
                    addr,
                    Limiter::new(1_000_000_000.),
                )
                .await;
            }
        });

        let (_client_a, conn_a) = connect_quic_client(addr, pin).await?;
        let (mut send_a, _recv_a) = conn_a.open_bi().await?;
        // 首帧让服务端的 accept_bi 返回；之后 stream 保持打开，relay 以它判断会话存活。
        send_a.write_all(b"a").await?;
        let (_client_b, conn_b) = connect_quic_client(addr, pin).await?;
        let (mut send_b, _recv_b) = conn_b.open_bi().await?;
        send_b.write_all(b"b").await?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        conn_a.send_datagram(Bytes::from_static(b"ping-datagram"))?;
        let received = tokio::time::timeout(Duration::from_secs(2), conn_b.read_datagram())
            .await
            .map_err(|_| anyhow::anyhow!("datagram 未在 2 秒内到达对端"))??;
        assert_eq!(&received[..], b"ping-datagram");

        conn_b.send_datagram(Bytes::from_static(b"pong-datagram"))?;
        let received = tokio::time::timeout(Duration::from_secs(2), conn_a.read_datagram())
            .await
            .map_err(|_| anyhow::anyhow!("反向 datagram 未在 2 秒内到达对端"))??;
        assert_eq!(&received[..], b"pong-datagram");

        relay_task.abort();
        Ok(())
    }

    /// 对端没有 datagram 能力时丢弃 datagram，业务流照常转发。
    #[tokio::test]
    async fn datagram_is_dropped_when_peer_has_no_datagram_support() -> ResultType<()> {
        let (endpoint, addr, pin) = quic_relay_endpoint().await?;
        let (peer_io, mut legacy_io) = tokio::io::duplex(64 * 1024);
        let relay_task = tokio::spawn({
            let endpoint = endpoint.clone();
            async move {
                let incoming = endpoint.accept().await.expect("incoming");
                let connection = incoming.await.expect("handshake");
                let inbound = accept_relay_stream(connection, addr).await.expect("stream");
                // legacy peer：trait 默认实现返回 None，没有 datagram 出口。
                let mut peer: Box<dyn crate::relay_server::StreamTrait> =
                    Box::new(FramedStream::from(peer_io, addr));
                crate::relay_server::relay_pair(
                    inbound,
                    &mut peer,
                    addr,
                    Limiter::new(1_000_000_000.),
                )
                .await;
            }
        });

        let (_client, conn) = connect_quic_client(addr, pin).await?;
        let (mut send, _recv) = conn.open_bi().await?;
        // 先确认 relay 已经转发业务流，再发 datagram：否则 datagram 可能在
        // relay 尚未处理时就被丢弃，断言失去意义。
        send.write_all(b"before").await?;
        let mut seen = read_until(&mut legacy_io, b"before").await?;

        conn.send_datagram(Bytes::from_static(b"dropped-datagram"))?;
        tokio::time::sleep(Duration::from_millis(100)).await;

        send.write_all(b"after").await?;
        seen.extend_from_slice(&read_until(&mut legacy_io, b"after").await?);
        assert!(
            !contains(&seen, b"dropped-datagram"),
            "datagram 不应落进 stream"
        );

        relay_task.abort();
        Ok(())
    }

    /// 从 legacy peer 侧读到 needle 为止；超时说明 relay 已经不再转发。
    async fn read_until(
        io: &mut tokio::io::DuplexStream,
        needle: &[u8],
    ) -> ResultType<Vec<u8>> {
        use hbb_common::tokio::io::AsyncReadExt;

        let mut seen = Vec::new();
        let mut buf = [0u8; 256];
        let read = async {
            while !contains(&seen, needle) {
                let n = io.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..n]);
            }
            Ok::<(), std::io::Error>(())
        };
        tokio::time::timeout(Duration::from_secs(2), read)
            .await
            .map_err(|_| anyhow::anyhow!("legacy peer 未在 2 秒内收到 {needle:?}"))??;
        if !contains(&seen, needle) {
            anyhow::bail!("legacy peer 已断开，未收到 {needle:?}");
        }
        Ok(seen)
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn pin_verifier_accepts_matching_self_signed_cert() {
        let certified = rcgen::generate_simple_self_signed(vec!["relay.local".to_owned()])
            .expect("generate cert");
        let cert = certified.cert.der().clone();
        let pin: [u8; 32] = Sha256::digest(cert.as_ref()).into();
        let auth_failed = Arc::new(AtomicBool::new(false));
        let verifier = PinVerifier::new(pin, auth_failed);
        let name = ServerName::try_from("relay").expect("server name");
        assert!(verifier
            .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
            .is_ok());
    }

    #[test]
    fn pin_verifier_rejects_mismatch_and_marks_auth_failed() {
        let certified = rcgen::generate_simple_self_signed(vec!["relay.local".to_owned()])
            .expect("generate cert");
        let cert = certified.cert.der().clone();
        let mut pin: [u8; 32] = Sha256::digest(cert.as_ref()).into();
        pin[0] ^= 0xff;
        let auth_failed = Arc::new(AtomicBool::new(false));
        let verifier = PinVerifier::new(pin, auth_failed.clone());
        let name = ServerName::try_from("relay").expect("server name");
        assert!(verifier
            .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
            .is_err());
        assert!(auth_failed.load(Ordering::SeqCst));
    }

    #[test]
    fn bot_token_roundtrip() {
        let secret = "test-secret";
        let uuid = "00000000-0000-4000-8000-000000000000";
        let digest = Sha256::digest(secret.as_bytes());
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&digest);
        let key = hmacsha256::Key(key_bytes);
        let tag = hmacsha256::authenticate(uuid.as_bytes(), &key);
        let token = format!("{}{}", BOT_TOKEN_PREFIX, STANDARD.encode(tag.0));
        assert!(verify_bot_token(&token, uuid, secret));
        assert!(!verify_bot_token(&token, uuid, "wrong"));
    }

    #[test]
    fn pin_roundtrip() {
        let pin = [7u8; 32];
        let value = format!("sha256:{}", STANDARD.encode(pin));
        assert_eq!(parse_pin(&value).expect("parse pin"), Some(pin));
        assert!(parse_pin("not-a-pin").is_err());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::relay_server::{RelayOptions, UpstreamConfig};
    use hbb_common::rendezvous_proto::{ConnType, RendezvousMessage, RequestRelay};
    use hbb_common::tokio;

    fn free_udp_port() -> u16 {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("bind temp udp")
            .local_addr()
            .expect("local addr")
            .port()
    }

    fn test_token(secret: &str, uuid: &str) -> String {
        let digest = Sha256::digest(secret.as_bytes());
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&digest);
        let key = hmacsha256::Key(key_bytes);
        let tag = hmacsha256::authenticate(uuid.as_bytes(), &key);
        format!("{}{}", BOT_TOKEN_PREFIX, STANDARD.encode(tag.0))
    }

    #[hbb_common::tokio::test]
    async fn quic_listener_pairs_a_pinned_client_and_rejects_wrong_pin() {
        let directory = tempfile::tempdir().expect("temp dir");
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        let certified = rcgen::generate_simple_self_signed(vec!["relay.local".to_owned()])
            .expect("generate cert");
        std::fs::write(&cert_path, certified.cert.pem()).expect("write cert");
        std::fs::write(&key_path, certified.key_pair.serialize_pem()).expect("write key");
        let pin: [u8; 32] = Sha256::digest(certified.cert.der().as_ref()).into();

        let secret = "test-secret";
        let options = Arc::new(RelayOptions {
            key: String::new(),
            token_secret: secret.to_owned(),
            upstream: UpstreamConfig {
                quic_addr: String::new(),
                tcp_addr: String::new(),
                pin: None,
                sni: String::new(),
                ipv6: IpPreference::Prefer,
            },
            services: Default::default(),
            service_timeout: Duration::from_millis(3_000),
        });
        let port = free_udp_port();
        let limiter = Limiter::new(f64::INFINITY);
        let listener = tokio::spawn(start_listener(
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port,
            Some(cert_path),
            Some(key_path),
            options,
            limiter,
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let target = format!("127.0.0.1:{port}");
        let uuid = "00000000-0000-4000-8000-000000000000";
        let request = |token: String| {
            let mut request = RequestRelay::new();
            request.uuid = uuid.to_owned();
            request.token = token;
            request.conn_type = ConnType::PORT_FORWARD.into();
            let mut message = RendezvousMessage::new();
            message.set_request_relay(request);
            message
        };

        let mut first = connect_upstream(&target, "relay", pin, IpPreference::Prefer)
            .await
            .expect("first pinned client connects");
        first
            .send(&request(test_token(secret, uuid)))
            .await
            .expect("send first relay request");

        let mut second = connect_upstream(&target, "relay", pin, IpPreference::Prefer)
            .await
            .expect("second pinned client connects");
        second
            .send(&request(test_token(secret, uuid)))
            .await
            .expect("send second relay request");

        first
            .send_bytes(Bytes::from_static(b"ping"))
            .await
            .expect("send relayed bytes");
        let received = tokio::time::timeout(Duration::from_secs(2), second.next())
            .await
            .expect("relay timeout")
            .expect("relay closed")
            .expect("relay error");
        assert_eq!(&received[..], b"ping");

        let mut bad_token = connect_upstream(&target, "relay", pin, IpPreference::Prefer)
            .await
            .expect("bad-token client connects");
        bad_token
            .send(&request(test_token("wrong-secret", uuid)))
            .await
            .expect("send bad token request");
        let closed = tokio::time::timeout(Duration::from_secs(2), bad_token.next()).await;
        assert!(
            !matches!(closed, Ok(Some(Ok(_)))),
            "invalid token must close the stream"
        );

        let mut wrong_pin = pin;
        wrong_pin[0] ^= 0xff;
        match connect_upstream(&target, "relay", wrong_pin, IpPreference::Prefer).await {
            Ok(_) => panic!("wrong pin must fail"),
            Err(error) => assert!(error.is_auth()),
        }

        listener.abort();
        drop(first);
        drop(second);
    }
}

#[cfg(test)]
mod ipv6_tests {
    use super::*;
    use crate::relay_server::{RelayOptions, UpstreamConfig};
    use hbb_common::rendezvous_proto::{ConnType, RendezvousMessage, RequestRelay};
    use hbb_common::tokio;

    fn free_ipv6_udp_port() -> Option<u16> {
        std::net::UdpSocket::bind("[::1]:0")
            .ok()
            .and_then(|socket| socket.local_addr().ok())
            .map(|addr| addr.port())
    }

    fn test_token(secret: &str, uuid: &str) -> String {
        let digest = Sha256::digest(secret.as_bytes());
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&digest);
        let key = hmacsha256::Key(key_bytes);
        let tag = hmacsha256::authenticate(uuid.as_bytes(), &key);
        format!("{}{}", BOT_TOKEN_PREFIX, STANDARD.encode(tag.0))
    }

    #[hbb_common::tokio::test]
    async fn ipv6_only_upstream_connects_to_dual_stack_listener() {
        let Some(port) = free_ipv6_udp_port() else {
            return;
        };
        let directory = tempfile::tempdir().expect("temp dir");
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        let certified = rcgen::generate_simple_self_signed(vec!["relay.local".to_owned()])
            .expect("generate cert");
        std::fs::write(&cert_path, certified.cert.pem()).expect("write cert");
        std::fs::write(&key_path, certified.key_pair.serialize_pem()).expect("write key");
        let pin: [u8; 32] = Sha256::digest(certified.cert.der().as_ref()).into();

        let secret = "test-secret";
        let options = Arc::new(RelayOptions {
            key: String::new(),
            token_secret: secret.to_owned(),
            upstream: UpstreamConfig {
                quic_addr: String::new(),
                tcp_addr: String::new(),
                pin: None,
                sni: String::new(),
                ipv6: IpPreference::Prefer,
            },
            services: Default::default(),
            service_timeout: Duration::from_millis(3_000),
        });
        let listener = tokio::spawn(start_listener(
            Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            port,
            Some(cert_path),
            Some(key_path),
            options,
            Limiter::new(f64::INFINITY),
        ));
        tokio::time::sleep(Duration::from_millis(100)).await;

        let target = format!("[::1]:{port}");
        let mut stream = connect_upstream(&target, "relay", pin, IpPreference::Only)
            .await
            .expect("IPv6-only pinned client connects");
        let uuid = "00000000-0000-4000-8000-000000000001";
        let mut request = RequestRelay::new();
        request.uuid = uuid.to_owned();
        request.token = test_token(secret, uuid);
        request.conn_type = ConnType::PORT_FORWARD.into();
        let mut message = RendezvousMessage::new();
        message.set_request_relay(request);
        stream.send(&message).await.expect("send relay request");

        listener.abort();
        drop(stream);
    }
}
