use async_speed_limit::Limiter;
use async_trait::async_trait;
use hbb_common::{
    allow_err, anyhow, bail,
    bytes::{Bytes, BytesMut},
    futures_util::{sink::SinkExt, stream::StreamExt},
    log,
    protobuf::Message as _,
    rendezvous_proto::*,
    sleep,
    tcp::FramedStream,
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{Mutex, RwLock},
        time::{interval, Duration},
    },
    ResultType,
};
use sodiumoxide::crypto::sign;
use std::{
    collections::{HashMap, HashSet},
    io::prelude::*,
    io::Error,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use crate::quic_relay::{self, IpPreference};

type Usage = (usize, usize, usize, usize);

lazy_static::lazy_static! {
    static ref PEERS: Mutex<HashMap<String, Box<dyn StreamTrait>>> = Default::default();
    static ref USAGE: RwLock<HashMap<String, Usage>> = Default::default();
    static ref BLACKLIST: RwLock<HashSet<String>> = Default::default();
    static ref BLOCKLIST: RwLock<HashSet<String>> = Default::default();
}

static DOWNGRADE_THRESHOLD_100: AtomicUsize = AtomicUsize::new(66); // 0.66
static DOWNGRADE_START_CHECK: AtomicUsize = AtomicUsize::new(1_800_000); // in ms
static LIMIT_SPEED: AtomicUsize = AtomicUsize::new(32 * 1024 * 1024); // in bit/s
static TOTAL_BANDWIDTH: AtomicUsize = AtomicUsize::new(1024 * 1024 * 1024); // in bit/s
static SINGLE_BANDWIDTH: AtomicUsize = AtomicUsize::new(128 * 1024 * 1024); // in bit/s
const BLACKLIST_FILE: &str = "blacklist.txt";
const BLOCKLIST_FILE: &str = "blocklist.txt";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transport {
    Tcp,
    WebSocket,
    Quic,
}

#[derive(Clone)]
pub(crate) struct UpstreamConfig {
    pub(crate) quic_addr: String,
    pub(crate) tcp_addr: String,
    pub(crate) pin: Option<[u8; 32]>,
    pub(crate) sni: String,
    pub(crate) ipv6: IpPreference,
}

pub(crate) struct RelayOptions {
    pub(crate) key: String,
    pub(crate) token_secret: String,
    pub(crate) upstream: UpstreamConfig,
}

#[derive(Clone)]
struct QuicListenerConfig {
    enabled: bool,
    bind: Option<IpAddr>,
    port: u16,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
}

#[tokio::main(flavor = "multi_thread")]
pub async fn start_with_bind(bind_addr: Option<IpAddr>, port: &str, key: &str) -> ResultType<()> {
    load_blocklists().await;
    let port: u16 = port.parse()?;
    log::info!("Listening on tcp :{}", port);
    log::info!("Listening on websocket :{}", port + 2);
    let key = get_server_sk(key)?;
    let (options, quic) = build_runtime_options(bind_addr, port, key)?;
    check_params();
    let limiter = Limiter::new(TOTAL_BANDWIDTH.load(Ordering::SeqCst) as _);
    let listen_signal = crate::common::listen_signal();
    tokio::select!(
        res = run_tcp_loop(bind_addr, port, options.clone(), limiter.clone()) => res,
        res = run_quic_loop(quic, options, limiter) => res,
        res = listen_signal => res,
    )
}

async fn load_blocklists() {
    load_ip_list(BLACKLIST_FILE, &BLACKLIST).await;
    load_ip_list(BLOCKLIST_FILE, &BLOCKLIST).await;
}

async fn load_ip_list(file_name: &str, list: &RwLock<HashSet<String>>) {
    if let Ok(mut file) = std::fs::File::open(file_name) {
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_ok() {
            for line in contents.lines() {
                if let Some(ip) = line.trim().split(' ').next() {
                    list.write().await.insert(ip.to_owned());
                }
            }
        }
    }
    log::info!("#{}: {}", file_name, list.read().await.len());
}

fn build_runtime_options(
    bind_addr: Option<IpAddr>,
    port: u16,
    key: String,
) -> ResultType<(Arc<RelayOptions>, QuicListenerConfig)> {
    let upstream_tcp = crate::common::get_arg("RELAY_UPSTREAM");
    let upstream_quic = crate::common::get_arg("RELAY_UPSTREAM_QUIC");
    let token_secret = crate::common::get_arg("RELAY_BOT_TOKEN_SECRET");
    let quic_enabled = parse_flag("RELAY_QUIC");
    let pin = quic_relay::parse_pin(&crate::common::get_arg("RELAY_UPSTREAM_QUIC_PIN"))?;
    let auth = crate::common::get_arg("RELAY_UPSTREAM_QUIC_AUTH");
    let fallback_on_auth_error = parse_flag("RELAY_UPSTREAM_QUIC_FALLBACK_ON_AUTH_ERROR");
    if (quic_enabled || !upstream_quic.is_empty()) && token_secret.is_empty() {
        bail!("RELAY_BOT_TOKEN_SECRET is required when QUIC relay is enabled");
    }
    if !auth.is_empty() && auth != "pin" {
        bail!("RELAY_UPSTREAM_QUIC_AUTH only supports pin in v1");
    }
    if !upstream_quic.is_empty() && pin.is_none() {
        bail!("RELAY_UPSTREAM_QUIC_PIN is required when RELAY_UPSTREAM_QUIC is set");
    }
    if fallback_on_auth_error {
        bail!("RELAY_UPSTREAM_QUIC_FALLBACK_ON_AUTH_ERROR is not supported in v1");
    }
    validate_role(&upstream_tcp, &upstream_quic)?;
    let sni = crate::common::get_arg("RELAY_UPSTREAM_QUIC_SNI");
    let ipv6 = IpPreference::from_arg(&crate::common::get_arg("RELAY_UPSTREAM_IPV6"));
    if !upstream_quic.is_empty() {
        log::info!(
            "Relay upstream quic: {} (sni={}, ipv6={:?}, auth=pin)",
            upstream_quic,
            sni,
            ipv6
        );
    }
    let options = Arc::new(RelayOptions {
        key,
        token_secret,
        upstream: UpstreamConfig {
            quic_addr: upstream_quic,
            tcp_addr: upstream_tcp,
            pin,
            sni,
            ipv6,
        },
    });
    let config = QuicListenerConfig {
        enabled: quic_enabled,
        bind: parse_quic_bind(&crate::common::get_arg("RELAY_QUIC_BIND"))?.or(bind_addr),
        port: crate::common::get_arg("RELAY_QUIC_PORT")
            .parse::<u16>()
            .ok()
            .filter(|value| *value > 0)
            .unwrap_or(port),
        cert: path_arg("RELAY_QUIC_CERT"),
        key: path_arg("RELAY_QUIC_KEY"),
    };
    Ok((options, config))
}

fn validate_role(upstream_tcp: &str, upstream_quic: &str) -> ResultType<()> {
    match crate::common::get_arg("RELAY_ROLE")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "standalone" => Ok(()),
        "master" if upstream_tcp.is_empty() && upstream_quic.is_empty() => Ok(()),
        "master" => bail!("RELAY_ROLE=master must not configure an upstream"),
        "edge" if !upstream_tcp.is_empty() || !upstream_quic.is_empty() => Ok(()),
        "edge" => bail!("RELAY_ROLE=edge requires an upstream"),
        role => bail!("invalid RELAY_ROLE: {role}"),
    }
}

async fn run_tcp_loop(
    bind_addr: Option<IpAddr>,
    port: u16,
    options: Arc<RelayOptions>,
    limiter: Limiter,
) -> ResultType<()> {
    loop {
        log::info!("Start");
        io_loop(
            crate::common::listen_tcp(bind_addr, port).await?,
            crate::common::listen_tcp(bind_addr, port + 2).await?,
            crate::common::listen_console(bind_addr, port).await?,
            options.clone(),
            limiter.clone(),
        )
        .await;
    }
}

async fn run_quic_loop(
    config: QuicListenerConfig,
    options: Arc<RelayOptions>,
    limiter: Limiter,
) -> ResultType<()> {
    if !config.enabled {
        return std::future::pending().await;
    }
    loop {
        if let Err(err) = quic_relay::start_listener(
            config.bind,
            config.port,
            config.cert.clone(),
            config.key.clone(),
            options.clone(),
            limiter.clone(),
        )
        .await
        {
            log::error!("quic listener failed: {}", err);
        }
        sleep(1.).await;
    }
}

fn parse_flag(name: &str) -> bool {
    matches!(
        crate::common::get_arg(name)
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "y" | "yes" | "true"
    )
}

fn path_arg(name: &str) -> Option<PathBuf> {
    let value = crate::common::get_arg(name);
    if value.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(value))
    }
}

fn parse_quic_bind(value: &str) -> ResultType<Option<IpAddr>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let value = if value.starts_with('[') {
        value
            .split(']')
            .next()
            .map(|value| value.trim_start_matches('['))
            .unwrap_or(value)
    } else if value.matches(':').count() > 1 {
        value
    } else {
        value.split(':').next().unwrap_or(value)
    };
    Ok(Some(value.parse().map_err(|_| {
        anyhow::anyhow!("invalid RELAY_QUIC_BIND: {value}")
    })?))
}

fn check_params() {
    let tmp = crate::common::get_arg("DOWNGRADE_THRESHOLD")
        .parse::<f64>()
        .unwrap_or(0.);
    if tmp > 0. {
        DOWNGRADE_THRESHOLD_100.store((tmp * 100.) as _, Ordering::SeqCst);
    }
    log::info!(
        "DOWNGRADE_THRESHOLD: {}",
        DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64 / 100.
    );
    let tmp = crate::common::get_arg("DOWNGRADE_START_CHECK")
        .parse::<usize>()
        .unwrap_or(0);
    if tmp > 0 {
        DOWNGRADE_START_CHECK.store(tmp * 1000, Ordering::SeqCst);
    }
    log::info!(
        "DOWNGRADE_START_CHECK: {}s",
        DOWNGRADE_START_CHECK.load(Ordering::SeqCst) / 1000
    );
    let tmp = crate::common::get_arg("LIMIT_SPEED")
        .parse::<f64>()
        .unwrap_or(0.);
    if tmp > 0. {
        LIMIT_SPEED.store((tmp * 1024. * 1024.) as usize, Ordering::SeqCst);
    }
    log::info!(
        "LIMIT_SPEED: {}Mb/s",
        LIMIT_SPEED.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    );
    let tmp = crate::common::get_arg("TOTAL_BANDWIDTH")
        .parse::<f64>()
        .unwrap_or(0.);
    if tmp > 0. {
        TOTAL_BANDWIDTH.store((tmp * 1024. * 1024.) as usize, Ordering::SeqCst);
    }

    log::info!(
        "TOTAL_BANDWIDTH: {}Mb/s",
        TOTAL_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    );
    let tmp = crate::common::get_arg("SINGLE_BANDWIDTH")
        .parse::<f64>()
        .unwrap_or(0.);
    if tmp > 0. {
        SINGLE_BANDWIDTH.store((tmp * 1024. * 1024.) as usize, Ordering::SeqCst);
    }
    log::info!(
        "SINGLE_BANDWIDTH: {}Mb/s",
        SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
    )
}

async fn check_cmd(cmd: &str, limiter: Limiter) -> String {
    use std::fmt::Write;

    let mut res = "".to_owned();
    let mut fds = cmd.trim().split(' ');
    match fds.next() {
        Some("h") => {
            res = format!(
                "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                "blacklist-add(ba) <ip>",
                "blacklist-remove(br) <ip>",
                "blacklist(b) <ip>",
                "blocklist-add(Ba) <ip>",
                "blocklist-remove(Br) <ip>",
                "blocklist(B) <ip>",
                "downgrade-threshold(dt) [value]",
                "downgrade-start-check(t) [value(second)]",
                "limit-speed(ls) [value(Mb/s)]",
                "total-bandwidth(tb) [value(Mb/s)]",
                "single-bandwidth(sb) [value(Mb/s)]",
                "usage(u)"
            )
        }
        Some("blacklist-add" | "ba") => {
            if let Some(ip) = fds.next() {
                for ip in ip.split('|') {
                    BLACKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
        Some("blacklist-remove" | "br") => {
            if let Some(ip) = fds.next() {
                if ip == "all" {
                    BLACKLIST.write().await.clear();
                } else {
                    for ip in ip.split('|') {
                        BLACKLIST.write().await.remove(ip);
                    }
                }
            }
        }
        Some("blacklist" | "b") => {
            if let Some(ip) = fds.next() {
                res = format!("{}\n", BLACKLIST.read().await.get(ip).is_some());
            } else {
                for ip in BLACKLIST.read().await.clone().into_iter() {
                    let _ = writeln!(res, "{ip}");
                }
            }
        }
        Some("blocklist-add" | "Ba") => {
            if let Some(ip) = fds.next() {
                for ip in ip.split('|') {
                    BLOCKLIST.write().await.insert(ip.to_owned());
                }
            }
        }
        Some("blocklist-remove" | "Br") => {
            if let Some(ip) = fds.next() {
                if ip == "all" {
                    BLOCKLIST.write().await.clear();
                } else {
                    for ip in ip.split('|') {
                        BLOCKLIST.write().await.remove(ip);
                    }
                }
            }
        }
        Some("blocklist" | "B") => {
            if let Some(ip) = fds.next() {
                res = format!("{}\n", BLOCKLIST.read().await.get(ip).is_some());
            } else {
                for ip in BLOCKLIST.read().await.clone().into_iter() {
                    let _ = writeln!(res, "{ip}");
                }
            }
        }
        Some("downgrade-threshold" | "dt") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        DOWNGRADE_THRESHOLD_100.store((v * 100.) as _, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!(
                    "{}\n",
                    DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64 / 100.
                );
            }
        }
        Some("downgrade-start-check" | "t") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<usize>() {
                    if v > 0 {
                        DOWNGRADE_START_CHECK.store(v * 1000, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!("{}s\n", DOWNGRADE_START_CHECK.load(Ordering::SeqCst) / 1000);
            }
        }
        Some("limit-speed" | "ls") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        LIMIT_SPEED.store((v * 1024. * 1024.) as _, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    LIMIT_SPEED.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("total-bandwidth" | "tb") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        TOTAL_BANDWIDTH.store((v * 1024. * 1024.) as _, Ordering::SeqCst);
                        limiter.set_speed_limit(TOTAL_BANDWIDTH.load(Ordering::SeqCst) as _);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    TOTAL_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("single-bandwidth" | "sb") => {
            if let Some(v) = fds.next() {
                if let Ok(v) = v.parse::<f64>() {
                    if v > 0. {
                        SINGLE_BANDWIDTH.store((v * 1024. * 1024.) as _, Ordering::SeqCst);
                    }
                }
            } else {
                res = format!(
                    "{}Mb/s\n",
                    SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64 / 1024. / 1024.
                );
            }
        }
        Some("usage" | "u") => {
            let mut tmp: Vec<(String, Usage)> = USAGE
                .read()
                .await
                .iter()
                .map(|x| (x.0.clone(), *x.1))
                .collect();
            tmp.sort_by(|a, b| ((b.1).1).partial_cmp(&(a.1).1).unwrap());
            for (ip, (elapsed, total, highest, speed)) in tmp {
                if elapsed == 0 {
                    continue;
                }
                let _ = writeln!(
                    res,
                    "{}: {}s {:.2}MB {}kb/s {}kb/s {}kb/s",
                    ip,
                    elapsed / 1000,
                    total as f64 / 1024. / 1024. / 8.,
                    highest,
                    total / elapsed,
                    speed
                );
            }
        }
        _ => {}
    }
    res
}

async fn io_loop(
    listener: TcpListener,
    listener2: TcpListener,
    listener_console: Option<TcpListener>,
    options: Arc<RelayOptions>,
    limiter: Limiter,
) {
    loop {
        tokio::select! {
            res = listener.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &options, &limiter, false).await;
                    }
                    Err(err) => {
                       log::error!("listener.accept failed: {}", err);
                       break;
                    }
                }
            }
            res = listener2.accept() => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &options, &limiter, true).await;
                    }
                    Err(err) => {
                       log::error!("listener2.accept failed: {}", err);
                       break;
                    }
                }
            }
            res = crate::common::accept_or_pending(listener_console.as_ref()) => {
                match res {
                    Ok((stream, addr))  => {
                        stream.set_nodelay(true).ok();
                        handle_connection(stream, addr, &options, &limiter, false).await;
                    }
                    Err(err) => {
                       log::error!("console listener.accept failed: {}", err);
                       break;
                    }
                }
            }
        }
    }
}

async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    options: &Arc<RelayOptions>,
    limiter: &Limiter,
    ws: bool,
) {
    let ip = hbb_common::try_into_v4(addr).ip();
    if !ws && ip.is_loopback() {
        let limiter = limiter.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let mut buffer = [0; 1024];
            if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                    let res = check_cmd(data, limiter).await;
                    stream.write_all(res.as_bytes()).await.ok();
                }
            }
        });
        return;
    }
    let ip = ip.to_string();
    if BLOCKLIST.read().await.get(&ip).is_some() {
        log::info!("{} blocked", ip);
        return;
    }
    let options = options.clone();
    let limiter = limiter.clone();
    tokio::spawn(async move {
        allow_err!(make_pair(stream, addr, options, limiter, ws).await);
    });
}

pub(crate) async fn is_blocked(ip: IpAddr) -> bool {
    BLOCKLIST.read().await.get(&ip.to_string()).is_some()
}

async fn make_pair(
    stream: TcpStream,
    mut addr: SocketAddr,
    options: Arc<RelayOptions>,
    limiter: Limiter,
    ws: bool,
) -> ResultType<()> {
    if ws {
        use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
        let callback = |req: &Request, response: Response| {
            let headers = req.headers();
            // X-Real-IP / X-Forwarded-For are trusted as-is so that the real
            // client IP is preserved when the WebSocket port runs behind a
            // reverse proxy (WSS). They are NOT validated: anyone who can reach
            // this port directly can spoof an arbitrary IP, bypassing IP-based
            // rate limiting / blocking and corrupting logged IPs. Do not expose
            // the WebSocket port directly to untrusted networks; only the
            // reverse proxy, which overwrites these headers, should be able to
            // connect to it.
            // https://github.com/rustdesk/rustdesk-server/issues/634
            let real_ip = headers
                .get("X-Real-IP")
                .or_else(|| headers.get("X-Forwarded-For"))
                .and_then(|header_value| header_value.to_str().ok());
            if let Some(ip) = real_ip {
                if ip.contains('.') {
                    addr = format!("{ip}:0").parse().unwrap_or(addr);
                } else {
                    addr = format!("[{ip}]:0").parse().unwrap_or(addr);
                }
            }
            Ok(response)
        };
        let ws_stream = tokio_tungstenite::accept_hdr_async(stream, callback).await?;
        make_pair_(ws_stream, addr, &options, limiter, Transport::WebSocket).await;
    } else {
        make_pair_(
            FramedStream::from(stream, addr),
            addr,
            &options,
            limiter,
            Transport::Tcp,
        )
        .await;
    }
    Ok(())
}

pub(crate) async fn make_pair_(
    mut stream: impl StreamTrait,
    addr: SocketAddr,
    options: &RelayOptions,
    limiter: Limiter,
    transport: Transport,
) {
    let Some(Ok(bytes)) = timeout(30_000, stream.recv()).await.ok().flatten() else {
        return;
    };
    let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) else {
        return;
    };
    let Some(rendezvous_message::Union::RequestRelay(request)) = msg_in.union else {
        return;
    };
    let is_bot = request.token.starts_with(quic_relay::BOT_TOKEN_PREFIX);
    if !authorize_request(&mut stream, &request, options, transport, addr, is_bot) {
        return;
    }
    if is_bot && !options.upstream.quic_addr.is_empty() || !options.upstream.tcp_addr.is_empty() {
        relay_upstream(stream, addr, options, limiter, bytes, is_bot, transport).await;
        return;
    }
    if !request.uuid.is_empty() {
        relay_local(stream, addr, limiter, request.uuid, transport).await;
    }
}

fn transport_name(transport: Transport) -> &'static str {
    match transport {
        Transport::Tcp => "tcp",
        Transport::WebSocket => "websocket",
        Transport::Quic => "quic",
    }
}

fn authorize_request(
    stream: &mut impl StreamTrait,
    request: &RequestRelay,
    options: &RelayOptions,
    transport: Transport,
    addr: SocketAddr,
    is_bot: bool,
) -> bool {
    if !options.key.is_empty() && request.licence_key != options.key {
        log::warn!("Relay authentication failed from {} - invalid key", addr);
        return false;
    }
    if is_bot && !quic_relay::verify_bot_token(&request.token, &request.uuid, &options.token_secret)
    {
        log::warn!(
            "Relay authentication failed from {} - invalid bot token",
            addr
        );
        stream.close_auth_failed();
        return false;
    }
    if transport == Transport::Quic && !is_bot {
        log::warn!("Relay QUIC request from {} is missing bot token", addr);
        stream.close_auth_failed();
        return false;
    }
    true
}

async fn relay_upstream(
    mut stream: impl StreamTrait,
    addr: SocketAddr,
    options: &RelayOptions,
    limiter: Limiter,
    bytes: BytesMut,
    is_bot: bool,
    inbound: Transport,
) {
    let Some((mut peer, transport, fallback)) =
        open_upstream(options, is_bot, &mut stream, addr).await
    else {
        return;
    };
    log::info!(
        "Relay upstream transport={} inbound={} fallback={} for {}",
        transport,
        transport_name(inbound),
        fallback,
        addr
    );
    if let Err(err) = peer.send_raw(bytes.freeze()).await {
        log::warn!("failed to send relay request upstream: {}", err);
        return;
    }
    relay_pair(stream, &mut peer, addr, limiter).await;
}

async fn open_upstream(
    options: &RelayOptions,
    is_bot: bool,
    stream: &mut impl StreamTrait,
    addr: SocketAddr,
) -> Option<(Box<dyn StreamTrait>, &'static str, &'static str)> {
    let mut fallback = "none";
    if is_bot && !options.upstream.quic_addr.is_empty() {
        let Some(pin) = options.upstream.pin else {
            log::warn!("relay upstream pin is missing");
            stream.close_auth_failed();
            return None;
        };
        match quic_relay::connect_upstream(
            &options.upstream.quic_addr,
            &options.upstream.sni,
            pin,
            options.upstream.ipv6,
        )
        .await
        {
            Ok(upstream) => return Some((Box::new(upstream), "quic", fallback)),
            Err(err) if err.is_auth() => {
                log::warn!("relay upstream authentication failed: {}", err);
                stream.close_auth_failed();
                return None;
            }
            Err(err) => {
                log::warn!("relay upstream quic unavailable: {}", err);
                if options.upstream.ipv6 == IpPreference::Only {
                    return None;
                }
                fallback = "network";
            }
        }
    }
    if options.upstream.tcp_addr.is_empty() {
        log::warn!("no relay upstream available for {}", addr);
        return None;
    }
    match FramedStream::new(&options.upstream.tcp_addr, None, 5_000).await {
        Ok(upstream) => Some((Box::new(upstream), "tcp", fallback)),
        Err(err) => {
            log::warn!(
                "failed to connect relay upstream {}: {}",
                options.upstream.tcp_addr,
                err
            );
            None
        }
    }
}

async fn relay_local(
    stream: impl StreamTrait,
    addr: SocketAddr,
    limiter: Limiter,
    uuid: String,
    transport: Transport,
) {
    let stream = stream;
    let mut peer = PEERS.lock().await.remove(&uuid);
    if let Some(peer) = peer.as_mut() {
        log::info!(
            "Relayrequest {} from {} transport={} got paired",
            uuid,
            addr,
            transport_name(transport)
        );
        relay_pair(stream, peer, addr, limiter).await;
    } else {
        log::info!(
            "New relay request {} from {} transport={}",
            uuid,
            addr,
            transport_name(transport)
        );
        PEERS.lock().await.insert(uuid.clone(), Box::new(stream));
        sleep(30.).await;
        PEERS.lock().await.remove(&uuid);
    }
}

async fn relay_pair(
    mut stream: impl StreamTrait,
    peer: &mut Box<dyn StreamTrait>,
    addr: SocketAddr,
    limiter: Limiter,
) {
    let id = format!("{}:{}", addr.ip(), addr.port());
    USAGE.write().await.insert(id.clone(), Default::default());
    if !stream.is_ws() && !peer.is_ws() {
        peer.set_raw();
        stream.set_raw();
        log::info!("Both are raw");
    }
    if let Err(err) = relay(addr, &mut stream, peer, limiter, id.clone()).await {
        log::info!("Relay of {} closed: {}", addr, err);
    } else {
        log::info!("Relay of {} closed", addr);
    }
    USAGE.write().await.remove(&id);
}

async fn relay(
    addr: SocketAddr,
    stream: &mut impl StreamTrait,
    peer: &mut Box<dyn StreamTrait>,
    total_limiter: Limiter,
    id: String,
) -> ResultType<()> {
    let ip = addr.ip().to_string();
    let mut tm = std::time::Instant::now();
    let mut elapsed = 0;
    let mut total = 0;
    let mut total_s = 0;
    let mut highest_s = 0;
    let mut downgrade: bool = false;
    let mut blacked: bool = false;
    let sb = SINGLE_BANDWIDTH.load(Ordering::SeqCst) as f64;
    let limiter = <Limiter>::new(sb);
    let blacklist_limiter = <Limiter>::new(LIMIT_SPEED.load(Ordering::SeqCst) as _);
    let downgrade_threshold =
        (sb * DOWNGRADE_THRESHOLD_100.load(Ordering::SeqCst) as f64 / 100. / 1000.) as usize; // in bit/ms
    let mut timer = interval(Duration::from_secs(3));
    let mut last_recv_time = std::time::Instant::now();
    loop {
        tokio::select! {
            res = peer.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    } else {
                        limiter.consume(nb).await;
                    }
                    total_limiter.consume(nb).await;
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        stream.send_raw(bytes.into()).await?;
                    }
                } else {
                    break;
                }
            },
            res = stream.recv() => {
                if let Some(Ok(bytes)) = res {
                    last_recv_time = std::time::Instant::now();
                    let nb = bytes.len() * 8;
                    if blacked || downgrade {
                        blacklist_limiter.consume(nb).await;
                    } else {
                        limiter.consume(nb).await;
                    }
                    total_limiter.consume(nb).await;
                    total += nb;
                    total_s += nb;
                    if !bytes.is_empty() {
                        peer.send_raw(bytes.into()).await?;
                    }
                } else {
                    break;
                }
            },
            _ = timer.tick() => {
                if last_recv_time.elapsed().as_secs() > 30 {
                    bail!("Timeout");
                }
            }
        }

        let n = tm.elapsed().as_millis() as usize;
        if n >= 1_000 {
            if BLOCKLIST.read().await.get(&ip).is_some() {
                log::info!("{} blocked", ip);
                break;
            }
            blacked = BLACKLIST.read().await.get(&ip).is_some();
            tm = std::time::Instant::now();
            let speed = total_s / n;
            if speed > highest_s {
                highest_s = speed;
            }
            elapsed += n;
            USAGE.write().await.insert(
                id.clone(),
                (elapsed as _, total as _, highest_s as _, speed as _),
            );
            total_s = 0;
            if elapsed > DOWNGRADE_START_CHECK.load(Ordering::SeqCst)
                && !downgrade
                && total > elapsed * downgrade_threshold
            {
                downgrade = true;
                log::info!(
                    "Downgrade {}, exceed downgrade threshold {}bit/ms in {}ms",
                    id,
                    downgrade_threshold,
                    elapsed
                );
            }
        }
    }
    Ok(())
}

fn get_server_sk(key: &str) -> ResultType<String> {
    let mut key = key.to_owned();
    if let Ok(sk) = base64::decode(&key) {
        if sk.len() == sign::SECRETKEYBYTES {
            log::info!("The key is a crypto private key");
            key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
        }
    }

    if key == "-" || key == "_" {
        let (pk, _) = crate::common::gen_sk(300)?;
        key = pk;
    }

    if !key.is_empty() {
        log::info!("Key: {}", key);
    }

    Ok(key)
}

#[async_trait]
pub(crate) trait StreamTrait: Send + Sync + 'static {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>>;
    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()>;
    fn is_ws(&self) -> bool;
    fn set_raw(&mut self);
    fn close_auth_failed(&mut self) {}
}

#[async_trait]
impl StreamTrait for FramedStream {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
        self.next().await
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        self.send_bytes(bytes).await
    }

    fn is_ws(&self) -> bool {
        false
    }

    fn set_raw(&mut self) {
        self.set_raw();
    }
}

#[async_trait]
impl StreamTrait for tokio_tungstenite::WebSocketStream<TcpStream> {
    async fn recv(&mut self) -> Option<Result<BytesMut, Error>> {
        if let Some(msg) = self.next().await {
            match msg {
                Ok(msg) => {
                    match msg {
                        tungstenite::Message::Binary(bytes) => {
                            Some(Ok(bytes[..].into())) // to-do: poor performance
                        }
                        _ => Some(Ok(BytesMut::new())),
                    }
                }
                Err(err) => Some(Err(Error::new(std::io::ErrorKind::Other, err.to_string()))),
            }
        } else {
            None
        }
    }

    async fn send_raw(&mut self, bytes: Bytes) -> ResultType<()> {
        Ok(self
            .send(tungstenite::Message::Binary(bytes.to_vec()))
            .await?) // to-do: poor performance
    }

    fn is_ws(&self) -> bool {
        true
    }

    fn set_raw(&mut self) {}
}
