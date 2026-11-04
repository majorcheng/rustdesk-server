use crate::common::{get_arg, now};
use crate::federation::Federation;
use crate::peer::{DirectoryPeer, PeerMap};
use axum::{
    extract::{Extension, Path, Query},
    http::{header, HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use hbb_common::tokio::sync::RwLock;
use hbb_common::{anyhow::anyhow, log, tokio, ResultType};
use serde::{Deserialize, Serialize};
use sodiumoxide::utils::memcmp;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const SNAPSHOT_TTL: Duration = Duration::from_secs(120);
const LINK_STALE_AFTER: Duration = Duration::from_secs(30);
const DEFAULT_LIMIT: usize = 1024;
const MAX_LIMIT: usize = 4096;
const TOKEN_MIN_LEN: usize = 32;
const TOKEN_MAX_LEN: usize = 256;

#[derive(Clone)]
struct DirectoryState {
    peers: PeerMap,
    federation: Federation,
    token: Arc<String>,
    snapshots: Arc<RwLock<std::collections::HashMap<String, StoredSnapshot>>>,
    next_snapshot: Arc<AtomicU64>,
}

#[derive(Clone)]
struct StoredSnapshot {
    peers: Arc<Vec<DirectoryPeer>>,
    sites: Arc<Vec<DirectorySite>>,
    created: Instant,
}

#[derive(Clone, Serialize)]
struct DirectorySite {
    node_id: String,
    connected: bool,
    last_control_observed_at: i64,
    observed_source_ip: Option<String>,
}

#[derive(Serialize)]
struct PeerView {
    id: String,
    uuid: String,
    pk: String,
    owner: String,
    source_ip: String,
    online: bool,
    lease_age_ms: Option<u64>,
}

impl From<DirectoryPeer> for PeerView {
    fn from(peer: DirectoryPeer) -> Self {
        Self {
            id: peer.id,
            uuid: base64::encode(peer.uuid),
            pk: base64::encode(peer.pk),
            owner: peer.owner,
            source_ip: peer.source_ip,
            online: peer.online,
            lease_age_ms: peer.lease_age_ms,
        }
    }
}

#[derive(Serialize)]
struct SnapshotResponse {
    snapshot_id: String,
    observed_at: i64,
    complete: bool,
    sites: Vec<DirectorySite>,
    peers: Vec<PeerView>,
    next_cursor: Option<usize>,
}

#[derive(Deserialize)]
struct SnapshotQuery {
    snapshot: Option<String>,
    cursor: Option<usize>,
    limit: Option<usize>,
}

pub(crate) async fn start(peers: PeerMap, federation: Federation) -> ResultType<()> {
    let bind = get_arg("FEDERATION_DIRECTORY_BIND");
    if bind.is_empty() {
        return Ok(());
    }
    let token = get_arg("FEDERATION_DIRECTORY_TOKEN");
    if token.is_empty() {
        return Err(anyhow!(
            "FEDERATION_DIRECTORY_TOKEN is required when FEDERATION_DIRECTORY_BIND is set"
        ));
    }
    if token.len() < TOKEN_MIN_LEN
        || token.len() > TOKEN_MAX_LEN
        || token.chars().any(char::is_whitespace)
    {
        return Err(anyhow!(
            "FEDERATION_DIRECTORY_TOKEN must be {TOKEN_MIN_LEN}..={TOKEN_MAX_LEN} non-whitespace bytes"
        ));
    }
    let addr: SocketAddr = bind
        .parse()
        .map_err(|_| anyhow!("FEDERATION_DIRECTORY_BIND must be IP:port"))?;
    if !addr.ip().is_loopback() || addr.port() == 0 {
        return Err(anyhow!(
            "FEDERATION_DIRECTORY_BIND must be a loopback IP and non-zero port"
        ));
    }
    let state = Arc::new(DirectoryState {
        peers,
        federation,
        token: Arc::new(token),
        snapshots: Default::default(),
        next_snapshot: Default::default(),
    });
    let app = Router::new()
        .route("/internal/v1/peer-snapshot", get(peer_snapshot))
        .route("/internal/v1/peers/:id", get(peer_identity))
        .layer(Extension(state));
    let server = axum::Server::bind(&addr).serve(app.into_make_service());
    log::info!("federation directory listening on {}", addr);
    tokio::spawn(async move {
        if let Err(err) = server.await {
            log::error!("federation directory stopped: {}", err);
        }
    });
    Ok(())
}

async fn peer_snapshot(
    Extension(state): Extension<Arc<DirectoryState>>,
    headers: HeaderMap,
    Query(query): Query<SnapshotQuery>,
) -> Result<Json<SnapshotResponse>, StatusCode> {
    authorize(&state, &headers)?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let cursor = query.cursor.unwrap_or(0);
    let (snapshot_id, stored) = match query.snapshot.as_deref().filter(|value| !value.is_empty()) {
        Some(id) => {
            let snapshots = state.snapshots.read().await;
            let Some(stored) = snapshots.get(id) else {
                return Err(StatusCode::GONE);
            };
            if stored.created.elapsed() > SNAPSHOT_TTL {
                return Err(StatusCode::GONE);
            }
            (id.to_owned(), stored.clone())
        }
        None => {
            let peers = state.peers.directory_snapshot().await.map_err(|error| {
                log::warn!("federation directory snapshot failed: {}", error);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            let sites = build_sites(&state.federation).await;
            let id = format!("{}", state.next_snapshot.fetch_add(1, Ordering::SeqCst));
            let stored = StoredSnapshot {
                peers: Arc::new(peers),
                sites: Arc::new(sites),
                created: Instant::now(),
            };
            let mut snapshots = state.snapshots.write().await;
            snapshots.retain(|_, item| item.created.elapsed() <= SNAPSHOT_TTL);
            snapshots.insert(id.clone(), stored.clone());
            (id, stored)
        }
    };
    if cursor > stored.peers.len() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let end = cursor.saturating_add(limit).min(stored.peers.len());
    let peers = stored.peers[cursor..end]
        .iter()
        .cloned()
        .map(PeerView::from)
        .collect();
    let next_cursor = (end < stored.peers.len()).then_some(end);
    Ok(Json(SnapshotResponse {
        snapshot_id,
        observed_at: now() as i64,
        complete: next_cursor.is_none(),
        sites: stored.sites.as_ref().clone(),
        peers,
        next_cursor,
    }))
}

async fn peer_identity(
    Extension(state): Extension<Arc<DirectoryState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<PeerView>, StatusCode> {
    authorize(&state, &headers)?;
    let peer = state.peers.directory_peer(&id).await.map_err(|error| {
        log::warn!("federation directory identity lookup failed: {}", error);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    peer.map(PeerView::from)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

fn authorize(state: &DirectoryState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let value = value.to_str().map_err(|_| StatusCode::UNAUTHORIZED)?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if token.len() != state.token.len() || !memcmp(token.as_bytes(), state.token.as_bytes()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(())
}

async fn build_sites(federation: &Federation) -> Vec<DirectorySite> {
    let observed_at = now() as i64;
    let mut sites = vec![DirectorySite {
        node_id: if federation.node_id().is_empty() {
            "local".to_owned()
        } else {
            federation.node_id().to_owned()
        },
        connected: true,
        last_control_observed_at: observed_at,
        observed_source_ip: None,
    }];
    for state in federation.node_states().await {
        sites.push(DirectorySite {
            node_id: state.node_id,
            connected: state.last_seen.elapsed() <= LINK_STALE_AFTER,
            last_control_observed_at: observed_at - state.last_seen.elapsed().as_secs() as i64,
            observed_source_ip: Some(state.source_ip.ip().to_string()),
        });
    }
    sites
}
