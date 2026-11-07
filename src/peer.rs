use crate::common::*;
use crate::database;
use crate::federation::PeerLease;
use crate::registration::KnownPeer;
use hbb_common::{
    bytes::Bytes,
    log,
    rendezvous_proto::*,
    tokio::sync::{Mutex, RwLock},
    ResultType,
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, collections::HashSet, net::SocketAddr, sync::Arc, time::Instant};

type IpBlockMap = HashMap<String, ((u32, Instant), (HashSet<String>, Instant))>;
type UserStatusMap = HashMap<Vec<u8>, Arc<(Option<Vec<u8>>, bool)>>;
type IpChangesMap = HashMap<String, (Instant, HashMap<String, i32>)>;
lazy_static::lazy_static! {
    pub(crate) static ref IP_BLOCKER: Mutex<IpBlockMap> = Default::default();
    pub(crate) static ref USER_STATUS: RwLock<UserStatusMap> = Default::default();
    pub(crate) static ref IP_CHANGES: Mutex<IpChangesMap> = Default::default();
}
pub const IP_CHANGE_DUR: u64 = 180;
pub const IP_CHANGE_DUR_X2: u64 = IP_CHANGE_DUR * 2;
pub const DAY_SECONDS: u64 = 3600 * 24;
pub const IP_BLOCK_DUR: u64 = 60;
// Same bound as the Pro server: a longer id is not a normal RustDesk id or hostname,
// and every peer entry and punch-request record keeps its own copy.
pub const MAX_PEER_ID_LEN: usize = 253;
pub(crate) const PEER_REG_TIMEOUT_MS: i64 = 30_000;

pub(crate) fn is_deliverable_addr(addr: SocketAddr) -> bool {
    addr.port() != 0 && !addr.ip().is_unspecified()
}

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct PeerInfo {
    #[serde(default)]
    pub(crate) ip: String,
}

pub(crate) struct Peer {
    pub(crate) socket_addr: SocketAddr,
    pub(crate) last_reg_time: Instant,
    pub(crate) guid: Vec<u8>,
    pub(crate) uuid: Bytes,
    pub(crate) pk: Bytes,
    // pub(crate) user: Option<Vec<u8>>,
    pub(crate) info: PeerInfo,
    // pub(crate) disabled: bool,
    pub(crate) reg_pk: (u32, Instant), // how often register_pk
    pub(crate) owner: String,
    /// 已登记的恢复公钥。内存副本用于避免按心跳重复读写 `peer_recovery` 表。
    pub(crate) recovery_pk: Bytes,
    /// 内存副本是否已经与 `peer_recovery` 表同步过；未同步时按需读库一次。
    pub(crate) recovery_loaded: bool,
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            socket_addr: "0.0.0.0:0".parse().unwrap(),
            last_reg_time: get_expired_time(),
            guid: Vec::new(),
            uuid: Bytes::new(),
            pk: Bytes::new(),
            info: Default::default(),
            // user: None,
            // disabled: false,
            reg_pk: (0, get_expired_time()),
            owner: String::new(),
            recovery_pk: Bytes::new(),
            recovery_loaded: false,
        }
    }
}

impl Peer {
    // Database records and remote leases keep the 0.0.0.0:0 placeholder until
    // the peer registers an address, so freshness alone is not enough to make
    // it a usable request target.
    pub(crate) fn is_reachable(&self) -> bool {
        (self.last_reg_time.elapsed().as_millis() as i64) < PEER_REG_TIMEOUT_MS
            && is_deliverable_addr(self.socket_addr)
    }
}

pub(crate) type LockPeer = Arc<RwLock<Peer>>;

#[derive(Clone, Debug)]
pub(crate) struct DirectoryPeer {
    pub(crate) id: String,
    pub(crate) uuid: Vec<u8>,
    pub(crate) pk: Vec<u8>,
    pub(crate) owner: String,
    pub(crate) source_ip: String,
    pub(crate) online: bool,
    pub(crate) lease_age_ms: Option<u64>,
}

#[derive(Clone)]
pub(crate) struct PeerMap {
    map: Arc<RwLock<HashMap<String, LockPeer>>>,
    pub(crate) db: database::Database,
    local_node: String,
}

impl PeerMap {
    pub(crate) async fn new(local_node: String) -> ResultType<Self> {
        let db = get_arg_opt("DB_URL").unwrap_or_else(|| {
            let mut db = "db_v2.sqlite3".to_owned();
            #[cfg(all(windows, not(debug_assertions)))]
            {
                if let Some(path) = hbb_common::config::Config::icon_path().parent() {
                    db = format!("{}\\{}", path.to_str().unwrap_or("."), db);
                }
            }
            #[cfg(not(windows))]
            {
                db = format!("./{db}");
            }
            db
        });
        log::info!("DB_URL={}", db);
        let pm = Self {
            map: Default::default(),
            db: database::Database::new(&db).await?,
            local_node,
        };
        Ok(pm)
    }

    #[inline]
    pub(crate) async fn update_pk(
        &mut self,
        id: String,
        peer: LockPeer,
        addr: SocketAddr,
        uuid: Bytes,
        pk: Bytes,
        ip: String,
    ) -> register_pk_response::Result {
        log::info!("update_pk {} {:?} {:?} {:?}", id, addr, uuid, pk);
        let (info_str, guid) = {
            let mut w = peer.write().await;
            w.socket_addr = addr;
            w.uuid = uuid.clone();
            w.pk = pk.clone();
            w.last_reg_time = Instant::now();
            w.info.ip = ip;
            w.owner = self.local_node.clone();
            (
                serde_json::to_string(&w.info).unwrap_or_default(),
                w.guid.clone(),
            )
        };
        if guid.is_empty() {
            match self.db.insert_peer(&id, &uuid, &pk, &info_str).await {
                Err(err) => {
                    log::error!("db.insert_peer failed: {}", err);
                    return register_pk_response::Result::SERVER_ERROR;
                }
                Ok(guid) => {
                    peer.write().await.guid = guid;
                }
            }
        } else {
            if let Err(err) = self.db.update_pk(&guid, &id, &pk, &info_str).await {
                log::error!("db.update_pk failed: {}", err);
                return register_pk_response::Result::SERVER_ERROR;
            }
            log::info!("pk updated instead of insert");
        }
        register_pk_response::Result::OK
    }

    #[inline]
    pub(crate) async fn get(&self, id: &str) -> Option<LockPeer> {
        let p = self.map.read().await.get(id).cloned();
        if p.is_some() {
            return p;
        } else if let Ok(Some(v)) = self.db.get_peer(id).await {
            let peer = Peer {
                guid: v.guid,
                uuid: v.uuid.into(),
                pk: v.pk.into(),
                // user: v.user,
                info: serde_json::from_str::<PeerInfo>(&v.info).unwrap_or_default(),
                // disabled: v.status == Some(0),
                owner: self.local_node.clone(),
                ..Default::default()
            };
            let peer = Arc::new(RwLock::new(peer));
            let mut map = self.map.write().await;
            return Some(map.entry(id.to_owned()).or_insert(peer).clone());
        }
        None
    }

    #[inline]
    pub(crate) async fn get_or(&self, id: &str) -> LockPeer {
        if let Some(p) = self.get(id).await {
            return p;
        }
        let mut w = self.map.write().await;
        if let Some(p) = w.get(id) {
            return p.clone();
        }
        let tmp = Arc::new(RwLock::new(Peer {
            owner: self.local_node.clone(),
            ..Default::default()
        }));
        w.insert(id.to_owned(), tmp.clone());
        tmp
    }

    #[inline]
    pub(crate) async fn get_in_memory(&self, id: &str) -> Option<LockPeer> {
        self.map.read().await.get(id).cloned()
    }

    #[inline]
    pub(crate) async fn is_in_memory(&self, id: &str) -> bool {
        self.map.read().await.contains_key(id)
    }

    pub(crate) async fn remote_owner(&self, id: &str) -> Option<String> {
        let peer = self.map.read().await.get(id).cloned()?;
        let peer = peer.read().await;
        if peer.owner.is_empty() || peer.owner == self.local_node {
            None
        } else {
            Some(peer.owner.clone())
        }
    }

    pub(crate) async fn upsert_remote(&self, owner: String, lease: PeerLease) {
        if owner.is_empty() || owner == self.local_node {
            return;
        }
        let peer = {
            let mut map = self.map.write().await;
            map.entry(lease.id.clone())
                .or_insert_with(|| Arc::new(RwLock::new(Peer::default())))
                .clone()
        };
        let store_recovery = {
            let mut peer = peer.write().await;
            // 只有本地注册已经失效时才让租约接管；可达的本地注册视为更新，不被远端覆盖。
            if peer.owner == self.local_node && peer.is_reachable() {
                return;
            }
            peer.socket_addr = "0.0.0.0:0".parse().unwrap_or(peer.socket_addr);
            peer.last_reg_time = Instant::now();
            peer.uuid = lease.uuid.into();
            peer.pk = lease.pk.into();
            peer.info.ip = lease.ip;
            peer.owner = owner;
            // 心跳会反复推动租约；只在恢复公钥真正变化时写库，避免按心跳放大写入。
            if !lease.recovery_pk.is_empty() {
                peer.recovery_loaded = true;
                if peer.recovery_pk != lease.recovery_pk.as_slice() {
                    peer.recovery_pk = lease.recovery_pk.clone().into();
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        if store_recovery {
            if let Err(err) = self.db.set_recovery(&lease.id, &lease.recovery_pk).await {
                log::error!("peer_recovery write failed for {}: {}", lease.id, err);
            }
        }
    }

    pub(crate) async fn remove_remote(&self, owner: &str) -> Vec<String> {
        let mut map = self.map.write().await;
        let ids: Vec<String> = map
            .iter()
            .filter_map(|(id, peer)| {
                if let Ok(peer) = peer.try_read() {
                    if peer.owner == owner {
                        return Some(id.clone());
                    }
                }
                None
            })
            .collect();
        for id in &ids {
            map.remove(id);
        }
        ids
    }

    pub(crate) async fn remove_remote_peer(&self, owner: &str, id: &str) {
        let mut map = self.map.write().await;
        let remove = map
            .get(id)
            .and_then(|peer| peer.try_read().ok())
            .map(|peer| peer.owner == owner)
            .unwrap_or(false);
        if remove {
            map.remove(id);
        }
    }

    pub(crate) async fn snapshot(&self, id: &str) -> Option<PeerLease> {
        let (uuid, pk, ip) = {
            let peer = self.map.read().await.get(id).cloned()?;
            let peer = peer.read().await;
            if peer.owner != self.local_node || peer.pk.is_empty() || !peer.is_reachable() {
                return None;
            }
            (peer.uuid.to_vec(), peer.pk.to_vec(), peer.info.ip.clone())
        };
        Some(PeerLease {
            id: id.to_owned(),
            uuid,
            pk,
            ip,
            recovery_pk: self.recovery(id).await.ok().flatten().unwrap_or_default(),
        })
    }

    /// 本地是否需要为这个 peer 建立（或接管）注册记录。
    ///
    /// 内存里只有远端租约、或本地记录已失效时都必须写一次：否则本节点的记录没有可用地址，
    /// 会一直向设备索要 `request_pk`，也永远不会发布自己的租约。
    pub(crate) async fn needs_local_takeover(&self, id: &str) -> bool {
        match self.get_in_memory(id).await {
            Some(peer) => {
                let peer = peer.read().await;
                peer.owner != self.local_node || !peer.is_reachable()
            }
            None => true,
        }
    }

    pub(crate) async fn recovery(&self, id: &str) -> ResultType<Option<Vec<u8>>> {
        if let Some(peer) = self.get_in_memory(id).await {
            let peer = peer.read().await;
            if peer.recovery_loaded {
                return Ok((!peer.recovery_pk.is_empty()).then(|| peer.recovery_pk.to_vec()));
            }
        }
        let stored = self.db.get_recovery(id).await?;
        if let Some(peer) = self.get_in_memory(id).await {
            let mut peer = peer.write().await;
            peer.recovery_loaded = true;
            match stored.as_ref() {
                Some(value) => peer.recovery_pk = value.clone().into(),
                None => peer.recovery_pk = Bytes::new(),
            }
        }
        Ok(stored)
    }

    pub(crate) async fn remember_recovery(&self, id: &str, recovery_pk: &[u8]) -> ResultType<()> {
        if let Some(peer) = self.get_in_memory(id).await {
            let mut peer = peer.write().await;
            peer.recovery_pk = recovery_pk.to_vec().into();
            peer.recovery_loaded = true;
        }
        self.db.set_recovery(id, recovery_pk).await
    }

    /// 注册判定可用的已有身份。
    ///
    /// uuid/pk 取当前视图：本地内存记录（本地注册或叶子租约）。来源 IP 只能来自本地注册，
    /// 远端租约里的地址是对方站点看到的地址，不可比。因此租约覆盖了本地记录时，
    /// 仍从本地 DB 行取可比来源地址。
    pub(crate) async fn known_peer(&self, id: &str) -> ResultType<Option<KnownPeer>> {
        if let Some(peer) = self.get_in_memory(id).await {
            let peer = peer.read().await;
            if !peer.uuid.is_empty() || !peer.pk.is_empty() {
                if peer.owner == self.local_node {
                    return Ok(Some(KnownPeer {
                        uuid: peer.uuid.to_vec(),
                        pk: peer.pk.to_vec(),
                        local_ip: Some(peer.info.ip.clone()),
                    }));
                }
                let uuid = peer.uuid.to_vec();
                let pk = peer.pk.to_vec();
                drop(peer);
                let local_ip = self
                    .db
                    .get_peer(id)
                    .await?
                    .map(|peer| peer_info_ip(&peer));
                return Ok(Some(KnownPeer {
                    uuid,
                    pk,
                    local_ip,
                }));
            }
        }
        let Some(peer) = self.db.get_peer(id).await? else {
            return Ok(None);
        };
        Ok(Some(KnownPeer {
            local_ip: Some(peer_info_ip(&peer)),
            uuid: peer.uuid,
            pk: peer.pk,
        }))
    }

    pub(crate) async fn snapshots(&self) -> Vec<PeerLease> {
        let ids: Vec<String> = self.map.read().await.keys().cloned().collect();
        let mut snapshots = Vec::new();
        for id in ids {
            if let Some(snapshot) = self.snapshot(&id).await {
                snapshots.push(snapshot);
            }
        }
        snapshots
    }

    pub(crate) async fn directory_snapshot(&self) -> ResultType<Vec<DirectoryPeer>> {
        let db_peers = self.db.list_peers().await?;
        let entries: Vec<(String, LockPeer)> = self
            .map
            .read()
            .await
            .iter()
            .map(|(id, peer)| (id.clone(), peer.clone()))
            .collect();
        let mut memory = HashMap::new();
        for (id, peer) in entries {
            let peer = peer.read().await;
            memory.insert(
                id.clone(),
                directory_peer_from_peer(&id, &peer, self.local_node.as_str()),
            );
        }
        let mut peers = Vec::with_capacity(db_peers.len().max(memory.len()));
        for db_peer in db_peers {
            if let Some(peer) = memory.remove(&db_peer.id) {
                peers.push(peer);
            } else {
                peers.push(directory_peer_from_db(db_peer, self.local_node.as_str()));
            }
        }
        peers.extend(memory.into_values());
        peers.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(peers)
    }

    pub(crate) async fn directory_peer(&self, id: &str) -> ResultType<Option<DirectoryPeer>> {
        if let Some(peer) = self.get_in_memory(id).await {
            let peer = peer.read().await;
            return Ok(Some(directory_peer_from_peer(
                id,
                &peer,
                self.local_node.as_str(),
            )));
        }
        let Some(db_peer) = self.db.get_peer(id).await? else {
            return Ok(None);
        };
        if let Some(peer) = self.get_in_memory(id).await {
            let peer = peer.read().await;
            return Ok(Some(directory_peer_from_peer(
                id,
                &peer,
                self.local_node.as_str(),
            )));
        }
        Ok(Some(directory_peer_from_db(
            db_peer,
            self.local_node.as_str(),
        )))
    }
}

fn directory_peer_from_peer(id: &str, peer: &Peer, local_node: &str) -> DirectoryPeer {
    let owner = if peer.owner.is_empty() {
        local_node.to_owned()
    } else {
        peer.owner.clone()
    };
    let online = if owner == local_node {
        peer.is_reachable()
    } else {
        (peer.last_reg_time.elapsed().as_millis() as i64) < PEER_REG_TIMEOUT_MS
    };
    DirectoryPeer {
        id: id.to_owned(),
        uuid: peer.uuid.to_vec(),
        pk: peer.pk.to_vec(),
        owner,
        source_ip: peer.info.ip.clone(),
        online,
        lease_age_ms: Some(peer.last_reg_time.elapsed().as_millis() as u64),
    }
}

fn peer_info_ip(peer: &database::Peer) -> String {
    serde_json::from_str::<PeerInfo>(&peer.info)
        .unwrap_or_default()
        .ip
}

fn directory_peer_from_db(peer: database::Peer, local_node: &str) -> DirectoryPeer {
    let info = serde_json::from_str::<PeerInfo>(&peer.info).unwrap_or_default();
    DirectoryPeer {
        id: peer.id,
        uuid: peer.uuid,
        pk: peer.pk,
        owner: local_node.to_owned(),
        source_ip: info.ip,
        online: false,
        lease_age_ms: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;
    use std::time::Duration;

    async fn test_peer_map() -> (PeerMap, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("peer.sqlite3");
        let db = database::Database::new(path.to_str().unwrap()).await.unwrap();
        (
            PeerMap {
                map: Default::default(),
                db,
                local_node: "B".to_owned(),
            },
            directory,
        )
    }

    fn remote_lease(id: &str) -> PeerLease {
        PeerLease {
            id: id.to_owned(),
            uuid: vec![2],
            pk: vec![3],
            ip: "36.112.108.165".to_owned(),
            recovery_pk: vec![4],
        }
    }

    #[hbb_common::tokio::test]
    async fn expired_database_peer_accepts_remote_lease() {
        let (peer_map, _directory) = test_peer_map().await;
        let id = "428172967";
        peer_map
            .db
            .insert_peer(id, &[1], &[1], r#"{"ip":"123.116.41.115"}"#)
            .await
            .unwrap();

        let peer = peer_map.get(id).await.expect("database peer should load");
        assert_eq!(peer.read().await.owner, "B");

        peer_map.upsert_remote("A".to_owned(), remote_lease(id)).await;

        let peer = peer_map.get_in_memory(id).await.expect("peer should remain");
        let peer = peer.read().await;
        assert_eq!(peer.owner, "A");
        assert_eq!(peer.info.ip, "36.112.108.165");
        assert_eq!(peer_map.remote_owner(id).await.as_deref(), Some("A"));
        assert!((peer.last_reg_time.elapsed().as_millis() as i64) < PEER_REG_TIMEOUT_MS);
    }

    #[hbb_common::tokio::test]
    async fn fresh_local_peer_keeps_local_lease() {
        let (peer_map, _directory) = test_peer_map().await;
        let id = "488257584";
        let peer = Arc::new(RwLock::new(Peer {
            socket_addr: "222.131.66.42:21116".parse().unwrap(),
            last_reg_time: Instant::now(),
            uuid: vec![1].into(),
            pk: vec![1].into(),
            info: PeerInfo {
                ip: "222.131.66.42".to_owned(),
            },
            owner: "B".to_owned(),
            ..Default::default()
        }));
        peer_map.map.write().await.insert(id.to_owned(), peer);

        peer_map.upsert_remote("A".to_owned(), remote_lease(id)).await;

        let peer = peer_map.get_in_memory(id).await.expect("peer should remain");
        let peer = peer.read().await;
        assert_eq!(peer.owner, "B");
        assert_eq!(peer.socket_addr, "222.131.66.42:21116".parse().unwrap());
        assert_eq!(peer.uuid.as_ref(), [1].as_slice());
        assert_eq!(peer.pk.as_ref(), [1].as_slice());
        assert_eq!(peer.info.ip, "222.131.66.42");
        assert!(peer_map.remote_owner(id).await.is_none());
    }

    #[hbb_common::tokio::test]
    async fn takeover_is_required_when_only_a_lease_exists() {
        let (peer_map, _directory) = test_peer_map().await;
        let id = "rb-64b8716b53b1dba65ebf3f0036c15840";
        assert!(peer_map.needs_local_takeover(id).await);

        peer_map
            .db
            .insert_peer(id, b"uuid-1", &[1u8; 32], r#"{"ip":"10.1.100.148"}"#)
            .await
            .unwrap();
        peer_map
            .upsert_remote("A".to_owned(), remote_lease(id))
            .await;
        // 内存里是远端租约：来源地址不可比，必须由本地注册接管。
        assert!(peer_map.needs_local_takeover(id).await);

        let peer = Arc::new(RwLock::new(Peer {
            socket_addr: "10.1.100.148:21116".parse().unwrap(),
            last_reg_time: Instant::now(),
            uuid: vec![1].into(),
            pk: vec![1].into(),
            info: PeerInfo {
                ip: "10.1.100.148".to_owned(),
            },
            owner: "B".to_owned(),
            ..Default::default()
        }));
        peer_map.map.write().await.insert(id.to_owned(), peer);
        assert!(!peer_map.needs_local_takeover(id).await);

        let stale = Arc::new(RwLock::new(Peer {
            socket_addr: "10.1.100.148:21116".parse().unwrap(),
            last_reg_time: Instant::now() - Duration::from_secs(120),
            uuid: vec![1].into(),
            pk: vec![1].into(),
            info: PeerInfo {
                ip: "10.1.100.148".to_owned(),
            },
            owner: "B".to_owned(),
            ..Default::default()
        }));
        peer_map.map.write().await.insert(id.to_owned(), stale);
        assert!(peer_map.needs_local_takeover(id).await);
    }

    #[hbb_common::tokio::test]
    async fn known_peer_keeps_local_ip_when_lease_wins() {
        let (peer_map, _directory) = test_peer_map().await;
        let id = "rb-64b8716b53b1dba65ebf3f0036c15840";
        peer_map
            .db
            .insert_peer(id, b"uuid-1", &[1u8; 32], r#"{"ip":"36.112.108.165"}"#)
            .await
            .unwrap();
        // 叶子租约覆盖内存记录：uuid/pk 取租约，可比来源 IP 仍取本地注册行。
        peer_map
            .upsert_remote(
                "A".to_owned(),
                PeerLease {
                    id: id.to_owned(),
                    uuid: b"uuid-1".to_vec(),
                    pk: vec![3u8; 32],
                    ip: "10.1.100.148".to_owned(),
                    recovery_pk: vec![4u8; 32],
                },
            )
            .await;

        let known = peer_map.known_peer(id).await.unwrap().expect("known peer");
        assert_eq!(known.pk, vec![3u8; 32]);
        assert_eq!(known.uuid, b"uuid-1".to_vec());
        assert_eq!(known.local_ip.as_deref(), Some("36.112.108.165"));
        // 租约携带的恢复公钥写入本地表，供后续本地轮换校验。
        assert_eq!(peer_map.recovery(id).await.unwrap(), Some(vec![4u8; 32]));
    }

    #[hbb_common::tokio::test]
    async fn expired_local_peer_is_not_published() {
        let (peer_map, _directory) = test_peer_map().await;
        let id = "rb-expired";
        let peer = Arc::new(RwLock::new(Peer {
            socket_addr: "127.0.0.1:21116".parse().unwrap(),
            last_reg_time: Instant::now() - Duration::from_secs(60),
            uuid: vec![1].into(),
            pk: vec![1].into(),
            info: PeerInfo {
                ip: "127.0.0.1".to_owned(),
            },
            owner: "B".to_owned(),
            ..Default::default()
        }));
        peer_map.map.write().await.insert(id.to_owned(), peer);

        assert!(peer_map.snapshots().await.is_empty());
    }

    #[hbb_common::tokio::test]
    async fn directory_snapshot_prefers_remote_lease_over_local_db() {
        let (peer_map, _directory) = test_peer_map().await;
        let id = "rb-remote";
        peer_map
            .db
            .insert_peer(id, &[1], &[1], r#"{"ip":"10.0.0.1"}"#)
            .await
            .unwrap();
        peer_map.upsert_remote("A".to_owned(), remote_lease(id)).await;

        let peers = peer_map.directory_snapshot().await.unwrap();
        let peer = peers.iter().find(|peer| peer.id == id).unwrap();
        assert_eq!(peer.owner, "A");
        assert_eq!(peer.uuid, vec![2]);
        assert_eq!(peer.pk, vec![3]);
        assert_eq!(peer.source_ip, "36.112.108.165");
        assert!(peer.online);

        let peer = peer_map.directory_peer(id).await.unwrap().unwrap();
        assert_eq!(peer.owner, "A");
        assert_eq!(peer.pk, vec![3]);
    }

    #[hbb_common::tokio::test]
    async fn directory_snapshot_includes_local_db_peer_as_offline() {
        let (peer_map, _directory) = test_peer_map().await;
        let id = "rb-local";
        peer_map
            .db
            .insert_peer(id, &[1], &[1], r#"{"ip":"10.0.0.1"}"#)
            .await
            .unwrap();

        let peers = peer_map.directory_snapshot().await.unwrap();
        let peer = peers.iter().find(|peer| peer.id == id).unwrap();
        assert_eq!(peer.owner, "B");
        assert_eq!(peer.uuid, vec![1]);
        assert_eq!(peer.pk, vec![1]);
        assert_eq!(peer.source_ip, "10.0.0.1");
        assert!(!peer.online);
        assert!(peer.lease_age_ms.is_none());
    }

    #[hbb_common::tokio::test]
    async fn directory_peer_returns_none_for_unknown_id() {
        let (peer_map, _directory) = test_peer_map().await;
        assert!(peer_map.directory_peer("rb-unknown").await.unwrap().is_none());
    }
}
