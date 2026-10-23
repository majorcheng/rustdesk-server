use crate::common::*;
use crate::database;
use crate::federation::PeerLease;
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
        }
    }
}

pub(crate) type LockPeer = Arc<RwLock<Peer>>;

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
        let mut peer = peer.write().await;
        if peer.owner == self.local_node
            && (peer.last_reg_time.elapsed().as_millis() as i64) < PEER_REG_TIMEOUT_MS
        {
            return;
        }
        peer.socket_addr = "0.0.0.0:0".parse().unwrap_or(peer.socket_addr);
        peer.last_reg_time = Instant::now();
        peer.uuid = lease.uuid.into();
        peer.pk = lease.pk.into();
        peer.info.ip = lease.ip;
        peer.owner = owner;
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
        let peer = self.map.read().await.get(id).cloned()?;
        let peer = peer.read().await;
        if peer.owner != self.local_node || peer.pk.is_empty() {
            return None;
        }
        Some(PeerLease {
            id: id.to_owned(),
            uuid: peer.uuid.to_vec(),
            pk: peer.pk.to_vec(),
            ip: peer.info.ip.clone(),
        })
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;

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
}
