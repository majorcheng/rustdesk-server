//! RustBot 服务流首包与服务映射。
//!
//! 服务帧沿用 relay 的 length-frame，只在 payload 开头使用独立标识，
//! 因此不需要修改 hbb_common 的 RendezvousMessage 定义。

use hbb_common::{
    bail,
    bytes::Bytes,
    sha2::{Digest, Sha256},
    sodiumoxide::{crypto::auth::hmacsha256, utils::memcmp},
    ResultType,
};
use std::{collections::HashMap, path::PathBuf};

/// 0x00 不是合法的 protobuf 字段 tag，可与 RendezvousMessage 稳定区分。
pub(crate) const MAGIC: [u8; 5] = [0x00, b'R', b'B', b'S', b'V'];
pub(crate) const VERSION: u8 = 1;
const REQUEST_ID_LEN: usize = 16;
const PROOF_LEN: usize = 32;
const MAX_SERVICE_ID_LEN: usize = 64;
const PROOF_DOMAIN: &[u8] = b"rustbot-service-v1";
const HEADER_LEN: usize = MAGIC.len() + 1 + REQUEST_ID_LEN + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServiceCode {
    Ok = 0,
    NotFound = 1,
    Denied = 2,
    Unavailable = 3,
    UnsupportedVersion = 4,
}

impl ServiceCode {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotFound => "service_not_found",
            Self::Denied => "denied",
            Self::Unavailable => "unavailable",
            Self::UnsupportedVersion => "unsupported_version",
        }
    }

    #[cfg(test)]
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Ok),
            1 => Some(Self::NotFound),
            2 => Some(Self::Denied),
            3 => Some(Self::Unavailable),
            4 => Some(Self::UnsupportedVersion),
            _ => None,
        }
    }
}

/// 服务名：小写字母或数字开头，只允许小写字母、数字、点、下划线和连字符。
pub(crate) fn valid_service_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit() => {}
        _ => return false,
    }
    value.len() <= MAX_SERVICE_ID_LEN
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// 设备自报身份：只用于审计，从不参与准入判定。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientInfo {
    pub(crate) peer_id: String,
    pub(crate) hdid: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceRequest {
    pub(crate) version: u8,
    pub(crate) service_id: String,
    pub(crate) request_id: [u8; REQUEST_ID_LEN],
    pub(crate) proof: [u8; PROOF_LEN],
    pub(crate) client_info: Option<ClientInfo>,
}

impl ServiceRequest {
    pub(crate) fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() < HEADER_LEN + PROOF_LEN || !is_service_frame(payload) {
            return None;
        }
        let version = payload[MAGIC.len()];
        if version == 0 {
            return None;
        }
        let mut request_id = [0u8; REQUEST_ID_LEN];
        request_id.copy_from_slice(&payload[MAGIC.len() + 1..MAGIC.len() + 1 + REQUEST_ID_LEN]);
        let id_len = payload[MAGIC.len() + 1 + REQUEST_ID_LEN] as usize;
        if id_len == 0 || payload.len() < HEADER_LEN + id_len + PROOF_LEN {
            return None;
        }
        let service_id = std::str::from_utf8(&payload[HEADER_LEN..HEADER_LEN + id_len]).ok()?;
        if !valid_service_id(service_id) {
            return None;
        }
        let proof_start = HEADER_LEN + id_len;
        let mut proof = [0u8; PROOF_LEN];
        proof.copy_from_slice(&payload[proof_start..proof_start + PROOF_LEN]);
        let client_info = parse_client_info(&payload[proof_start + PROOF_LEN..])?;
        Some(Self {
            version,
            service_id: service_id.to_owned(),
            request_id,
            proof,
            client_info,
        })
    }

    #[cfg(test)]
    pub(crate) fn encode(&self) -> Bytes {
        let id = self.service_id.as_bytes();
        let mut payload = Vec::with_capacity(HEADER_LEN + id.len() + PROOF_LEN + 64);
        payload.extend_from_slice(&MAGIC);
        payload.push(self.version);
        payload.extend_from_slice(&self.request_id);
        payload.push(id.len() as u8);
        payload.extend_from_slice(id);
        payload.extend_from_slice(&self.proof);
        if let Some(info) = &self.client_info {
            let mut body = Vec::with_capacity(info.peer_id.len() + info.hdid.len() + 4);
            push_u16(&mut body, info.peer_id.as_bytes());
            push_u16(&mut body, info.hdid.as_bytes());
            push_u16(&mut payload, &body);
        }
        Bytes::from(payload)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServiceResult {
    pub(crate) version: u8,
    pub(crate) request_id: [u8; REQUEST_ID_LEN],
    pub(crate) code: ServiceCode,
}

impl ServiceResult {
    pub(crate) fn encode(&self) -> Bytes {
        let mut payload = Vec::with_capacity(HEADER_LEN + 1);
        payload.extend_from_slice(&MAGIC);
        payload.push(self.version);
        payload.extend_from_slice(&self.request_id);
        payload.push(self.code as u8);
        Bytes::from(payload)
    }

    #[cfg(test)]
    pub(crate) fn parse(payload: &[u8]) -> Option<Self> {
        if payload.len() != HEADER_LEN || !is_service_frame(payload) {
            return None;
        }
        let mut request_id = [0u8; REQUEST_ID_LEN];
        request_id.copy_from_slice(&payload[MAGIC.len() + 1..MAGIC.len() + 1 + REQUEST_ID_LEN]);
        Some(Self {
            version: payload[MAGIC.len()],
            request_id,
            code: ServiceCode::from_u8(payload[HEADER_LEN - 1])?,
        })
    }
}

fn push_u16(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

fn take_u16<'a>(input: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(2)?;
    let len = u16::from_be_bytes(input.get(*offset..end)?.try_into().ok()?) as usize;
    *offset = end;
    let end = offset.checked_add(len)?;
    let value = input.get(*offset..end)?;
    *offset = end;
    Some(value)
}

/// 尾部可选块：`u16 长度 + {peer_id, hdid}`。没有尾部视为旧客户端。
fn parse_client_info(tail: &[u8]) -> Option<Option<ClientInfo>> {
    if tail.is_empty() {
        return Some(None);
    }
    let mut offset = 0;
    let body = take_u16(tail, &mut offset)?;
    if offset != tail.len() {
        return None;
    }
    let mut inner = 0;
    let peer_id = std::str::from_utf8(take_u16(body, &mut inner)?).ok()?;
    let hdid = std::str::from_utf8(take_u16(body, &mut inner)?).ok()?;
    if inner != body.len() || peer_id.is_empty() || peer_id.len() > 64 || hdid.len() > 255 {
        return None;
    }
    Some(Some(ClientInfo {
        peer_id: peer_id.to_owned(),
        hdid: hdid.to_owned(),
    }))
}

pub(crate) fn is_service_frame(payload: &[u8]) -> bool {
    payload.starts_with(&MAGIC)
}

/// 准入证明的输入：域串 + 版本 + 请求标识 + 服务名。
fn proof_input(version: u8, service_id: &str, request_id: &[u8; REQUEST_ID_LEN]) -> Vec<u8> {
    let mut input = Vec::with_capacity(PROOF_DOMAIN.len() + 1 + REQUEST_ID_LEN + service_id.len());
    input.extend_from_slice(PROOF_DOMAIN);
    input.push(version);
    input.extend_from_slice(request_id);
    input.extend_from_slice(service_id.as_bytes());
    input
}

/// 与 relay bot token 使用同一 secret 派生方式，但域串独立，不能互相挪用。
pub(crate) fn proof(
    secret: &str,
    version: u8,
    service_id: &str,
    request_id: &[u8; REQUEST_ID_LEN],
) -> [u8; PROOF_LEN] {
    let digest = Sha256::digest(secret.as_bytes());
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&digest);
    let key = hmacsha256::Key(key_bytes);
    hmacsha256::authenticate(&proof_input(version, service_id, request_id), &key).0
}

pub(crate) fn verify(secret: &str, request: &ServiceRequest) -> bool {
    if secret.is_empty() {
        return false;
    }
    let expected = proof(
        secret,
        request.version,
        &request.service_id,
        &request.request_id,
    );
    memcmp(&expected, &request.proof)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ServiceTarget {
    Unix(PathBuf),
    Tcp(String),
}

/// 解析 `RELAY_SERVICES`：`name=unix:/path,name2=tcp:127.0.0.1:21202`。
pub(crate) fn parse_targets(value: &str) -> ResultType<HashMap<String, ServiceTarget>> {
    let mut targets = HashMap::new();
    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let Some((name, target)) = entry.split_once('=') else {
            bail!("RELAY_SERVICES 条目缺少 '='：{entry}");
        };
        let name = name.trim();
        if !valid_service_id(name) {
            bail!("RELAY_SERVICES 服务名无效：{name}");
        }
        let target = target.trim();
        let parsed = if let Some(path) = target.strip_prefix("unix:") {
            if path.is_empty() {
                bail!("RELAY_SERVICES 的 unix 目标缺少路径：{entry}");
            }
            ServiceTarget::Unix(PathBuf::from(path))
        } else if let Some(addr) = target.strip_prefix("tcp:") {
            if addr.is_empty() {
                bail!("RELAY_SERVICES 的 tcp 目标缺少地址：{entry}");
            }
            ServiceTarget::Tcp(addr.to_owned())
        } else {
            bail!("RELAY_SERVICES 目标必须以 unix: 或 tcp: 开头：{entry}");
        };
        if targets.insert(name.to_owned(), parsed).is_some() {
            bail!("RELAY_SERVICES 服务名重复：{name}");
        }
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(version: u8, service_id: &str, request_id: [u8; REQUEST_ID_LEN]) -> ServiceRequest {
        ServiceRequest {
            version,
            service_id: service_id.to_owned(),
            request_id,
            proof: proof("secret", version, service_id, &request_id),
            client_info: None,
        }
    }

    #[test]
    fn service_frame_roundtrip() {
        let request = request(1, "rustnet.management", [9u8; REQUEST_ID_LEN]);
        let encoded = request.encode();
        assert!(is_service_frame(&encoded));
        assert_eq!(ServiceRequest::parse(&encoded), Some(request));
    }

    #[test]
    fn client_info_roundtrip_and_tampering() {
        let mut request = request(1, "rustnet.observer", [4u8; REQUEST_ID_LEN]);
        request.client_info = Some(ClientInfo {
            peer_id: "rb-64b8716b53b1dba65ebf3f0036c15840".to_owned(),
            hdid: "Y0PF-W74P-1PSM-ZWV9".to_owned(),
        });
        let encoded = request.encode();
        assert_eq!(ServiceRequest::parse(&encoded), Some(request.clone()));

        // 无尾部时保持旧格式
        let mut legacy = request.clone();
        legacy.client_info = None;
        assert_eq!(ServiceRequest::parse(&legacy.encode()), Some(legacy));

        // 尾部截断必须整帧被拒
        assert!(ServiceRequest::parse(&encoded[..encoded.len() - 1]).is_none());
        // 尾部带多余字节也必须被拒
        let mut extra = encoded.to_vec();
        extra.push(0);
        assert!(ServiceRequest::parse(&extra).is_none());
    }

    #[test]
    fn service_frame_is_not_confused_with_rendezvous_message() {
        // 合法 protobuf 的首字节是字段 tag，最小为 0x08；服务标识以 0x00 开头。
        assert!(!is_service_frame(&[0x08, 0x01, 0x12, 0x00]));
        assert!(!is_service_frame(b"rustbot-quic-v1:abc"));
        assert!(is_service_frame(&MAGIC));
    }

    #[test]
    fn proof_binds_service_version_and_request_id() {
        let request = request(1, "rustnet.management", [3u8; REQUEST_ID_LEN]);
        assert!(verify("secret", &request));
        assert!(!verify("other", &request));
        assert!(!verify("", &request));

        let mut tampered = request.clone();
        tampered.service_id = "rustnet.other".to_owned();
        assert!(!verify("secret", &tampered));

        let mut tampered = request.clone();
        tampered.version = 2;
        assert!(!verify("secret", &tampered));

        let mut tampered = request;
        tampered.request_id[0] ^= 0xff;
        assert!(!verify("secret", &tampered));
    }

    #[test]
    fn rejects_malformed_requests() {
        let request = request(1, "rustnet.management", [1u8; REQUEST_ID_LEN]);
        let encoded = request.encode();

        assert!(ServiceRequest::parse(&encoded[..encoded.len() - 1]).is_none());
        let mut wrong_magic = encoded.to_vec();
        wrong_magic[1] = b'X';
        assert!(ServiceRequest::parse(&wrong_magic).is_none());
        let mut zero_version = encoded.to_vec();
        zero_version[MAGIC.len()] = 0;
        assert!(ServiceRequest::parse(&zero_version).is_none());
        let mut bad_id = encoded.to_vec();
        bad_id[HEADER_LEN] = b' ';
        assert!(ServiceRequest::parse(&bad_id).is_none());
        let mut long_id = encoded.to_vec();
        long_id[MAGIC.len() + 1 + REQUEST_ID_LEN] = 0;
        assert!(ServiceRequest::parse(&long_id).is_none());
    }

    #[test]
    fn result_roundtrip() {
        let result = ServiceResult {
            version: 1,
            request_id: [4u8; REQUEST_ID_LEN],
            code: ServiceCode::Unavailable,
        };
        let encoded = result.encode();
        assert_eq!(ServiceResult::parse(&encoded), Some(result));
    }

    #[test]
    fn service_id_rules() {
        assert!(valid_service_id("rustnet.management"));
        assert!(valid_service_id("a"));
        assert!(!valid_service_id(""));
        assert!(!valid_service_id(".hidden"));
        assert!(!valid_service_id("Upper"));
        assert!(!valid_service_id("with space"));
        assert!(!valid_service_id(&"a".repeat(MAX_SERVICE_ID_LEN + 1)));
    }

    #[test]
    fn target_parsing() {
        let targets = parse_targets("rustnet.management=unix:/run/rustbot-api/management.sock,")
            .unwrap_or_default();
        assert_eq!(
            targets.get("rustnet.management"),
            Some(&ServiceTarget::Unix(PathBuf::from(
                "/run/rustbot-api/management.sock"
            )))
        );

        let targets = parse_targets("a=tcp:127.0.0.1:21202").unwrap_or_default();
        assert_eq!(
            targets.get("a"),
            Some(&ServiceTarget::Tcp("127.0.0.1:21202".to_owned()))
        );

        assert!(parse_targets("").unwrap_or_default().is_empty());
        assert!(parse_targets("no separator").is_err());
        assert!(parse_targets("a=http://127.0.0.1").is_err());
        assert!(parse_targets("a=unix:").is_err());
        assert!(parse_targets("a=tcp:1.2.3.4:1,a=tcp:1.2.3.5:1").is_err());
    }
}
